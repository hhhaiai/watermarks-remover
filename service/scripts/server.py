#!/usr/bin/env python3
"""HTTP service exposing the watermarks-remover cleaning pipeline.

Stdlib-only. The agent skill and any web app can call it over HTTP instead of
running the CLI scripts locally.

Endpoints:
    GET  /health         -> {"ok": true, "version": ...}
    GET  /capabilities   -> which optional tools / pixel backends are present
    GET  /openapi.json   -> dynamically generated OpenAPI 3.0.3 spec
    POST /inspect        -> {"file": <base64>, "name": "x.png"} -> findings JSON
    POST /detect         -> {"file": <base64>, "name": "x.txt"} -> watermark detector reports
    POST /extract        -> {"file": <base64>, "name": "x.txt"} -> normalized evidence report
    POST /extract/batch  -> {"files": [{"file": <base64>, "name": "x.txt"}, ...]}
    POST /v1/extract     -> versioned alias for the evidence report contract
    POST /v1/extract/batch -> versioned batch evidence contract
    POST /clean          -> {"file": <base64>, "name": "x.png", "options": {...}}
                         -> {"cleaned": <base64>, "report": {...}}
    POST /inspect/batch  -> {"files": [{"file": <base64>, "name": "x.png"}, ...]}
                         -> {"results": [{"name", "ok", "kind", "report", "suspicious"}, ...]}
    POST /detect/batch   -> {"files": [{"file": <base64>, "name": "x.txt"}, ...]}
                         -> {"results": [{"name", "ok", "kind", "detections", "report"}, ...]}
    POST /clean/batch    -> {"files": [{"file": <base64>, "name": "x.png", "options": {...}}, ...]}
                         -> {"results": [{"name", "ok", "kind", "cleaned", "report"}, ...]}

Batch endpoints loop the same single-file pipeline as /inspect, /detect, and /clean; a
per-file failure (unknown format, oversized name, bad option) shows up as
that entry's "ok": false with an "error" string and never aborts the rest of
the batch. Capped at WATERMARKS_MAX_BATCH_FILES entries per request (default
50) — the existing MAX_BODY_BYTES envelope cap still bounds total payload
size the same as a single-file request.

Hardening mirrors the CLIs: input size caps, binary-as-text guard, atomic
writes, loopback-only bind by default, optional bearer API key. Run it as an
unprivileged user (the Docker image does). Intended for a trusted network;
expose through a reverse proxy if reachable from untrusted clients.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import subprocess
import sys
import tempfile
import uuid
from functools import cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from av_meta import clean_av, detect_av_format, inspect_av
from common import (
    MAX_INPUT_BYTES,
    eprint,
    looks_binary,
    safe_arg,
    subprocess_creationflags,
    subprocess_preexec_fn,
    which,
)
from container_meta import (
    DEEP_IMAGE_MODES,
    clean_container,
    detect_container_format,
    inspect_container,
)
from format_dispatch import classify_bytes
from image_meta import clean_image, inspect_image, run_synthid_score
from image_meta import detect_format as detect_image_format
from score_stylometry import score_text_stylometry
from text_detectors import (
    detector_status,
    normalize_detector_report,
    run_all_text_detectors,
    run_text_detectors,
)
from text_unicode import clean_text, extract_unicode_evidence, inspect_text

VERSION = os.environ.get("WATERMARKS_SERVER_VERSION", "dev")
EVIDENCE_SCHEMA_NAME = "watermarks-remover.evidence"
EVIDENCE_SCHEMA_VERSION = "1.0.0"
EVIDENCE_STATUS_VALUES = (
    "detected",
    "not_detected",
    "inconclusive",
    "unavailable",
    "error",
)

# Optional bearer token: when set, every request must send
# `Authorization: Bearer <key>`. Empty means no auth (default).
API_KEY = os.environ.get("WATERMARKS_SERVER_API_KEY", "").strip()

# Body cap for the JSON envelope. Base64 inflates by 4/3, so the decoded file
# stays well under MAX_INPUT_BYTES for the same cap.
MAX_BODY_BYTES = MAX_INPUT_BYTES + (MAX_INPUT_BYTES >> 1)

# Per-request file count cap for /inspect/batch and /clean/batch. MAX_BODY_BYTES
# already bounds total payload size; this bounds worst-case CPU/thread time from
# a request packing many tiny files into one call.
MAX_BATCH_FILES = int(os.environ.get("WATERMARKS_MAX_BATCH_FILES", "50"))

ALLOWED_CLEAN_OPTIONS = {
    "nfkc": bool,
    "aggressive_homoglyphs": bool,
    "keep_non_ai_metadata": bool,
    "also_layer_a_text": bool,
    "remove_pixel": str,
    "strip_all_metadata": bool,
    "detect_before": bool,
    "detect_after": bool,
    "deep_images": str,
}


@cache
def _ghostscript_usable() -> bool:
    """True when a Ghostscript binary is present and runnable.

    Cached and guarded like _tool_usable: /capabilities is polled, and probing
    spawns a process every time otherwise.
    """
    from container_meta import which_ghostscript

    gs = which_ghostscript()
    if not gs:
        return False
    try:
        r = subprocess.run(
            [gs, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            preexec_fn=subprocess_preexec_fn,
            creationflags=subprocess_creationflags,
        )
        return r.returncode == 0
    except Exception:
        return False


def _json_ok(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


# Flag that makes each tool print its version and exit 0. They disagree:
# exiftool treats `--version` as an unknown option and prints usage instead.
_VERSION_FLAG = {"c2patool": "--version", "exiftool": "-ver", "qpdf": "--version"}


@cache
def _tool_usable(cmd: str) -> bool:
    """True only when the tool is on PATH *and* can actually execute.

    `which` alone answers the wrong question. A binary built for another
    architecture sits on PATH and still dies before main() -- the published
    image pins a multi-arch base digest, so an arm64 host gets an arm64 image
    carrying the x86_64-only c2patool release. Advertising that as available
    is what lets a probe which never ran read as a clean verdict downstream.

    Cached: a container's tool set cannot change while the process lives.
    """
    path = which(cmd)
    if not path:
        return False
    try:
        r = subprocess.run(
            [path, _VERSION_FLAG.get(cmd, "--version")],
            capture_output=True,
            text=True,
            timeout=10,
            preexec_fn=subprocess_preexec_fn,
            check=False,
            creationflags=subprocess_creationflags,
        )
    except Exception:
        return False
    return r.returncode == 0


def capabilities() -> dict[str, Any]:
    return {
        "version": VERSION,
        "api_versions": ["legacy", "v1"],
        "evidence_schema": {
            "name": EVIDENCE_SCHEMA_NAME,
            "version": EVIDENCE_SCHEMA_VERSION,
            "status_values": list(EVIDENCE_STATUS_VALUES),
        },
        "tools": {
            "c2patool": _tool_usable("c2patool"),
            "exiftool": _tool_usable("exiftool"),
            "qpdf": _tool_usable("qpdf"),
            "ghostscript": _ghostscript_usable(),
        },
        "pixel_backends": {
            "ctrlregen": bool(os.environ.get("NOAI_WATERMARK_DIR")),
            "diffusion": bool(os.environ.get("MARKDIFFUSION_DIR")),
        },
        "scorers": {
            "synthid": bool(os.environ.get("REVERSE_SYNTHID_DIR")),
            "synthid_http": bool(os.environ.get("WATERMARKS_SYNTHID_SCORER_URL")),
            "stylometry": True,
        },
        "text_detectors": detector_status(),
        "harnesses": {
            "markllm": bool(os.environ.get("MARKLLM_DIR")),
        },
    }


# OpenAPI generation. The spec is built from this single declarative table
# plus live runtime values (version, auth, allowed options), so it can never
# drift from the endpoints the handler actually serves. Served at /openapi.json.


def _schema(**props: Any) -> dict[str, Any]:
    return props


def _file_request(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "required": ["file"],
        "properties": {
            "file": {
                "type": "string",
                "description": "Base64-encoded file bytes",
                "example": "SGVsbG8gd29ybGQ=",
            },
            "name": {
                "type": "string",
                "description": "Original filename (extension drives format routing)",
                "example": "notes.md",
            },
        },
    }
    if extra:
        schema["properties"].update(extra["properties"])
        schema["required"] = schema["required"] + extra.get("required", [])
    return schema


def _clean_request_schema() -> dict[str, Any]:
    options: dict[str, Any] = {}
    for key, kind in ALLOWED_CLEAN_OPTIONS.items():
        if kind is bool:
            options[key] = _schema(type="boolean")
        else:
            options[key] = _schema(type="string")
    return _file_request(
        {
            "properties": {
                "options": _schema(type="object", properties=options, additionalProperties=False)
            },
        }
    )


def _evidence_item_response_schema() -> dict[str, Any]:
    return _schema(
        type="object",
        required=[
            "evidence_id",
            "schema_version",
            "source_sha256",
            "layer",
            "extractor",
            "status",
            "carrier",
            "confidence_level",
            "verification",
            "locator",
        ],
        properties={
            "evidence_id": _schema(type="string", pattern="^ev_[a-f0-9]{24}$"),
            "schema_version": _schema(type="string", enum=[EVIDENCE_SCHEMA_VERSION]),
            "source_sha256": _schema(type="string", pattern="^[a-f0-9]{64}$"),
            "layer": _schema(type="string"),
            "extractor": _schema(type="string"),
            "status": _schema(type="string", enum=list(EVIDENCE_STATUS_VALUES)),
            "carrier": _schema(type="string"),
            "confidence_level": _schema(
                type="string",
                enum=["confirmed", "probable", "informational", "unknown"],
            ),
            "verification": _schema(
                type="object",
                required=["status", "method"],
                properties={
                    "status": _schema(
                        type="string",
                        enum=[
                            "verified",
                            "candidate",
                            "not_applicable",
                            "unavailable",
                            "error",
                        ],
                    ),
                    "method": _schema(type="string"),
                },
            ),
            "locator": _schema(type="object", additionalProperties=True),
        },
        additionalProperties=True,
    )


def _evidence_response_schema() -> dict[str, Any]:
    return _schema(
        type="object",
        required=[
            "ok",
            "request_id",
            "schema",
            "workflow",
            "source",
            "verdict",
            "coverage",
            "evidence",
            "evidence_summary",
            "limitations",
            "extractor_versions",
            "report",
            "detections",
        ],
        properties={
            "ok": _schema(type="boolean", enum=[True]),
            "request_id": _schema(type="string"),
            "schema": _schema(
                type="object",
                required=["name", "version", "status_values"],
                properties={
                    "name": _schema(type="string", enum=[EVIDENCE_SCHEMA_NAME]),
                    "version": _schema(type="string", enum=[EVIDENCE_SCHEMA_VERSION]),
                    "status_values": _schema(
                        type="array",
                        items=_schema(type="string", enum=list(EVIDENCE_STATUS_VALUES)),
                    ),
                },
            ),
            "workflow": _schema(
                type="object",
                required=["stage", "read_only", "input_mutated"],
                properties={
                    "stage": _schema(type="string", enum=["extract"]),
                    "read_only": _schema(type="boolean", enum=[True]),
                    "input_mutated": _schema(type="boolean", enum=[False]),
                },
            ),
            "source": _schema(
                type="object",
                required=["sha256", "size", "declared_filename", "media_type", "kind"],
                properties={
                    "sha256": _schema(type="string", pattern="^[a-f0-9]{64}$"),
                    "size": _schema(type="integer", minimum=0),
                    "declared_filename": _schema(type="string"),
                    "media_type": _schema(type="string"),
                    "detected_media_type": _schema(type="string"),
                    "declared_media_type": _schema(type="string"),
                    "kind": _schema(
                        type="string",
                        enum=["text", "image", "container", "av", "unknown"],
                    ),
                },
            ),
            "verdict": _schema(type="string", enum=list(EVIDENCE_STATUS_VALUES)),
            "coverage": _schema(type="number", minimum=0, maximum=1),
            "evidence": _schema(type="array", items=_evidence_item_response_schema()),
            "evidence_summary": _schema(
                type="object",
                required=[
                    "evidence_count",
                    "status_counts",
                    "layer_counts",
                    "verification_counts",
                ],
                properties={
                    "evidence_count": _schema(type="integer", minimum=0),
                    "status_counts": _schema(type="object", additionalProperties=True),
                    "layer_counts": _schema(type="object", additionalProperties=True),
                    "verification_counts": _schema(type="object", additionalProperties=True),
                },
            ),
            "limitations": _schema(type="array", items=_schema(type="string")),
            "extractor_versions": _schema(type="object", additionalProperties=True),
            "report": _schema(type="object", additionalProperties=True),
            "detections": _schema(type="array", items=_schema(type="object")),
        },
    )


_OPENAPI_PATHS: dict[str, dict[str, Any]] = {
    "/health": {
        "get": {
            "summary": "Liveness and version",
            "responses": {
                "200": _schema(
                    type="object",
                    properties={"ok": _schema(type="boolean"), "version": _schema(type="string")},
                )
            },
        }
    },
    "/capabilities": {
        "get": {
            "summary": "Which optional tools and heavy backends are available",
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "version": _schema(type="string"),
                        "api_versions": _schema(
                            type="array",
                            items=_schema(type="string", enum=["legacy", "v1"]),
                        ),
                        "evidence_schema": _schema(
                            type="object",
                            required=["name", "version", "status_values"],
                            properties={
                                "name": _schema(type="string", enum=[EVIDENCE_SCHEMA_NAME]),
                                "version": _schema(type="string", enum=[EVIDENCE_SCHEMA_VERSION]),
                                "status_values": _schema(
                                    type="array",
                                    items=_schema(type="string", enum=list(EVIDENCE_STATUS_VALUES)),
                                ),
                            },
                        ),
                        "tools": _schema(
                            type="object",
                            properties={
                                k: _schema(type="boolean")
                                for k in ("c2patool", "exiftool", "qpdf", "ghostscript")
                            },
                        ),
                        "pixel_backends": _schema(
                            type="object",
                            properties={
                                k: _schema(type="boolean") for k in ("ctrlregen", "diffusion")
                            },
                        ),
                        "scorers": _schema(
                            type="object",
                            properties={
                                "synthid": _schema(type="boolean"),
                                "synthid_http": _schema(type="boolean"),
                                "stylometry": _schema(type="boolean"),
                            },
                        ),
                        "harnesses": _schema(
                            type="object", properties={"markllm": _schema(type="boolean")}
                        ),
                        "text_detectors": _schema(
                            type="object",
                            additionalProperties=_schema(type="boolean"),
                        ),
                    },
                )
            },
        }
    },
    "/openapi.json": {
        "get": {
            "summary": "This OpenAPI 3.0.3 document, generated dynamically",
            "responses": {
                "200": _schema(type="object", description="An OpenAPI 3.0.3 document"),
            },
        }
    },
    "/inspect": {
        "post": {
            "summary": "Inspect a file for AI provenance marks (text / image / container auto-routed)",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_file_request(
                            {
                                "properties": {
                                    "detect": _schema(
                                        type="boolean",
                                        description=(
                                            "Also run configured text watermark detectors "
                                            "(opt-in; may call vendor APIs and send text "
                                            "to them)"
                                        ),
                                    )
                                },
                                "required": [],
                            }
                        )
                    )
                },
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "kind": _schema(type="string", enum=["text", "image", "container", "av"]),
                        "suspicious": _schema(type="boolean"),
                        "report": _schema(type="object"),
                    },
                )
            },
        }
    },
    "/clean": {
        "post": {
            "summary": "Clean a file; returns the cleaned bytes and an actions/stats report",
            "requestBody": _schema(
                required=True,
                content={"application/json": _schema(schema=_clean_request_schema())},
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "kind": _schema(type="string", enum=["text", "image", "container", "av"]),
                        "cleaned": _schema(
                            type="string", description="Base64-encoded cleaned file bytes"
                        ),
                        "report": _schema(type="object"),
                    },
                )
            },
        }
    },
    "/detect": {
        "post": {
            "summary": "Run watermark detectors on a file (text: vendor/statistical; image: SynthID score)",
            "requestBody": _schema(
                required=True,
                content={"application/json": _schema(schema=_file_request())},
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "kind": _schema(type="string", enum=["text", "image", "container", "av"]),
                        "detections": _schema(type="array", items=_schema(type="object")),
                    },
                )
            },
        }
    },
    "/extract": {
        "post": {
            "summary": "Extract normalized watermark/provenance evidence without modifying the input",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_file_request(
                            {
                                "properties": {
                                    "mime": _schema(
                                        type="string",
                                        description="Optional client-declared MIME type; never overrides byte classification",
                                    )
                                }
                            }
                        )
                    )
                },
            ),
            "responses": {"200": _evidence_response_schema()},
        }
    },
    "/extract/batch": {
        "post": {
            "summary": f"Extract normalized evidence from up to {MAX_BATCH_FILES} files",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_schema(
                            type="object",
                            required=["files"],
                            properties={"files": _schema(type="array", items=_file_request())},
                        )
                    )
                },
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "request_id": _schema(type="string"),
                        "results": _schema(
                            type="array",
                            items=_schema(
                                oneOf=[
                                    _evidence_response_schema(),
                                    _schema(
                                        type="object",
                                        required=["name", "ok", "request_id", "error"],
                                        properties={
                                            "name": _schema(type="string"),
                                            "ok": _schema(type="boolean", enum=[False]),
                                            "request_id": _schema(type="string"),
                                            "error": _schema(type="string"),
                                        },
                                    ),
                                ]
                            ),
                        ),
                    },
                )
            },
        }
    },
    "/inspect/batch": {
        "post": {
            "summary": f"Inspect up to {MAX_BATCH_FILES} files in one request",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_schema(
                            type="object",
                            required=["files"],
                            properties={"files": _schema(type="array", items=_file_request())},
                        )
                    )
                },
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "results": _schema(
                            type="array",
                            items=_schema(
                                type="object",
                                properties={
                                    "name": _schema(type="string"),
                                    "ok": _schema(type="boolean"),
                                    "kind": _schema(
                                        type="string",
                                        enum=["text", "image", "container", "av", "unknown"],
                                    ),
                                    "suspicious": _schema(type="boolean"),
                                    "report": _schema(type="object"),
                                    "error": _schema(type="string"),
                                },
                            ),
                        ),
                    },
                )
            },
        }
    },
    "/detect/batch": {
        "post": {
            "summary": f"Run watermark detectors on up to {MAX_BATCH_FILES} files in one request",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_schema(
                            type="object",
                            required=["files"],
                            properties={"files": _schema(type="array", items=_file_request())},
                        )
                    )
                },
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "results": _schema(
                            type="array",
                            items=_schema(
                                type="object",
                                properties={
                                    "name": _schema(type="string"),
                                    "ok": _schema(type="boolean"),
                                    "kind": _schema(
                                        type="string",
                                        enum=["text", "image", "container", "av"],
                                    ),
                                    "detections": _schema(
                                        type="array", items=_schema(type="object")
                                    ),
                                    "report": _schema(type="object"),
                                    "error": _schema(type="string"),
                                },
                            ),
                        ),
                    },
                )
            },
        }
    },
    "/clean/batch": {
        "post": {
            "summary": f"Clean up to {MAX_BATCH_FILES} files in one request",
            "requestBody": _schema(
                required=True,
                content={
                    "application/json": _schema(
                        schema=_schema(
                            type="object",
                            required=["files"],
                            properties={
                                "files": _schema(type="array", items=_clean_request_schema())
                            },
                        )
                    )
                },
            ),
            "responses": {
                "200": _schema(
                    type="object",
                    properties={
                        "ok": _schema(type="boolean"),
                        "results": _schema(
                            type="array",
                            items=_schema(
                                type="object",
                                properties={
                                    "name": _schema(type="string"),
                                    "ok": _schema(type="boolean"),
                                    "kind": _schema(
                                        type="string", enum=["text", "image", "container", "av"]
                                    ),
                                    "cleaned": _schema(type="string"),
                                    "report": _schema(type="object"),
                                    "error": _schema(type="string"),
                                },
                            ),
                        ),
                    },
                )
            },
        }
    },
}

# Keep the legacy endpoints while making the evidence contract explicitly
# versioned. Both paths execute the same implementation and return the same
# schema, so clients can migrate without a flag day.
_OPENAPI_PATHS["/v1/extract"] = {
    "post": {
        **_OPENAPI_PATHS["/extract"]["post"],
        "summary": "Extract Evidence Schema v1 without modifying the input",
    }
}
_OPENAPI_PATHS["/v1/extract/batch"] = {
    "post": {
        **_OPENAPI_PATHS["/extract/batch"]["post"],
        "summary": f"Extract Evidence Schema v1 from up to {MAX_BATCH_FILES} files",
    }
}

_ERROR_SCHEMA = _schema(
    type="object",
    properties={"ok": _schema(type="boolean", enum=[False]), "error": _schema(type="string")},
)
_COMMON_ERRORS = {
    "400": {
        "description": "Bad request",
        "content": {"application/json": {"schema": _ERROR_SCHEMA}},
    },
    "401": {
        "description": "Missing/invalid bearer token",
        "content": {"application/json": {"schema": _ERROR_SCHEMA}},
    },
    "404": {"description": "Not found", "content": {"application/json": {"schema": _ERROR_SCHEMA}}},
    "413": {
        "description": "Request body too large",
        "content": {"application/json": {"schema": _ERROR_SCHEMA}},
    },
    "500": {
        "description": "Internal error",
        "content": {"application/json": {"schema": _ERROR_SCHEMA}},
    },
}


def openapi_spec() -> dict[str, Any]:
    paths: dict[str, Any] = {}
    for path, ops in _OPENAPI_PATHS.items():
        for method, op in ops.items():
            responses = dict(_COMMON_ERRORS)
            for status, body in op["responses"].items():
                responses[status] = {
                    "description": "Success",
                    "content": {"application/json": {"schema": body}},
                }
            paths.setdefault(path, {})[method] = {
                "summary": op["summary"],
                "responses": responses,
                **((op.get("requestBody") and {"requestBody": op["requestBody"]}) or {}),
            }

    spec: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": "watermarks-remover service",
            "version": VERSION,
            "description": "Strip multi-vendor AI provenance marks (Unicode, C2PA/EXIF/XMP, containers). "
            "Files are passed base64-encoded in JSON; cleaned bytes come back base64-encoded.",
        },
        "paths": paths,
    }
    if API_KEY:
        spec["components"] = {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            }
        }
        spec["security"] = [{"bearerAuth": []}]
    return spec


def _safe_name(name: str) -> str:
    """Reduce a client-supplied filename to a bare basename safe for temp use.

    CodeQL (uncontrolled data in path expression): a name like '../../x'
    would otherwise let the write below escape the request temp dir. Fold
    Windows separators too, and fall back to a neutral name for '.', '..' or
    empty results.
    """
    base = Path(name.replace("\\", "/")).name
    if base in ("", ".", ".."):
        return "input"
    return base


def _tmp_path(tmpdir: Path, *parts: str) -> Path:
    """Join *parts* under *tmpdir* and refuse anything that escapes it.

    Defense-in-depth for the CodeQL "uncontrolled data in path expression"
    findings: even if a caller slips a separator through, the write can never
    land outside the request temp dir.
    """
    path = tmpdir.joinpath(*parts)
    if path.parent != tmpdir:
        raise ValueError("unsafe filename")
    return path


def _decode_input(body: dict[str, Any]) -> tuple[bytes, str]:
    raw = body.get("file")
    if not isinstance(raw, str):
        raise ValueError("missing string field 'file' (base64-encoded bytes)")
    name = body.get("name")
    if name is not None and not isinstance(name, str):
        raise ValueError("'name' must be a string")
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("'file' is not valid base64") from None
    return data, _safe_name(name or "")


def _parse_clean_options(options: Any) -> dict[str, Any]:
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise ValueError("'options' must be an object")
    for key, value in options.items():
        if key not in ALLOWED_CLEAN_OPTIONS:
            raise ValueError(f"unknown option: {key}")
        expected_type = ALLOWED_CLEAN_OPTIONS[key]
        if not isinstance(value, expected_type):
            type_name = "boolean" if expected_type is bool else "string"
            raise ValueError(f"option {key!r} must be a {type_name}")
    # An unrecognised deep_images value used to fall back to "auto", which turns
    # a request for lossless cleaning into one that may recompress. Reject it
    # here, where every caller -- single file and batch alike -- passes through.
    deep_images = options.get("deep_images")
    if deep_images is not None and deep_images not in DEEP_IMAGE_MODES:
        raise ValueError(f"option 'deep_images' must be one of {sorted(DEEP_IMAGE_MODES)}")
    return options


def _batch_items(
    body: dict[str, Any],
) -> list[tuple[str, bytes, dict[str, Any], str | None]]:
    """Decode a batch request's 'files' array into (name, data, options, error) tuples.

    A malformed individual entry (bad base64, unknown option) becomes an error
    string paired with that entry rather than raising, so one bad file never
    aborts the rest of the batch. Only 'files' itself being missing, empty, or
    over MAX_BATCH_FILES raises — that is a malformed request, not a per-file
    problem.
    """
    files = body.get("files")
    if not isinstance(files, list):
        raise ValueError("missing array field 'files'")
    if not files:
        raise ValueError("'files' must not be empty")
    if len(files) > MAX_BATCH_FILES:
        raise ValueError(f"'files' exceeds the {MAX_BATCH_FILES}-file batch limit")

    items: list[tuple[str, bytes, dict[str, Any], str | None]] = []
    for entry in files:
        if not isinstance(entry, dict):
            items.append(("", b"", {}, "each entry in 'files' must be an object"))
            continue
        try:
            data, name = _decode_input(entry)
        except ValueError as e:
            fallback_name = entry.get("name") if isinstance(entry.get("name"), str) else ""
            items.append((fallback_name, b"", {}, str(e)))
            continue
        try:
            options = _parse_clean_options(entry.get("options"))
        except ValueError as e:
            items.append((name, b"", {}, str(e)))
            continue
        items.append((name, data, options, None))
    return items


def _inspect_payload(data: bytes, name: str, run_detect: bool) -> dict[str, Any]:
    kind = classify_bytes(data, Path(name).suffix)
    if kind == "unknown":
        return {
            "ok": True,
            "kind": "unknown",
            "report": {"note": "unrecognized format; use a filename with a known extension"},
            "suspicious": False,
        }
    with tempfile.TemporaryDirectory(prefix="wm-inspect-") as tmp:
        path = _tmp_path(Path(tmp), name or "input")
        path.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(
                    "refusing to inspect bytes that look like a binary container as text"
                )
            raw_text = data.decode("utf-8", errors="surrogateescape")
            report = inspect_text(raw_text).to_dict()
            s_rep = score_text_stylometry(raw_text, path=name or "<text>")
            report["stylometry"] = normalize_detector_report(
                {"detector": "stylometry", "available": True, **s_rep.to_dict()}
            )
            if run_detect:
                report["text_detectors"] = run_all_text_detectors(raw_text)
        elif kind == "image":
            report = inspect_image(path).to_dict()
            if isinstance(report.get("synthid"), dict):
                report["synthid"] = normalize_detector_report(report["synthid"])
        elif kind == "av":
            report = inspect_av(path).to_dict()
        else:
            report = inspect_container(path).to_dict()
    detected_wm = any(
        entry.get("available") and entry.get("is_watermarked")
        for entry in report.get("text_detectors") or []
    )
    embedded_file_hit = bool(
        ((report.get("details") or {}).get("embedded_files") or {}).get("detected_count")
    )
    suspicious = (
        bool(report.get("suspicious_total"))
        or bool(report.get("has_c2pa") or report.get("has_ai_metadata"))
        or bool(report.get("stylometry", {}).get("score", 0.0) >= 0.65)
        or detected_wm
        or embedded_file_hit
        or bool(
            isinstance(report.get("synthid"), dict)
            and report["synthid"].get("available")
            and report["synthid"].get("is_watermarked")
        )
    )
    return {"ok": True, "kind": kind, "report": report, "suspicious": suspicious}


def _detect_payload(data: bytes, name: str) -> dict[str, Any]:
    kind = classify_bytes(data, Path(name).suffix)
    with tempfile.TemporaryDirectory(prefix="wm-detect-") as tmp:
        path = _tmp_path(Path(tmp), name or "input")
        path.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(
                    "refusing to detect bytes that look like a binary container as text"
                )
            raw_text = data.decode("utf-8", errors="surrogateescape")
            detections: list[dict[str, Any]] = run_all_text_detectors(raw_text)
            s_rep = score_text_stylometry(raw_text, path=name or "<text>")
            detections.append(
                normalize_detector_report(
                    {"detector": "stylometry", "available": True, **s_rep.to_dict()}
                )
            )
            return {"ok": True, "kind": kind, "detections": detections}
        elif kind == "image":
            score = run_synthid_score(path)
            if score is None:
                score = {
                    "detector": "synthid",
                    "available": False,
                    "error": (
                        "no SynthID scorer configured (set "
                        "WATERMARKS_SYNTHID_SCORER_URL or REVERSE_SYNTHID_DIR)"
                    ),
                }
            else:
                score.setdefault("detector", "synthid")
            score = normalize_detector_report(score)
            detections = [score]
            return {"ok": True, "kind": kind, "detections": detections}
        elif kind == "av":
            return {
                "ok": True,
                "kind": kind,
                "detections": [],
                "report": inspect_av(path).to_dict(),
            }
        else:
            detections = []
            report = inspect_container(path).to_dict()
            return {
                "ok": True,
                "kind": kind,
                "detections": detections,
                "report": report,
            }


def _media_type(name: str, kind: str, report: dict[str, Any], declared: str | None) -> str:
    """Choose a descriptive MIME without allowing it to override byte routing."""
    if isinstance(declared, str) and declared.strip():
        return declared.strip().lower()
    format_name = str(report.get("format", "")).lower()
    known = {
        "png": "image/png",
        "jpeg": "image/jpeg",
        "webp": "image/webp",
        "avif": "image/avif",
        "heic": "image/heic",
        "bmp": "image/bmp",
        "gif": "image/gif",
        "tiff": "image/tiff",
        "mp4": "video/mp4",
        "mov": "video/quicktime",
        "m4a": "audio/mp4",
        "wav": "audio/wav",
        "mp3": "audio/mpeg",
        "pdf": "application/pdf",
        "svg": "image/svg+xml",
    }
    if format_name in known:
        return known[format_name]
    guessed = mimetypes.guess_type(name)[0]
    if guessed:
        return guessed
    return {
        "text": "text/plain",
        "image": "application/octet-stream",
        "av": "application/octet-stream",
        "container": "application/octet-stream",
    }.get(kind, "application/octet-stream")


def _evidence_item(
    *,
    layer: str,
    extractor: str,
    status: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "layer": layer,
        "extractor": extractor,
        "status": status,
    }
    if details:
        item.update(details)
    return item


def _evidence_carrier(item: dict[str, Any]) -> str:
    layer = str(item.get("layer", "unknown"))
    extractor = str(item.get("extractor", "unknown"))
    if layer == "unicode":
        return str(item.get("kind") or "unicode_format_control")
    if layer == "c2pa":
        return "c2pa_manifest"
    if layer == "metadata":
        if item.get("c2pa_candidate"):
            return "c2pa_or_metadata_candidate"
        return "file_metadata"
    if layer == "text_statistical":
        return f"statistical_text:{extractor.lower()}"
    if layer == "image_pixel":
        return "image_pixel_watermark"
    if layer == "audio_video_pixel":
        return "audio_video_watermark"
    if layer == "embedded_image":
        return "pdf_embedded_image"
    if layer == "embedded_file":
        return "pdf_embedded_file"
    return layer


def _evidence_locator(item: dict[str, Any]) -> dict[str, Any]:
    locator: dict[str, Any] = {}
    for key in (
        "character_offset",
        "byte_offset",
        "part",
        "part_character_offset",
        "part_utf8_byte_offset",
        "stream_offset",
        "decoded_offset",
        "offset",
        "field",
        "path",
        "sample_offsets",
    ):
        if key in item and item[key] is not None:
            locator[key] = item[key]
    samples = item.get("samples")
    if isinstance(samples, list) and samples:
        locator["samples"] = [
            {
                key: sample[key]
                for key in (
                    "run_index",
                    "text_character_offset",
                    "part_character_offset",
                    "part_utf8_byte_offset",
                    "source_fragment",
                )
                if key in sample
            }
            for sample in samples[:10]
            if isinstance(sample, dict)
        ]
    return locator


def _evidence_confidence(item: dict[str, Any]) -> str:
    explicit = item.get("confidence")
    if explicit in {"confirmed", "probable", "informational", "unknown"}:
        return str(explicit)
    status = item.get("status")
    if status == "detected":
        return "probable"
    if status in {"not_detected", "inconclusive", "unavailable"}:
        return "informational"
    return "unknown"


def _c2pa_signature_is_valid(item: dict[str, Any]) -> bool:
    serialized = json.dumps(item, ensure_ascii=True, sort_keys=True).lower()
    return any(
        marker in serialized
        for marker in (
            '"signature_status":"valid"',
            '"signature_status": "valid"',
            '"validation_status":"valid"',
            '"validation_status": "valid"',
        )
    )


def _evidence_verification(item: dict[str, Any]) -> dict[str, str]:
    status = str(item.get("status", "inconclusive"))
    layer = str(item.get("layer", "unknown"))
    extractor = str(item.get("extractor", "unknown"))
    if status == "unavailable":
        return {"status": "unavailable", "method": extractor}
    if status == "error":
        return {"status": "error", "method": extractor}
    if status == "not_detected":
        return {"status": "not_applicable", "method": extractor}
    if status == "inconclusive":
        return {"status": "candidate", "method": extractor}
    if layer == "unicode" and extractor == "UnicodeCarrierExtractor":
        return {"status": "verified", "method": "deterministic_codepoint_observation"}
    if layer == "c2pa" and _c2pa_signature_is_valid(item):
        return {"status": "verified", "method": "c2pa_signature_validation"}
    return {"status": "candidate", "method": extractor}


def _normalize_evidence_schema(
    evidence: list[dict[str, Any]], source_sha256: str
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    layer_counts: dict[str, int] = {}
    verification_counts: dict[str, int] = {}
    for index, original in enumerate(evidence):
        item = dict(original)
        status = str(item.get("status", "inconclusive"))
        if status not in EVIDENCE_STATUS_VALUES:
            status = "error"
            item["status"] = status
            item.setdefault("error", "extractor returned an unsupported evidence status")
        canonical = json.dumps(item, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        evidence_id = (
            "ev_" + hashlib.sha256(f"{source_sha256}:{index}:{canonical}".encode()).hexdigest()[:24]
        )
        verification = _evidence_verification(item)
        item.update(
            {
                "evidence_id": evidence_id,
                "schema_version": EVIDENCE_SCHEMA_VERSION,
                "source_sha256": source_sha256,
                "carrier": _evidence_carrier(item),
                # Preserve extractor-specific confidence values, which may be
                # numeric scores. The normalized qualitative classification
                # has its own field so legacy consumers do not change type.
                "confidence_level": _evidence_confidence(item),
                "verification": verification,
                "locator": _evidence_locator(item),
            }
        )
        normalized.append(item)
        layer = str(item.get("layer", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
        layer_counts[layer] = layer_counts.get(layer, 0) + 1
        verification_status = verification["status"]
        verification_counts[verification_status] = (
            verification_counts.get(verification_status, 0) + 1
        )
    return normalized, {
        "evidence_count": len(normalized),
        "status_counts": status_counts,
        "layer_counts": layer_counts,
        "verification_counts": verification_counts,
    }


def _extract_payload(
    data: bytes,
    name: str,
    declared_mime: str | None = None,
) -> dict[str, Any]:
    """Extract evidence while preserving the existing inspect/detect APIs."""
    kind = classify_bytes(data, Path(name).suffix)
    source_hash = hashlib.sha256(data).hexdigest()
    source: dict[str, Any] = {
        "sha256": source_hash,
        "size": len(data),
        "declared_filename": name or "input",
        "media_type": _media_type(name, kind, {}, declared_mime),
        "kind": kind,
    }
    evidence: list[dict[str, Any]] = []
    limitations: list[str] = []
    extractor_count = 0
    extractor_completed = 0
    verdict = "not_detected"
    report: dict[str, Any] = {}
    detections: list[dict[str, Any]] = []

    if kind == "unknown":
        verdict = "inconclusive"
        limitations.append("unrecognized format; no extractor was selected")
    else:
        with tempfile.TemporaryDirectory(prefix="wm-extract-") as tmp:
            path = _tmp_path(Path(tmp), name or "input")
            path.write_bytes(data)
            if kind == "text":
                if looks_binary(data):
                    raise ValueError(
                        "refusing to extract bytes that look like a binary container as text"
                    )
                raw_text = data.decode("utf-8", errors="surrogateescape")
                text_report = inspect_text(raw_text).to_dict()
                text_report["stylometry"] = normalize_detector_report(
                    {
                        "detector": "stylometry",
                        "available": True,
                        **score_text_stylometry(raw_text, path=name or "<text>").to_dict(),
                    }
                )
                report = text_report
                unicode_evidence = extract_unicode_evidence(raw_text)
                for occurrence in unicode_evidence["occurrences"]:
                    evidence.append(
                        _evidence_item(
                            layer="unicode",
                            extractor="UnicodeCarrierExtractor",
                            status="detected",
                            details=occurrence,
                        )
                    )
                if unicode_evidence["candidate_decodings"]:
                    evidence.extend(
                        _evidence_item(
                            layer="unicode",
                            extractor="UnicodeCandidateDecoder",
                            status="inconclusive",
                            details=candidate,
                        )
                        for candidate in unicode_evidence["candidate_decodings"]
                    )
                detections = run_all_text_detectors(raw_text)
                stylometry = report["stylometry"]
                detections.append(stylometry)
                extractor_count = len(detections)
                extractor_completed = sum(
                    item.get("status") not in {"unavailable", "error"} for item in detections
                )
                for item in detections:
                    evidence.append(
                        _evidence_item(
                            layer="text_statistical",
                            extractor=str(item.get("detector", "text-detector")),
                            status=str(item.get("status", "inconclusive")),
                            details={
                                key: value
                                for key, value in item.items()
                                if key not in {"detector", "status", "available"}
                            },
                        )
                    )
                if (
                    any(item.get("status") == "detected" for item in detections)
                    or unicode_evidence["occurrences"]
                ):
                    verdict = "detected"
                elif any(item.get("status") == "error" for item in detections):
                    verdict = "error"
                elif any(
                    item.get("status") in {"unavailable", "inconclusive"} for item in detections
                ):
                    verdict = "inconclusive"
                else:
                    verdict = "not_detected"
                limitations.extend(
                    str(item.get("error"))
                    for item in detections
                    if item.get("status") in {"unavailable", "error"} and item.get("error")
                )
            elif kind == "image":
                report = inspect_image(path).to_dict()
                if isinstance(report.get("synthid"), dict):
                    report["synthid"] = normalize_detector_report(report["synthid"])
                metadata_hit = bool(report.get("has_c2pa") or report.get("has_ai_metadata"))
                metadata_details: dict[str, Any] = {
                    "findings": report.get("findings", []),
                    "c2pa_candidate": bool(report.get("has_c2pa")),
                    "ai_metadata": bool(report.get("has_ai_metadata")),
                }
                c2pa_tools = report.get("tools", {}).get("c2patool", {})
                if isinstance(c2pa_tools, dict) and c2pa_tools.get("json_summary"):
                    metadata_details["c2pa_manifest"] = c2pa_tools["json_summary"]
                # The byte-level image parser is a provenance candidate scan;
                # a c2patool result, when installed, is the separate
                # structured-manifest probe. Keep both facts visible.
                evidence.append(
                    _evidence_item(
                        layer="metadata",
                        extractor="ImageMetadataExtractor",
                        status="detected" if metadata_hit else "not_detected",
                        details=metadata_details,
                    )
                )
                if report.get("has_c2pa"):
                    evidence.append(
                        _evidence_item(
                            layer="c2pa",
                            extractor="C2PAManifestExtractor",
                            status="detected",
                            details={"findings": report.get("findings", [])},
                        )
                    )
                synthid = report.get("synthid")
                if not isinstance(synthid, dict):
                    synthid = {
                        "detector": "synthid",
                        "available": False,
                        "status": "unavailable",
                        "error": (
                            "no SynthID scorer configured (set "
                            "WATERMARKS_SYNTHID_SCORER_URL or REVERSE_SYNTHID_DIR)"
                        ),
                    }
                    report["synthid"] = synthid
                extractor_count = 2  # metadata scan + pixel scorer
                extractor_completed = 1 + int(synthid.get("status") not in {"unavailable", "error"})
                evidence.append(
                    _evidence_item(
                        layer="image_pixel",
                        extractor="SynthIDImageDetector",
                        status=str(synthid.get("status", "inconclusive")),
                        details={
                            key: value
                            for key, value in synthid.items()
                            if key not in {"detector", "status", "available"}
                        },
                    )
                )
                if synthid.get("error"):
                    limitations.append(str(synthid["error"]))
                if (
                    synthid.get("status") == "detected"
                    or report.get("has_c2pa")
                    or report.get("has_ai_metadata")
                ):
                    verdict = "detected"
                elif synthid.get("status") == "not_detected":
                    verdict = "not_detected"
                elif synthid.get("status") == "error":
                    verdict = "error"
                else:
                    verdict = "inconclusive"
            elif kind == "av":
                report = inspect_av(path).to_dict()
                metadata_hit = bool(report.get("has_c2pa") or report.get("has_ai_metadata"))
                evidence.append(
                    _evidence_item(
                        layer="metadata",
                        extractor="AVMetadataExtractor",
                        status="detected" if metadata_hit else "not_detected",
                        details={"findings": report.get("findings", [])},
                    )
                )
                evidence.append(
                    _evidence_item(
                        layer="audio_video_pixel",
                        extractor="AudioVideoWatermarkDecoder",
                        status="unavailable",
                        details={
                            "error": "audio/video pixel and audio watermark decoders are not configured"
                        },
                    )
                )
                extractor_count = 2
                extractor_completed = 1
                if metadata_hit:
                    verdict = "detected"
                else:
                    verdict = "inconclusive"
                    limitations.append(
                        "audio/video pixel and audio watermark decoders are not configured"
                    )
            else:
                report = inspect_container(path).to_dict()
                embedded_files = (report.get("details") or {}).get("embedded_files") or {}
                embedded_file_hit = bool(embedded_files.get("detected_count"))
                metadata_hit = bool(
                    report.get("has_c2pa")
                    or report.get("has_ai_metadata")
                    or report.get("layer_a_hits")
                    or embedded_file_hit
                )
                evidence.append(
                    _evidence_item(
                        layer="metadata",
                        extractor="ContainerMetadataExtractor",
                        status="detected" if metadata_hit else "not_detected",
                        details={"findings": report.get("findings", [])},
                    )
                )
                for finding in report.get("findings", []):
                    evidence.append(
                        _evidence_item(
                            layer="metadata",
                            extractor="ContainerMetadataExtractor",
                            status="detected",
                            details={"finding": finding},
                        )
                    )
                for hit in report.get("layer_a_hits", []):
                    evidence.append(
                        _evidence_item(
                            layer="unicode",
                            extractor="UnicodeCarrierExtractor",
                            status="detected",
                            details=hit,
                        )
                    )
                embedded_images = (report.get("details") or {}).get("embedded_images") or {}
                for candidate in embedded_images.get("candidates", []):
                    evidence.append(
                        _evidence_item(
                            layer="embedded_image",
                            extractor="PDFEmbeddedImageExtractor",
                            status=str(candidate.get("evidence_status", "inconclusive")),
                            details=candidate,
                        )
                    )
                limitations.extend(embedded_images.get("limitations", []))
                for candidate in embedded_files.get("candidates", []):
                    evidence.append(
                        _evidence_item(
                            layer="embedded_file",
                            extractor="PDFEmbeddedFileExtractor",
                            status=str(candidate.get("evidence_status", "inconclusive")),
                            details=candidate,
                        )
                    )
                limitations.extend(embedded_files.get("limitations", []))
                extractor_count = 1
                extractor_completed = 1
                if metadata_hit:
                    verdict = "detected"
                else:
                    verdict = "not_detected"
                    limitations.extend(report.get("notes", []))
                # PDF marker scans are useful candidates, but a signed C2PA
                # claim is not verified by the stdlib parser. Expose that
                # missing validator instead of making a clean PDF look fully
                # covered when c2patool is absent or unusable.
                if report.get("format") == "pdf":
                    c2pa_tool = (report.get("tools") or {}).get("c2patool") or {}
                    if c2pa_tool.get("has_manifest"):
                        evidence.append(
                            _evidence_item(
                                layer="c2pa",
                                extractor="C2PAManifestExtractor",
                                status="detected",
                                details={
                                    "manifest": c2pa_tool.get("json_summary"),
                                },
                            )
                        )
                    elif c2pa_tool.get("available") and c2pa_tool.get("ok"):
                        evidence.append(
                            _evidence_item(
                                layer="c2pa",
                                extractor="C2PAManifestExtractor",
                                status="not_detected",
                            )
                        )
                    else:
                        extractor_count += 1
                        evidence.append(
                            _evidence_item(
                                layer="c2pa",
                                extractor="C2PAManifestExtractor",
                                status="unavailable",
                                details={
                                    "error": "c2patool is unavailable or inconclusive; PDF C2PA signature validation was not run"
                                },
                            )
                        )
                        if verdict == "not_detected":
                            verdict = "inconclusive"

    detected_media_type = _media_type(name, kind, report, None)
    source["detected_media_type"] = detected_media_type
    if isinstance(declared_mime, str) and declared_mime.strip():
        source["declared_media_type"] = declared_mime.strip().lower()
    source["media_type"] = _media_type(name, kind, report, declared_mime)
    if kind == "unknown":
        coverage = 0.0
    elif extractor_count:
        coverage = round(extractor_completed / extractor_count, 3)
    else:
        coverage = 1.0
    evidence, evidence_summary = _normalize_evidence_schema(evidence, source_hash)
    return {
        "ok": True,
        "request_id": f"wm_{uuid.uuid4().hex[:20]}",
        "schema": {
            "name": EVIDENCE_SCHEMA_NAME,
            "version": EVIDENCE_SCHEMA_VERSION,
            "status_values": list(EVIDENCE_STATUS_VALUES),
        },
        "workflow": {
            "stage": "extract",
            "read_only": True,
            "input_mutated": False,
        },
        "source": source,
        "verdict": verdict,
        "coverage": coverage,
        "evidence": evidence,
        "evidence_summary": evidence_summary,
        "limitations": limitations,
        "extractor_versions": {
            "server": VERSION,
            "format_dispatch": "byte-and-extension-router-v1",
            "unicode": "layer-a-v1",
            "evidence_schema": EVIDENCE_SCHEMA_VERSION,
        },
        "report": report,
        "detections": detections,
    }


def _clean_payload(data: bytes, name: str, options: dict[str, Any]) -> dict[str, Any]:
    kind = classify_bytes(data, Path(name).suffix)
    if kind == "unknown":
        raise ValueError(
            "unrecognized file format; use a filename with a known extension "
            "(e.g. notes.txt) or a supported image/container name"
        )

    with tempfile.TemporaryDirectory(prefix="wm-clean-") as tmp:
        tmpdir = Path(tmp)
        src = _tmp_path(tmpdir, name or "input")
        src.write_bytes(data)
        if kind == "text":
            if looks_binary(data):
                raise ValueError(
                    "refusing to clean bytes that look like a binary container as text"
                )
            text = data.decode("utf-8", errors="surrogateescape")
            detect_before = bool(options.get("detect_before"))
            detect_after = bool(options.get("detect_after"))
            detector_reports: dict[str, Any] = {}
            if detect_before:
                detector_reports["before"] = run_text_detectors(text)
            cleaned, stats = clean_text(
                text,
                nfkc=bool(options.get("nfkc")),
                aggressive_homoglyphs=bool(options.get("aggressive_homoglyphs")),
            )
            if detect_after:
                detector_reports["after"] = run_text_detectors(cleaned)
            cleaned_bytes = cleaned.encode("utf-8", errors="surrogateescape")
            report: dict[str, Any] = {"kind": "text", "stats": stats, "length": len(cleaned)}
            if detector_reports:
                report["text_detectors"] = detector_reports
        elif kind == "image":
            ext = Path(name).suffix
            if not ext:
                from image_meta import detect_format

                fmt_name = detect_format(data)
                ext = f".{fmt_name}" if fmt_name != "unknown" else ".png"
            dest = _tmp_path(tmpdir, f"out{ext}")
            strip_all = not bool(options.get("keep_non_ai_metadata"))
            if "strip_all_metadata" in options:
                strip_all = bool(options["strip_all_metadata"])
            remove_pixel = options.get("remove_pixel")
            if remove_pixel not in (None, "ctrlregen", "diffusion"):
                raise ValueError("remove_pixel must be one of: ctrlregen, diffusion")
            result = clean_image(
                src,
                dest,
                strip_all_metadata=strip_all,
                remove_pixel=remove_pixel,
                score_synthid_before=bool(options.get("detect_before")),
                score_synthid_after=bool(options.get("detect_after")),
            )
            if bool(options.get("detect_before")) and result.get("synthid_before") is None:
                result["synthid_before"] = run_synthid_score(src)
            if bool(options.get("detect_after")) and result.get("synthid_after") is None:
                result["synthid_after"] = run_synthid_score(dest)
            for phase in ("synthid_before", "synthid_after"):
                if isinstance(result.get(phase), dict):
                    result[phase] = normalize_detector_report(result[phase])
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "image", **result}
        elif kind == "av":
            dest = _tmp_path(tmpdir, f"out{Path(name).suffix or '.bin'}")
            strip_all = not bool(options.get("keep_non_ai_metadata"))
            if "strip_all_metadata" in options:
                strip_all = bool(options["strip_all_metadata"])
            result = clean_av(src, dest, strip_all_metadata=strip_all)
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "av", **result}
        else:
            ext = Path(name).suffix
            container_fmt = None
            if not ext:
                from container_meta import detect_container_format

                container_fmt = detect_container_format(Path("input"), data)
                ext_map = {
                    "svg": ".svg",
                    "pdf": ".pdf",
                    "docx": ".docx",
                    "xlsx": ".xlsx",
                    "pptx": ".pptx",
                    "odt": ".odt",
                    "epub": ".epub",
                    "html": ".html",
                    "markdown": ".md",
                }
                ext = ext_map.get(container_fmt, "")
            dest = _tmp_path(tmpdir, f"out{ext}")
            result = clean_container(
                src,
                dest,
                fmt=container_fmt,
                also_layer_a_text=bool(options.get("also_layer_a_text", True)),
                deep_images=str(options.get("deep_images", "auto")),
            )
            cleaned_bytes = dest.read_bytes()
            report = {"kind": "container", **result}
        report.pop("input", None)
        report.pop("output", None)

    validation = _validate_cleaned_output(data, cleaned_bytes, name, kind, report)
    report["validation"] = validation
    report["source_sha256"] = hashlib.sha256(data).hexdigest()
    report["output_sha256"] = hashlib.sha256(cleaned_bytes).hexdigest()
    return {
        "ok": bool(validation["ok"]),
        "kind": kind,
        "cleaned": base64.b64encode(cleaned_bytes).decode("ascii"),
        "report": report,
    }


def _validate_cleaned_output(
    original: bytes,
    cleaned: bytes,
    name: str,
    kind: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Run cheap post-clean invariants before reporting a successful output.

    This is intentionally separate from watermark detection. A detector can
    be unavailable while the output is structurally valid, and a metadata
    finding can be gone while a broken container must still be rejected.
    Optional heavyweight validators (ffprobe/qpdf/renderers) remain surfaced
    by their respective reports rather than being silently treated as run.
    """
    result: dict[str, Any] = {
        "ok": bool(cleaned),
        "kind_before": kind,
        "bytes_in": len(original),
        "bytes_out": len(cleaned),
        "sha256_before": hashlib.sha256(original).hexdigest(),
        "sha256_after": hashlib.sha256(cleaned).hexdigest(),
    }
    if not cleaned:
        result["error"] = "cleaner returned empty output"
        return result

    expected_format = str(report.get("format") or "")
    actual_format = "unknown"
    try:
        if kind == "text":
            if looks_binary(cleaned):
                result["ok"] = False
                result["error"] = "cleaned text now looks like binary data"
            else:
                cleaned.decode("utf-8", errors="surrogateescape")
            actual_format = "text"
        elif kind == "image":
            actual_format = detect_image_format(cleaned)
        elif kind == "av":
            actual_format = detect_av_format(cleaned)
        elif kind == "container":
            actual_format = detect_container_format(Path(name), cleaned)
    except (OSError, ValueError, UnicodeError) as exc:
        result["ok"] = False
        result["error"] = f"post-clean parse failed: {exc}"

    result["format_before"] = expected_format or None
    result["format_after"] = actual_format
    if kind != "text" and expected_format and actual_format != expected_format:
        result["ok"] = False
        result["error"] = f"post-clean format changed from {expected_format} to {actual_format}"

    validators = _run_external_structure_parity(original, cleaned, kind, actual_format)
    if validators:
        result["validators"] = validators
        broken = next(
            (name for name, payload in validators.items() if payload.get("status") == "broken"),
            None,
        )
        if broken:
            result["ok"] = False
            result["error"] = f"{broken} accepted the input but rejected the cleaned output"
    if not result["ok"] and "error" not in result:
        result["error"] = "post-clean structural invariant failed"
    return result


def _run_external_structure_parity(
    original: bytes,
    cleaned: bytes,
    kind: str,
    actual_format: str,
) -> dict[str, Any]:
    """Compare optional parser behavior before and after cleaning.

    A malformed fixture rejected both before and after is inconclusive, not a
    cleaning regression. Only a parser that accepts the original and rejects
    the cleaned copy can break the overall validation gate.
    """
    if kind == "container" and actual_format == "pdf":
        tool_name = "qpdf"
        tool = which(tool_name)
        suffix = ".pdf"
    elif kind == "av" and actual_format in {"mp4", "wav", "mp3"}:
        tool_name = "ffprobe"
        tool = which(tool_name)
        suffix = f".{actual_format}"
    else:
        return {}
    if not tool:
        return {
            tool_name: {
                "available": False,
                "status": "unavailable",
                "error": f"{tool_name} is not installed",
            }
        }

    def probe(path: Path) -> dict[str, Any]:
        command = (
            [tool, "--check", safe_arg(str(path))]
            if tool_name == "qpdf"
            else [
                tool,
                "-v",
                "error",
                "-show_entries",
                "format=format_name,duration:stream=index,codec_type",
                "-of",
                "json",
                safe_arg(str(path)),
            ]
        )
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
                creationflags=subprocess_creationflags,
                preexec_fn=subprocess_preexec_fn,
            )
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        accepted = completed.returncode in ({0, 3} if tool_name == "qpdf" else {0})
        payload: dict[str, Any] = {
            "ok": accepted,
            "returncode": completed.returncode,
        }
        output = ((completed.stdout or "") + (completed.stderr or "")).strip()
        if output:
            payload["snippet"] = output.replace(str(path), "<asset>")[:2000]
        if tool_name == "ffprobe" and accepted:
            try:
                parsed = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError:
                parsed = {}
            payload["stream_count"] = len(parsed.get("streams", []))
            payload["format"] = parsed.get("format", {})
        return payload

    with tempfile.TemporaryDirectory(prefix="wm-validate-") as tmp:
        base = Path(tmp)
        before_path = base / f"before{suffix}"
        after_path = base / f"after{suffix}"
        before_path.write_bytes(original)
        after_path.write_bytes(cleaned)
        before = probe(before_path)
        after = probe(after_path)

    before_ok = bool(before.get("ok"))
    after_ok = bool(after.get("ok"))
    stream_mismatch = bool(
        tool_name == "ffprobe"
        and before_ok
        and after_ok
        and before.get("stream_count") != after.get("stream_count")
    )
    if stream_mismatch:
        status = "broken"
        after["error"] = "stream count changed after cleaning"
    elif before_ok and after_ok:
        status = "verified"
    elif before_ok and not after_ok:
        status = "broken"
    else:
        status = "inconclusive"
    return {
        tool_name: {
            "available": True,
            "status": status,
            "before": before,
            "after": after,
        }
    }


class Handler(BaseHTTPRequestHandler):
    server_version = f"watermarks-remover/{VERSION}"

    def _request_id(self) -> str:
        current = getattr(self, "request_id", "")
        if current:
            return current
        incoming = (self.headers.get("X-Request-ID") or "").strip()
        if (
            not incoming
            or len(incoming) > 128
            or not all(char.isalnum() or char in "._:-" for char in incoming)
        ):
            incoming = f"wm_{uuid.uuid4().hex[:20]}"
        self.request_id = incoming
        return incoming

    def log_message(self, fmt: str, *args: object) -> None:
        eprint(f"{self._request_id()} {self.address_string()} - {fmt % args}")

    def _authorized(self) -> bool:
        if not API_KEY:
            return True
        header = self.headers.get("Authorization", "")
        return hmac.compare_digest(header, f"Bearer {API_KEY}")

    def _read_json(self) -> dict[str, Any] | None:
        raw = self.headers.get("Content-Length")
        if raw is None or not raw.isdigit():
            return None
        length = int(raw)
        if length > MAX_BODY_BYTES:
            return None
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, OSError):
            return None
        if not isinstance(body, dict):
            return None
        return body

    def _respond(self, status: int, payload: dict[str, Any]) -> None:
        request_id = self._request_id()
        if "request_id" not in payload:
            payload = {"request_id": request_id, **payload}
        data = _json_ok(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-ID", request_id)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if not self._authorized():
            self._respond(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return
        if path == "/health":
            self._respond(HTTPStatus.OK, {"ok": True, "version": VERSION})
        elif path == "/capabilities":
            self._respond(HTTPStatus.OK, {"ok": True, **capabilities()})
        elif path == "/openapi.json":
            self._respond(HTTPStatus.OK, openapi_spec())
        else:
            self._respond(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._authorized():
            self._respond(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "unauthorized"})
            return
        path = {
            "/v1/extract": "/extract",
            "/v1/extract/batch": "/extract/batch",
        }.get(path, path)
        if path not in (
            "/inspect",
            "/clean",
            "/detect",
            "/extract",
            "/extract/batch",
            "/inspect/batch",
            "/detect/batch",
            "/clean/batch",
        ):
            self._respond(HTTPStatus.NOT_FOUND, {"ok": False, "error": "not found"})
            return
        body = self._read_json()
        if body is None:
            raw_len = self.headers.get("Content-Length")
            oversized = raw_len is not None and raw_len.isdigit() and int(raw_len) > MAX_BODY_BYTES
            self._respond(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE if oversized else HTTPStatus.BAD_REQUEST,
                {"ok": False, "error": "invalid request body"},
            )
            return
        try:
            if path == "/inspect/batch":
                self._handle_inspect_batch(body)
            elif path == "/detect/batch":
                self._handle_detect_batch(body)
            elif path == "/extract/batch":
                self._handle_extract_batch(body)
            elif path == "/clean/batch":
                self._handle_clean_batch(body)
            else:
                data, name = _decode_input(body)
                if path == "/inspect":
                    self._handle_inspect(data, name, body)
                elif path == "/detect":
                    self._handle_detect(data, name)
                elif path == "/extract":
                    self._handle_extract(data, name, body)
                else:
                    self._handle_clean(data, name, body)
        except ValueError as e:
            self._respond(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(e)})
        except Exception as e:
            eprint(f"error handling {path}: {e!r}")
            self._respond(
                HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": "internal error"}
            )

    def _handle_inspect(self, data: bytes, name: str, body: dict[str, Any]) -> None:
        run_detect = body.get("detect") is True
        self._respond(HTTPStatus.OK, _inspect_payload(data, name, run_detect))

    def _handle_inspect_batch(self, body: dict[str, Any]) -> None:
        items = _batch_items(body)
        run_detect = body.get("detect") is True
        results = []
        for name, data, _options, error in items:
            if error is not None:
                results.append({"name": name, "ok": False, "error": error})
                continue
            try:
                payload = _inspect_payload(data, name, run_detect)
            except ValueError as e:
                results.append({"name": name, "ok": False, "error": str(e)})
                continue
            results.append({"name": name, **payload})
        self._respond(HTTPStatus.OK, {"ok": True, "results": results})

    def _handle_detect(self, data: bytes, name: str) -> None:
        self._respond(HTTPStatus.OK, _detect_payload(data, name))

    def _handle_extract(self, data: bytes, name: str, body: dict[str, Any]) -> None:
        declared_mime = body.get("mime")
        if declared_mime is not None and not isinstance(declared_mime, str):
            raise ValueError("'mime' must be a string")
        payload = _extract_payload(data, name, declared_mime)
        payload["request_id"] = self._request_id()
        self._respond(HTTPStatus.OK, payload)

    def _handle_extract_batch(self, body: dict[str, Any]) -> None:
        items = _batch_items(body)
        results = []
        for index, (name, data, _options, error) in enumerate(items):
            item_request_id = f"{self._request_id()}:{index + 1}"
            if error is not None:
                results.append(
                    {"name": name, "ok": False, "request_id": item_request_id, "error": error}
                )
                continue
            raw_files = body.get("files", [])
            entry = raw_files[index] if index < len(raw_files) else {}
            declared_mime = entry.get("mime") if isinstance(entry, dict) else None
            if declared_mime is not None and not isinstance(declared_mime, str):
                results.append(
                    {
                        "name": name,
                        "ok": False,
                        "request_id": item_request_id,
                        "error": "'mime' must be a string",
                    }
                )
                continue
            try:
                payload = _extract_payload(data, name, declared_mime)
                payload["request_id"] = item_request_id
            except ValueError as exc:
                payload = {
                    "ok": False,
                    "request_id": item_request_id,
                    "error": str(exc),
                }
            results.append({"name": name, **payload})
        self._respond(HTTPStatus.OK, {"ok": True, "results": results})

    def _handle_detect_batch(self, body: dict[str, Any]) -> None:
        items = _batch_items(body)
        results = []
        for name, data, _options, error in items:
            if error is not None:
                results.append({"name": name, "ok": False, "error": error})
                continue
            try:
                payload = _detect_payload(data, name)
            except ValueError as e:
                results.append({"name": name, "ok": False, "error": str(e)})
                continue
            results.append({"name": name, **payload})
        self._respond(HTTPStatus.OK, {"ok": True, "results": results})

    def _handle_clean(self, data: bytes, name: str, body: dict[str, Any]) -> None:
        options = _parse_clean_options(body.get("options"))
        self._respond(HTTPStatus.OK, _clean_payload(data, name, options))

    def _handle_clean_batch(self, body: dict[str, Any]) -> None:
        items = _batch_items(body)
        results = []
        for name, data, options, error in items:
            if error is not None:
                results.append({"name": name, "ok": False, "error": error})
                continue
            try:
                payload = _clean_payload(data, name, options)
            except ValueError as e:
                results.append({"name": name, "ok": False, "error": str(e)})
                continue
            results.append({"name": name, **payload})
        self._respond(HTTPStatus.OK, {"ok": True, "results": results})


def main() -> int:
    global API_KEY  # noqa: PLW0603 — CLI overrides env
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("WATERMARKS_SERVER_HOST", "127.0.0.1"))
    p.add_argument(
        "--port", type=int, default=int(os.environ.get("WATERMARKS_SERVER_PORT", "8765"))
    )
    p.add_argument("--api-key", default=API_KEY, help="require this bearer token (default: none)")
    p.add_argument("-V", "--version", action="store_true", help="print version and exit")
    args = p.parse_args()

    if args.version:
        print(VERSION)
        return 0

    API_KEY = args.api_key

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        eprint(f"warning: binding {args.host} — intended for a trusted network only")
    if API_KEY:
        eprint("API key required for requests")
    else:
        eprint("warning: no API key set — only bind to loopback or a trusted network")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    eprint(f"watermarks-remover service {VERSION} on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        eprint("shutting down")
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
