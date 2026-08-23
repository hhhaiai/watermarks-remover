"""Tests for the HTTP detection surface: /detect, /inspect detect flag,
/clean detect_before/detect_after, capabilities, and the SynthID sidecar."""

from __future__ import annotations

import base64
import http.client
import io
import json
import struct
import subprocess
import sys
import threading
import zipfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "service" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import image_meta
import server
import text_detectors


def _png_chunk(ctype: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(ctype)
    crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)


def _watermarked_png() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\x00\x00")
    text = b"Comment\x00c2pa test contentcredentials"
    return (
        sig
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"tEXt", text)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _post(conn, path: str, payload: dict) -> tuple[int, dict]:
    conn.request(
        "POST",
        path,
        body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, json.loads(data) if data else {}


def test_extract_text_returns_hash_and_occurrence_evidence(conn):
    text = "A\u200bB\u200cC\u200bD"
    status, body = _post(
        conn,
        "/extract",
        {"file": _b64(text.encode()), "name": "notes.txt", "mime": "text/plain"},
    )
    assert status == 200
    assert body["ok"] is True
    assert body["source"]["kind"] == "text"
    assert body["source"]["media_type"] == "text/plain"
    assert len(body["source"]["sha256"]) == 64
    assert body["verdict"] == "detected"
    assert body["schema"] == {
        "name": "watermarks-remover.evidence",
        "version": "1.0.0",
        "status_values": [
            "detected",
            "not_detected",
            "inconclusive",
            "unavailable",
            "error",
        ],
    }
    assert body["workflow"] == {
        "stage": "extract",
        "read_only": True,
        "input_mutated": False,
    }
    unicode_items = [item for item in body["evidence"] if item["layer"] == "unicode"]
    occurrences = [item for item in unicode_items if "character_offset" in item]
    assert [item["codepoint"] for item in occurrences] == ["U+200B", "U+200C", "U+200B"]
    assert occurrences[1]["byte_offset"] > occurrences[0]["byte_offset"]
    assert all(item["evidence_id"].startswith("ev_") for item in body["evidence"])
    assert all(item["source_sha256"] == body["source"]["sha256"] for item in body["evidence"])
    assert occurrences[0]["carrier"] == "zwj_family"
    assert occurrences[0]["verification"] == {
        "status": "verified",
        "method": "deterministic_codepoint_observation",
    }
    assert occurrences[0]["confidence_level"] == "probable"
    assert occurrences[0]["locator"] == {
        "character_offset": 1,
        "byte_offset": 1,
    }
    assert body["evidence_summary"]["evidence_count"] == len(body["evidence"])
    assert body["evidence_summary"]["verification_counts"]["verified"] == 3


def test_evidence_normalization_preserves_extractor_confidence() -> None:
    source_sha256 = "a" * 64
    evidence, summary = server._normalize_evidence_schema(
        [
            {
                "layer": "unicode",
                "extractor": "UnicodeCandidatePayloadDecoder",
                "status": "inconclusive",
                "confidence": 0.45,
            }
        ],
        source_sha256,
    )
    assert evidence[0]["confidence"] == 0.45
    assert evidence[0]["confidence_level"] == "informational"
    assert evidence[0]["source_sha256"] == source_sha256
    assert summary["evidence_count"] == 1


def test_v1_extract_is_evidence_compatible_with_legacy_alias(conn):
    payload = {
        "file": _b64("证据\u200b绑定".encode()),
        "name": "proof.txt",
        "mime": "text/plain",
    }
    legacy_status, legacy = _post(conn, "/extract", payload)
    v1_status, v1 = _post(conn, "/v1/extract", payload)
    assert legacy_status == v1_status == 200
    for key in (
        "schema",
        "workflow",
        "source",
        "verdict",
        "coverage",
        "evidence",
        "evidence_summary",
        "limitations",
        "extractor_versions",
        "detections",
    ):
        assert v1[key] == legacy[key], key
    assert v1["request_id"] != legacy["request_id"]


def test_v1_extract_batch_returns_schema_per_item(conn):
    status, body = _post(
        conn,
        "/v1/extract/batch",
        {
            "files": [
                {"file": _b64(b"plain"), "name": "plain.txt"},
                {"file": _b64(b"A\xe2\x80\x8bB"), "name": "marked.txt"},
            ]
        },
    )
    assert status == 200
    assert [item["schema"]["version"] for item in body["results"]] == ["1.0.0", "1.0.0"]
    assert body["results"][1]["evidence_summary"]["status_counts"]["detected"] == 1


def test_extract_unknown_format_is_inconclusive(conn):
    status, body = _post(conn, "/extract", {"file": _b64(b"\x00\x01\x02"), "name": "blob.bin"})
    assert status == 200
    assert body["source"]["kind"] == "unknown"
    assert body["verdict"] == "inconclusive"
    assert body["coverage"] == 0.0


def test_extract_escapes_surrogateescaped_context(conn):
    status, body = _post(
        conn,
        "/extract",
        {"file": _b64(b"A\xff\xe2\x80\x8bB"), "name": "notes.txt"},
    )
    assert status == 200
    occurrence = next(item for item in body["evidence"] if "character_offset" in item)
    assert "\\udcff" in occurrence["context_before"]


def test_extract_image_reports_completed_metadata_scan_and_unavailable_pixel_scan(conn):
    status, body = _post(
        conn,
        "/extract",
        {
            "file": _b64(_watermarked_png().replace(b"c2pa test contentcredentials", b"plain")),
            "name": "pixel.png",
        },
    )
    assert status == 200
    assert body["source"]["detected_media_type"] == "image/png"
    metadata = next(
        item for item in body["evidence"] if item["extractor"] == "ImageMetadataExtractor"
    )
    synthid = next(item for item in body["evidence"] if item["extractor"] == "SynthIDImageDetector")
    assert metadata["status"] == "not_detected"
    assert synthid["status"] == "unavailable"
    assert body["coverage"] == 0.5
    assert body["verdict"] == "inconclusive"


def test_extract_pdf_scans_raw_embedded_image_stream(conn):
    embedded = _watermarked_png()
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /XObject /Subtype /Image >>\nstream\n"
        + embedded
        + b"\nendstream\nendobj\n"
        b"%%EOF\n"
    )
    status, body = _post(conn, "/extract", {"file": _b64(pdf), "name": "image.pdf"})
    assert status == 200
    assert body["source"]["kind"] == "container"
    embedded_report = body["report"]["details"]["embedded_images"]
    assert embedded_report["candidate_count"] == 1
    assert embedded_report["candidates"][0]["format"] == "png"
    assert embedded_report["candidates"][0]["has_c2pa"] is True
    embedded_evidence = next(
        item for item in body["evidence"] if item["extractor"] == "PDFEmbeddedImageExtractor"
    )
    assert embedded_evidence["status"] == "detected"
    assert any(item["layer"] == "metadata" for item in body["evidence"])


def test_extract_pdf_scans_bounded_flate_decoded_image_stream(conn):
    embedded = _watermarked_png()
    compressed = zlib.compress(embedded)
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /XObject /Subtype /Image /Filter /FlateDecode >>\nstream\n"
        + compressed
        + b"\nendstream\nendobj\n"
        b"%%EOF\n"
    )
    status, body = _post(conn, "/extract", {"file": _b64(pdf), "name": "flate.pdf"})
    assert status == 200
    candidate = body["report"]["details"]["embedded_images"]["candidates"][0]
    assert candidate["filter"] == "FlateDecode"
    assert candidate["offset"] is None
    assert candidate["decoded_offset"] == 0
    assert candidate["has_c2pa"] is True


def test_extract_pdf_scans_embedded_text_file_unicode(conn):
    attachment = "A\u200bB".encode()
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /EmbeddedFile /Subtype /text#2Fplain /Length 5 >>\nstream\n"
        + attachment
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    status, body = _post(conn, "/extract", {"file": _b64(pdf), "name": "attachment.pdf"})
    assert status == 200
    assert body["verdict"] == "detected"
    report = body["report"]["details"]["embedded_files"]
    assert report["candidate_count"] == 1
    assert report["detected_count"] == 1
    candidate = report["candidates"][0]
    assert candidate["subtype"] == "text/plain"
    assert candidate["content"]["kind"] == "text"
    assert candidate["content"]["layer_a_total"] == 1
    evidence = next(
        item for item in body["evidence"] if item["extractor"] == "PDFEmbeddedFileExtractor"
    )
    assert evidence["status"] == "detected"


def test_extract_pdf_embedded_file_unknown_filter_is_inconclusive(conn):
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /EmbeddedFile /Filter /ASCII85Decode /Length 4 >>\nstream\n"
        b"test\nendstream\nendobj\n%%EOF\n"
    )
    status, body = _post(conn, "/extract", {"file": _b64(pdf), "name": "filtered.pdf"})
    assert status == 200
    candidate = body["report"]["details"]["embedded_files"]["candidates"][0]
    assert candidate["evidence_status"] == "inconclusive"
    assert candidate["limitation"] == "attachment filter chain is not supported"


def test_extract_batch_keeps_per_item_request_ids_and_mime(conn):
    status, body = _post(
        conn,
        "/extract/batch",
        {
            "files": [
                {"file": _b64(b"plain"), "name": "a.txt", "mime": "text/custom"},
                {"file": _b64(b"A\xe2\x80\x8bB"), "name": "b.txt"},
            ]
        },
    )
    assert status == 200
    assert body["ok"] is True
    assert len(body["request_id"]) > 3
    assert body["results"][0]["request_id"] == f"{body['request_id']}:1"
    assert body["results"][1]["request_id"] == f"{body['request_id']}:2"
    assert body["results"][0]["source"]["declared_media_type"] == "text/custom"
    assert body["results"][1]["verdict"] == "detected"


def test_extract_docx_returns_part_local_unicode_evidence(conn):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>A&#x200B;B\u2060C</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )

    status, body = _post(
        conn,
        "/extract",
        {"file": _b64(buf.getvalue()), "name": "evidence.docx"},
    )
    assert status == 200
    assert body["source"]["kind"] == "container"
    assert body["verdict"] == "detected"
    unicode_items = [item for item in body["evidence"] if item["layer"] == "unicode"]
    assert {item["codepoint"] for item in unicode_items} == {"U+200B", "U+2060"}
    assert {item["part"] for item in unicode_items} == {"word/document.xml"}
    entity = next(item for item in unicode_items if item["codepoint"] == "U+200B")
    assert entity["samples"][0]["source_fragment"] == "&#x200B;"


def test_external_structure_parity_breaks_only_when_output_regresses(monkeypatch):
    monkeypatch.setattr(server, "which", lambda cmd: "/fake/qpdf" if cmd == "qpdf" else None)

    def fake_run(command, **kwargs):
        path = str(command[-1])
        return subprocess.CompletedProcess(command, 2 if "after.pdf" in path else 0, "", "bad")

    monkeypatch.setattr(server.subprocess, "run", fake_run)
    result = server._run_external_structure_parity(
        b"%PDF-1.4\n%%EOF\n", b"%PDF-1.4\n%%EOF\n", "container", "pdf"
    )
    assert result["qpdf"]["status"] == "broken"


def _get(conn, path: str) -> tuple[int, dict]:
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, json.loads(data) if data else {}


class _FakeResp:
    def __init__(self, data: dict):
        self._data = json.dumps(data).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._data


@pytest.fixture(scope="module")
def conn() -> http.client.HTTPConnection:
    srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
    yield c
    c.close()
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in (
        "WATERMARKS_SYNTHID_SCORER_URL",
        "WATERMARKS_SYNTHID_SCORER_API_KEY",
        "MARKLLM_DIR",
    ):
        monkeypatch.delenv(key, raising=False)


def test_capabilities_exposes_detectors(conn):
    status, body = _get(conn, "/capabilities")
    assert status == 200
    assert set(body["text_detectors"]) == {"markllm", "gumbel", "claude-text"}
    assert "synthid_http" in body["scorers"]


def test_openapi_includes_detect(conn):
    status, body = _get(conn, "/openapi.json")
    assert status == 200
    assert "/detect" in body["paths"]
    assert (
        "detect_before"
        in body["paths"]["/clean"]["post"]["requestBody"]["content"]["application/json"]["schema"][
            "properties"
        ]["options"]["properties"]
    )


def test_detect_text_without_detectors(conn):
    payload = {"file": _b64(b"some plain text"), "name": "notes.txt"}
    status, body = _post(conn, "/detect", payload)
    assert status == 200
    assert body["kind"] == "text"
    names = {d["detector"] for d in body["detections"]}
    assert "stylometry" in names
    assert "claude-text" in names  # placeholder always reports unavailable


def _markllm_watermarked(monkeypatch, tmp_path):
    """Configure the MarkLLM detector with a stubbed subprocess result."""
    upstream = tmp_path / "MarkLLM"
    upstream.mkdir()
    monkeypatch.setenv("MARKLLM_DIR", str(upstream))

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout=json.dumps({"is_watermarked": True, "score": 1.0})
        )

    monkeypatch.setattr(text_detectors.subprocess, "run", fake_run)


def test_detect_text_with_markllm(conn, monkeypatch, tmp_path):
    _markllm_watermarked(monkeypatch, tmp_path)
    payload = {"file": _b64(b"watermarked prose here"), "name": "notes.txt"}
    status, body = _post(conn, "/detect", payload)
    assert status == 200
    markllm = next(d for d in body["detections"] if d["detector"] == "markllm")
    assert markllm["available"] is True
    assert markllm["is_watermarked"] is True


def test_inspect_detect_is_opt_in(conn, monkeypatch, tmp_path):
    _markllm_watermarked(monkeypatch, tmp_path)
    txt = b"watermarked prose here"
    # without the flag: no detector calls, no text_detectors key
    status, body = _post(conn, "/inspect", {"file": _b64(txt), "name": "notes.txt"})
    assert status == 200
    assert "text_detectors" not in body["report"]
    # with the flag: detector results appear and can flip suspicious
    status, body = _post(conn, "/inspect", {"file": _b64(txt), "name": "notes.txt", "detect": True})
    assert status == 200
    assert "text_detectors" in body["report"]
    assert body["suspicious"] is True


def test_clean_text_detect_before_after(conn, monkeypatch, tmp_path):
    _markllm_watermarked(monkeypatch, tmp_path)
    txt = ("watermarked prose here. " * 5).encode("utf-8")
    status, body = _post(
        conn,
        "/clean",
        {
            "file": _b64(txt),
            "name": "notes.txt",
            "options": {"detect_before": True, "detect_after": True},
        },
    )
    assert status == 200
    det = body["report"]["text_detectors"]
    assert set(det) == {"before", "after"}
    assert det["before"][0]["is_watermarked"] is True
    assert det["after"][0]["is_watermarked"] is True


def test_clean_reports_hashes_and_post_clean_validation(conn):
    txt = b"A\xe2\x80\x8bB"
    status, body = _post(conn, "/clean", {"file": _b64(txt), "name": "notes.txt"})
    assert status == 200
    assert body["ok"] is True
    validation = body["report"]["validation"]
    assert validation["ok"] is True
    assert validation["format_after"] == "text"
    assert len(validation["sha256_before"]) == 64
    assert len(validation["sha256_after"]) == 64
    assert body["report"]["source_sha256"] == validation["sha256_before"]


def test_clean_image_detect_before_after_sidecar(conn, monkeypatch):
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_URL", "http://scorer:8766")
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_ALLOWED_HOSTS", "scorer")
    monkeypatch.setattr(image_meta, "_synthid_resolve_addresses", lambda host, port: ("127.0.0.1",))
    monkeypatch.setattr(
        image_meta,
        "_synthid_http_request",
        lambda *args, **kwargs: {
            "available": True,
            "is_watermarked": True,
            "confidence": 0.91,
            "phase_match": 0.8,
        },
    )
    status, body = _post(
        conn,
        "/clean",
        {
            "file": _b64(_watermarked_png()),
            "name": "shot.png",
            "options": {"detect_before": True, "detect_after": True},
        },
    )
    assert status == 200
    report = body["report"]
    assert report["synthid_before"]["is_watermarked"] is True
    assert report["synthid_after"]["is_watermarked"] is True


def test_run_synthid_score_http_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_URL", "http://scorer:8766")
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_ALLOWED_HOSTS", "scorer")
    seen = {}

    monkeypatch.setattr(image_meta, "_synthid_resolve_addresses", lambda host, port: ("127.0.0.1",))

    def fake_request(
        scheme,
        host,
        port,
        path,
        addresses,
        body,
        headers,
        timeout,
        max_response_bytes,
    ):
        seen["url"] = f"{scheme}://{host}:{port}{path}"
        seen["timeout"] = timeout
        seen["addresses"] = addresses
        return {"available": True, "is_watermarked": False, "confidence": 0.1}

    monkeypatch.setattr(image_meta, "_synthid_http_request", fake_request)
    img = tmp_path / "x.png"
    img.write_bytes(_watermarked_png())
    payload = image_meta.run_synthid_score(img)
    assert payload["available"] is True
    assert payload["is_watermarked"] is False
    assert seen["url"] == "http://scorer:8766/score"
    assert seen["timeout"] == 60.0
    assert seen["addresses"] == ("127.0.0.1",)


def test_synthid_score_http_rejects_unallowlisted_host(tmp_path, monkeypatch):
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_URL", "https://example.test")
    img = tmp_path / "x.png"
    img.write_bytes(_watermarked_png())
    payload = image_meta.run_synthid_score(img)
    assert payload["available"] is False
    assert "not allowlisted" in payload["error"]


def test_synthid_score_http_rejects_link_local_target(tmp_path, monkeypatch):
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_URL", "http://scorer:8766")
    monkeypatch.setenv("WATERMARKS_SYNTHID_SCORER_ALLOWED_HOSTS", "scorer")
    monkeypatch.setattr(
        image_meta,
        "_synthid_resolve_addresses",
        lambda host, port: (_ for _ in ()).throw(
            ValueError("refusing unsafe scorer address for scorer: 169.254.169.254")
        ),
    )
    img = tmp_path / "x.png"
    img.write_bytes(_watermarked_png())
    payload = image_meta.run_synthid_score(img)
    assert payload["available"] is False
    assert "unsafe scorer address" in payload["error"]


def test_detect_image_no_scorer(conn):
    status, body = _post(conn, "/detect", {"file": _b64(_watermarked_png()), "name": "shot.png"})
    assert status == 200
    assert body["kind"] == "image"
    assert body["detections"][0]["available"] is False


def test_detect_batch_text_files(conn):
    status, body = _post(
        conn,
        "/detect/batch",
        {
            "files": [
                {"file": _b64(b"Hello world from simple clean text."), "name": "doc1.txt"},
                {"file": _b64(b"Second document test."), "name": "doc2.txt"},
            ]
        },
    )
    assert status == 200
    assert body["ok"] is True
    assert len(body["results"]) == 2
    res1, res2 = body["results"]
    assert res1["name"] == "doc1.txt"
    assert res1["ok"] is True
    assert res1["kind"] == "text"
    assert any(d["detector"] == "stylometry" for d in res1["detections"])
    assert res2["name"] == "doc2.txt"
    assert res2["ok"] is True


def test_detect_batch_mixed_formats(conn):
    status, body = _post(
        conn,
        "/detect/batch",
        {
            "files": [
                {"file": _b64(b"Plain text note"), "name": "a.txt"},
                {"file": _b64(_watermarked_png()), "name": "b.png"},
            ]
        },
    )
    assert status == 200
    assert body["ok"] is True
    results = {r["name"]: r for r in body["results"]}
    assert results["a.txt"]["kind"] == "text"
    assert results["b.png"]["kind"] == "image"


def test_detect_batch_bad_entry_does_not_abort_others(conn):
    status, body = _post(
        conn,
        "/detect/batch",
        {
            "files": [
                {"file": "!!!not_base64!!!", "name": "bad.txt"},
                {"file": _b64(b"Valid text"), "name": "good.txt"},
            ]
        },
    )
    assert status == 200
    assert body["ok"] is True
    results = {r["name"]: r for r in body["results"]}
    assert results["bad.txt"]["ok"] is False
    assert "base64" in results["bad.txt"]["error"]
    assert results["good.txt"]["ok"] is True


def test_detect_batch_empty_rejected(conn):
    status, body = _post(conn, "/detect/batch", {"files": []})
    assert status == 400
    assert "must not be empty" in body["error"]


def test_detect_batch_openapi_spec_registered(conn):
    status, body = _get(conn, "/openapi.json")
    assert status == 200
    assert "/detect/batch" in body["paths"]
    assert "post" in body["paths"]["/detect/batch"]
