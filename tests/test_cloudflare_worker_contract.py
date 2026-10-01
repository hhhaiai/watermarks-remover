from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT / "worker" / "src" / "index.js").read_text(encoding="utf-8")
CONFIG = (ROOT / "worker" / "wrangler.toml").read_text(encoding="utf-8")


ROUTES = (
    ("GET", "/health"),
    ("GET", "/capabilities"),
    ("GET", "/openapi.json"),
    ("POST", "/inspect"),
    ("POST", "/detect"),
    ("POST", "/extract"),
    ("POST", "/extract/batch"),
    ("POST", "/v1/extract"),
    ("POST", "/v1/extract/batch"),
    ("POST", "/clean"),
    ("POST", "/inspect/batch"),
    ("POST", "/detect/batch"),
    ("POST", "/clean/batch"),
)


def test_worker_config_does_not_embed_runtime_secrets():
    assert 'name = "remove-watermark-api"' in CONFIG
    assert 'main = "src/index.js"' in CONFIG
    assert "API_KEY =" not in CONFIG
    assert "BACKEND_URL" not in CONFIG.split("# Secrets", 1)[0]


def test_worker_allowlist_matches_public_api_routes():
    for method, path in ROUTES:
        assert f'"{method} {path}"' in WORKER


def test_worker_requires_client_bearer_and_keeps_backend_key_server_side():
    assert 'const expected = (env.API_KEY || "").trim();' in WORKER
    assert 'value === `Bearer ${expected}`' in WORKER
    assert 'headers.delete("authorization")' in WORKER
    assert 'env.BACKEND_API_KEY' in WORKER
    assert 'error: "backend authentication is not configured"' in WORKER
    assert 'env.API_KEY' not in WORKER.split('function forwardedHeaders', 1)[1]


def test_worker_has_backend_fail_closed_and_request_correlation():
    assert 'error: "backend is not configured"' in WORKER
    assert 'error: "backend unavailable"' in WORKER
    assert 'headers.set("X-Request-ID", id)' in WORKER
    assert '"X-Request-ID": id' in WORKER
    assert 'throw new Error("BACKEND_URL must use https")' in WORKER
    assert 'redirect: "manual"' in WORKER
    assert 'error: "backend redirect not allowed"' in WORKER


def test_worker_rejects_unlisted_routes_and_large_requests():
    assert 'error: "not found"' in WORKER
    assert 'error: "request body too large"' in WORKER
    assert 'const MAX_BODY_BYTES = 95 * 1024 * 1024;' in WORKER
    assert 'bytes = await request.arrayBuffer();' in WORKER
    assert 'if (bytes.byteLength > MAX_BODY_BYTES)' in WORKER
    assert 'error: "invalid request body"' in WORKER


def test_worker_local_secret_files_are_not_allowed_by_gitignore():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "worker/.dev.vars*" in gitignore
    assert "worker/.env*" in gitignore
    assert "worker/.wrangler/" in gitignore
