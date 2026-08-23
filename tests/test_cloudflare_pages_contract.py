"""Static contract checks for the Cloudflare Pages adapter on the cf branch."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FUNCTION = (ROOT / "functions" / "api" / "[[path]].js").read_text(encoding="utf-8")
SERVER = (ROOT / "service" / "scripts" / "server.py").read_text(encoding="utf-8")
WRANGLER = (ROOT / "wrangler.toml").read_text(encoding="utf-8")
HEADERS = (ROOT / "public" / "_headers").read_text(encoding="utf-8")
INDEX = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "public" / "app.js").read_text(encoding="utf-8")


ROUTES = (
    ("GET", "/health"),
    ("GET", "/capabilities"),
    ("GET", "/openapi.json"),
    ("POST", "/inspect"),
    ("POST", "/detect"),
    ("POST", "/clean"),
    ("POST", "/inspect/batch"),
    ("POST", "/detect/batch"),
    ("POST", "/clean/batch"),
)


def test_pages_build_output_and_static_entrypoint_are_present() -> None:
    assert 'pages_build_output_dir = "public"' in WRANGLER
    assert (ROOT / "public" / "index.html").is_file()
    assert 'src="/i18n.js?' in INDEX
    assert 'src="/app.js?' in INDEX
    assert 'href="/styles.css?' in INDEX
    assert (ROOT / "public" / "i18n.js").is_file()
    assert (ROOT / "public" / "styles.css").is_file()


def test_pages_proxy_routes_match_python_service_routes() -> None:
    for method, path in ROUTES:
        assert f'"{method} {path}"' in FUNCTION
        assert f'"{path}"' in SERVER


def test_pages_preview_csp_allows_in_memory_media() -> None:
    assert "img-src 'self' data: blob:" in HEADERS
    assert "media-src 'self' data: blob:" in HEADERS


def test_pages_client_uses_cloudflare_safe_upload_cap() -> None:
    assert "const MAX_BROWSER_FILE_BYTES = 70 * 1024 * 1024;" in APP
    assert "cloudflare_payload_error" in APP


def test_pages_function_keeps_backend_credentials_server_side() -> None:
    assert "WATERMARKS_BACKEND_API_KEY" in FUNCTION
    assert "Authorization" in FUNCTION
    assert "WATERMARKS_BACKEND_API_KEY" not in INDEX
    assert "WATERMARKS_BACKEND_API_KEY" not in APP
