"""Static contract checks for the Cloudflare Pages adapter on the cf branch."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNCTION = (ROOT / "functions" / "api" / "[[path]].js").read_text(encoding="utf-8")
SERVER = (ROOT / "service" / "scripts" / "server.py").read_text(encoding="utf-8")
WRANGLER = (ROOT / "wrangler.toml").read_text(encoding="utf-8")
HEADERS = (ROOT / "public" / "_headers").read_text(encoding="utf-8")
INDEX = (ROOT / "public" / "index.html").read_text(encoding="utf-8")
APP = (ROOT / "public" / "app.js").read_text(encoding="utf-8")
I18N = (ROOT / "public" / "i18n.js").read_text(encoding="utf-8")
STYLES = (ROOT / "public" / "styles.css").read_text(encoding="utf-8")


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

THEMES = (
    "system",
    "light",
    "dark",
    "anthropic",
    "rose",
    "lake",
    "sunset",
    "forest",
    "sea",
    "lavender",
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


def test_pages_client_runs_all_configured_detectors_for_scan_and_clean() -> None:
    assert 'request("/capabilities")' in APP
    assert 'request("/v1/extract"' in APP
    assert 'request("/extract"' in APP
    assert 'request("/detect"' in APP
    assert "options.detect_before = true;" in APP
    assert "options.detect_after = true;" in APP
    assert "mergeCleanReport" in APP


def test_pages_function_keeps_backend_credentials_server_side() -> None:
    assert "WATERMARKS_BACKEND_API_KEY" in FUNCTION
    assert "Authorization" in FUNCTION
    assert "WATERMARKS_BACKEND_API_KEY" not in INDEX
    assert "WATERMARKS_BACKEND_API_KEY" not in APP


def test_pages_function_correlates_requests_across_the_backend_boundary() -> None:
    assert 'headers.set("X-Request-ID", requestIdValue)' in FUNCTION
    assert '"X-Request-ID": requestIdValue' in FUNCTION
    assert "request_id: requestIdValue" in FUNCTION


def test_faq_open_state_rotates_only_the_chevron() -> None:
    assert INDEX.count('class="faq-question"') == 3
    assert INDEX.count('class="faq-chevron"') == 3
    assert ".faq-list details[open] summary .faq-chevron" in STYLES
    assert ".faq-list details[open] summary span" not in STYLES


def test_theme_presets_are_complete_and_theme_adaptive() -> None:
    for theme in THEMES:
        assert f'value="{theme}"' in INDEX
        assert f'"{theme}"' in APP
        assert f"theme_{theme}" in I18N
    for theme in THEMES:
        if theme != "system":
            assert f'html[data-theme="{theme}"]' in STYLES

    assert 'class="theme-swatch"' in INDEX
    assert 'value="midnight"' not in INDEX
    assert 'value="violet"' not in INDEX
    assert "color-mix(in srgb, var(--accent)" in STYLES


def test_system_theme_follows_os_and_migrates_legacy_preferences() -> None:
    assert 'window.matchMedia("(prefers-color-scheme: light)")' in APP
    assert 'document.documentElement.dataset.themePreference = theme' in APP
    assert "SYSTEM_THEME_QUERY.addEventListener" in APP
    assert 'midnight: "sea"' in APP
    assert 'violet: "lavender"' in APP
    assert '.getPropertyValue("--bg")' in APP


def test_default_language_follows_browser_without_overriding_saved_choice() -> None:
    assert "function detectBrowserLocale()" in APP
    assert "window.navigator.languages" in APP
    assert "window.navigator.language" in APP
    assert 'language === "zh"' in APP
    assert 'return "zh-CN"' in APP
    assert 'language === "pt"' in APP
    assert 'return "pt-BR"' in APP
    assert 'locale: detectBrowserLocale()' in APP
    assert 'localePreference: "browser"' in APP
    assert 'state.localePreference = "manual"' in APP
    assert 'window.addEventListener("languagechange"' in APP
    assert 'state.localePreference === "browser"' in APP
