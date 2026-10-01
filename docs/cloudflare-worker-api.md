# Cloudflare Worker API

This project has two separate Cloudflare surfaces:

```text
browser UI → Pages Function → Python cleaning service
API client → remove-watermark-api Worker → Python cleaning service
```

The Worker is an authenticated edge proxy. It **does not run Python, Pillow,
qpdf, exiftool, C2PA tools, CtrlRegen, or MarkDiffusion inside Workers**. A
real cleaning backend must be reachable over HTTPS from Cloudflare.

The Worker requires both `API_KEY` and `BACKEND_API_KEY`; it fails closed when
the backend credential is absent. The current client key is a temporary,
operator-provided value and is not suitable for a public production API. Rotate
it to a long random secret and add Cloudflare WAF/rate limiting before sharing
the endpoint outside a controlled test.

## Deploy

Do not put a key or backend URL in `worker/wrangler.toml` or source code.
Configure three secrets (the client key is currently held in Cloudflare Secret
Store and should be rotated before public release):

```bash
npx wrangler secret put API_KEY --config worker/wrangler.toml
npx wrangler secret put BACKEND_URL --config worker/wrangler.toml
npx wrangler secret put BACKEND_API_KEY --config worker/wrangler.toml
npx wrangler deploy --config worker/wrangler.toml
```

`BACKEND_API_KEY` must match `WATERMARKS_SERVER_API_KEY` on the Python service.
The Worker removes the caller's `Authorization` header and injects only this
server-side credential upstream.

The edge request cap is 95 MiB for the JSON/base64 envelope. The existing web
client's 70 MiB raw-file cap expands to roughly 93.4 MiB and is intended to
remain below that envelope limit; larger uploads require a direct-upload/R2
design.

The deploy command prints the Worker URL. Keep it separate from the Pages URL;
the Pages Function is a UI transport and does not require exposing the API key
to browser JavaScript.

## Verify before publishing the URL

First verify the HTTPS origin directly:

```bash
curl -fsS "$BACKEND_URL/health" \
  -H "Authorization: Bearer $BACKEND_API_KEY"
```

Then verify the Worker. Do not print the key in shell history or logs:

```bash
API_URL='https://remove-watermark-api.<account>.workers.dev'
curl -i "$API_URL/health"
curl -i "$API_URL/health" -H 'Authorization: Bearer <operator-key>'
curl -i "$API_URL/not-allowed" -H 'Authorization: Bearer <operator-key>'
```

Expected states are `401` without the key, `200` only when the backend is
reachable and the key is valid, and `404` for an unlisted route. A Worker
deployment that returns `503 backend is not configured` or `502 backend
unavailable` is not a usable public API.

## Capability boundary

The API reports the Python backend's capabilities. Metadata stripping can be
verified by re-inspection. Pixel-domain watermarks require a configured
CtrlRegen/MarkDiffusion backend and detector before they can be described as
removed. No Worker or API key can guarantee that every commercial AI detector
will classify an image as human-made.
