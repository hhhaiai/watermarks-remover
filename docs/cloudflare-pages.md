# Cloudflare Pages deployment

This repository now contains a Pages-compatible web client under `public/` and
a Pages Function under `functions/api/[[path]].js`. Pages hosts the static UI;
the existing Python service remains the processing backend because Pages
Functions run JavaScript, not the Python process and system tools used by the
cleaners.

## Architecture

```text
browser → https://remove-watermark.page.dev/
             ├── static UI (Cloudflare Pages)
             └── /api/* (Pages Function) → WATERMARKS_BACKEND_URL
                                           → service/scripts/server.py
```

The proxy only exposes the service routes already supported by this project.
If `WATERMARKS_BACKEND_API_KEY` is configured, it is injected at the Pages
Function boundary and is never sent to browser JavaScript.

## Main → cf parity policy

`cf` is not a fork of the cleaning engine. Before a Pages deployment, update
`main`, fast-forward `cf` to that commit, and keep the Cloudflare-only files
beside the unchanged `service/` tree. The Pages Function is deliberately a
same-origin transport layer; the Python service remains the single source of
truth for classification, inspection, detection, cleaning, options, limits,
and optional backends.

The proxy route allow-list must stay in parity with `service/scripts/server.py`:

| Service route | Pages route | Method |
| --- | --- | --- |
| `/health` | `/api/health` | GET |
| `/capabilities` | `/api/capabilities` | GET |
| `/openapi.json` | `/api/openapi.json` | GET |
| `/inspect` | `/api/inspect` | POST |
| `/detect` | `/api/detect` | POST |
| `/clean` | `/api/clean` | POST |
| `/inspect/batch` | `/api/inspect/batch` | POST |
| `/detect/batch` | `/api/detect/batch` | POST |
| `/clean/batch` | `/api/clean/batch` | POST |

Do not add a second cleaning implementation to `public/app.js`: the client
only encodes the file, forwards the request, and renders the returned report
and cleaned bytes. This preserves new `main` formats and options when the
Python service is updated.

## 1. Run the backend

Run the core container on a host reachable from Cloudflare. The backend URL
must be an HTTPS URL in production:

```bash
docker build -f service/Dockerfile -t watermarks-remover service/
docker run -d --name watermarks-remover \
  --restart unless-stopped \
  -p 8765:8765 \
  -e WATERMARKS_SERVER_API_KEY='replace-with-a-long-random-value' \
  --read-only --tmpfs /tmp \
  watermarks-remover
```

Put TLS in front of port `8765` using the backend host's reverse proxy or a
private service tunnel. Verify the origin before connecting Pages:

```bash
curl -fsS https://backend.example.com/health
```

## 2. Configure the Pages project

Install/authenticate Wrangler, then create the project. Deploy from the
repository root and use the `cf` branch as the production branch if that is
where the deployment is maintained:

```bash
npx wrangler login
npx wrangler pages project create remove-watermark
npx wrangler pages deploy public --project-name remove-watermark --branch cf
```

The root `wrangler.toml` sets the project name and `public` as the Pages build
output directory. There is no npm build step.

In **Pages → remove-watermark → Settings → Variables and Secrets**, add these
production variables:

| Variable | Type | Value |
| --- | --- | --- |
| `WATERMARKS_BACKEND_URL` | Variable | `https://backend.example.com` |
| `WATERMARKS_BACKEND_API_KEY` | Secret | the same value as `WATERMARKS_SERVER_API_KEY` |

After saving variables, create a new deployment so the Function picks them up.
Check `https://remove-watermark.page.dev/api/health` before testing uploads.

## 3. Attach the custom domain

In **Pages → remove-watermark → Custom domains**, add:

```text
remove-watermark.page.dev
```

Follow the DNS validation shown by Cloudflare. The target URL is also embedded
as the canonical URL in `public/index.html`.

For the Pages project created from this branch, the current DNS record is:

| Type | Name | Target | Proxy |
| --- | --- | --- | --- |
| CNAME | `remove-watermark` | `remove-watermark-ddj.pages.dev` | DNS-only while validating |

That record makes `remove-watermark.page.dev` resolve to this Pages project.
The Pages custom-domain status should change from `pending` after DNS
propagation and certificate issuance. If `page.dev` is managed in another
Cloudflare account or at another DNS provider, add the record there; the
current Pages account does not contain an active `page.dev` zone.

## Local verification

With a locally running backend on `http://127.0.0.1:8765`, run the Pages dev
server and set the local-only variable inline:

```bash
npx wrangler pages dev public \
  --binding WATERMARKS_BACKEND_URL=http://127.0.0.1:8765
```

If the local backend has bearer authentication enabled, add a second binding:

```bash
npx wrangler pages dev public \
  --binding WATERMARKS_BACKEND_URL=http://127.0.0.1:8765 \
  --binding WATERMARKS_BACKEND_API_KEY='replace-with-the-local-key'
```

Open the local URL printed by Wrangler. The UI should show **服务在线**, and
the browser requests should use `/api/health`, `/api/inspect`, and `/api/clean`
rather than contacting the backend directly.

## Operational notes

- Pages does not replace the Python backend. Keep the backend container behind
  HTTPS and configure the shared bearer key in both locations.
- The browser UI caps a single file at 75 MiB. Requests are JSON envelopes with
  base64-encoded bytes, so this leaves room below the default 100 MiB
  Cloudflare Pages/Workers request limit. The backend's decoded input cap is
  larger, but the Pages edge limit applies first. Larger uploads require a
  direct-upload/R2 design rather than increasing this client-side constant.
- When the backend is not configured, the text tab still has a clearly labeled
  browser-local fallback for `U+00AD`, `U+200B`, and `U+FEFF`. This is not a
  replacement for the Python service's full text rules; image, video, Office,
  PDF, and complete inspection/cleaning require the backend.
- The Pages Function returns `503 backend is not configured` until
  `WATERMARKS_BACKEND_URL` is set, instead of failing the static deployment.
- The UI creates a download in memory and does not persist the original file.
