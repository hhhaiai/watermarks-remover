const ROUTES = new Set([
  "GET /health",
  "GET /capabilities",
  "GET /openapi.json",
  "POST /inspect",
  "POST /detect",
  "POST /extract",
  "POST /extract/batch",
  "POST /v1/extract",
  "POST /v1/extract/batch",
  "POST /clean",
  "POST /inspect/batch",
  "POST /detect/batch",
  "POST /clean/batch",
]);

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

// Leave headroom below the Workers request and isolate memory limits. The
// browser's 70 MiB raw-file cap expands to roughly 93.4 MiB in JSON/base64.
const MAX_BODY_BYTES = 95 * 1024 * 1024;

function requestId(request) {
  const incoming = (request.headers.get("x-request-id") || "").trim();
  if (incoming && incoming.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(incoming)) return incoming;
  return `wm_${crypto.randomUUID().replaceAll("-", "").slice(0, 20)}`;
}

function jsonResponse(status, payload, id, extra = {}) {
  return new Response(JSON.stringify({ request_id: id, ...payload }), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Request-ID": id,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Request-ID",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      ...extra,
    },
  });
}

function unauthorized(id) {
  return jsonResponse(
    401,
    { ok: false, error: "unauthorized" },
    id,
    { "WWW-Authenticate": "Bearer" },
  );
}

function authorized(request, env) {
  const expected = (env.API_KEY || "").trim();
  if (!expected) return false;
  const value = request.headers.get("authorization") || "";
  return value === `Bearer ${expected}`;
}

function routePath(request) {
  const url = new URL(request.url);
  return url.pathname.replace(/\/+$/, "") || "/";
}

function targetUrl(raw, path, search) {
  let base;
  try {
    base = new URL(raw);
  } catch {
    throw new Error("BACKEND_URL is not a valid URL");
  }
  if (base.protocol !== "https:") {
    throw new Error("BACKEND_URL must use https");
  }
  const prefix = base.pathname.replace(/\/+$/, "");
  base.pathname = `${prefix}${path}` || "/";
  base.search = search;
  base.hash = "";
  return base;
}

function forwardedHeaders(request, env, id) {
  const headers = new Headers(request.headers);
  for (const name of HOP_BY_HOP) headers.delete(name);
  headers.delete("host");
  headers.delete("content-length");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("cf-visitor");
  headers.delete("authorization");
  headers.set("X-Request-ID", id);
  const backendKey = (env.BACKEND_API_KEY || "").trim();
  if (backendKey) headers.set("Authorization", `Bearer ${backendKey}`);
  return headers;
}

function responseHeaders(upstream, id) {
  const headers = new Headers();
  for (const [name, value] of upstream.headers) {
    if (!HOP_BY_HOP.has(name.toLowerCase())) headers.set(name, value);
  }
  headers.set("Cache-Control", "no-store");
  headers.set("X-Request-ID", upstream.headers.get("X-Request-ID") || id);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  return headers;
}

export default {
  async fetch(request, env) {
    const id = requestId(request);
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Request-ID",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Max-Age": "600",
          "X-Request-ID": id,
        },
      });
    }

    if (!authorized(request, env)) return unauthorized(id);

    const path = routePath(request);
    const method = request.method.toUpperCase();
    if (!ROUTES.has(`${method} ${path}`)) {
      return jsonResponse(404, { ok: false, error: "not found" }, id);
    }

    const backendUrl = (env.BACKEND_URL || "").trim();
    if (!backendUrl) {
      return jsonResponse(503, { ok: false, error: "backend is not configured" }, id);
    }

    const backendKey = (env.BACKEND_API_KEY || "").trim();
    if (!backendKey) {
      return jsonResponse(503, { ok: false, error: "backend authentication is not configured" }, id);
    }

    let body;
    if (method !== "GET" && method !== "HEAD") {
      // Content-Length is optional for chunked requests. Buffer the bounded
      // JSON envelope so a client cannot bypass the edge cap with streaming.
      let bytes;
      try {
        bytes = await request.arrayBuffer();
      } catch (error) {
        console.error("remove-watermark-api request body read failed", error);
        return jsonResponse(400, { ok: false, error: "invalid request body" }, id);
      }
      if (bytes.byteLength > MAX_BODY_BYTES) {
        return jsonResponse(413, { ok: false, error: "request body too large" }, id);
      }
      body = bytes;
    }

    let target;
    try {
      target = targetUrl(backendUrl, path, new URL(request.url).search);
    } catch (error) {
      return jsonResponse(500, { ok: false, error: error.message }, id);
    }

    try {
      const upstream = await fetch(target, {
        method,
        headers: forwardedHeaders(request, env, id),
        body,
        redirect: "manual",
      });
      if (upstream.status >= 300 && upstream.status < 400) {
        return jsonResponse(502, { ok: false, error: "backend redirect not allowed" }, id);
      }
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: responseHeaders(upstream, id),
      });
    } catch (error) {
      console.error("remove-watermark-api backend fetch failed", error);
      return jsonResponse(502, { ok: false, error: "backend unavailable" }, id);
    }
  },
};
