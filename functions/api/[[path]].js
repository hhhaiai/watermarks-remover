const ALLOWED_ROUTES = new Map([
  ["GET /health", true],
  ["GET /capabilities", true],
  ["GET /openapi.json", true],
  ["POST /inspect", true],
  ["POST /detect", true],
  ["POST /extract", true],
  ["POST /extract/batch", true],
  ["POST /v1/extract", true],
  ["POST /v1/extract/batch", true],
  ["POST /clean", true],
  ["POST /inspect/batch", true],
  ["POST /detect/batch", true],
  ["POST /clean/batch", true],
]);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

function requestId(request) {
  const incoming = (request.headers.get("x-request-id") || "").trim();
  if (incoming && incoming.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(incoming)) {
    return incoming;
  }
  return `wm_${crypto.randomUUID().replaceAll("-", "").slice(0, 20)}`;
}

function jsonResponse(status, payload, requestIdValue) {
  return new Response(JSON.stringify({ request_id: requestIdValue, ...payload }), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Request-ID": requestIdValue,
    },
  });
}

function routePath(context) {
  const value = context.params?.path;
  if (Array.isArray(value)) return `/${value.join("/")}`;
  if (typeof value === "string" && value) return `/${value}`;
  return "/";
}

function backendTarget(rawBase, path, search) {
  let base;
  try {
    base = new URL(rawBase);
  } catch {
    throw new Error("WATERMARKS_BACKEND_URL is not a valid URL");
  }

  if (base.protocol !== "http:" && base.protocol !== "https:") {
    throw new Error("WATERMARKS_BACKEND_URL must use http or https");
  }

  const prefix = base.pathname.replace(/\/+$/, "");
  const suffix = path.replace(/^\/+/, "");
  base.pathname = `${prefix}/${suffix}` || "/";
  base.search = search;
  base.hash = "";
  return base;
}

function forwardedHeaders(request, env, requestIdValue) {
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("cf-visitor");
  headers.set("X-Request-ID", requestIdValue);

  // The browser never needs to know the backend credential. When configured,
  // the Pages Function replaces any client-supplied Authorization header.
  const apiKey = (env.WATERMARKS_BACKEND_API_KEY || "").trim();
  if (apiKey) {
    headers.set("Authorization", `Bearer ${apiKey}`);
  } else if (!request.headers.has("Authorization")) {
    headers.delete("Authorization");
  }

  for (const name of HOP_BY_HOP_HEADERS) headers.delete(name);
  return headers;
}

function responseHeaders(upstream, requestIdValue) {
  const headers = new Headers();
  for (const [name, value] of upstream.headers) {
    if (!HOP_BY_HOP_HEADERS.has(name.toLowerCase())) headers.set(name, value);
  }
  headers.set("Cache-Control", "no-store");
  if (!headers.has("X-Request-ID")) headers.set("X-Request-ID", requestIdValue);
  return headers;
}

export async function onRequest(context) {
  const { request, env } = context;
  const requestIdValue = requestId(request);
  const path = routePath(context);
  const method = request.method.toUpperCase();

  if (!ALLOWED_ROUTES.has(`${method} ${path}`)) {
    return jsonResponse(404, { ok: false, error: "not found" }, requestIdValue);
  }

  const backendUrl = (env.WATERMARKS_BACKEND_URL || "").trim();
  if (!backendUrl) {
    return jsonResponse(503, {
      ok: false,
      error: "backend is not configured",
    }, requestIdValue);
  }

  let target;
  try {
    target = backendTarget(backendUrl, path, new URL(request.url).search);
  } catch (error) {
    return jsonResponse(500, { ok: false, error: error.message }, requestIdValue);
  }

  try {
    const upstream = await fetch(target, {
      method,
      headers: forwardedHeaders(request, env, requestIdValue),
      body: method === "GET" || method === "HEAD" ? undefined : request.body,
    });

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders(upstream, requestIdValue),
    });
  } catch (error) {
    console.error("Cloudflare Pages backend proxy failed", error);
    return jsonResponse(502, { ok: false, error: "backend unavailable" }, requestIdValue);
  }
}
