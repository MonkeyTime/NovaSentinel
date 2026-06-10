import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const host = process.env.NOVASENTINEL_ADMIN_HOST || "127.0.0.1";
const port = Number.parseInt(process.env.NOVASENTINEL_ADMIN_PORT || "8790", 10);
const rootDir = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === "production";

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "),
  ...(isProduction ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
};
const maxBodyBytes = 20 * 1024 * 1024;

const contentTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".ico", "image/x-icon"]
]);
const allowedStaticExtensions = new Set([".html", ".js", ".css", ".json", ".svg", ".ico"]);

function isSafeStaticPath(filePath) {
  const relative = path.relative(rootDir, filePath);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) return false;
  if (relative.includes("..")) return false;
  const normalized = `/${relative.replace(/\\/g, "/")}`;
  if (normalized.includes("/.")) return false;

  const unsafeSegments = [
    "/node_modules/",
    "/.git/",
    "/release_uploads/",
    "/.env",
  ];
  const lower = normalized.toLowerCase();
  if (unsafeSegments.some((segment) => lower.includes(segment))) return false;

  const extension = path.extname(normalized).toLowerCase();
  return extension ? allowedStaticExtensions.has(extension) : false;
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": headers["Content-Type"] || "application/json; charset=utf-8",
    ...(securityHeaders),
    "Cache-Control": headers["Cache-Control"] || "no-store",
    ...headers
  });
  res.end(payload);
}

function sendJson(res, status, body) {
  send(res, status, body);
}

function parseCloudRequest(raw) {
  const payload = typeof raw === "string" ? raw : "";
  if (!payload) {
    const error = new Error("missing_cloud_request");
    error.statusCode = 400;
    throw error;
  }
  try {
    return JSON.parse(payload);
  } catch {
    const error = new Error("invalid_cloud_request");
    error.statusCode = 400;
    throw error;
  }
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBodyBytes) {
      const error = new Error("request_too_large");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function callCloudApi(cloudUrl, path, body, method = "POST") {
  const endpoint = new URL(path, parseCloudUrl(cloudUrl));
  const response = await fetch(endpoint, {
    method,
    headers: {
      Accept: "application/json",
      ...(method === "GET" ? {} : { "Content-Type": "application/json" }),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const payloadText = await response.text();
  let payload = {};
  try {
    payload = payloadText ? JSON.parse(payloadText) : {};
  } catch {
    payload = { message: payloadText?.slice(0, 200) || "invalid json response" };
  }
  if (!response.ok) {
    const error = new Error(payload.error || payload.message || `HTTP ${response.status}`);
    error.statusCode = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function parseCloudUrl(raw) {
  if (!raw || typeof raw !== "string") {
    throw new Error("missing_cloud_url");
  }
  const parsed = new URL(raw);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("unsupported_cloud_url");
  }
  const trusted = process.env.NOVASENTINEL_ADMIN_ALLOWED_CLOUD_HOSTS?.trim();
  const allowedHosts = trusted
    ? trusted.split(",").map((host) => host.trim().toLowerCase()).filter(Boolean)
    : ["127.0.0.1", "localhost"];
  const hostname = parsed.hostname.toLowerCase();
  if (!allowedHosts.includes(hostname)) {
    throw new Error("cloud_host_not_allowed");
  }
  parsed.username = "";
  parsed.password = "";
  parsed.hash = "";
  return parsed;
}

async function fetchCloudHealth(cloudUrl) {
  const base = parseCloudUrl(cloudUrl);
  const endpoint = new URL("/api/health", base);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 6000);
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      signal: controller.signal,
      headers: { Accept: "application/json" }
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text.slice(0, 500) };
    }
    return {
      ok: response.ok,
      status: response.status,
      cloud_origin: base.origin,
      body: json
    };
  } finally {
    clearTimeout(timeout);
  }
}

function serveStatic(req, res, url) {
  const requestedPath = url.pathname === "/" ? "/index.html" : url.pathname;
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(requestedPath);
  } catch {
    sendJson(res, 400, { error: "bad_request" });
    return;
  }
  const resolved = path.resolve(path.join(rootDir, decodedPath));

  if (!isSafeStaticPath(resolved)) {
    sendJson(res, 403, { error: "forbidden" });
    return;
  }

  fs.readFile(resolved, (error, data) => {
    if (error) {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    const extension = path.extname(resolved).toLowerCase();
    send(res, 200, data, {
      "Content-Type": contentTypes.get(extension) || "application/octet-stream",
      "Cache-Control": extension === ".html" ? "no-store" : "public, max-age=300"
    });
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || `${host}:${port}`}`);

  if (req.method === "GET" && url.pathname === "/api/local/health") {
    sendJson(res, 200, {
      ok: true,
      service: "novasentinel-admin-console",
      mode: "local",
      host,
      port
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/cloud/health") {
    try {
      const result = await fetchCloudHealth(url.searchParams.get("url"));
      sendJson(res, result.ok ? 200 : 502, result);
    } catch (error) {
      sendJson(res, 400, {
        ok: false,
        error: error.message === "missing_cloud_url" || error.message === "unsupported_cloud_url"
          ? error.message
          : "cloud_health_failed"
      });
    }
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/cloud/license-info") {
    try {
      const payload = parseCloudRequest(await readBody(req));
      const cloudUrl = String(payload.cloudUrl || "").trim();
      const licenseKey = String(payload.licenseKey || "").trim();
      const channel = String(payload.channel || "stable").trim().toLowerCase();
      if (!cloudUrl || !licenseKey) {
        sendJson(res, 400, {
          ok: false,
          error: "missing_cloud_request_data",
          message: "cloudUrl and licenseKey are required.",
        });
        return;
      }
      const result = await callCloudApi(cloudUrl, "/api/admin-console/license/info", {
        license_key: licenseKey,
        channel,
      });
      sendJson(res, 200, result);
    } catch (error) {
      sendJson(res, error.statusCode || 500, {
        ok: false,
        error: error.message || "cloud_lookup_failed",
        details: error.payload || undefined,
      });
    }
    return;
  }

  if (req.method !== "GET" && req.method !== "HEAD") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }

  serveStatic(req, res, url);
});

server.listen(port, host, () => {
  console.log(`NovaSentinel Admin Console listening on http://${host}:${port}`);
});
