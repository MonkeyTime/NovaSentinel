const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");
const { DatabaseSync } = require("node:sqlite");
const QRCode = require("qrcode");

const rootDir = __dirname;
const repoDir = path.resolve(rootDir, "..");
const dataDir = path.join(rootDir, "data");
const releaseUploadDir = path.join(dataDir, "release_uploads");
const downloadDir = path.join(dataDir, "downloads");
const backupDir = path.join(dataDir, "backups");
const dbPath = process.env.NOVASENTINEL_PREMIUM_DB || path.join(dataDir, "premium_cloud.sqlite3");
const host = process.env.HOST || "127.0.0.1";
const port = Number.parseInt(process.env.PORT || "8780", 10);
const sessionCookie = "ns_session";
const sessionTtlSeconds = 8 * 60 * 60;
const challengeTtlSeconds = 5 * 60;
const maxBodyBytes = 300 * 1024 * 1024;
const backupIntervalHours = Math.max(1, Number.parseInt(process.env.NOVASENTINEL_BACKUP_INTERVAL_HOURS || "24", 10));
const backupRetention = Math.max(2, Number.parseInt(process.env.NOVASENTINEL_BACKUP_RETENTION || "14", 10));
const premiumSeatPriceEur = 12;
const publicBaseUrl = process.env.PUBLIC_BASE_URL || `http://${host}:${port}`;
const publicOrigin = new URL(publicBaseUrl);
const isSecureDeployment = publicOrigin.protocol === "https:" || process.env.NODE_ENV === "production";
const stripeSecretKey = process.env.STRIPE_SECRET_KEY || "";
const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET || "";
const premiumSigningPrivateKeyPem = process.env.PREMIUM_ED25519_PRIVATE_KEY_PEM || "";
const githubToken = process.env.GITHUB_TOKEN || "";
const premiumFeatures = [
  "premium_updates",
  "beta_channel",
  "local_ioc_lookup",
  "post_alert_context",
];

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(releaseUploadDir, { recursive: true });
fs.mkdirSync(downloadDir, { recursive: true });
fs.mkdirSync(backupDir, { recursive: true });
const db = new DatabaseSync(dbPath);
db.exec("PRAGMA foreign_keys = ON");
db.exec("PRAGMA journal_mode = WAL");

const mimeTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".svg": "image/svg+xml",
  ".exe": "application/vnd.microsoft.portable-executable",
  ".zip": "application/zip",
};

const ratePolicies = {
  login: { limit: 12, windowSeconds: 10 * 60 },
  claim: { limit: 10, windowSeconds: 15 * 60 },
  checkout: { limit: 12, windowSeconds: 10 * 60 },
  premiumVerify: { limit: 60, windowSeconds: 10 * 60 },
  consoleLookup: { limit: 30, windowSeconds: 10 * 60 },
  logout: { limit: 12, windowSeconds: 10 * 60 },
};

const lockPolicies = {
  login: { failures: 5, lockSeconds: 15 * 60 },
  mfa: { failures: 6, lockSeconds: 15 * 60 },
  claim: { failures: 8, lockSeconds: 20 * 60 },
  checkout: { failures: 8, lockSeconds: 20 * 60 },
  premiumVerify: { failures: 12, lockSeconds: 20 * 60 },
  consoleLookup: { failures: 12, lockSeconds: 20 * 60 },
  logout: { failures: 10, lockSeconds: 5 * 60 },
};

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
    "connect-src 'self'",
    "font-src 'self' data:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "),
  ...(isSecureDeployment ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
};
const maxInstallerUploadBytes = Math.max(1, Number.parseInt(process.env.NOVASENTINEL_MAX_INSTALLER_UPLOAD_BYTES || "26214400", 10));
const blockedStaticExtensions = new Set([".env", ".db", ".sqlite", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".bak", ".pem", ".key"]);
const blockedStaticSegments = ["/data/", "/node_modules/", "/.git/", "/backups/", "/release_uploads/"];

function nowIso() {
  return new Date().toISOString();
}

function nowEpoch() {
  return Math.floor(Date.now() / 1000);
}

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      billing_email TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER REFERENCES organizations(id),
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('user', 'superadmin')),
      mfa_secret TEXT NOT NULL,
      mfa_enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER NOT NULL REFERENCES organizations(id),
      license_key TEXT NOT NULL UNIQUE,
      plan TEXT NOT NULL DEFAULT 'premium',
      seats INTEGER NOT NULL,
      active_seats INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'active',
      channel TEXT NOT NULL DEFAULT 'stable',
      entitlement_version INTEGER NOT NULL DEFAULT 1,
      entitlement_expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS organization_invites (
      id TEXT PRIMARY KEY,
      organization_id INTEGER NOT NULL REFERENCES organizations(id),
      license_id INTEGER NOT NULL REFERENCES licenses(id),
      email TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      claimed_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS activations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_id INTEGER NOT NULL REFERENCES licenses(id),
      device_name TEXT NOT NULL,
      device_id TEXT NOT NULL,
      app_version TEXT NOT NULL,
      channel TEXT NOT NULL,
      activated_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS checkout_sessions (
      id TEXT PRIMARY KEY,
      organization_name TEXT NOT NULL,
      billing_email TEXT NOT NULL,
      seats INTEGER NOT NULL,
      amount_eur INTEGER NOT NULL,
      status TEXT NOT NULL,
      stripe_session_id TEXT,
      stripe_url TEXT,
      created_at TEXT NOT NULL,
      confirmed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS login_challenges (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      csrf_token TEXT,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS releases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      version TEXT NOT NULL,
      channel TEXT NOT NULL,
      status TEXT NOT NULL,
      installer_path TEXT,
      installer_url TEXT,
      sha256 TEXT,
      size_bytes INTEGER,
      notes TEXT,
      published_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_user_id INTEGER REFERENCES users(id),
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_counters (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      window_start INTEGER NOT NULL DEFAULT 0,
      locked_until INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
    CREATE INDEX IF NOT EXISTS idx_security_counters_locked_until ON security_counters(locked_until);

    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
    BEGIN
      SELECT RAISE(ABORT, 'audit_events_append_only');
    END;

    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
    BEGIN
      SELECT RAISE(ABORT, 'audit_events_append_only');
    END;
  `);
  migrateColumn("sessions", "csrf_token", "TEXT");
  migrateColumn("releases", "installer_path", "TEXT");
  migrateColumn("releases", "installer_url", "TEXT");
  migrateColumn("releases", "sha256", "TEXT");
  migrateColumn("releases", "size_bytes", "INTEGER");
  migrateColumn("releases", "notes", "TEXT");
  migrateColumn("checkout_sessions", "license_id", "INTEGER");
}

function migrateColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
  if (!columns.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function safeEquals(valueA, valueB) {
  const left = Buffer.from(String(valueA || ""), "utf8");
  const right = Buffer.from(String(valueB || ""), "utf8");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function base32Secret(bytes = 20) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const byte of crypto.randomBytes(bytes)) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let index = 0; index < bits.length; index += 5) {
    output += alphabet[Number.parseInt(bits.slice(index, index + 5).padEnd(5, "0"), 2)];
  }
  return output;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const iterations = 210000;
  const digest = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return `pbkdf2_sha256$${iterations}$${salt.toString("base64url")}$${digest.toString("base64url")}`;
}

function verifyPassword(password, encoded) {
  try {
    const [algorithm, iterationText, saltText, digestText] = String(encoded || "").split("$");
    if (algorithm !== "pbkdf2_sha256") return false;
    const iterations = Number.parseInt(iterationText, 10);
    if (!Number.isFinite(iterations) || iterations <= 0 || iterations > 500000) return false;
    const salt = Buffer.from(saltText || "", "base64url");
    const expected = Buffer.from(digestText || "", "base64url");
    if (!salt.length || !expected.length) return false;
    const actual = crypto.pbkdf2Sync(String(password || ""), salt, iterations, expected.length, "sha256");
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function base32Decode(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = String(value || "").replace(/=+$/g, "").toUpperCase();
  let bits = "";
  for (const char of clean) {
    const found = alphabet.indexOf(char);
    if (found < 0) continue;
    bits += found.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function totpCode(secret, timestamp = Date.now()) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(timestamp / 1000 / 30)));
  const digest = crypto.createHmac("sha1", base32Decode(secret)).update(counter).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(value % 1000000).padStart(6, "0");
}

function verifyTotp(secret, code) {
  const clean = String(code || "").replace(/\D/g, "");
  if (clean.length !== 6) return false;
  return [-1, 0, 1].some((drift) => crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(totpCode(secret, Date.now() + drift * 30000))));
}

function normalizeIp(value) {
  const normalized = String(value || "").trim();
  return normalized.startsWith("::ffff:") ? normalized.slice(7) : normalized;
}

function audit(actorUserId, action, targetType, targetId, details = {}) {
  db.prepare(`
    INSERT INTO audit_events(actor_user_id, action, target_type, target_id, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(actorUserId || null, action, targetType, String(targetId || ""), JSON.stringify(details), nowIso());
}

function clientIp(req) {
  const trustForwarded = process.env.NOVASENTINEL_TRUST_PROXY === "1";
  const forwarded = trustForwarded ? String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() : "";
  return normalizeIp(forwarded || req.socket.remoteAddress || "unknown");
}

function securityKey(parts) {
  return parts.map((part) => String(part || "").trim().toLowerCase()).join(":").slice(0, 240);
}

function rateLimit(req, bucket, parts = []) {
  const policy = ratePolicies[bucket];
  if (!policy) return;
  const key = securityKey(["rate", bucket, clientIp(req), ...parts]);
  const now = nowEpoch();
  const row = db.prepare("SELECT * FROM security_counters WHERE key = ?").get(key);
  if (!row || row.window_start + policy.windowSeconds <= now) {
    db.prepare("INSERT OR REPLACE INTO security_counters(key, count, window_start, locked_until, updated_at) VALUES (?, 1, ?, 0, ?)").run(key, now, nowIso());
    return;
  }
  if (row.count >= policy.limit) {
    const error = new Error("Trop de requêtes. Réessayez plus tard.");
    error.statusCode = 429;
    error.code = "rate_limited";
    error.retryAfter = Math.max(1, row.window_start + policy.windowSeconds - now);
    throw error;
  }
  db.prepare("UPDATE security_counters SET count = count + 1, updated_at = ? WHERE key = ?").run(nowIso(), key);
}

function requireNotLocked(bucket, parts) {
  const key = securityKey(["lock", bucket, ...parts]);
  const row = db.prepare("SELECT * FROM security_counters WHERE key = ?").get(key);
  if (row && row.locked_until > nowEpoch()) {
    const error = new Error("Compte temporairement verrouillé après trop d'échecs.");
    error.statusCode = 423;
    error.code = "temporarily_locked";
    error.retryAfter = Math.max(1, row.locked_until - nowEpoch());
    throw error;
  }
}

function recordFailure(bucket, parts) {
  const policy = lockPolicies[bucket];
  if (!policy) return;
  const key = securityKey(["lock", bucket, ...parts]);
  const now = nowEpoch();
  const row = db.prepare("SELECT * FROM security_counters WHERE key = ?").get(key);
  const count = row && row.window_start + policy.lockSeconds > now ? row.count + 1 : 1;
  const lockedUntil = count >= policy.failures ? now + policy.lockSeconds : 0;
  db.prepare("INSERT OR REPLACE INTO security_counters(key, count, window_start, locked_until, updated_at) VALUES (?, ?, ?, ?, ?)").run(
    key,
    count,
    row?.window_start && row.window_start + policy.lockSeconds > now ? row.window_start : now,
    lockedUntil,
    nowIso(),
  );
}

function clearFailures(bucket, parts) {
  db.prepare("DELETE FROM security_counters WHERE key = ?").run(securityKey(["lock", bucket, ...parts]));
}

function passwordPolicyError(password) {
  const value = String(password || "");
  if (value.length < 14) return "weak_password";
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/\d/.test(value) || !/[^A-Za-z0-9]/.test(value)) return "password_policy";
  return "";
}

function sessionCookieHeader(token, maxAge) {
  return `${sessionCookie}=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${isSecureDeployment ? "; Secure" : ""}`;
}

function currentSession(req) {
  const token = parseCookies(req)[sessionCookie];
  if (!token) return null;
  const row = db
    .prepare(
      `
      SELECT sessions.token, sessions.csrf_token, sessions.expires_at, users.*
      FROM sessions JOIN users ON users.id = sessions.user_id
      WHERE sessions.token = ? AND sessions.expires_at > ?
    `,
    )
    .get(token, nowEpoch());
  if (!row) return null;
  if (!row.csrf_token) {
    const csrfToken = randomToken(32);
    db.prepare("UPDATE sessions SET csrf_token = ? WHERE token = ?").run(csrfToken, token);
    row.csrf_token = csrfToken;
  }
  return row;
}

function requireCsrf(req) {
  const session = currentSession(req);
  const provided = String(req.headers["x-csrf-token"] || "");
  const expected = String(session?.csrf_token || "");
  if (!session || !provided || provided.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
    const error = new Error("Token CSRF invalide.");
    error.statusCode = 403;
    error.code = "invalid_csrf";
    throw error;
  }
  return session;
}

function sqlString(value) {
  return `'${String(value).replace(/'/g, "''")}'`;
}

function backupDatabase(reason = "scheduled") {
  if (!fs.existsSync(dbPath)) return null;
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const target = path.join(backupDir, `premium_cloud-${stamp}.sqlite3`);
  db.exec(`VACUUM INTO ${sqlString(target)}`);
  audit(null, "database_backup_created", "database", path.basename(target), { reason, path: target });
  rotateBackups();
  return target;
}

function rotateBackups() {
  const backups = fs
    .readdirSync(backupDir)
    .filter((name) => name.endsWith(".sqlite3"))
    .map((name) => ({ name, path: path.join(backupDir, name), mtime: fs.statSync(path.join(backupDir, name)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  for (const backup of backups.slice(backupRetention)) fs.rmSync(backup.path, { force: true });
}

function cleanupSecurityCounters() {
  const cutoff = nowEpoch() - 7 * 24 * 60 * 60;
  db.prepare("DELETE FROM security_counters WHERE locked_until < ? AND window_start < ?").run(nowEpoch(), cutoff);
}

function json(res, statusCode, payload, headers = {}) {
  const body = Buffer.from(JSON.stringify(payload, null, 2), "utf8");
  res.writeHead(statusCode, {
    ...securityHeaders,
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    ...headers,
  });
  res.end(body);
}

function parseCookies(req) {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((item) => item.trim())
      .filter(Boolean)
      .map((item) => {
        const index = item.indexOf("=");
        if (index <= 0) return null;
        try {
          return [decodeURIComponent(item.slice(0, index)), decodeURIComponent(item.slice(index + 1))];
        } catch {
          return null;
        }
      })
      .filter(Boolean),
  );
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBodyBytes) {
      const error = new Error("Payload trop volumineux.");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req) {
  const body = await readBody(req);
  if (!body.length) return {};
  try {
    return JSON.parse(body.toString("utf8"));
  } catch {
    const error = new Error("Payload JSON invalide.");
    error.statusCode = 400;
    error.code = "invalid_json";
    throw error;
  }
}

function cleanupLoginChallenges() {
  db.prepare("DELETE FROM login_challenges WHERE expires_at < ?").run(nowEpoch());
}

function cleanupExpiredSessions() {
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(nowEpoch());
}

async function readMultipart(req) {
  const contentType = String(req.headers["content-type"] || "");
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!boundaryMatch) {
    const error = new Error("Boundary multipart manquante.");
    error.statusCode = 400;
    throw error;
  }
  const boundary = Buffer.from(`--${boundaryMatch[1] || boundaryMatch[2]}`);
  const body = await readBody(req);
  const fields = {};
  const files = {};
  let cursor = 0;
  while (cursor < body.length) {
    const start = body.indexOf(boundary, cursor);
    if (start < 0) break;
    const next = body.indexOf(boundary, start + boundary.length);
    if (next < 0) break;
    let part = body.subarray(start + boundary.length, next);
    cursor = next;
    if (part.subarray(0, 2).toString() === "--") break;
    if (part.subarray(0, 2).toString() === "\r\n") part = part.subarray(2);
    if (part.subarray(part.length - 2).toString() === "\r\n") part = part.subarray(0, part.length - 2);
    const split = part.indexOf(Buffer.from("\r\n\r\n"));
    if (split < 0) continue;
    const headerText = part.subarray(0, split).toString("utf8");
    const content = part.subarray(split + 4);
    const disposition = headerText.match(/content-disposition:\s*form-data;([^\r\n]+)/i)?.[1] || "";
    const name = disposition.match(/name="([^"]+)"/i)?.[1];
    if (!name) continue;
    const filename = disposition.match(/filename="([^"]*)"/i)?.[1];
    if (filename) {
      files[name] = {
        filename,
        contentType: headerText.match(/content-type:\s*([^\r\n]+)/i)?.[1] || "application/octet-stream",
        data: content,
      };
    } else {
      fields[name] = content.toString("utf8");
    }
  }
  return { fields, files };
}

function currentUser(req) {
  return currentSession(req);
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    organization_id: user.organization_id,
    mfa_enabled: Boolean(user.mfa_enabled),
  };
}

function requireUser(req) {
  const user = currentUser(req);
  if (!user) {
    const error = new Error("Authentification requise.");
    error.statusCode = 401;
    throw error;
  }
  return user;
}

function requireRole(req, role) {
  const user = requireUser(req);
  if (user.role !== role) {
    const error = new Error(`Role ${role} requis.`);
    error.statusCode = 403;
    throw error;
  }
  return user;
}

async function createStripeCheckoutSession(localSession) {
  if (!stripeSecretKey) {
    const error = new Error("STRIPE_SECRET_KEY manquant: aucune session Stripe reelle ne peut etre creee.");
    error.statusCode = 503;
    throw error;
  }
  const params = new URLSearchParams();
  params.set("mode", "payment");
  params.set("success_url", `${publicBaseUrl}/subscribe/?checkout=${encodeURIComponent(localSession.id)}&status=success`);
  params.set("cancel_url", `${publicBaseUrl}/subscribe/?checkout=${encodeURIComponent(localSession.id)}&status=cancel`);
  params.set("client_reference_id", localSession.id);
  params.set("customer_email", localSession.billing_email);
  params.set("line_items[0][quantity]", String(localSession.seats));
  params.set("line_items[0][price_data][currency]", "eur");
  params.set("line_items[0][price_data][product_data][name]", "NovaSentinel Premium");
  params.set("line_items[0][price_data][unit_amount]", String(premiumSeatPriceEur * 100));
  params.set("metadata[local_session_id]", localSession.id);
  params.set("metadata[organization_name]", localSession.organization_name);
  params.set("metadata[seats]", String(localSession.seats));

  const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${stripeSecretKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params,
  });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload?.error?.message || "Stripe Checkout a refuse la creation de session.");
    error.statusCode = 502;
    throw error;
  }
  if (!payload?.id || !payload?.url) {
    const error = new Error("Réponse Stripe invalide.");
    error.statusCode = 502;
    throw error;
  }
  return payload;
}

function verifyStripeSignature(rawBody, signatureHeader) {
  if (!stripeWebhookSecret) {
    const error = new Error("STRIPE_WEBHOOK_SECRET manquant.");
    error.statusCode = 503;
    throw error;
  }
  const parts = Object.fromEntries(
    String(signatureHeader || "")
      .split(",")
      .map((part) => part.split("=", 2))
      .filter((part) => part.length === 2),
  );
  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) {
    const error = new Error("Signature Stripe absente ou invalide.");
    error.statusCode = 400;
    throw error;
  }
  const signedAt = Number.parseInt(String(timestamp), 10);
  if (!Number.isFinite(signedAt) || Math.abs(nowEpoch() - signedAt) > 300) {
    const error = new Error("Signature Stripe expirée ou invalide.");
    error.statusCode = 400;
    throw error;
  }
  const signedPayload = `${timestamp}.${rawBody.toString("utf8")}`;
  const expected = crypto.createHmac("sha256", stripeWebhookSecret).update(signedPayload).digest("hex");
  if (!safeEquals(signature, expected)) {
    const error = new Error("Signature Stripe incorrecte.");
    error.statusCode = 400;
    throw error;
  }
}

function validatePaidStripeCheckout(checkout, stripeSession) {
  if (!stripeSession || typeof stripeSession !== "object") {
    const error = new Error("Session Stripe invalide.");
    error.statusCode = 400;
    error.code = "invalid_stripe_session";
    throw error;
  }
  if (String(stripeSession.id || "") !== String(checkout.stripe_session_id || "")) {
    const error = new Error("Session Stripe inattendue pour ce paiement.");
    error.statusCode = 400;
    error.code = "stripe_session_mismatch";
    throw error;
  }
  if (String(stripeSession.client_reference_id || stripeSession.metadata?.local_session_id || "") !== String(checkout.id)) {
    const error = new Error("Reference Stripe invalide pour ce paiement.");
    error.statusCode = 400;
    error.code = "stripe_reference_mismatch";
    throw error;
  }
  if (String(stripeSession.payment_status || "") !== "paid") {
    const error = new Error("Paiement Stripe non confirme.");
    error.statusCode = 402;
    error.code = "stripe_payment_not_paid";
    throw error;
  }
  if (String(stripeSession.currency || "").toLowerCase() !== "eur") {
    const error = new Error("Devise Stripe inattendue.");
    error.statusCode = 400;
    error.code = "stripe_currency_mismatch";
    throw error;
  }
  const expectedAmountCents = Number(checkout.amount_eur) * 100;
  const paidAmountCents = Number(stripeSession.amount_total || 0);
  if (!Number.isFinite(paidAmountCents) || paidAmountCents !== expectedAmountCents) {
    const error = new Error("Montant Stripe inattendu pour ce nombre de postes.");
    error.statusCode = 400;
    error.code = "stripe_amount_mismatch";
    throw error;
  }
  const metadataSeats = Number.parseInt(String(stripeSession.metadata?.seats || checkout.seats), 10);
  if (!Number.isFinite(metadataSeats) || metadataSeats !== Number(checkout.seats)) {
    const error = new Error("Nombre de postes Stripe inattendu.");
    error.statusCode = 400;
    error.code = "stripe_seats_mismatch";
    throw error;
  }
}

function createLicenseFromPaidCheckout(sessionId, stripeSession) {
  const checkout = db.prepare("SELECT * FROM checkout_sessions WHERE id = ?").get(sessionId);
  if (!checkout) {
    const error = new Error("Session checkout inconnue.");
    error.statusCode = 404;
    throw error;
  }
  if (checkout.status === "confirmed") {
    if (checkout.license_id) return db.prepare("SELECT * FROM licenses WHERE id = ?").get(checkout.license_id);
    return db.prepare("SELECT * FROM licenses WHERE organization_id = (SELECT id FROM organizations WHERE billing_email = ? ORDER BY id DESC LIMIT 1) ORDER BY id DESC LIMIT 1").get(checkout.billing_email);
  }
  validatePaidStripeCheckout(checkout, stripeSession);
  const insertOrg = db.prepare("INSERT INTO organizations(name, billing_email, created_at) VALUES (?, ?, ?)");
  const orgResult = insertOrg.run(checkout.organization_name, checkout.billing_email, nowIso());
  const organizationId = Number(orgResult.lastInsertRowid);
  const licenseKey = makeLicenseKey(checkout.organization_name);
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const licenseResult = db
    .prepare(
      `
      INSERT INTO licenses(organization_id, license_key, seats, active_seats, status, channel, entitlement_expires_at, created_at, updated_at)
      VALUES (?, ?, ?, 0, 'active', 'stable', ?, ?, ?)
    `,
    )
    .run(organizationId, licenseKey, checkout.seats, expiresAt, nowIso(), nowIso());
  const licenseId = Number(licenseResult.lastInsertRowid);
  const inviteId = randomToken(24);
  db.prepare(
    "INSERT INTO organization_invites(id, organization_id, license_id, email, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).run(inviteId, organizationId, licenseId, checkout.billing_email, nowEpoch() + 7 * 24 * 60 * 60, nowIso());
  db.prepare("UPDATE checkout_sessions SET status = 'confirmed', license_id = ?, confirmed_at = ? WHERE id = ?").run(licenseId, nowIso(), sessionId);
  audit(null, "stripe_checkout_paid_license_created", "license", licenseId, {
    session_id: sessionId,
    stripe_session_id: stripeSession.id || "",
    seats: checkout.seats,
    amount_eur: checkout.amount_eur,
  });
  return db.prepare("SELECT * FROM licenses WHERE id = ?").get(licenseId);
}

function makeLicenseKey(org) {
  const slug =
    String(org || "ORG")
      .toUpperCase()
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^A-Z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 12) || "ORG";
  return `NSP-PREMIUM-${slug}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

function deploymentPayload(licenseKey) {
  return {
    premium_deployment_json: { license_key: licenseKey },
    intune_script: [
      "$dir = Join-Path $env:ProgramData 'NovaSentinel'",
      "New-Item -ItemType Directory -Force -Path $dir | Out-Null",
      `@'{\n  "license_key": "${licenseKey}"\n}'@ | Set-Content -Encoding UTF8 (Join-Path $dir 'premium_deployment.json')`,
    ].join("\n"),
  };
}

function maskLicenseKeyForDisplay(licenseKey) {
  const value = String(licenseKey || "").trim();
  if (!value) return "";
  if (value.length <= 10) return "*".repeat(value.length);
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function resolveLicenseForConsole(licenseKey) {
  const license = db
    .prepare(
      `
      SELECT licenses.*, organizations.name AS organization_name, organizations.billing_email
      FROM licenses
      JOIN organizations ON organizations.id = licenses.organization_id
      WHERE licenses.license_key = ?
    `,
    )
    .get(licenseKey);
  if (!license) {
    return null;
  }

  const activationCount = db.prepare("SELECT COUNT(*) AS count FROM activations WHERE license_id = ?").get(license.id)?.count || 0;
  const latestRelease = db
    .prepare(
      "SELECT * FROM releases WHERE channel = ? AND status = 'published' AND installer_url != '' AND sha256 != '' ORDER BY id DESC LIMIT 1",
    )
    .get(license.channel || "stable");
  const availableSeats = Math.max(0, Number(license.seats || 0) - Number(activationCount || 0));
  const release = publicRelease(latestRelease);
  return {
    license: {
      id: license.id,
      organization_id: license.organization_id,
      license_mask: maskLicenseKeyForDisplay(license.license_key),
      plan: license.plan,
      seats: license.seats,
      active_seats: activationCount,
      status: license.status,
      channel: license.channel || "stable",
      entitlement_expires_at: license.entitlement_expires_at,
      entitlement_version: license.entitlement_version || 1,
      updated_at: license.updated_at,
    },
    organization: {
      id: license.organization_id,
      name: license.organization_name || "",
      billing_email: license.billing_email || "",
    },
    deployment: deploymentPayload(license.license_key),
    release,
    available_seats: availableSeats,
  };
}

function isExpiredEntitlement(expiresAt) {
  if (!expiresAt) return false;
  try {
    const parsed = new Date(expiresAt);
    if (Number.isNaN(parsed.getTime())) return true;
    return parsed.getTime() <= Date.now();
  } catch {
    return true;
  }
}

function sanitizeReleasePart(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

function publicRelease(release) {
  if (!release) return null;
  const installerUrl = release.installer_url?.startsWith("/") ? new URL(release.installer_url, publicBaseUrl).toString() : release.installer_url || "";
  return {
    id: release.id,
    version: release.version,
    channel: release.channel,
    status: release.status,
    installer_url: installerUrl,
    sha256: release.sha256 || "",
    size_bytes: release.size_bytes || 0,
    notes: release.notes || "",
    published_at: release.published_at,
  };
}

function updateAvailable(currentVersion, latestVersion) {
  if (!currentVersion || !latestVersion) return Boolean(latestVersion);
  if (currentVersion === latestVersion) return false;
  const current = String(currentVersion).split(".").map((part) => Number.parseInt(part, 10));
  const latest = String(latestVersion).split(".").map((part) => Number.parseInt(part, 10));
  for (let index = 0; index < Math.max(current.length, latest.length); index += 1) {
    const left = Number.isFinite(current[index]) ? current[index] : 0;
    const right = Number.isFinite(latest[index]) ? latest[index] : 0;
    if (right > left) return true;
    if (right < left) return false;
  }
  return false;
}

function updatePayloadFromRelease(release) {
  if (!release) return null;
  let installerUrl = "";
  try {
    installerUrl = release.installer_url?.startsWith("/") ? new URL(release.installer_url, publicBaseUrl).toString() : release.installer_url || "";
  } catch {
    installerUrl = "";
  }
  const pathname = installerUrl ? new URL(installerUrl).pathname : "";
  let assetName = `NovaSentinel-Setup-${release.version}.exe`;
  if (pathname) {
    try {
      assetName = decodeURIComponent(path.basename(pathname)) || assetName;
    } catch {
      // best effort fallback to basename
    }
  }
  return {
    version: release.version,
    tag: `v${release.version}`,
    name: `NovaSentinel ${release.version}`,
    asset_name: assetName,
    download_url: installerUrl,
    sha256: release.sha256 || "",
    release_url: installerUrl.includes("github.com") ? installerUrl.replace(/\/download\/([^/]+)\/.*/, "/tag/$1") : "",
    published_at: release.published_at,
    notes: release.notes || "",
  };
}

function latestReleasePayload(channel, currentVersion) {
  const release = db
    .prepare("SELECT * FROM releases WHERE channel = ? AND status = 'published' AND installer_url != '' AND sha256 != '' ORDER BY id DESC LIMIT 1")
    .get(channel);
  const publicData = publicRelease(release);
  const update = updatePayloadFromRelease(release);
  const payload = {
    update_available: updateAvailable(currentVersion, release?.version),
    current_version: currentVersion,
    channel,
    release: publicData,
    update,
  };
  if (update && premiumSigningPrivateKeyPem) {
    payload.signature = signPayload(update);
  }
  return payload;
}

function createReleaseRecord({ version, channel, installerUrl, installerPath, sha256, sizeBytes, notes, actorUserId }) {
  const result = db
    .prepare(
      `
      INSERT INTO releases(version, channel, status, installer_path, installer_url, sha256, size_bytes, notes, published_at)
      VALUES (?, ?, 'published', ?, ?, ?, ?, ?, ?)
    `,
    )
    .run(version, channel, installerPath || null, installerUrl || "", sha256 || "", sizeBytes || 0, notes || "", nowIso());
  const release = db.prepare("SELECT * FROM releases WHERE id = ?").get(Number(result.lastInsertRowid));
  audit(actorUserId, "release_published", "release", release.id, {
    version,
    channel,
    installer_url: release.installer_url || "",
    sha256: release.sha256 || "",
    size_bytes: release.size_bytes || 0,
  });
  return publicRelease(release);
}

function githubHeaders(extra = {}) {
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "NovaSentinel-Premium-Cloud",
    "X-GitHub-Api-Version": "2022-11-28",
    ...(githubToken ? { Authorization: `Bearer ${githubToken}` } : {}),
    ...extra,
  };
}

function parseGitHubReleaseAssetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl || ""));
  } catch {
    return null;
  }
  if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== "github.com") return null;
  const parts = parsed.pathname.split("/").filter(Boolean);
  const releasesIndex = parts.indexOf("releases");
  if (parts.length < 6 || releasesIndex !== 2 || parts[3] !== "download") return null;
  const owner = parts[0];
  const repo = parts[1];
  let tag = "";
  let assetName = "";
  try {
    tag = decodeURIComponent(parts[4]);
    assetName = decodeURIComponent(parts.slice(5).join("/"));
  } catch {
    return null;
  }
  if (!owner || !repo || !tag || !assetName) return null;
  return { owner, repo, tag, assetName, downloadUrl: parsed.toString() };
}

async function fetchGithubJson(url) {
  const response = await fetch(url, { headers: githubHeaders() });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload?.message || "GitHub a refusé la récupération des métadonnées.");
    error.statusCode = response.status >= 500 ? 502 : 400;
    throw error;
  }
  return payload;
}

async function hashRemoteAsset(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.hostname.toLowerCase() !== "github.com") {
    const error = new Error("Seules les URLs GitHub Releases sont inspectées automatiquement.");
    error.statusCode = 400;
    throw error;
  }
  const response = await fetch(url, { headers: githubHeaders({ Accept: "application/octet-stream" }) });
  if (!response.ok) {
    const error = new Error(`Téléchargement GitHub impossible (${response.status}).`);
    error.statusCode = response.status >= 500 ? 502 : 400;
    throw error;
  }
  const hash = crypto.createHash("sha256");
  let sizeBytes = 0;
  for await (const chunk of response.body) {
    sizeBytes += chunk.length;
    if (sizeBytes > maxBodyBytes) {
      const error = new Error("Installateur GitHub trop volumineux pour inspection.");
      error.statusCode = 413;
      throw error;
    }
    hash.update(chunk);
  }
  return { sha256: hash.digest("hex"), size_bytes: sizeBytes };
}

async function inspectGithubReleaseAsset(rawUrl) {
  const parsed = parseGitHubReleaseAssetUrl(rawUrl);
  if (!parsed) {
    const error = new Error("URL GitHub Releases invalide. Utilisez l'URL de téléchargement d'un asset de release.");
    error.statusCode = 400;
    throw error;
  }
  const apiUrl = `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/releases/tags/${encodeURIComponent(parsed.tag)}`;
  const release = await fetchGithubJson(apiUrl);
  const asset = (release.assets || []).find((item) => item.name === parsed.assetName || item.browser_download_url === parsed.downloadUrl);
  const downloadUrl = asset?.browser_download_url || parsed.downloadUrl;
  const hash = await hashRemoteAsset(downloadUrl);
  const tagVersion = String(release.tag_name || parsed.tag).replace(/^v/i, "");
  return {
    owner: parsed.owner,
    repo: parsed.repo,
    tag: release.tag_name || parsed.tag,
    release_name: release.name || release.tag_name || parsed.tag,
    asset_name: asset?.name || parsed.assetName,
    version: tagVersion,
    channel: release.prerelease || /(?:beta|alpha|rc)/i.test(release.tag_name || parsed.tag) ? "beta" : "stable",
    installer_url: downloadUrl,
    sha256: hash.sha256,
    size_bytes: hash.size_bytes || asset?.size || 0,
    notes: String(release.body || "").slice(0, 4000),
    published_at: release.published_at || release.created_at || "",
  };
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${jsonAsciiString(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  if (typeof value === "string") return jsonAsciiString(value);
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  return "null";
}

function jsonAsciiString(value) {
  return JSON.stringify(String(value)).replace(/[^\x00-\x7F]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function signPayload(payload) {
  if (!premiumSigningPrivateKeyPem) {
    const error = new Error("PREMIUM_ED25519_PRIVATE_KEY_PEM manquant: impossible de signer un entitlement.");
    error.statusCode = 503;
    throw error;
  }
  const key = crypto.createPrivateKey(premiumSigningPrivateKeyPem.replace(/\\n/g, "\n"));
  return crypto.sign(null, Buffer.from(canonicalJson(payload), "utf8"), key).toString("base64");
}

function otpauthUri(email, mfaSecret) {
  const account = encodeURIComponent(email);
  return `otpauth://totp/NovaSentinel:${account}?secret=${mfaSecret}&issuer=NovaSentinel`;
}

async function totpEnrollment(email, mfaSecret) {
  const otpauth = otpauthUri(email, mfaSecret);
  const mfaQrDataUrl = await QRCode.toDataURL(otpauth, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 220,
    color: {
      dark: "#12201b",
      light: "#ffffff",
    },
  });
  return { mfa_secret: mfaSecret, otpauth, mfa_qr_data_url: mfaQrDataUrl };
}

async function handleApi(req, res, url) {
  if (req.method === "GET" && url.pathname === "/api/health") {
    return json(res, 200, {
      ok: true,
      database: dbPath,
      stripe_configured: Boolean(stripeSecretKey),
      premium_signing_configured: Boolean(premiumSigningPrivateKeyPem),
    });
  }

  if (req.method === "GET" && url.pathname === "/api/session") {
    const session = currentSession(req);
    return json(res, 200, { authenticated: Boolean(session), user: publicUser(session), csrf_token: session?.csrf_token || "" });
  }

  if ((req.method === "GET" || req.method === "POST") && ["/api/releases/latest", "/api/premium/releases/latest"].includes(url.pathname)) {
    const payload = req.method === "POST" ? await readJson(req) : {};
    const channel = String(url.searchParams.get("channel") || payload.channel || "stable").slice(0, 20);
    const currentVersion = String(url.searchParams.get("current_version") || payload.current_version || payload.app_version || "");
    return json(res, 200, latestReleasePayload(channel, currentVersion));
  }

  if (req.method === "POST" && url.pathname === "/api/login") {
    rateLimit(req, "login");
    cleanupLoginChallenges();
    const payload = await readJson(req);
    const email = String(payload.email || "").trim().toLowerCase();
    const password = String(payload.password || "");
    requireNotLocked("login", [email, clientIp(req)]);
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !verifyPassword(password, user.password_hash)) {
      recordFailure("login", [email, clientIp(req)]);
      audit(user?.id || null, "login_failed", "user", email, { reason: "invalid_credentials" });
      return json(res, 401, { error: "invalid_credentials" });
    }
    clearFailures("login", [email, clientIp(req)]);
    const challengeId = randomToken(24);
    db.prepare("INSERT INTO login_challenges(id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)").run(
      challengeId,
      user.id,
      nowEpoch() + challengeTtlSeconds,
      nowIso(),
    );
    audit(user.id, "login_password_verified", "user", user.id, {});
    return json(res, 200, { mfa_required: Boolean(user.mfa_enabled), challenge_id: challengeId, role: user.role });
  }

  if (req.method === "POST" && url.pathname === "/api/login/verify") {
    rateLimit(req, "login", ["mfa"]);
    cleanupLoginChallenges();
    const payload = await readJson(req);
    const challenge = db
      .prepare(
        `
        SELECT login_challenges.*, users.email, users.role, users.mfa_secret, users.mfa_enabled, users.organization_id
        FROM login_challenges JOIN users ON users.id = login_challenges.user_id
        WHERE login_challenges.id = ?
      `,
      )
      .get(String(payload.challenge_id || ""));
    if (!challenge || challenge.expires_at < nowEpoch()) {
      if (challenge?.id) db.prepare("DELETE FROM login_challenges WHERE id = ?").run(challenge.id);
      return json(res, 401, { error: "challenge_expired" });
    }
    requireNotLocked("mfa", [challenge.email, clientIp(req)]);
    if (challenge.mfa_enabled && !verifyTotp(challenge.mfa_secret, payload.code)) {
      recordFailure("mfa", [challenge.email, clientIp(req)]);
      audit(challenge.user_id, "mfa_failed", "user", challenge.user_id, {});
      return json(res, 401, { error: "invalid_mfa" });
    }
    const token = randomToken(32);
    const csrfToken = randomToken(32);
    db.prepare("DELETE FROM login_challenges WHERE id = ?").run(challenge.id);
    db.prepare("INSERT INTO sessions(token, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)").run(
      token,
      challenge.user_id,
      csrfToken,
      nowEpoch() + sessionTtlSeconds,
      nowIso(),
    );
    clearFailures("mfa", [challenge.email, clientIp(req)]);
    audit(challenge.user_id, "login_success", "user", challenge.user_id, { role: challenge.role });
    return json(
      res,
      200,
      {
        authenticated: true,
        redirect: challenge.role === "superadmin" ? "/dashboard/superadmin/" : "/dashboard/user/",
        user: publicUser({ ...challenge, id: challenge.user_id }),
        csrf_token: csrfToken,
      },
      { "Set-Cookie": sessionCookieHeader(token, sessionTtlSeconds) },
    );
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    const token = parseCookies(req)[sessionCookie];
    if (!token) {
      return json(res, 200, { ok: true }, { "Set-Cookie": sessionCookieHeader("", 0) });
    }
    const ip = clientIp(req);
    rateLimit(req, "logout");
    requireNotLocked("logout", [token, ip]);
    requireCsrf(req);
    clearFailures("logout", [token, ip]);
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    return json(res, 200, { ok: true }, { "Set-Cookie": sessionCookieHeader("", 0) });
  }

  if (req.method === "POST" && url.pathname === "/api/checkout/sessions") {
    rateLimit(req, "checkout");
    const payload = await readJson(req);
    const org = String(payload.org || "").trim();
    const email = String(payload.email || "").trim().toLowerCase();
    const seats = Math.max(1, Math.min(5000, Number.parseInt(payload.seats || "1", 10)));
    requireNotLocked("checkout", [email, clientIp(req)]);
    if (!org || !email.includes("@")) {
      recordFailure("checkout", [email, clientIp(req)]);
      return json(res, 400, { error: "invalid_checkout_payload" });
    }
    const sessionId = `ns_chk_${randomToken(18)}`;
    const amount = seats * premiumSeatPriceEur;
    const localSession = {
      id: sessionId,
      organization_name: org,
      billing_email: email,
      seats,
      amount_eur: amount,
    };
    const stripeSession = await createStripeCheckoutSession(localSession);
    db.prepare(
      `
      INSERT INTO checkout_sessions(id, organization_name, billing_email, seats, amount_eur, status, stripe_session_id, stripe_url, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)
    `,
    ).run(sessionId, org, email, seats, amount, stripeSession.id, stripeSession.url, nowIso());
    clearFailures("checkout", [email, clientIp(req)]);
    audit(null, "checkout_session_created", "checkout_session", sessionId, { org, email, seats, stripe_session_id: stripeSession.id });
    return json(res, 201, { id: sessionId, status: "pending", amount_eur: amount, stripe_session_id: stripeSession.id, stripe_checkout_url: stripeSession.url });
  }

  if (req.method === "POST" && url.pathname === "/api/stripe/webhook") {
    const rawBody = await readBody(req);
    verifyStripeSignature(rawBody, req.headers["stripe-signature"]);
    let event;
    try {
      event = JSON.parse(rawBody.toString("utf8"));
    } catch {
      const error = new Error("Payload webhook Stripe invalide.");
      error.statusCode = 400;
      error.code = "invalid_stripe_payload";
      throw error;
    }
    if (event.type === "checkout.session.completed" || event.type === "checkout.session.async_payment_succeeded") {
      const stripeSession = event.data.object;
      const localSessionId = stripeSession.client_reference_id || stripeSession.metadata?.local_session_id;
      if (event.type === "checkout.session.completed" && stripeSession.payment_status !== "paid") {
        db.prepare("UPDATE checkout_sessions SET status = 'pending_payment', stripe_session_id = COALESCE(?, stripe_session_id) WHERE id = ?").run(
          stripeSession.id || null,
          localSessionId || "",
        );
        audit(null, "stripe_checkout_completed_waiting_payment", "checkout_session", localSessionId || "", {
          stripe_session_id: stripeSession.id || "",
          payment_status: stripeSession.payment_status || "",
        });
        return json(res, 200, { received: true, pending_payment: true });
      }
      const license = createLicenseFromPaidCheckout(localSessionId, stripeSession);
      return json(res, 200, { received: true, license_id: license.id });
    }
    audit(null, "stripe_webhook_ignored", "stripe_event", event.id || event.type, { type: event.type });
    return json(res, 200, { received: true, ignored: true });
  }

  if (req.method === "POST" && url.pathname === "/api/organizations/claim") {
    rateLimit(req, "claim");
    const payload = await readJson(req);
    const email = String(payload.email || "").trim().toLowerCase();
    const password = String(payload.password || "");
    const licenseKey = String(payload.license_key || "").trim();
    requireNotLocked("claim", [licenseKey || email, clientIp(req)]);
    const license = db
      .prepare("SELECT licenses.*, organizations.billing_email FROM licenses JOIN organizations ON organizations.id = licenses.organization_id WHERE licenses.license_key = ? AND licenses.status = 'active'")
      .get(licenseKey);
    if (!license) {
      recordFailure("claim", [licenseKey || email, clientIp(req)]);
      return json(res, 404, { error: "license_not_found" });
    }
    if (email !== license.billing_email) {
      recordFailure("claim", [licenseKey || email, clientIp(req)]);
      return json(res, 403, { error: "billing_email_required" });
    }
    const passwordError = passwordPolicyError(password);
    if (passwordError) return json(res, 400, { error: passwordError });
    const existing = db.prepare("SELECT COUNT(*) AS count FROM users WHERE organization_id = ?").get(license.organization_id).count;
    if (existing > 0) return json(res, 409, { error: "organization_already_claimed" });
    const mfaSecret = base32Secret();
    const result = db
      .prepare("INSERT INTO users(organization_id, email, password_hash, role, mfa_secret, created_at) VALUES (?, ?, ?, 'user', ?, ?)")
      .run(license.organization_id, email, hashPassword(password), mfaSecret, nowIso());
    audit(Number(result.lastInsertRowid), "organization_claimed", "organization", license.organization_id, { license_id: license.id });
    clearFailures("claim", [licenseKey || email, clientIp(req)]);
    return json(res, 201, { ok: true, email, ...(await totpEnrollment(email, mfaSecret)) });
  }

  if (req.method === "POST" && url.pathname === "/api/premium/verify") {
    rateLimit(req, "premiumVerify");
    const payload = await readJson(req);
    const licenseKey = String(payload.license_key || payload.key || "").trim();
    const deviceId = String(payload.device_id || "").trim();
    const deviceName = String(payload.device_name || payload.hostname || "unknown-device").trim().slice(0, 120);
    const appVersion = String(payload.app_version || "unknown").trim().slice(0, 40);
    const channel = String(payload.channel || "stable").trim().slice(0, 20);
    if (!licenseKey || !deviceId) return json(res, 400, { error: "license_key_and_device_id_required" });
    requireNotLocked("premiumVerify", [licenseKey, clientIp(req)]);
    const license = db
      .prepare("SELECT licenses.*, organizations.name AS organization_name FROM licenses JOIN organizations ON organizations.id = licenses.organization_id WHERE licenses.license_key = ?")
      .get(licenseKey);
    if (!license || license.status !== "active") {
      recordFailure("premiumVerify", [licenseKey, clientIp(req)]);
      return json(res, 403, { error: "license_inactive_or_unknown" });
    }
    const existing = db.prepare("SELECT * FROM activations WHERE license_id = ? AND device_id = ?").get(license.id, deviceId);
    if (existing) {
      db.prepare("UPDATE activations SET device_name = ?, app_version = ?, channel = ?, last_seen_at = ? WHERE id = ?").run(deviceName, appVersion, channel, nowIso(), existing.id);
    } else {
      const activeCount = db.prepare("SELECT COUNT(*) AS count FROM activations WHERE license_id = ?").get(license.id).count;
      if (activeCount >= license.seats) return json(res, 403, { error: "seat_limit_reached" });
      db.prepare(
        "INSERT INTO activations(license_id, device_name, device_id, app_version, channel, activated_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).run(license.id, deviceName, deviceId, appVersion, channel, nowIso(), nowIso());
      db.prepare("UPDATE licenses SET active_seats = active_seats + 1, updated_at = ? WHERE id = ?").run(nowIso(), license.id);
      audit(null, "device_activated", "license", license.id, { device_id: deviceId, device_name: deviceName });
    }
    const entitlement = {
      license_id: String(license.id),
      plan: "premium",
      status: "active",
      customer: license.organization_name,
      device_id: deviceId,
      features: premiumFeatures,
      expires_at: license.entitlement_expires_at,
      checked_at: nowIso(),
    };
    clearFailures("premiumVerify", [licenseKey, clientIp(req)]);
    return json(res, 200, { entitlement, signature: signPayload(entitlement) });
  }

  if (req.method === "POST" && url.pathname === "/api/admin-console/license/info") {
    rateLimit(req, "consoleLookup");
    const payload = await readJson(req);
    const licenseKey = String(payload.license_key || "").trim();
    const requestedChannel = String(payload.channel || "stable").trim().toLowerCase();
    const channel = requestedChannel === "beta" ? "beta" : "stable";
    if (!licenseKey) return json(res, 400, { error: "license_key_required" });
    requireNotLocked("consoleLookup", [licenseKey, clientIp(req)]);
    const data = resolveLicenseForConsole(licenseKey);
    if (!data || data.license.status !== "active" || isExpiredEntitlement(data.license.entitlement_expires_at)) {
      recordFailure("consoleLookup", [licenseKey, clientIp(req)]);
      return json(res, 404, { error: "license_inactive_or_unknown" });
    }
    clearFailures("consoleLookup", [licenseKey, clientIp(req)]);
    data.channel = channel;
    if (data.license.channel !== channel) {
      const releaseByChannel = db
        .prepare(
          "SELECT * FROM releases WHERE channel = ? AND status = 'published' AND installer_url != '' AND sha256 != '' ORDER BY id DESC LIMIT 1",
        )
        .get(channel);
      data.release = publicRelease(releaseByChannel);
    }
    if (!data.deployment?.premium_deployment_json) {
      data.deployment = deploymentPayload(licenseKey);
    }
    audit(null, "admin_console_license_lookup", "license", String(data.license.id), {
      channel,
    });
    return json(res, 200, { ok: true, ...data });
  }

  if (req.method === "GET" && url.pathname === "/api/dashboard/user") {
    const user = requireUser(req);
    const orgId = user.role === "superadmin" && url.searchParams.get("organization_id") ? Number(url.searchParams.get("organization_id")) : user.organization_id;
    if (!orgId) return json(res, 403, { error: "organization_required" });
    const organization = db.prepare("SELECT * FROM organizations WHERE id = ?").get(orgId);
    const licenses = db.prepare("SELECT * FROM licenses WHERE organization_id = ? ORDER BY id DESC").all(orgId);
    const licenseIds = licenses.map((license) => license.id);
    const activations = licenseIds.length
      ? db.prepare(`SELECT * FROM activations WHERE license_id IN (${licenseIds.map(() => "?").join(",")}) ORDER BY last_seen_at DESC`).all(...licenseIds)
      : [];
    const seats = licenses.reduce((sum, license) => sum + license.seats, 0);
    const activeSeats = licenses.reduce((sum, license) => sum + license.active_seats, 0);
    return json(res, 200, {
      organization,
      metrics: {
        seats,
        active_seats: activeSeats,
        available_seats: Math.max(0, seats - activeSeats),
        last_activation: activations[0]?.device_name || "Aucune",
        channel: licenses[0]?.channel || "stable",
        version: db.prepare("SELECT version FROM releases WHERE channel = ? ORDER BY id DESC LIMIT 1").get(licenses[0]?.channel || "stable")?.version || "n/a",
      },
      licenses,
      activations,
      deployment: licenses[0] ? deploymentPayload(licenses[0].license_key) : null,
    });
  }

  if (req.method === "GET" && url.pathname === "/api/dashboard/superadmin") {
    requireRole(req, "superadmin");
    const organizations = db
      .prepare(
        `
        SELECT organizations.*, COALESCE(SUM(licenses.seats), 0) AS seats, COALESCE(SUM(licenses.active_seats), 0) AS active_seats
        FROM organizations LEFT JOIN licenses ON licenses.organization_id = organizations.id
        GROUP BY organizations.id ORDER BY organizations.id DESC
      `,
      )
      .all();
    const licenses = db
      .prepare("SELECT licenses.*, organizations.name AS organization_name FROM licenses JOIN organizations ON organizations.id = licenses.organization_id ORDER BY licenses.id DESC")
      .all();
    const auditEvents = db.prepare("SELECT * FROM audit_events ORDER BY id DESC LIMIT 50").all().map(readAudit);
    const releases = db.prepare("SELECT * FROM releases ORDER BY id DESC LIMIT 10").all().map(publicRelease);
    const seats = licenses.reduce((sum, license) => sum + license.seats, 0);
    return json(res, 200, {
      metrics: {
        organizations: organizations.length,
        seats,
        active_seats: licenses.reduce((sum, license) => sum + license.active_seats, 0),
        mrr_eur: seats * premiumSeatPriceEur,
        admin_alerts: licenses.filter((license) => license.status !== "active").length,
      },
      organizations,
      licenses,
      audit_events: auditEvents,
      releases,
    });
  }

  if (req.method === "POST" && url.pathname.match(/^\/api\/superadmin\/licenses\/\d+\/revoke$/)) {
    requireCsrf(req);
    const user = requireRole(req, "superadmin");
    const licenseId = url.pathname.split("/")[4];
    const payload = await readJson(req);
    db.prepare("UPDATE licenses SET status = 'revoked', updated_at = ? WHERE id = ?").run(nowIso(), licenseId);
    audit(user.id, "license_revoked", "license", licenseId, { reason: payload.reason || "superadmin_action" });
    return json(res, 200, { ok: true, license_id: licenseId, status: "revoked" });
  }

  if (req.method === "POST" && url.pathname === "/api/superadmin/licenses/issue") {
    requireCsrf(req);
    const user = requireRole(req, "superadmin");
    const payload = await readJson(req);
    const org = String(payload.org || "").trim();
    const email = String(payload.email || "").trim().toLowerCase();
    const seats = Math.max(1, Math.min(5000, Number.parseInt(payload.seats || "1", 10)));
    if (!org || !email.includes("@")) return json(res, 400, { error: "invalid_license_issue_payload" });
    const orgResult = db.prepare("INSERT INTO organizations(name, billing_email, created_at) VALUES (?, ?, ?)").run(org, email, nowIso());
    const organizationId = Number(orgResult.lastInsertRowid);
    const licenseKey = makeLicenseKey(org);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    const licenseResult = db
      .prepare(
        `
        INSERT INTO licenses(organization_id, license_key, seats, active_seats, status, channel, entitlement_expires_at, created_at, updated_at)
        VALUES (?, ?, ?, 0, 'active', 'stable', ?, ?, ?)
      `,
      )
      .run(organizationId, licenseKey, seats, expiresAt, nowIso(), nowIso());
    const licenseId = Number(licenseResult.lastInsertRowid);
    audit(user.id, "manual_license_issued", "license", licenseId, { organization: org, billing_email: email, seats });
    return json(res, 201, {
      ok: true,
      organization: db.prepare("SELECT * FROM organizations WHERE id = ?").get(organizationId),
      license: db.prepare("SELECT * FROM licenses WHERE id = ?").get(licenseId),
    });
  }

  if (req.method === "POST" && url.pathname === "/api/superadmin/releases/inspect-github-url") {
    requireCsrf(req);
    requireRole(req, "superadmin");
    const payload = await readJson(req);
    const release = await inspectGithubReleaseAsset(payload.installer_url);
    return json(res, 200, { ok: true, release });
  }

  if (req.method === "POST" && url.pathname.match(/^\/api\/superadmin\/licenses\/\d+\/resign$/)) {
    requireCsrf(req);
    const user = requireRole(req, "superadmin");
    const licenseId = url.pathname.split("/")[4];
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare("UPDATE licenses SET entitlement_version = entitlement_version + 1, entitlement_expires_at = ?, updated_at = ? WHERE id = ?").run(expiresAt, nowIso(), licenseId);
    audit(user.id, "entitlement_resigned", "license", licenseId, {});
    return json(res, 200, { ok: true, license: db.prepare("SELECT * FROM licenses WHERE id = ?").get(licenseId) });
  }

  if (req.method === "POST" && url.pathname === "/api/superadmin/releases/publish") {
    requireCsrf(req);
    const user = requireRole(req, "superadmin");
    const contentType = String(req.headers["content-type"] || "");
    let payload;
    let upload;
    if (contentType.startsWith("multipart/form-data")) {
      const multipart = await readMultipart(req);
      payload = multipart.fields;
      upload = multipart.files.installer;
      if (upload?.filename) {
        const normalizedFileName = String(upload.filename).toLowerCase();
        if (!normalizedFileName.endsWith(".exe")) {
          return json(res, 400, { error: "installer_invalid_file_type" });
        }
      }
      if (upload?.data && upload.data.length > maxInstallerUploadBytes) {
        return json(res, 413, { error: "installer_too_large" });
      }
    } else {
      payload = await readJson(req);
    }
    const version = String(payload.version || "").trim();
    const channel = String(payload.channel || "stable").trim().slice(0, 20);
    const notes = String(payload.notes || "").trim().slice(0, 4000);
    if (!version) return json(res, 400, { error: "version_required" });
    if (!["stable", "beta"].includes(channel)) return json(res, 400, { error: "invalid_release_channel" });
    let installerPath = "";
    let installerUrl = String(payload.installer_url || "").trim();
    let sha256 = String(payload.sha256 || "").trim().toLowerCase();
    let sizeBytes = 0;
    if (upload?.data?.length) {
      const safeVersion = sanitizeReleasePart(version);
      const safeChannel = sanitizeReleasePart(channel);
      const fileName = `NovaSentinelSetup-${safeVersion}-${safeChannel}.exe`;
      installerPath = path.join(releaseUploadDir, fileName);
      fs.writeFileSync(installerPath, upload.data);
      sha256 = crypto.createHash("sha256").update(upload.data).digest("hex");
      sizeBytes = upload.data.length;
      installerUrl = `/release-downloads/${encodeURIComponent(fileName)}`;
    }
    if (!installerUrl) return json(res, 400, { error: "installer_required" });
    if (!sha256 || !/^[0-9a-f]{64}$/.test(sha256)) return json(res, 400, { error: "sha256_required" });
    const release = createReleaseRecord({ version, channel, installerUrl, installerPath, sha256, sizeBytes, notes, actorUserId: user.id });
    return json(res, 201, { ok: true, release });
  }

  if (req.method === "GET" && url.pathname === "/api/superadmin/audit/export") {
    requireRole(req, "superadmin");
    return json(res, 200, { audit_events: db.prepare("SELECT * FROM audit_events ORDER BY id DESC LIMIT 500").all().map(readAudit) });
  }

  if (req.method === "POST" && url.pathname === "/api/superadmin/backups/create") {
    requireCsrf(req);
    const user = requireRole(req, "superadmin");
    const backupPath = backupDatabase("superadmin_manual");
    audit(user.id, "database_backup_requested", "database", backupPath ? path.basename(backupPath) : "none", {});
    return json(res, 201, { ok: true, backup: backupPath ? path.basename(backupPath) : "" });
  }

  return json(res, 404, { error: "not_found" });
}

function readAudit(row) {
  return { ...row, details: JSON.parse(row.details || "{}") };
}

function latestReleaseArtifact(pattern) {
  const candidates = [downloadDir, path.join(repoDir, "release")];
  const files = candidates.flatMap((candidateDir) => {
    if (!fs.existsSync(candidateDir)) return [];
    return fs.readdirSync(candidateDir)
      .filter((name) => pattern.test(name))
      .map((name) => {
        const resolved = path.join(candidateDir, name);
        return { resolved, mtimeMs: fs.statSync(resolved).mtimeMs };
      });
  });
  files.sort((left, right) => right.mtimeMs - left.mtimeMs);
  return files[0]?.resolved || "";
}

function serveDownloadFile(res, fileName) {
  const safeName = path.basename(fileName);
  if (!safeName || safeName !== fileName || isSensitiveStaticName(safeName)) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  serveFile(res, path.join(downloadDir, safeName));
}

function serveAssetFile(res, fileName) {
  const safeName = path.basename(fileName);
  if (!safeName || safeName !== fileName || isSensitiveStaticName(safeName) || !/^[a-z0-9._-]+$/i.test(safeName)) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  serveFile(res, path.join(rootDir, "assets", safeName));
}

function isSensitiveStaticName(fileName) {
  const safeName = path.basename(String(fileName || ""));
  if (!safeName || safeName.startsWith(".")) return true;
  return blockedStaticExtensions.has(path.extname(safeName).toLowerCase());
}

function hasHiddenOrBlockedStaticSegment(normalizedPath) {
  const lower = normalizedPath.toLowerCase();
  if (blockedStaticSegments.some((segment) => lower.includes(segment))) return true;
  return normalizedPath.split("/").filter(Boolean).some((segment) => segment.startsWith("."));
}

function serveStatic(req, res, url) {
  if (url.pathname.startsWith("/dashboard/")) {
    const user = currentUser(req);
    if (!user) {
      redirect(res, `/login/?next=${encodeURIComponent(url.pathname)}`);
      return;
    }
    if (url.pathname.startsWith("/dashboard/superadmin/") && user.role !== "superadmin") {
      redirect(res, "/dashboard/user/");
      return;
    }
  }
  if (url.pathname === "/assets/novasentinel_icon.png") {
    serveFile(res, path.join(rootDir, "assets", "novasentinel_icon.png"));
    return;
  }
  if (url.pathname === "/assets/novasentinel_icon.ico") {
    serveFile(res, path.join(rootDir, "assets", "novasentinel_icon.ico"));
    return;
  }
  if (url.pathname === "/favicon.ico") {
    serveFile(res, path.join(rootDir, "assets", "favicon.ico"));
    return;
  }
  if (url.pathname === "/robots.txt") {
    serveFile(res, path.join(rootDir, "robots.txt"));
    return;
  }
  if (url.pathname === "/sitemap.xml") {
    serveFile(res, path.join(rootDir, "sitemap.xml"));
    return;
  }
  if (url.pathname === "/site.webmanifest") {
    serveFile(res, path.join(rootDir, "site.webmanifest"));
    return;
  }
  if (url.pathname.startsWith("/assets/")) {
    try {
      serveAssetFile(res, decodeURIComponent(url.pathname.replace("/assets/", "")));
    } catch {
      res.writeHead(400, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad request");
    }
    return;
  }
  if (url.pathname === "/downloads/NovaSentinelSetup.exe") {
    serveFile(res, latestReleaseArtifact(/^(NovaSentinelSetup\.exe|NovaSentinel-Setup-.+\.exe)$/i));
    return;
  }
  if (url.pathname === "/downloads/NovaSentinelAdminConsole.zip") {
    serveFile(res, latestReleaseArtifact(/^(NovaSentinelAdminConsole\.zip|novasentinel-admin-console-.+\.zip)$/i));
    return;
  }
  if (url.pathname.startsWith("/downloads/")) {
    let fileName = "";
    try {
      fileName = path.basename(decodeURIComponent(url.pathname.replace("/downloads/", "")));
    } catch {
      res.writeHead(400, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad request");
      return;
    }
    serveDownloadFile(res, fileName);
    return;
  }
  if (url.pathname.startsWith("/release-downloads/")) {
    let fileName = "";
    try {
      fileName = path.basename(decodeURIComponent(url.pathname.replace("/release-downloads/", "")));
    } catch {
      res.writeHead(400, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Bad request");
      return;
    }
    if (isSensitiveStaticName(fileName) || !/^[a-z0-9._-]+$/i.test(fileName)) {
      res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    serveFile(res, path.join(releaseUploadDir, fileName));
    return;
  }
  let requestPath;
  try {
    requestPath = decodeURIComponent(url.pathname);
  } catch {
    res.writeHead(400, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Bad request");
    return;
  }
  if (requestPath === "/") requestPath = "/index.html";
  if (requestPath.includes("..")) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  const target = path.join(rootDir, requestPath);
  const resolved = path.resolve(target);
  const relative = path.relative(rootDir, resolved);
  const normalized = `/${relative.replace(/\\/g, "/")}`;
  const extension = path.extname(relative).toLowerCase();
  if (
    !relative
    || relative.startsWith("..")
    || path.isAbsolute(relative)
    || /\\0/.test(requestPath)
    || hasHiddenOrBlockedStaticSegment(normalized)
  ) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  if (blockedStaticExtensions.has(extension) || isSensitiveStaticName(path.basename(relative))) {
    res.writeHead(403, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }
  let servedPath = resolved;
  if (fs.existsSync(servedPath) && fs.statSync(servedPath).isDirectory()) servedPath = path.join(servedPath, "index.html");
  if (!fs.existsSync(servedPath) || !fs.statSync(servedPath).isFile()) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  serveFile(res, servedPath);
}

function redirect(res, location) {
  res.writeHead(302, { ...securityHeaders, Location: location });
  res.end();
}

function serveFile(res, resolved) {
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    res.writeHead(404, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
    return;
  }
  const body = fs.readFileSync(resolved);
  res.writeHead(200, { ...securityHeaders, "Content-Type": mimeTypes[path.extname(resolved)] || "application/octet-stream", "Content-Length": body.length });
  res.end(body);
}

initDb();
if (process.env.NOVASENTINEL_INIT_DB_ONLY === "1") {
  console.log(`SQLite database initialized: ${dbPath}`);
  db.close();
  process.exit(0);
}
cleanupSecurityCounters();
cleanupLoginChallenges();
cleanupExpiredSessions();
setInterval(() => {
  cleanupLoginChallenges();
  cleanupExpiredSessions();
  cleanupSecurityCounters();
}, 10 * 60 * 1000).unref?.();
if (process.env.NOVASENTINEL_DISABLE_DB_BACKUPS !== "1") {
  const backupTimer = setInterval(() => {
    try {
      backupDatabase("scheduled");
    } catch (error) {
      console.error("Scheduled database backup failed:", error.message);
    }
  }, backupIntervalHours * 60 * 60 * 1000);
  backupTimer.unref?.();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, publicBaseUrl);
  try {
    if (url.pathname.startsWith("/api/")) {
      await handleApi(req, res, url);
      return;
    }
    serveStatic(req, res, url);
  } catch (error) {
    const statusCode = error.statusCode || 500;
    if (error.retryAfter && statusCode >= 400) {
      const retryAfter = Math.ceil(error.retryAfter);
      res.setHeader("Retry-After", String(retryAfter));
    }
    json(res, statusCode, {
      error: error.code || (statusCode >= 500 ? "server_error" : "request_error"),
      message: error.message,
      ...(error.retryAfter ? { retry_after: Math.ceil(error.retryAfter) } : {}),
    });
  }
});

server.listen(port, host, () => {
  console.log(`NovaSentinel Premium Cloud listening on ${publicBaseUrl}`);
  console.log(`SQLite database: ${dbPath}`);
});
