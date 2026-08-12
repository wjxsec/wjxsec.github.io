const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_RETENTION_DAYS = 90;
const MAX_EVENT_BODY_BYTES = 1024;
const MAX_PATH_LENGTH = 512;
const MAX_HOST_LENGTH = 253;
const ADMIN_PAGE_LIMIT = 50;
const DEFAULT_ALLOWED_ORIGIN = "https://wjxsec.github.io";
export const SYNTHETIC_KEY_VERSION = "synthetic-v1";
export const SYNTHETIC_TEST_KEY_BASE64 = "7uYzmLd21zJCZAcIB78Z2jAVeNqXfLkI9o2mVThFVgc=";
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/v1/visit") {
      return handleVisit(request, env);
    }
    if (url.pathname === "/v1/admin/summary") {
      return handleSummary(request, env, url);
    }
    if (url.pathname === "/v1/admin/visits") {
      return handleVisits(request, env, url);
    }
    if (url.pathname.startsWith("/v1/admin/visits/")) {
      return handleVisitDetail(request, env, url);
    }

    return jsonResponse({ error: "Not found" }, 404);
  },

  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(pruneExpired(env.DB, Date.now()));
  }
};

async function handleVisit(request, env) {
  const allowedOrigin = getAllowedOrigin(env);
  const origin = request.headers.get("Origin");

  if (request.method === "OPTIONS") {
    if (origin !== allowedOrigin) {
      return jsonResponse({ error: "Forbidden" }, 403);
    }
    return new Response(null, { status: 204, headers: publicCorsHeaders(allowedOrigin) });
  }
  if (request.method !== "POST") {
    return publicJsonResponse({ error: "Method not allowed" }, 405, allowedOrigin);
  }
  if (origin !== allowedOrigin) {
    return jsonResponse({ error: "Forbidden" }, 403);
  }
  if (hasPrivacySignal(request)) {
    return new Response(null, { status: 204, headers: publicCorsHeaders(allowedOrigin) });
  }
  if (!isCollectorConfigured(env)) {
    return publicJsonResponse({ error: "Collector is not configured" }, 503, allowedOrigin);
  }

  const contentType = (request.headers.get("Content-Type") || "").toLowerCase();
  if (contentType.split(";", 1)[0].trim() !== "text/plain") {
    return publicJsonResponse({ error: "Unsupported content type" }, 415, allowedOrigin);
  }
  const declaredContentLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredContentLength > MAX_EVENT_BODY_BYTES) {
    return publicJsonResponse({ error: "Request body is too large" }, 413, allowedOrigin);
  }

  const ipAddress = normalizeIp(request.headers.get("CF-Connecting-IP"));
  if (!ipAddress) {
    return publicJsonResponse({ error: "Source IP is unavailable" }, 400, allowedOrigin);
  }

  const rateLimit = await enforceRateLimit(env.VISIT_RATE_LIMITER, `visit:${ipAddress}`);
  if (rateLimit === "unavailable") {
    return publicJsonResponse({ error: "Collector is not configured" }, 503, allowedOrigin);
  }
  if (rateLimit === "limited") {
    return publicJsonResponse(
      { error: "Too many requests" },
      429,
      allowedOrigin,
      { "Retry-After": "60" }
    );
  }

  let payload;
  try {
    const body = await readLimitedText(request, MAX_EVENT_BODY_BYTES);
    if (body.tooLarge) {
      return publicJsonResponse({ error: "Request body is too large" }, 413, allowedOrigin);
    }
    payload = JSON.parse(body.text);
  } catch {
    return publicJsonResponse({ error: "Invalid request body" }, 400, allowedOrigin);
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return publicJsonResponse({ error: "Invalid request body" }, 400, allowedOrigin);
  }

  const now = Date.now();
  const retentionDays = getRetentionDays(env);
  const expiresAt = now + retentionDays * DAY_MS;
  const eventId = crypto.randomUUID();
  const aad = buildAad(eventId, now, expiresAt);
  let protectedIp;
  let ipHmac;
  let encryptionKeyVersion;

  try {
    encryptionKeyVersion = getCurrentEncryptionKeyVersion(env);
    protectedIp = await encryptIp(ipAddress, env.IP_ENCRYPTION_KEY, aad);
    ipHmac = await hmacIp(ipAddress, env.IP_HMAC_KEY);
  } catch {
    return publicJsonResponse({ error: "Collector is not configured" }, 503, allowedOrigin);
  }

  const cf = request.cf || {};
  try {
    await env.DB.prepare(
      `INSERT INTO visitor_events (
        event_id, observed_at, expires_at, ip_ciphertext, ip_iv,
        encryption_key_version, ip_hmac, country_code, region_code, city,
        asn, page_path, referrer_host
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        eventId,
        now,
        expiresAt,
        protectedIp.ciphertext,
        protectedIp.iv,
        encryptionKeyVersion,
        ipHmac,
        normalizeText(cf.country, 2),
        normalizeText(cf.regionCode, 16),
        normalizeText(cf.city, 128),
        normalizeAsn(cf.asn),
        normalizePath(payload.path),
        normalizeHost(payload.referrerHost)
      )
      .run();
  } catch {
    return publicJsonResponse({ error: "Could not record the visit" }, 500, allowedOrigin);
  }

  return new Response(null, { status: 204, headers: publicCorsHeaders(allowedOrigin) });
}

async function handleSummary(request, env, url) {
  if (request.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }
  const accessFailure = await requireAdminAccess(request, env);
  if (accessFailure) {
    return accessFailure;
  }

  const retentionDays = getRetentionDays(env);
  const days = parsePositiveInteger(url.searchParams.get("days"), 30, retentionDays);
  const now = Date.now();
  const since = now - days * DAY_MS;

  try {
    const [totals, countries, regions, cities, asns] = await Promise.all([
      selectFirst(
        env.DB,
        `SELECT COUNT(*) AS events, COUNT(DISTINCT ip_hmac) AS unique_ip_hashes,
          SUM(CASE WHEN encryption_key_version = 'synthetic-v1'
            AND page_path GLOB '/__test__/*'
            AND referrer_host = 'synthetic-test.invalid' THEN 1 ELSE 0 END) AS synthetic_events,
          COUNT(DISTINCT CASE WHEN encryption_key_version = 'synthetic-v1'
            AND page_path GLOB '/__test__/*'
            AND referrer_host = 'synthetic-test.invalid' THEN ip_hmac END) AS synthetic_unique_ip_hashes
         FROM visitor_events WHERE observed_at >= ? AND expires_at > ?`,
        [since, now]
      ),
      selectAll(
        env.DB,
        `SELECT COALESCE(country_code, 'Unknown') AS country, COUNT(*) AS events
         FROM visitor_events WHERE observed_at >= ? AND expires_at > ?
         GROUP BY country_code ORDER BY events DESC, country ASC LIMIT 50`,
        [since, now]
      ),
      selectAll(
        env.DB,
        `SELECT COALESCE(region_code, 'Unknown') AS region, COUNT(*) AS events
         FROM visitor_events WHERE observed_at >= ? AND expires_at > ?
         GROUP BY region_code ORDER BY events DESC, region ASC LIMIT 50`,
        [since, now]
      ),
      selectAll(
        env.DB,
        `SELECT COALESCE(city, 'Unknown') AS city, COUNT(*) AS events
         FROM visitor_events WHERE observed_at >= ? AND expires_at > ?
         GROUP BY city ORDER BY events DESC, city ASC LIMIT 50`,
        [since, now]
      ),
      selectAll(
        env.DB,
        `SELECT asn, COUNT(*) AS events
         FROM visitor_events WHERE observed_at >= ? AND expires_at > ?
         GROUP BY asn ORDER BY events DESC, asn ASC LIMIT 50`,
        [since, now]
      )
    ]);

    return jsonResponse({
      retention_days: retentionDays,
      range_start: new Date(since).toISOString(),
      range_end: new Date(now).toISOString(),
      events: Number(totals.events || 0),
      unique_ip_hashes: Number(totals.unique_ip_hashes || 0),
      synthetic_events: Number(totals.synthetic_events || 0),
      synthetic_unique_ip_hashes: Number(totals.synthetic_unique_ip_hashes || 0),
      countries,
      regions,
      cities,
      asns
    });
  } catch {
    return jsonResponse({ error: "Could not read the summary" }, 500);
  }
}

async function handleVisits(request, env, url) {
  if (request.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }
  const accessFailure = await requireAdminAccess(request, env);
  if (accessFailure) {
    return accessFailure;
  }

  const limit = parsePositiveInteger(url.searchParams.get("limit"), 50, ADMIN_PAGE_LIMIT);
  const beforeId = parsePositiveInteger(url.searchParams.get("before"), null, Number.MAX_SAFE_INTEGER);
  const now = Date.now();
  const query = beforeId
    ? `SELECT id, event_id, observed_at, expires_at, ip_ciphertext, ip_iv,
         encryption_key_version, country_code, region_code, city, asn, page_path, referrer_host
       FROM visitor_events WHERE id < ? AND expires_at > ? ORDER BY id DESC LIMIT ?`
    : `SELECT id, event_id, observed_at, expires_at, ip_ciphertext, ip_iv,
         encryption_key_version, country_code, region_code, city, asn, page_path, referrer_host
       FROM visitor_events WHERE expires_at > ? ORDER BY id DESC LIMIT ?`;
  const bindings = beforeId ? [beforeId, now, limit] : [now, limit];

  try {
    const records = await selectAll(env.DB, query, bindings);
    const visits = await Promise.all(records.map(async (record) => {
      let ipMasked = "unavailable";
      try {
        ipMasked = maskIp(await decryptRecordIp(record, env));
      } catch {
        // A damaged ciphertext or retired key must not expose a raw IP or
        // make all other records unavailable.
      }
      return {
        id: record.id,
        event_id: record.event_id,
        observed_at: record.observed_at,
        expires_at: record.expires_at,
        ip_masked: ipMasked,
        synthetic: isSyntheticRecord(record),
        country_code: record.country_code,
        region_code: record.region_code,
        city: record.city,
        asn: record.asn,
        page_path: record.page_path,
        referrer_host: record.referrer_host
      };
    }));

    return jsonResponse({
      retention_days: getRetentionDays(env),
      visits,
      next_before: visits.length === limit ? visits[visits.length - 1].id : null
    });
  } catch {
    return jsonResponse({ error: "Could not read visitor records" }, 500);
  }
}

async function handleVisitDetail(request, env, url) {
  if (request.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }
  const accessFailure = await requireAdminAccess(request, env);
  if (accessFailure) {
    return accessFailure;
  }
  if (request.headers.get("X-Confirm-Raw-IP") !== "yes") {
    return jsonResponse({ error: "Explicit raw-IP confirmation is required" }, 428);
  }

  let eventId;
  try {
    eventId = decodeURIComponent(url.pathname.slice("/v1/admin/visits/".length));
  } catch {
    return jsonResponse({ error: "Invalid event ID" }, 400);
  }
  if (!isUuid(eventId)) {
    return jsonResponse({ error: "Invalid event ID" }, 400);
  }
  const actorHash = await verifyPanelRequestAttestation(request, env);
  if (!actorHash) {
    return jsonResponse({ error: "Private panel authentication required" }, 403);
  }

  const now = Date.now();
  try {
    const record = await selectFirst(
      env.DB,
      `SELECT event_id, observed_at, expires_at, ip_ciphertext, ip_iv,
       encryption_key_version, country_code, region_code, city, asn, page_path, referrer_host
       FROM visitor_events WHERE event_id = ? AND expires_at > ?`,
      [eventId, now]
    );
    if (!record.event_id) {
      return jsonResponse({ error: "Not found" }, 404);
    }

    const ipAddress = await decryptRecordIp(record, env);
    await writeAdminAudit(
      env.DB,
      now,
      record.expires_at,
      "reveal_raw_ip",
      eventId,
      1,
      actorHash,
      "cloudflare_access"
    );

    return jsonResponse({
      event_id: record.event_id,
      observed_at: record.observed_at,
      expires_at: record.expires_at,
      ip_address: ipAddress,
      country_code: record.country_code,
      region_code: record.region_code,
      city: record.city,
      asn: record.asn,
      page_path: record.page_path,
      referrer_host: record.referrer_host
    });
  } catch {
    return jsonResponse({ error: "Could not read the raw-IP record" }, 500);
  }
}

export async function pruneExpired(db, now) {
  if (!db) {
    return;
  }
  await Promise.all([
    db.prepare("DELETE FROM visitor_events WHERE expires_at <= ?").bind(now).run(),
    db.prepare("DELETE FROM admin_audit WHERE expires_at <= ?").bind(now).run()
  ]);
}

export async function encryptIp(ipAddress, secret, aad) {
  const key = await importEncryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: textEncoder.encode(aad) },
    key,
    textEncoder.encode(ipAddress)
  );
  return { ciphertext: bytesToBase64(new Uint8Array(ciphertext)), iv: bytesToBase64(iv) };
}

export async function decryptIp(ciphertext, iv, secret, aad) {
  const key = await importEncryptionKey(secret);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(iv), additionalData: textEncoder.encode(aad) },
    key,
    base64ToBytes(ciphertext)
  );
  return textDecoder.decode(plaintext);
}

export async function hmacIp(ipAddress, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(ipAddress));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function maskIp(ipAddress) {
  if (isIpv4(ipAddress)) {
    const segments = ipAddress.split(".");
    return `${segments[0]}.${segments[1]}.${segments[2]}.0`;
  }
  return isIpv6(ipAddress) ? "IPv6 (masked)" : "masked";
}

export function constantTimeEqual(expected, supplied) {
  if (expected.length !== supplied.length) {
    return false;
  }
  let mismatch = 0;
  for (let index = 0; index < expected.length; index += 1) {
    mismatch |= expected.charCodeAt(index) ^ supplied.charCodeAt(index);
  }
  return mismatch === 0;
}

function isCollectorConfigured(env) {
  return Boolean(
    env.DB && env.IP_ENCRYPTION_KEY && env.IP_HMAC_KEY &&
    env.VISIT_RATE_LIMITER && typeof env.VISIT_RATE_LIMITER.limit === "function"
  );
}

function isAdminConfigured(env) {
  return Boolean(
    env.DB && env.IP_ENCRYPTION_KEY && env.ADMIN_TOKEN &&
    env.ADMIN_RATE_LIMITER && typeof env.ADMIN_RATE_LIMITER.limit === "function"
  );
}

async function requireAdminAccess(request, env) {
  if (!isAdminConfigured(env)) {
    return jsonResponse({ error: "Collector is not configured" }, 503);
  }
  const authorized = isAuthorized(request, env);
  const sourceIp = normalizeIp(request.headers.get("CF-Connecting-IP")) || "unknown";
  const panelActor = authorized ? await verifyPanelRequestAttestation(request, env) : null;
  const rateKey = panelActor ? `panel:${panelActor}` : `admin:${sourceIp}`;
  const rateLimit = await enforceRateLimit(env.ADMIN_RATE_LIMITER, rateKey);
  if (rateLimit === "unavailable") {
    return jsonResponse({ error: "Collector is not configured" }, 503);
  }
  if (rateLimit === "limited") {
    return jsonResponse({ error: "Too many requests" }, 429, { "Retry-After": "60" });
  }
  return authorized ? null : unauthorizedResponse();
}

async function enforceRateLimit(limiter, key) {
  if (!limiter || typeof limiter.limit !== "function") {
    return "unavailable";
  }
  try {
    const result = await limiter.limit({ key });
    if (!result || typeof result.success !== "boolean") {
      return "unavailable";
    }
    return result.success ? "allowed" : "limited";
  } catch {
    return "unavailable";
  }
}

function getAllowedOrigin(env) {
  return env.ALLOWED_ORIGIN || DEFAULT_ALLOWED_ORIGIN;
}

function getRetentionDays(env) {
  const configured = Number(env.RETENTION_DAYS || MAX_RETENTION_DAYS);
  if (!Number.isFinite(configured)) {
    return MAX_RETENTION_DAYS;
  }
  return Math.min(Math.max(Math.floor(configured), 1), MAX_RETENTION_DAYS);
}

function getCurrentEncryptionKeyVersion(env) {
  const version = env.IP_ENCRYPTION_KEY_VERSION || "v1";
  if (
    typeof version !== "string" ||
    !/^[A-Za-z0-9_-]{1,32}$/.test(version) ||
    version === SYNTHETIC_KEY_VERSION
  ) {
    throw new Error("Invalid encryption key version");
  }
  return version;
}

function getEncryptionKeyForRecord(record, env) {
  if (isSyntheticRecord(record)) {
    return SYNTHETIC_TEST_KEY_BASE64;
  }
  if (record.encryption_key_version === getCurrentEncryptionKeyVersion(env)) {
    return env.IP_ENCRYPTION_KEY;
  }
  const previousVersion = env.IP_ENCRYPTION_KEY_PREVIOUS_VERSION;
  if (
    typeof previousVersion === "string" &&
    /^[A-Za-z0-9_-]{1,32}$/.test(previousVersion) &&
    previousVersion !== SYNTHETIC_KEY_VERSION &&
    record.encryption_key_version === previousVersion &&
    env.IP_ENCRYPTION_KEY_PREVIOUS
  ) {
    return env.IP_ENCRYPTION_KEY_PREVIOUS;
  }
  throw new Error("No key is available for this record");
}

function isSyntheticRecord(record) {
  return record.encryption_key_version === SYNTHETIC_KEY_VERSION &&
    typeof record.page_path === "string" &&
    record.page_path.startsWith("/__test__/") &&
    record.referrer_host === "synthetic-test.invalid";
}

function hasPrivacySignal(request) {
  const dnt = (request.headers.get("DNT") || "").trim().toLowerCase();
  return dnt === "1" || dnt === "yes" || request.headers.get("Sec-GPC") === "1";
}

function publicCorsHeaders(allowedOrigin) {
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Cache-Control": "no-store",
    "Vary": "Origin"
  };
}

function publicJsonResponse(body, status, allowedOrigin, extraHeaders = {}) {
  return jsonResponse(body, status, { ...publicCorsHeaders(allowedOrigin), ...extraHeaders });
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function unauthorizedResponse() {
  return jsonResponse({ error: "Unauthorized" }, 401, { "WWW-Authenticate": "Bearer" });
}

function isAuthorized(request, env) {
  const expected = env.ADMIN_TOKEN;
  const authorization = request.headers.get("Authorization") || "";
  const prefix = "Bearer ";
  const supplied = authorization.startsWith(prefix) ? authorization.slice(prefix.length) : "";
  return typeof expected === "string" && expected.length > 0 && constantTimeEqual(expected, supplied);
}

function normalizeIp(value) {
  if (typeof value !== "string") {
    return null;
  }
  const ipAddress = value.trim();
  if (ipAddress.length === 0 || ipAddress.length > 64 || (!isIpv4(ipAddress) && !isIpv6(ipAddress))) {
    return null;
  }
  return ipAddress.toLowerCase();
}

function isIpv4(value) {
  const segments = value.split(".");
  return segments.length === 4 && segments.every((segment) => /^\d{1,3}$/.test(segment) && Number(segment) <= 255);
}

function isIpv6(value) {
  if (!/^[0-9a-fA-F:]+$/.test(value) || value.length > 39) {
    return false;
  }
  const firstDoubleColon = value.indexOf("::");
  if (firstDoubleColon !== value.lastIndexOf("::")) {
    return false;
  }
  const [left, right] = firstDoubleColon === -1 ? [value, null] : value.split("::");
  const leftSegments = left ? left.split(":") : [];
  const rightSegments = right ? right.split(":") : [];
  const validSegment = (segment) => /^[0-9a-fA-F]{1,4}$/.test(segment);
  if (!leftSegments.every(validSegment) || !rightSegments.every(validSegment)) {
    return false;
  }
  const segmentCount = leftSegments.length + rightSegments.length;
  return firstDoubleColon === -1 ? segmentCount === 8 : segmentCount < 8;
}

function normalizeText(value, maxLength) {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.replace(/[\u0000-\u001F\u007F]/g, "").trim().slice(0, maxLength);
  return normalized || null;
}

function normalizeAsn(value) {
  const asn = Number(value);
  return Number.isSafeInteger(asn) && asn >= 0 ? asn : null;
}

function normalizePath(value) {
  if (typeof value !== "string") {
    return "/";
  }
  const path = value.replace(/[\u0000-\u001F\u007F]/g, "").trim().split(/[?#]/, 1)[0];
  if (!path.startsWith("/") || path.length > MAX_PATH_LENGTH || !/^\/[A-Za-z0-9._~/-]*$/.test(path)) {
    return "/";
  }
  return path || "/";
}

function normalizeHost(value) {
  if (typeof value !== "string" || value.length > MAX_HOST_LENGTH) {
    return null;
  }
  try {
    const host = new URL(`https://${value.trim()}`).hostname.toLowerCase();
    return host.length > 0 && host.length <= MAX_HOST_LENGTH ? host : null;
  } catch {
    return null;
  }
}

function normalizeActorHash(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value) ? value : null;
}

async function verifyPanelRequestAttestation(request, env) {
  const actorHash = normalizeActorHash(request.headers.get("X-Admin-Actor-Hash"));
  const timestampText = request.headers.get("X-Admin-Actor-Timestamp") || "";
  const signature = request.headers.get("X-Admin-Actor-Signature") || "";
  const timestamp = Number(timestampText);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    !actorHash ||
    !Number.isSafeInteger(timestamp) ||
    Math.abs(nowSeconds - timestamp) > 120 ||
    !/^[0-9a-f]{64}$/.test(signature) ||
    typeof env.PANEL_HMAC_KEY !== "string" ||
    env.PANEL_HMAC_KEY.length < 32
  ) {
    return null;
  }
  try {
    const url = new URL(request.url);
    const requestTarget = `${url.pathname}${url.search}`;
    const expected = await hmacIp(
      `${requestTarget}:${actorHash}:${timestamp}`,
      env.PANEL_HMAC_KEY
    );
    return constantTimeEqual(expected, signature) ? actorHash : null;
  } catch {
    return null;
  }
}

function parsePositiveInteger(value, fallback, maximum) {
  if (value === null) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback;
}

function buildAad(eventId, observedAt, expiresAt) {
  return `${eventId}:${observedAt}:${expiresAt}`;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function decryptRecordIp(record, env) {
  const ipAddress = await decryptIp(
    record.ip_ciphertext,
    record.ip_iv,
    getEncryptionKeyForRecord(record, env),
    buildAad(record.event_id, record.observed_at, record.expires_at)
  );
  if (isSyntheticRecord(record) && !isDocumentationIp(ipAddress)) {
    throw new Error("Synthetic record is outside documentation address ranges");
  }
  return ipAddress;
}

function isDocumentationIp(value) {
  const ipAddress = normalizeIp(value);
  return Boolean(ipAddress) && (
    /^192\.0\.2\.|^198\.51\.100\.|^203\.0\.113\./.test(ipAddress) ||
    /^2001:0?db8:/.test(ipAddress)
  );
}

async function writeAdminAudit(
  db,
  now,
  sourceExpiresAt,
  action,
  eventId,
  resultCount,
  actorHash,
  authMethod
) {
  const expiresAt = Math.min(Number(sourceExpiresAt), now + MAX_RETENTION_DAYS * DAY_MS);
  await db.prepare(
    `INSERT INTO admin_audit (
       occurred_at, expires_at, action, event_id, result_count, actor_hash, auth_method
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(now, expiresAt, action, eventId, resultCount, actorHash, authMethod)
    .run();
}

async function readLimitedText(request, maximumBytes) {
  const stream = request.body;
  if (!stream || typeof stream.getReader !== "function") {
    const text = await request.text();
    return { text, tooLarge: textEncoder.encode(text).byteLength > maximumBytes };
  }

  const reader = stream.getReader();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      totalBytes += chunk.byteLength;
      if (totalBytes > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The request is already being rejected, so cancellation is best effort.
        }
        return { text: "", tooLarge: true };
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }

  const bodyBytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bodyBytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: textDecoder.decode(bodyBytes), tooLarge: false };
}

async function selectFirst(db, query, bindings) {
  const rows = await selectAll(db, query, bindings);
  return rows[0] || {};
}

async function selectAll(db, query, bindings) {
  const result = await db.prepare(query).bind(...bindings).all();
  return result.results || [];
}

async function importEncryptionKey(secret) {
  const raw = base64ToBytes(secret);
  if (raw.byteLength !== 32) {
    throw new Error("IP_ENCRYPTION_KEY must be a 32-byte base64 value");
  }
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
