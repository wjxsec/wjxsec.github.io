const MAX_ACCESS_TOKEN_BYTES = 8192;
const MAX_REVEAL_BODY_BYTES = 256;
const MAX_UPSTREAM_BODY_BYTES = 1024 * 1024;
const MAX_VISIT_LIMIT = 50;
const MAX_RANGE_DAYS = 90;
const JWKS_CACHE_MS = 5 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const jwksCache = new Map();

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  }
};

export async function handleRequest(request, env, accessFetch = fetch) {
  const url = new URL(request.url);
  const sourceIp = (request.headers.get("CF-Connecting-IP") || "unknown").slice(0, 80);
  const preAuthLimit = await requirePanelRateLimit(env, `auth:${sourceIp}`);
  if (preAuthLimit) {
    return preAuthLimit;
  }
  const access = await authenticateAccess(request, env, accessFetch);
  if (!access.ok) {
    return access.response;
  }

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    return panelResponse(PANEL_HTML, "text/html; charset=utf-8");
  }
  if (request.method === "GET" && url.pathname === "/assets/admin.css") {
    return panelResponse(PANEL_STYLES, "text/css; charset=utf-8");
  }
  if (request.method === "GET" && url.pathname === "/assets/admin.js") {
    return panelResponse(PANEL_SCRIPT, "text/javascript; charset=utf-8");
  }
  if (url.pathname === "/api/summary") {
    return handleSummary(request, env, url, access.actorHash);
  }
  if (url.pathname === "/api/visits") {
    return handleVisits(request, env, url, access.actorHash);
  }
  if (url.pathname.startsWith("/api/visits/") && url.pathname.endsWith("/reveal")) {
    return handleReveal(request, env, url, access.actorHash);
  }

  return panelJson({ error: "Not found" }, 404);
}

async function handleSummary(request, env, url, actorHash) {
  if (request.method !== "GET") {
    return methodNotAllowed("GET");
  }
  const limited = await requirePanelRateLimit(env, actorHash);
  if (limited) {
    return limited;
  }
  const days = parsePositiveInteger(url.searchParams.get("days"), 30, MAX_RANGE_DAYS);
  return callCollector(env, `/v1/admin/summary?days=${days}`, { actorHash });
}

async function handleVisits(request, env, url, actorHash) {
  if (request.method !== "GET") {
    return methodNotAllowed("GET");
  }
  const limited = await requirePanelRateLimit(env, actorHash);
  if (limited) {
    return limited;
  }
  const limit = parsePositiveInteger(url.searchParams.get("limit"), 25, MAX_VISIT_LIMIT);
  const before = parsePositiveInteger(url.searchParams.get("before"), null, Number.MAX_SAFE_INTEGER);
  const query = new URLSearchParams({ limit: String(limit) });
  if (before) {
    query.set("before", String(before));
  }
  return callCollector(env, `/v1/admin/visits?${query.toString()}`, { actorHash });
}

async function handleReveal(request, env, url, actorHash) {
  if (request.method !== "POST") {
    return methodNotAllowed("POST");
  }
  if (!isSameOriginAdminRequest(request, env)) {
    return panelJson({ error: "Cross-origin request rejected" }, 403);
  }
  const contentType = (request.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    return panelJson({ error: "Unsupported content type" }, 415);
  }
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_REVEAL_BODY_BYTES) {
    return panelJson({ error: "Request body is too large" }, 413);
  }

  let payload;
  try {
    const body = await readLimitedText(request, MAX_REVEAL_BODY_BYTES);
    if (body.tooLarge) {
      return panelJson({ error: "Request body is too large" }, 413);
    }
    payload = JSON.parse(body.text);
  } catch {
    return panelJson({ error: "Invalid request body" }, 400);
  }
  if (!payload || payload.confirm !== "REVEAL") {
    return panelJson({ error: "Explicit confirmation is required" }, 428);
  }

  const prefix = "/api/visits/";
  const suffix = "/reveal";
  let eventId;
  try {
    eventId = decodeURIComponent(url.pathname.slice(prefix.length, -suffix.length));
  } catch {
    return panelJson({ error: "Invalid event ID" }, 400);
  }
  if (!isUuid(eventId)) {
    return panelJson({ error: "Invalid event ID" }, 400);
  }

  const limited = await requirePanelRateLimit(env, `reveal:${actorHash}`);
  if (limited) {
    return limited;
  }

  return callCollector(env, `/v1/admin/visits/${eventId}`, {
    reveal: true,
    actorHash
  });
}

async function authenticateAccess(request, env, accessFetch) {
  if (
    !env.ACCESS_TEAM_DOMAIN ||
    !env.ACCESS_AUD ||
    !env.ACCESS_ALLOWED_EMAIL ||
    !env.ADMIN_AUDIT_HMAC_KEY
  ) {
    return { ok: false, response: panelJson({ error: "Panel authentication is not configured" }, 503) };
  }
  const token = request.headers.get("Cf-Access-Jwt-Assertion") || "";
  if (!token) {
    return { ok: false, response: panelJson({ error: "Cloudflare Access authentication required" }, 401) };
  }
  try {
    const payload = await verifyAccessJwt(token, {
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      audience: env.ACCESS_AUD,
      fetchImpl: accessFetch
    });
    if (typeof payload.sub !== "string" || payload.sub.length === 0 || payload.sub.length > 512) {
      throw new Error("Access subject is invalid");
    }
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    if (!email || email !== String(env.ACCESS_ALLOWED_EMAIL).trim().toLowerCase()) {
      throw new Error("Access identity is not allowed");
    }
    return {
      ok: true,
      payload,
      actorHash: await hmacText(payload.sub, env.ADMIN_AUDIT_HMAC_KEY)
    };
  } catch {
    return { ok: false, response: panelJson({ error: "Cloudflare Access token rejected" }, 403) };
  }
}

export async function verifyAccessJwt(token, { teamDomain, audience, fetchImpl = fetch, now = Date.now() }) {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_ACCESS_TOKEN_BYTES) {
    throw new Error("Access token is invalid");
  }
  const segments = token.split(".");
  if (segments.length !== 3 || segments.some((segment) => !/^[A-Za-z0-9_-]+$/.test(segment))) {
    throw new Error("Access token is malformed");
  }

  const header = decodeJwtJson(segments[0]);
  const payload = decodeJwtJson(segments[1]);
  if (header.alg !== "RS256" || typeof header.kid !== "string" || header.kid.length > 256) {
    throw new Error("Access token algorithm is not allowed");
  }

  const teamHost = normalizeTeamDomain(teamDomain);
  const expectedIssuer = `https://${teamHost}`;
  if (normalizeIssuer(payload.iss) !== expectedIssuer) {
    throw new Error("Access token issuer does not match");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (typeof audience !== "string" || audience.length === 0 || !audiences.includes(audience)) {
    throw new Error("Access token audience does not match");
  }

  const nowSeconds = Math.floor(now / 1000);
  if (!Number.isFinite(payload.exp) || payload.exp <= nowSeconds - CLOCK_SKEW_SECONDS) {
    throw new Error("Access token has expired");
  }
  if (Number.isFinite(payload.nbf) && payload.nbf > nowSeconds + CLOCK_SKEW_SECONDS) {
    throw new Error("Access token is not active");
  }

  const jwk = await findAccessJwk(teamHost, header.kid, fetchImpl, now);
  if (!jwk || jwk.kty !== "RSA") {
    throw new Error("Access signing key is unavailable");
  }

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const verified = await crypto.subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    key,
    base64UrlToBytes(segments[2]),
    textEncoder.encode(`${segments[0]}.${segments[1]}`)
  );
  if (!verified) {
    throw new Error("Access token signature is invalid");
  }
  return payload;
}

async function findAccessJwk(teamHost, kid, fetchImpl, now) {
  let cached = jwksCache.get(teamHost);
  const hadFreshCache = Boolean(cached && cached.expiresAt > now);
  if (!hadFreshCache) {
    cached = await loadAccessJwks(teamHost, fetchImpl, now, 0);
  }
  let match = cached.keys.find((key) => key && key.kid === kid && key.kty === "RSA" && key.use !== "enc") || null;
  if (match || !hadFreshCache) {
    return match;
  }
  if (!cached.unknownKidRefreshAt || now - cached.unknownKidRefreshAt >= JWKS_CACHE_MS) {
    cached = await loadAccessJwks(teamHost, fetchImpl, now, now);
    match = cached.keys.find((key) => key && key.kid === kid && key.kty === "RSA" && key.use !== "enc") || null;
  }
  return match;
}

async function loadAccessJwks(teamHost, fetchImpl, now, unknownKidRefreshAt) {
  const response = await fetchImpl(`https://${teamHost}/cdn-cgi/access/certs`, {
    headers: { Accept: "application/json" },
    redirect: "error"
  });
  if (!response || !response.ok) {
    throw new Error("Could not load Access signing keys");
  }
  const body = await response.json();
  if (!body || !Array.isArray(body.keys) || body.keys.length === 0 || body.keys.length > 32) {
    throw new Error("Access signing keys are invalid");
  }
  const cached = {
    keys: body.keys,
    expiresAt: now + JWKS_CACHE_MS,
    unknownKidRefreshAt
  };
  jwksCache.set(teamHost, cached);
  return cached;
}

export function clearJwksCacheForTests() {
  jwksCache.clear();
}

async function requirePanelRateLimit(env, key) {
  if (!env.PANEL_RATE_LIMITER || typeof env.PANEL_RATE_LIMITER.limit !== "function") {
    return panelJson({ error: "Panel rate limiting is not configured" }, 503);
  }
  try {
    const result = await env.PANEL_RATE_LIMITER.limit({ key });
    if (!result || result.success !== true) {
      return panelJson({ error: "Too many requests" }, 429, { "Retry-After": "60" });
    }
    return null;
  } catch {
    return panelJson({ error: "Panel rate limiting is unavailable" }, 503);
  }
}

async function callCollector(env, path, { reveal = false, actorHash = "" } = {}) {
  if (!env.COLLECTOR || typeof env.COLLECTOR.fetch !== "function" || !env.COLLECTOR_ADMIN_TOKEN) {
    return panelJson({ error: "Management service is not configured" }, 503);
  }
  if (!actorHash || !env.COLLECTOR_PANEL_HMAC_KEY) {
    return panelJson({ error: "Private management channel is not configured" }, 503);
  }
  const issuedAt = Math.floor(Date.now() / 1000);
  const signature = await hmacText(
    `${path}:${actorHash}:${issuedAt}`,
    env.COLLECTOR_PANEL_HMAC_KEY
  );
  const headers = new Headers({
    Accept: "application/json",
    Authorization: `Bearer ${env.COLLECTOR_ADMIN_TOKEN}`,
    "X-Admin-Actor-Hash": actorHash,
    "X-Admin-Actor-Timestamp": String(issuedAt),
    "X-Admin-Actor-Signature": signature
  });
  if (reveal) {
    headers.set("X-Confirm-Raw-IP", "yes");
  }

  let upstream;
  try {
    upstream = await env.COLLECTOR.fetch(new Request(`https://collector.internal${path}`, {
      method: "GET",
      headers,
      redirect: "error"
    }));
  } catch {
    return panelJson({ error: "Management service is unavailable" }, 502);
  }

  let bytes;
  try {
    bytes = new Uint8Array(await upstream.arrayBuffer());
  } catch {
    return panelJson({ error: "Management service returned an invalid response" }, 502);
  }
  if (bytes.byteLength > MAX_UPSTREAM_BODY_BYTES) {
    return panelJson({ error: "Management response is too large" }, 502);
  }

  let body;
  try {
    body = JSON.parse(textDecoder.decode(bytes));
  } catch {
    return panelJson({ error: "Management service returned an invalid response" }, 502);
  }

  if (upstream.status === 401 || upstream.status === 403 || upstream.status >= 500) {
    return panelJson({ error: "Management service is unavailable" }, 502);
  }
  const status = upstream.status >= 200 && upstream.status < 500 ? upstream.status : 502;
  const extraHeaders = upstream.status === 429 ? { "Retry-After": upstream.headers.get("Retry-After") || "60" } : {};
  return panelJson(body, status, extraHeaders);
}

function isSameOriginAdminRequest(request, env) {
  let expectedOrigin;
  try {
    expectedOrigin = new URL(env.PANEL_ORIGIN).origin;
  } catch {
    return false;
  }
  return request.headers.get("Origin") === expectedOrigin &&
    request.headers.get("Sec-Fetch-Site") === "same-origin" &&
    request.headers.get("X-WJXSEC-Admin-Action") === "reveal";
}

function methodNotAllowed(method) {
  return panelJson({ error: "Method not allowed" }, 405, { Allow: method });
}

function panelResponse(body, contentType, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": contentType,
      ...panelSecurityHeaders(),
      ...headers
    }
  });
}

function panelJson(body, status = 200, headers = {}) {
  return panelResponse(JSON.stringify(body), "application/json; charset=utf-8", status, headers);
}

function panelSecurityHeaders() {
  return {
    "Cache-Control": "private, no-store, max-age=0",
    Pragma: "no-cache",
    "Content-Security-Policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; worker-src 'none'",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY"
  };
}

function normalizeTeamDomain(value) {
  if (typeof value !== "string" || value.length > 253) {
    throw new Error("Access team domain is invalid");
  }
  const candidate = value.includes("://") ? value : `https://${value}`;
  const url = new URL(candidate);
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || !host.endsWith(".cloudflareaccess.com")) {
    throw new Error("Access team domain is invalid");
  }
  return host;
}

function normalizeIssuer(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.replace(/\/+$/, "");
}

function decodeJwtJson(segment) {
  const value = JSON.parse(textDecoder.decode(base64UrlToBytes(segment)));
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("JWT object is invalid");
  }
  return value;
}

function base64UrlToBytes(value) {
  const remainder = value.length % 4;
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + (remainder ? "=".repeat(4 - remainder) : "");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hmacText(value, secret) {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("Audit key is not configured");
  }
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, textEncoder.encode(value));
  return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parsePositiveInteger(value, fallback, maximum) {
  if (value === null) {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? Math.min(parsed, maximum) : fallback;
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function readLimitedText(request, maximumBytes) {
  const stream = request.body;
  if (!stream || typeof stream.getReader !== "function") {
    const text = await request.text();
    return { text, tooLarge: textEncoder.encode(text).byteLength > maximumBytes };
  }
  const reader = stream.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
      total += chunk.byteLength;
      if (total > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // Best-effort cancellation while rejecting the request.
        }
        return { text: "", tooLarge: true };
      }
      chunks.push(chunk);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: textDecoder.decode(bytes), tooLarge: false };
}

const PANEL_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>访问分析 · 私密控制台</title>
  <link rel="stylesheet" href="/assets/admin.css">
</head>
<body>
  <header class="topbar">
    <div>
      <p class="eyebrow">WJXSEC · PRIVATE</p>
      <h1>访问分析控制台</h1>
    </div>
    <div class="topbar-actions">
      <span class="secure-badge"><span aria-hidden="true">●</span> Cloudflare Access 已验证</span>
      <a class="quiet-link" href="/cdn-cgi/access/logout">安全退出</a>
    </div>
  </header>

  <main>
    <section class="notice" aria-label="数据说明">
      <strong>敏感数据保护已启用。</strong>
      <span>列表仅显示脱敏 IP；完整 IP 必须逐条确认查看，并会写入审计记录。在线记录最长保留 90 天。</span>
    </section>

    <section class="toolbar" aria-label="筛选与刷新">
      <label for="range">统计范围</label>
      <select id="range">
        <option value="7">最近 7 天</option>
        <option value="30" selected>最近 30 天</option>
        <option value="90">最近 90 天</option>
      </select>
      <button id="refresh" class="primary" type="button">刷新数据</button>
      <span id="refreshed-at" class="muted" aria-live="polite"></span>
    </section>

    <div id="error" class="error" role="alert" hidden></div>

    <section class="metrics" aria-label="流量摘要">
      <article class="metric-card">
        <span>访问事件</span>
        <strong id="events">—</strong>
        <small>所选时间范围</small>
      </article>
      <article class="metric-card">
        <span>唯一来源</span>
        <strong id="unique-sources">—</strong>
        <small>加密 IP 哈希估算</small>
      </article>
      <article class="metric-card">
        <span>数据保留</span>
        <strong id="retention">90 天</strong>
        <small>到期后应用不可访问</small>
      </article>
    </section>

    <section class="insights-grid" aria-label="归属地摘要">
      <article class="panel">
        <div class="panel-heading"><h2>国家 / 地区</h2><span>Top 5</span></div>
        <ol id="countries" class="rank-list"></ol>
      </article>
      <article class="panel">
        <div class="panel-heading"><h2>城市</h2><span>Top 5</span></div>
        <ol id="cities" class="rank-list"></ol>
      </article>
      <article class="panel">
        <div class="panel-heading"><h2>ASN</h2><span>Top 5</span></div>
        <ol id="asns" class="rank-list"></ol>
      </article>
    </section>

    <section class="panel visits-panel" aria-labelledby="visits-heading">
      <div class="panel-heading table-heading">
        <div>
          <h2 id="visits-heading">最近访问记录</h2>
          <p>默认仅展示脱敏地址与近似归属地</p>
        </div>
        <button id="next-page" class="secondary" type="button" disabled>下一页</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>时间</th>
              <th>脱敏 IP</th>
              <th>归属地</th>
              <th>ASN</th>
              <th>页面</th>
              <th>来源</th>
              <th><span class="sr-only">操作</span></th>
            </tr>
          </thead>
          <tbody id="visits-body"></tbody>
        </table>
        <p id="empty-state" class="empty" hidden>当前没有可显示的访问记录。</p>
      </div>
    </section>
  </main>

  <dialog id="detail-dialog" aria-labelledby="detail-title">
    <div class="dialog-head">
      <div>
        <p class="eyebrow">SENSITIVE RECORD</p>
        <h2 id="detail-title">访问详情</h2>
      </div>
      <button id="close-dialog" class="icon-button" type="button" aria-label="关闭">×</button>
    </div>
    <dl id="detail-list" class="detail-list"></dl>
    <div class="reveal-box">
      <label class="confirm-row">
        <input id="reveal-confirm" type="checkbox">
        <span>我确认需要查看此条记录的完整 IP，并了解该操作会被审计。</span>
      </label>
      <button id="reveal" class="danger" type="button" disabled>查看完整 IP</button>
      <div id="raw-result" class="raw-result" hidden>
        <span>完整 IP（30 秒后自动隐藏）</span>
        <code id="raw-ip"></code>
      </div>
      <p id="reveal-status" class="muted" role="status"></p>
    </div>
  </dialog>

  <script src="/assets/admin.js" defer></script>
</body>
</html>`;

const PANEL_STYLES = `:root {
  color-scheme: light;
  --ink: #17202a;
  --muted: #667085;
  --line: #e6e9ee;
  --paper: #ffffff;
  --canvas: #f4f6f8;
  --brand: #153a5b;
  --brand-soft: #e8f0f6;
  --good: #147d64;
  --danger: #b42318;
  --danger-soft: #fff1f0;
  --shadow: 0 18px 45px rgba(24, 39, 57, .08);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background: var(--canvas);
  color: var(--ink);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
button, select, input { font: inherit; }
button, select, a { -webkit-tap-highlight-color: transparent; }
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 26px max(24px, calc((100vw - 1240px) / 2));
  background: var(--paper);
  border-bottom: 1px solid var(--line);
}
h1, h2, p { margin: 0; }
h1 { margin-top: 2px; font-size: clamp(24px, 3vw, 34px); letter-spacing: -.035em; }
h2 { font-size: 17px; letter-spacing: -.015em; }
.eyebrow { color: var(--brand); font-size: 11px; font-weight: 800; letter-spacing: .16em; }
.topbar-actions, .toolbar { display: flex; align-items: center; gap: 12px; }
.secure-badge {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 7px 11px;
  border-radius: 999px;
  color: var(--good);
  background: #eaf8f3;
  font-size: 12px;
  font-weight: 750;
}
.secure-badge span { font-size: 8px; }
.quiet-link { color: var(--muted); text-decoration: none; font-size: 13px; }
.quiet-link:hover { color: var(--ink); }
main { width: min(1240px, calc(100% - 40px)); margin: 28px auto 56px; }
.notice {
  display: flex;
  gap: 8px;
  padding: 14px 16px;
  border: 1px solid #cfe3dc;
  border-radius: 12px;
  background: #f2fbf8;
  color: #245e50;
  font-size: 13px;
}
.toolbar { margin: 24px 0 16px; }
.toolbar label { color: var(--muted); font-size: 13px; font-weight: 650; }
select, button {
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: 9px;
  background: var(--paper);
  color: var(--ink);
}
select { padding: 0 36px 0 11px; }
button { padding: 0 14px; cursor: pointer; font-weight: 700; }
button:disabled { cursor: not-allowed; opacity: .48; }
button:focus-visible, select:focus-visible, input:focus-visible, a:focus-visible { outline: 3px solid rgba(21, 58, 91, .25); outline-offset: 2px; }
.primary { border-color: var(--brand); background: var(--brand); color: white; }
.secondary { color: var(--brand); border-color: #c9d7e3; }
.danger { border-color: var(--danger); background: var(--danger); color: white; }
.muted { color: var(--muted); font-size: 12px; }
.error { margin-bottom: 16px; padding: 12px 14px; border: 1px solid #f5c2bd; border-radius: 10px; background: var(--danger-soft); color: var(--danger); }
.metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.metric-card, .panel {
  border: 1px solid var(--line);
  border-radius: 14px;
  background: var(--paper);
  box-shadow: var(--shadow);
}
.metric-card { display: grid; gap: 7px; padding: 20px; }
.metric-card span { color: var(--muted); font-size: 12px; font-weight: 700; }
.metric-card strong { font-size: 31px; letter-spacing: -.04em; }
.metric-card small { color: var(--muted); }
.insights-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px; }
.panel { padding: 20px; }
.panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.panel-heading > span { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
.rank-list { display: grid; gap: 11px; margin: 18px 0 0; padding: 0; list-style: none; counter-reset: rank; }
.rank-list li { display: grid; grid-template-columns: 22px 1fr auto; gap: 8px; align-items: center; counter-increment: rank; }
.rank-list li::before { content: counter(rank); color: #98a2b3; font-size: 11px; font-weight: 800; }
.rank-list b { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 650; }
.rank-list span { color: var(--muted); font-variant-numeric: tabular-nums; }
.visits-panel { margin-top: 16px; padding: 0; overflow: hidden; }
.table-heading { padding: 20px; border-bottom: 1px solid var(--line); }
.table-heading p { margin-top: 3px; color: var(--muted); font-size: 12px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 900px; }
th, td { padding: 13px 14px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: middle; }
th { background: #fafbfc; color: var(--muted); font-size: 11px; font-weight: 800; letter-spacing: .04em; text-transform: uppercase; }
td { font-size: 13px; }
td code, .raw-result code { font: 650 12px/1.4 ui-monospace, SFMono-Regular, Consolas, monospace; }
tbody tr:hover { background: #fafcff; }
.record-button { min-height: 32px; padding: 0 10px; color: var(--brand); border-color: #c9d7e3; font-size: 12px; }
.empty { padding: 34px; text-align: center; color: var(--muted); }
dialog {
  width: min(580px, calc(100% - 28px));
  padding: 0;
  border: 0;
  border-radius: 16px;
  color: var(--ink);
  box-shadow: 0 28px 90px rgba(16, 24, 40, .3);
}
dialog::backdrop { background: rgba(15, 23, 42, .55); backdrop-filter: blur(3px); }
.dialog-head { display: flex; align-items: center; justify-content: space-between; padding: 20px 22px; border-bottom: 1px solid var(--line); }
.icon-button { width: 36px; padding: 0; border: 0; font-size: 26px; font-weight: 400; }
.detail-list { display: grid; grid-template-columns: 120px 1fr; margin: 0; padding: 20px 22px; gap: 10px 14px; }
.detail-list dt { color: var(--muted); font-size: 12px; }
.detail-list dd { margin: 0; overflow-wrap: anywhere; font-size: 13px; }
.reveal-box { padding: 18px 22px 22px; border-top: 1px solid var(--line); background: #fffafa; }
.confirm-row { display: flex; align-items: flex-start; gap: 10px; margin-bottom: 14px; font-size: 13px; }
.confirm-row input { width: 17px; height: 17px; margin-top: 2px; accent-color: var(--danger); }
.raw-result { display: grid; gap: 5px; margin-top: 14px; padding: 13px; border: 1px solid #f3b8b2; border-radius: 10px; background: white; }
.raw-result span { color: var(--danger); font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: .05em; }
.raw-result code { font-size: 17px; overflow-wrap: anywhere; }
#reveal-status { margin-top: 10px; }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
@media (max-width: 820px) {
  .topbar, .notice { align-items: flex-start; flex-direction: column; }
  .metrics, .insights-grid { grid-template-columns: 1fr; }
  .toolbar { flex-wrap: wrap; }
  .muted { width: 100%; }
}
@media (max-width: 520px) {
  .topbar { padding: 20px; }
  .topbar-actions { align-items: flex-start; flex-direction: column; }
  main { width: min(100% - 24px, 1240px); margin-top: 18px; }
  .detail-list { grid-template-columns: 1fr; }
  .detail-list dt { margin-top: 7px; }
}`;

const PANEL_SCRIPT = `(function () {
  "use strict";
  var state = {
    visits: [],
    nextBefore: null,
    selected: null,
    hideTimer: null,
    revealController: null,
    revealGeneration: 0,
    rawExpiresAt: 0
  };
  var elements = {
    range: document.getElementById("range"),
    refresh: document.getElementById("refresh"),
    refreshedAt: document.getElementById("refreshed-at"),
    error: document.getElementById("error"),
    events: document.getElementById("events"),
    uniqueSources: document.getElementById("unique-sources"),
    retention: document.getElementById("retention"),
    countries: document.getElementById("countries"),
    cities: document.getElementById("cities"),
    asns: document.getElementById("asns"),
    visitsBody: document.getElementById("visits-body"),
    emptyState: document.getElementById("empty-state"),
    nextPage: document.getElementById("next-page"),
    dialog: document.getElementById("detail-dialog"),
    closeDialog: document.getElementById("close-dialog"),
    detailList: document.getElementById("detail-list"),
    revealConfirm: document.getElementById("reveal-confirm"),
    reveal: document.getElementById("reveal"),
    rawResult: document.getElementById("raw-result"),
    rawIp: document.getElementById("raw-ip"),
    revealStatus: document.getElementById("reveal-status")
  };

  function text(value, fallback) {
    return value === null || value === undefined || value === "" ? (fallback || "—") : String(value);
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function setError(message) {
    elements.error.textContent = message || "";
    elements.error.hidden = !message;
  }

  async function api(path, options) {
    var response = await fetch(path, Object.assign({
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    }, options || {}));
    var body;
    try { body = await response.json(); } catch (_error) { body = {}; }
    if (!response.ok) throw new Error(body.error || "请求失败（HTTP " + response.status + "）");
    return body;
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString();
  }

  function formatTime(value) {
    var date = new Date(Number(value));
    return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { hour12: false });
  }

  function renderRankList(node, rows, labelKey) {
    clear(node);
    (rows || []).slice(0, 5).forEach(function (row) {
      var item = document.createElement("li");
      var label = document.createElement("b");
      var count = document.createElement("span");
      label.textContent = text(row[labelKey], "Unknown");
      count.textContent = formatNumber(row.events);
      item.append(label, count);
      node.append(item);
    });
    if (!node.childNodes.length) {
      var empty = document.createElement("li");
      var label = document.createElement("b");
      label.textContent = "暂无数据";
      empty.append(label, document.createElement("span"));
      node.append(empty);
    }
  }

  function renderSummary(summary) {
    elements.events.textContent = formatNumber(summary.events);
    elements.uniqueSources.textContent = formatNumber(summary.unique_ip_hashes);
    elements.retention.textContent = formatNumber(summary.retention_days) + " 天";
    renderRankList(elements.countries, summary.countries, "country");
    renderRankList(elements.cities, summary.cities, "city");
    renderRankList(elements.asns, summary.asns, "asn");
  }

  function appendCell(row, value, code) {
    var cell = document.createElement("td");
    var content = code ? document.createElement("code") : document.createElement("span");
    content.textContent = text(value);
    cell.append(content);
    row.append(cell);
  }

  function renderVisits(data) {
    state.visits = Array.isArray(data.visits) ? data.visits : [];
    state.nextBefore = data.next_before || null;
    clear(elements.visitsBody);
    state.visits.forEach(function (visit) {
      var row = document.createElement("tr");
      appendCell(row, formatTime(visit.observed_at));
      appendCell(row, visit.ip_masked, true);
      appendCell(row, [visit.city, visit.region_code, visit.country_code].filter(Boolean).join(" / "));
      appendCell(row, visit.asn ? "AS" + visit.asn : "—");
      appendCell(row, visit.page_path, true);
      appendCell(row, visit.referrer_host);
      var actionCell = document.createElement("td");
      var button = document.createElement("button");
      button.type = "button";
      button.className = "record-button";
      button.textContent = "查看";
      button.setAttribute("data-event-id", visit.event_id);
      actionCell.append(button);
      row.append(actionCell);
      elements.visitsBody.append(row);
    });
    elements.emptyState.hidden = state.visits.length > 0;
    elements.nextPage.disabled = !state.nextBefore;
  }

  async function refresh(resetPage) {
    setError("");
    elements.refresh.disabled = true;
    elements.nextPage.disabled = true;
    try {
      var days = elements.range.value;
      var visitsPath = "/api/visits?limit=25";
      if (!resetPage && state.nextBefore) visitsPath += "&before=" + encodeURIComponent(state.nextBefore);
      var results = await Promise.all([api("/api/summary?days=" + encodeURIComponent(days)), api(visitsPath)]);
      renderSummary(results[0]);
      renderVisits(results[1]);
      elements.refreshedAt.textContent = "更新于 " + new Date().toLocaleTimeString([], { hour12: false });
    } catch (error) {
      setError(error.message || "无法加载管理数据");
    } finally {
      elements.refresh.disabled = false;
      elements.nextPage.disabled = !state.nextBefore;
    }
  }

  function addDetail(label, value, code) {
    var term = document.createElement("dt");
    var definition = document.createElement("dd");
    term.textContent = label;
    if (code) {
      var element = document.createElement("code");
      element.textContent = text(value);
      definition.append(element);
    } else {
      definition.textContent = text(value);
    }
    elements.detailList.append(term, definition);
  }

  function clearRawIp() {
    state.revealGeneration += 1;
    if (state.revealController) state.revealController.abort();
    state.revealController = null;
    if (state.hideTimer) window.clearTimeout(state.hideTimer);
    state.hideTimer = null;
    state.rawExpiresAt = 0;
    elements.rawIp.textContent = "";
    elements.rawResult.hidden = true;
    elements.revealStatus.textContent = "";
  }

  function openDetail(eventId) {
    var visit = state.visits.find(function (item) { return item.event_id === eventId; });
    if (!visit) return;
    state.selected = visit;
    clear(elements.detailList);
    clearRawIp();
    elements.revealConfirm.checked = false;
    elements.reveal.disabled = true;
    addDetail("访问时间", formatTime(visit.observed_at));
    addDetail("脱敏 IP", visit.ip_masked, true);
    addDetail("近似归属地", [visit.city, visit.region_code, visit.country_code].filter(Boolean).join(" / "));
    addDetail("ASN", visit.asn ? "AS" + visit.asn : "—");
    addDetail("页面", visit.page_path, true);
    addDetail("来源域名", visit.referrer_host);
    addDetail("记录到期", formatTime(visit.expires_at));
    elements.dialog.showModal();
  }

  async function revealRawIp() {
    if (!state.selected || !elements.revealConfirm.checked) return;
    clearRawIp();
    var eventId = state.selected.event_id;
    var generation = state.revealGeneration;
    var controller = new AbortController();
    state.revealController = controller;
    elements.reveal.disabled = true;
    elements.revealStatus.textContent = "正在安全读取…";
    try {
      var body = await api("/api/visits/" + encodeURIComponent(eventId) + "/reveal", {
        method: "POST",
        signal: controller.signal,
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "X-WJXSEC-Admin-Action": "reveal"
        },
        body: JSON.stringify({ confirm: "REVEAL" })
      });
      if (
        controller.signal.aborted ||
        generation !== state.revealGeneration ||
        !elements.dialog.open ||
        !elements.revealConfirm.checked ||
        !state.selected ||
        state.selected.event_id !== eventId
      ) return;
      elements.rawIp.textContent = text(body.ip_address, "不可用");
      elements.rawResult.hidden = false;
      elements.revealStatus.textContent = "已记录本次查看操作。";
      state.rawExpiresAt = Date.now() + 30000;
      state.hideTimer = window.setTimeout(function () {
        clearRawIp();
        elements.revealStatus.textContent = "完整 IP 已自动隐藏。";
      }, 30000);
    } catch (error) {
      if (controller.signal.aborted) return;
      elements.revealStatus.textContent = error.message || "无法读取完整 IP";
    } finally {
      if (state.revealController === controller) state.revealController = null;
      if (generation === state.revealGeneration) {
        elements.reveal.disabled = !elements.revealConfirm.checked;
      }
    }
  }

  elements.refresh.addEventListener("click", function () { refresh(true); });
  elements.range.addEventListener("change", function () { refresh(true); });
  elements.nextPage.addEventListener("click", function () { refresh(false); });
  elements.visitsBody.addEventListener("click", function (event) {
    var button = event.target.closest("button[data-event-id]");
    if (button) openDetail(button.getAttribute("data-event-id"));
  });
  elements.revealConfirm.addEventListener("change", function () {
    elements.reveal.disabled = !elements.revealConfirm.checked;
    if (!elements.revealConfirm.checked) clearRawIp();
  });
  elements.reveal.addEventListener("click", revealRawIp);
  elements.closeDialog.addEventListener("click", function () { elements.dialog.close(); });
  elements.dialog.addEventListener("close", function () {
    state.selected = null;
    clearRawIp();
  });
  document.addEventListener("visibilitychange", function () {
    if (document.hidden || (state.rawExpiresAt && Date.now() >= state.rawExpiresAt)) clearRawIp();
  });
  window.addEventListener("pagehide", clearRawIp);

  refresh(true);
}());`;
