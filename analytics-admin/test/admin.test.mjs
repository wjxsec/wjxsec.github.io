import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import test from "node:test";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}
if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}

const { clearJwksCacheForTests, handleRequest, verifyAccessJwt } = await import("../src/index.js");
const encoder = new TextEncoder();
const teamDomain = "wjxsec-test.cloudflareaccess.com";
const audience = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const origin = "https://wjxsec-visitor-admin.example.workers.dev";
const collectorToken = "collector-secret-not-for-the-browser";
const panelHmacKey = "panel-channel-hmac-secret-that-is-at-least-thirty-two-characters";

const keyPair = await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  },
  true,
  ["sign", "verify"]
);
const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
publicJwk.kid = "test-access-key";
publicJwk.alg = "RS256";
publicJwk.use = "sig";

function base64Url(value) {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return Buffer.from(bytes).toString("base64url");
}

async function makeToken(overrides = {}, headerOverrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: publicJwk.kid, ...headerOverrides };
  const payload = {
    iss: `https://${teamDomain}`,
    aud: [audience],
    sub: "access-user-123",
    email: "owner@example.com",
    exp: now + 600,
    iat: now,
    ...overrides
  };
  const signingInput = `${base64Url(JSON.stringify(header))}.${base64Url(JSON.stringify(payload))}`;
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    keyPair.privateKey,
    encoder.encode(signingInput)
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}

function makeJwksFetch() {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return new Response(JSON.stringify({ keys: [publicJwk] }), {
      headers: { "Content-Type": "application/json" }
    });
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

function makeLimiter(success = true) {
  return {
    calls: [],
    async limit(input) {
      this.calls.push(input);
      return { success };
    }
  };
}

function makeEnvironment(collector) {
  return {
    ACCESS_TEAM_DOMAIN: teamDomain,
    ACCESS_AUD: audience,
    ACCESS_ALLOWED_EMAIL: "owner@example.com",
    ADMIN_AUDIT_HMAC_KEY: "audit-hmac-secret-that-is-at-least-thirty-two-characters",
    PANEL_ORIGIN: origin,
    COLLECTOR_ADMIN_TOKEN: collectorToken,
    COLLECTOR_PANEL_HMAC_KEY: panelHmacKey,
    COLLECTOR: collector,
    PANEL_RATE_LIMITER: makeLimiter()
  };
}

async function makeAccessRequest(path, options = {}) {
  const token = options.token || await makeToken();
  const headers = new Headers(options.headers || {});
  headers.set("CF-Connecting-IP", "203.0.113.27");
  if (!options.noToken) {
    headers.set("Cf-Access-Jwt-Assertion", token);
  }
  return new Request(`${origin}${path}`, {
    method: options.method || "GET",
    headers,
    body: options.body
  });
}

test("Access JWT verification checks signature, issuer, audience, and expiry", async () => {
  clearJwksCacheForTests();
  const jwksFetch = makeJwksFetch();
  const token = await makeToken();
  const payload = await verifyAccessJwt(token, { teamDomain, audience, fetchImpl: jwksFetch });
  assert.equal(payload.sub, "access-user-123");
  assert.deepEqual(jwksFetch.calls, [`https://${teamDomain}/cdn-cgi/access/certs`]);

  const wrongAudience = await makeToken({ aud: ["wrong-audience"] });
  await assert.rejects(() => verifyAccessJwt(
    wrongAudience,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));
  const wrongIssuer = await makeToken({ iss: "https://attacker.cloudflareaccess.com" });
  await assert.rejects(() => verifyAccessJwt(
    wrongIssuer,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));
  const expired = await makeToken({ exp: Math.floor(Date.now() / 1000) - 120 });
  await assert.rejects(() => verifyAccessJwt(
    expired,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));
  const notYetActive = await makeToken({ nbf: Math.floor(Date.now() / 1000) + 300 });
  await assert.rejects(() => verifyAccessJwt(
    notYetActive,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));

  const segments = token.split(".");
  segments[2] = `${segments[2][0] === "A" ? "B" : "A"}${segments[2].slice(1)}`;
  await assert.rejects(() => verifyAccessJwt(
    segments.join("."),
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));

  const unknownKid = await makeToken({}, { kid: "unknown-key-1" });
  const anotherUnknownKid = await makeToken({}, { kid: "unknown-key-2" });
  await assert.rejects(() => verifyAccessJwt(
    unknownKid,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));
  await assert.rejects(() => verifyAccessJwt(
    anotherUnknownKid,
    { teamDomain, audience, fetchImpl: jwksFetch }
  ));
  assert.equal(jwksFetch.calls.length, 2, "unknown kid refreshes JWKS at most once per cache TTL");
});

test("the private panel requires Access and ships no browser-side administrator secret", async () => {
  clearJwksCacheForTests();
  const collector = { fetch: async () => new Response("{}") };
  const env = makeEnvironment(collector);
  const jwksFetch = makeJwksFetch();

  const unauthenticated = await handleRequest(await makeAccessRequest("/", { noToken: true }), env, jwksFetch);
  assert.equal(unauthenticated.status, 401);

  const page = await handleRequest(await makeAccessRequest("/"), env, jwksFetch);
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.match(page.headers.get("Content-Security-Policy"), /default-src 'none'/);
  assert.equal(page.headers.get("Cache-Control"), "private, no-store, max-age=0");
  assert.equal(page.headers.get("Access-Control-Allow-Origin"), null);
  assert.doesNotMatch(html, /ADMIN_TOKEN|collector-secret|Authorization\s*:/i);

  const script = await handleRequest(await makeAccessRequest("/assets/admin.js"), env, jwksFetch);
  const javascript = await script.text();
  assert.doesNotMatch(javascript, /collector-secret|Bearer\s|localStorage|sessionStorage|console\./i);
  assert.match(javascript, /X-WJXSEC-Admin-Action/);
});

test("summary and list APIs only proxy fixed server-side requests with the secret", async () => {
  clearJwksCacheForTests();
  const requests = [];
  const collector = {
    async fetch(request) {
      requests.push(request);
      const path = new URL(request.url).pathname;
      const body = path.endsWith("summary")
        ? { events: 2, unique_ip_hashes: 1, retention_days: 90, countries: [], cities: [], asns: [] }
        : { visits: [], next_before: null, retention_days: 90 };
      return new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json" } });
    }
  };
  const env = makeEnvironment(collector);
  const jwksFetch = makeJwksFetch();

  const summary = await handleRequest(await makeAccessRequest("/api/summary?days=999&ignored=secret"), env, jwksFetch);
  assert.equal(summary.status, 200);
  assert.equal(new URL(requests[0].url).pathname + new URL(requests[0].url).search, "/v1/admin/summary?days=90");
  assert.equal(requests[0].headers.get("Authorization"), `Bearer ${collectorToken}`);
  assert.match(requests[0].headers.get("X-Admin-Actor-Hash"), /^[0-9a-f]{64}$/);
  assert.match(requests[0].headers.get("X-Admin-Actor-Signature"), /^[0-9a-f]{64}$/);
  assert.equal(requests[0].headers.get("Cookie"), null);

  const visits = await handleRequest(await makeAccessRequest("/api/visits?limit=500&before=42&url=https://attacker.example"), env, jwksFetch);
  assert.equal(visits.status, 200);
  assert.equal(new URL(requests[1].url).pathname + new URL(requests[1].url).search, "/v1/admin/visits?limit=50&before=42");
});

test("raw IP reveal is POST-only, same-origin, explicitly confirmed, and actor-audited", async () => {
  clearJwksCacheForTests();
  const eventId = "123e4567-e89b-42d3-a456-426614174000";
  const requests = [];
  const collector = {
    async fetch(request) {
      requests.push(request);
      return new Response(JSON.stringify({ event_id: eventId, ip_address: "203.0.113.27" }), {
        headers: { "Content-Type": "application/json" }
      });
    }
  };
  const env = makeEnvironment(collector);
  const jwksFetch = makeJwksFetch();

  const getAttempt = await handleRequest(await makeAccessRequest(`/api/visits/${eventId}/reveal`), env, jwksFetch);
  assert.equal(getAttempt.status, 405);

  const crossOrigin = await handleRequest(await makeAccessRequest(`/api/visits/${eventId}/reveal`, {
    method: "POST",
    headers: {
      Origin: "https://attacker.example",
      "Sec-Fetch-Site": "cross-site",
      "X-WJXSEC-Admin-Action": "reveal",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ confirm: "REVEAL" })
  }), env, jwksFetch);
  assert.equal(crossOrigin.status, 403);
  assert.equal(env.PANEL_RATE_LIMITER.calls.some((call) => String(call.key).startsWith("reveal:")), false);

  const unconfirmed = await handleRequest(await makeAccessRequest(`/api/visits/${eventId}/reveal`, {
    method: "POST",
    headers: {
      Origin: origin,
      "Sec-Fetch-Site": "same-origin",
      "X-WJXSEC-Admin-Action": "reveal",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ confirm: "NO" })
  }), env, jwksFetch);
  assert.equal(unconfirmed.status, 428);

  const revealed = await handleRequest(await makeAccessRequest(`/api/visits/${eventId}/reveal`, {
    method: "POST",
    headers: {
      Origin: origin,
      "Sec-Fetch-Site": "same-origin",
      "X-WJXSEC-Admin-Action": "reveal",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ confirm: "REVEAL" })
  }), env, jwksFetch);
  assert.equal(revealed.status, 200);
  assert.equal((await revealed.json()).ip_address, "203.0.113.27");
  const upstream = requests[0];
  assert.equal(upstream.headers.get("X-Confirm-Raw-IP"), "yes");
  assert.match(upstream.headers.get("X-Admin-Actor-Hash"), /^[0-9a-f]{64}$/);
  assert.match(upstream.headers.get("X-Admin-Actor-Timestamp"), /^\d{10}$/);
  assert.match(upstream.headers.get("X-Admin-Actor-Signature"), /^[0-9a-f]{64}$/);
  assert.equal(upstream.headers.get("Authorization"), `Bearer ${collectorToken}`);
});

test("unknown routes never become an open management proxy", async () => {
  clearJwksCacheForTests();
  let calls = 0;
  const env = makeEnvironment({ fetch: async () => { calls += 1; return new Response("{}"); } });
  const response = await handleRequest(await makeAccessRequest("/api/proxy?url=https://attacker.example"), env, makeJwksFetch());
  assert.equal(response.status, 404);
  assert.equal(calls, 0);
});
