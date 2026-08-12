import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { webcrypto } from "node:crypto";
import { ReadableStream } from "node:stream/web";
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

const {
  default: worker,
  decryptIp,
  encryptIp,
  hmacIp,
  maskIp,
  pruneExpired,
  SYNTHETIC_KEY_VERSION,
  SYNTHETIC_TEST_KEY_BASE64
} = await import("../src/index.js");
const encoder = new TextEncoder();

class FakeStatement {
  constructor(database, query) {
    this.database = database;
    this.query = query;
    this.values = [];
  }

  bind(...values) {
    this.values = values;
    return this;
  }

  async run() {
    this.database.runs.push({ query: this.query, values: this.values });
    return { success: true };
  }

  async all() {
    this.database.queries.push({ query: this.query, values: this.values });
    return { results: this.database.resultSets.shift() || [] };
  }
}

class FakeDatabase {
  constructor() {
    this.runs = [];
    this.queries = [];
    this.resultSets = [];
  }

  prepare(query) {
    return new FakeStatement(this, query);
  }
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

function makeEnvironment(database, options = {}) {
  return {
    DB: database,
    IP_ENCRYPTION_KEY: options.encryptionKey || Buffer.alloc(32, 7).toString("base64"),
    IP_HMAC_KEY: "test-ip-hmac-secret",
    ADMIN_TOKEN: "test-admin-token",
    PANEL_HMAC_KEY: "test-panel-hmac-key-that-is-long-enough-for-authentication",
    ALLOWED_ORIGIN: "https://wjxsec.github.io",
    RETENTION_DAYS: "90",
    IP_ENCRYPTION_KEY_VERSION: options.keyVersion || "v1",
    IP_ENCRYPTION_KEY_PREVIOUS_VERSION: options.previousKeyVersion || "",
    IP_ENCRYPTION_KEY_PREVIOUS: options.previousEncryptionKey || "",
    VISIT_RATE_LIMITER: options.visitLimiter || makeLimiter(),
    ADMIN_RATE_LIMITER: options.adminLimiter || makeLimiter()
  };
}

function readableText(text, chunkSize = text.length || 1) {
  const bytes = encoder.encode(text);
  return new ReadableStream({
    start(controller) {
      for (let offset = 0; offset < bytes.byteLength; offset += chunkSize) {
        controller.enqueue(bytes.slice(offset, offset + chunkSize));
      }
      controller.close();
    }
  });
}

function makeRequest({
  method = "POST",
  origin = "https://wjxsec.github.io",
  body = { path: "/privacy.html", referrerHost: "example.org" },
  rawBody,
  chunkSize,
  cf = { country: "CN", regionCode: "SN", city: "Xi'an", asn: 4134 },
  headers = {}
} = {}) {
  const bodyText = rawBody ?? JSON.stringify(body);
  const requestHeaders = new Headers({
    Origin: origin,
    "Content-Type": "text/plain;charset=UTF-8",
    "CF-Connecting-IP": "203.0.113.27",
    ...headers
  });
  return {
    url: "https://wjxsec-visitor-collector.example.workers.dev/v1/visit",
    method,
    headers: requestHeaders,
    cf,
    body: readableText(bodyText, chunkSize),
    text: async () => bodyText
  };
}

function makeAdminRequest(path, headers = {}) {
  return {
    url: `https://worker.example${path}`,
    method: "GET",
    headers: new Headers({
      Authorization: "Bearer test-admin-token",
      "CF-Connecting-IP": "203.0.113.27",
      ...headers
    })
  };
}

test("the collector encrypts the Cloudflare source IP and stores only sanitized metadata", async () => {
  const database = new FakeDatabase();
  const env = makeEnvironment(database);
  const response = await worker.fetch(
    makeRequest({
      body: {
        path: "/research?private=value#section",
        referrerHost: "referrer.example",
        ipAddress: "198.51.100.2"
      },
      headers: { "X-Forwarded-For": "198.51.100.55" }
    }),
    env
  );

  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "https://wjxsec.github.io");
  assert.deepEqual(env.VISIT_RATE_LIMITER.calls, [{ key: "visit:203.0.113.27" }]);
  const insert = database.runs.find((entry) => entry.query.includes("INSERT INTO visitor_events"));
  assert.ok(insert);

  const [eventId, observedAt, expiresAt, ciphertext, iv, keyVersion, hmac, country, region, city, asn, pagePath, referrerHost] = insert.values;
  assert.notEqual(ciphertext, "203.0.113.27");
  assert.notEqual(hmac, "203.0.113.27");
  assert.equal(keyVersion, "v1");
  assert.equal(country, "CN");
  assert.equal(region, "SN");
  assert.equal(city, "Xi'an");
  assert.equal(asn, 4134);
  assert.equal(pagePath, "/research");
  assert.equal(referrerHost, "referrer.example");
  assert.equal(expiresAt - observedAt, 90 * 24 * 60 * 60 * 1000);
  assert.equal(
    await decryptIp(ciphertext, iv, env.IP_ENCRYPTION_KEY, `${eventId}:${observedAt}:${expiresAt}`),
    "203.0.113.27"
  );
  assert.equal(database.runs.filter((entry) => entry.query.startsWith("DELETE FROM")).length, 0);
});

test("the collector honors privacy signals and rejects abusive or invalid requests before storage", async () => {
  const privacyDatabase = new FakeDatabase();
  const privacyEnv = makeEnvironment(privacyDatabase);
  const dntResponse = await worker.fetch(makeRequest({ headers: { DNT: "1" } }), privacyEnv);
  assert.equal(dntResponse.status, 204);
  assert.equal(privacyDatabase.runs.length, 0);
  assert.equal(privacyEnv.VISIT_RATE_LIMITER.calls.length, 0);

  const database = new FakeDatabase();
  const env = makeEnvironment(database);
  const forbidden = await worker.fetch(makeRequest({ origin: "https://attacker.example" }), env);
  assert.equal(forbidden.status, 403);

  const methodNotAllowed = await worker.fetch(makeRequest({ method: "GET" }), env);
  assert.equal(methodNotAllowed.status, 405);

  const unavailable = await worker.fetch(makeRequest({ headers: { "CF-Connecting-IP": "" } }), env);
  assert.equal(unavailable.status, 400);

  const malformed = await worker.fetch(makeRequest({ headers: { "CF-Connecting-IP": "999.0.0.1" } }), env);
  assert.equal(malformed.status, 400);

  const largeBody = await worker.fetch(makeRequest({ rawBody: JSON.stringify({ path: `/${"x".repeat(2000)}` }), chunkSize: 16 }), env);
  assert.equal(largeBody.status, 413);
  assert.equal(database.runs.length, 0);

  const rateLimitedDatabase = new FakeDatabase();
  const rateLimitedEnv = makeEnvironment(rateLimitedDatabase, { visitLimiter: makeLimiter(false) });
  const rateLimited = await worker.fetch(makeRequest(), rateLimitedEnv);
  assert.equal(rateLimited.status, 429);
  assert.equal(rateLimitedDatabase.runs.length, 0);
});

test("admin list masks IPs, raw detail requires confirmation, and audit expiry never exceeds the source record", async () => {
  const database = new FakeDatabase();
  const env = makeEnvironment(database);
  const now = Date.now();
  const record = {
    id: 9,
    event_id: "123e4567-e89b-42d3-a456-426614174000",
    observed_at: now - 1000,
    expires_at: now + 1000,
    encryption_key_version: "v1",
    country_code: "CN",
    region_code: "SN",
    city: "Xi'an",
    asn: 4134,
    page_path: "/",
    referrer_host: null
  };
  const encrypted = await encryptIp(
    "203.0.113.27",
    env.IP_ENCRYPTION_KEY,
    `${record.event_id}:${record.observed_at}:${record.expires_at}`
  );
  record.ip_ciphertext = encrypted.ciphertext;
  record.ip_iv = encrypted.iv;

  database.resultSets.push([record]);
  const listResponse = await worker.fetch(makeAdminRequest("/v1/admin/visits?limit=1"), env);
  const listBody = await listResponse.json();
  assert.equal(listResponse.status, 200);
  assert.equal(listResponse.headers.get("Access-Control-Allow-Origin"), null);
  assert.equal(listBody.visits[0].ip_masked, "203.0.113.0");
  assert.equal("ip_address" in listBody.visits[0], false);

  const unconfirmed = await worker.fetch(makeAdminRequest(`/v1/admin/visits/${record.event_id}`), env);
  assert.equal(unconfirmed.status, 428);

  const bearerOnly = await worker.fetch(
    makeAdminRequest(`/v1/admin/visits/${record.event_id}`, { "X-Confirm-Raw-IP": "yes" }),
    env
  );
  assert.equal(bearerOnly.status, 403);

  const actorHash = "a".repeat(64);
  const actorTimestamp = Math.floor(Date.now() / 1000);
  const actorSignature = await hmacIp(
    `/v1/admin/visits/${record.event_id}:${actorHash}:${actorTimestamp}`,
    env.PANEL_HMAC_KEY
  );

  const badSignature = await worker.fetch(
    makeAdminRequest(`/v1/admin/visits/${record.event_id}`, {
      "X-Confirm-Raw-IP": "yes",
      "X-Admin-Actor-Hash": actorHash,
      "X-Admin-Actor-Timestamp": String(actorTimestamp),
      "X-Admin-Actor-Signature": "0".repeat(64)
    }),
    env
  );
  assert.equal(badSignature.status, 403);

  const expiredTimestamp = actorTimestamp - 121;
  const expiredSignature = await hmacIp(
    `/v1/admin/visits/${record.event_id}:${actorHash}:${expiredTimestamp}`,
    env.PANEL_HMAC_KEY
  );
  const expiredAttestation = await worker.fetch(
    makeAdminRequest(`/v1/admin/visits/${record.event_id}`, {
      "X-Confirm-Raw-IP": "yes",
      "X-Admin-Actor-Hash": actorHash,
      "X-Admin-Actor-Timestamp": String(expiredTimestamp),
      "X-Admin-Actor-Signature": expiredSignature
    }),
    env
  );
  assert.equal(expiredAttestation.status, 403);

  const otherPathSignature = await hmacIp(
    `/v1/admin/summary?days=30:${actorHash}:${actorTimestamp}`,
    env.PANEL_HMAC_KEY
  );
  const crossPathReplay = await worker.fetch(
    makeAdminRequest(`/v1/admin/visits/${record.event_id}`, {
      "X-Confirm-Raw-IP": "yes",
      "X-Admin-Actor-Hash": actorHash,
      "X-Admin-Actor-Timestamp": String(actorTimestamp),
      "X-Admin-Actor-Signature": otherPathSignature
    }),
    env
  );
  assert.equal(crossPathReplay.status, 403);

  database.resultSets.push([record]);
  const detailResponse = await worker.fetch(
    makeAdminRequest(`/v1/admin/visits/${record.event_id}`, {
      "X-Confirm-Raw-IP": "yes",
      "X-Admin-Actor-Hash": actorHash,
      "X-Admin-Actor-Timestamp": String(actorTimestamp),
      "X-Admin-Actor-Signature": actorSignature
    }),
    env
  );
  assert.equal(detailResponse.status, 200);
  assert.equal((await detailResponse.json()).ip_address, "203.0.113.27");
  const audit = database.runs.find((entry) => entry.query.includes("INSERT INTO admin_audit"));
  assert.ok(audit);
  assert.equal(audit.values[1], record.expires_at);
  assert.equal(audit.values[5], actorHash);
  assert.equal(audit.values[6], "cloudflare_access");
});

test("explicitly marked synthetic records use only the public test key", async () => {
  const database = new FakeDatabase();
  const env = makeEnvironment(database, { encryptionKey: Buffer.alloc(32, 9).toString("base64") });
  const now = Date.now();
  const record = {
    id: 10,
    event_id: "0279fbe1-73db-4c4d-aedf-000000000101",
    observed_at: now - 1000,
    expires_at: now - 1000 + 90 * 24 * 60 * 60 * 1000,
    encryption_key_version: SYNTHETIC_KEY_VERSION,
    country_code: "JP",
    region_code: "TEST-13",
    city: "TEST · Tokyo",
    asn: 64512,
    page_path: "/__test__/tokyo",
    referrer_host: "synthetic-test.invalid"
  };
  const encrypted = await encryptIp(
    "192.0.2.17",
    SYNTHETIC_TEST_KEY_BASE64,
    `${record.event_id}:${record.observed_at}:${record.expires_at}`
  );
  record.ip_ciphertext = encrypted.ciphertext;
  record.ip_iv = encrypted.iv;

  database.resultSets.push([record]);
  const response = await worker.fetch(makeAdminRequest("/v1/admin/visits?limit=1"), env);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.visits[0].ip_masked, "192.0.2.0");
  assert.equal(body.visits[0].synthetic, true);

  record.page_path = "/";
  database.resultSets.push([record]);
  const rejected = await worker.fetch(makeAdminRequest("/v1/admin/visits?limit=1"), env);
  assert.equal((await rejected.json()).visits[0].ip_masked, "unavailable");
});

test("the summary includes aggregated geography and ASN without returning raw IPs", async () => {
  const database = new FakeDatabase();
  const env = makeEnvironment(database);
  database.resultSets.push(
    [{ events: 3, unique_ip_hashes: 2, synthetic_events: 1, synthetic_unique_ip_hashes: 1 }],
    [{ country: "CN", events: 3 }],
    [{ region: "SN", events: 3 }],
    [{ city: "Xi'an", events: 3 }],
    [{ asn: 4134, events: 3 }]
  );

  const response = await worker.fetch(makeAdminRequest("/v1/admin/summary?days=30"), env);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.events, 3);
  assert.equal(body.unique_ip_hashes, 2);
  assert.equal(body.synthetic_events, 1);
  assert.equal(body.synthetic_unique_ip_hashes, 1);
  assert.deepEqual(body.cities, [{ city: "Xi'an", events: 3 }]);
  const totalsQuery = database.queries[0].query;
  assert.match(totalsQuery, /encryption_key_version = 'synthetic-v1'/);
  assert.match(totalsQuery, /page_path GLOB '\/__test__\/\*'/);
  assert.match(totalsQuery, /referrer_host = 'synthetic-test\.invalid'/);
  assert.deepEqual(body.asns, [{ asn: 4134, events: 3 }]);
  assert.equal("ip_address" in body, false);
});

test("key rotation retains access to records encrypted with the configured previous key", async () => {
  const database = new FakeDatabase();
  const oldKey = Buffer.alloc(32, 5).toString("base64");
  const newKey = Buffer.alloc(32, 6).toString("base64");
  const env = makeEnvironment(database, {
    encryptionKey: newKey,
    keyVersion: "v2",
    previousEncryptionKey: oldKey,
    previousKeyVersion: "v1"
  });
  const now = Date.now();
  const record = {
    id: 10,
    event_id: "123e4567-e89b-42d3-a456-426614174001",
    observed_at: now - 1000,
    expires_at: now + 1000,
    encryption_key_version: "v1",
    country_code: "US",
    region_code: "CA",
    city: "San Francisco",
    asn: 123,
    page_path: "/",
    referrer_host: null
  };
  const encrypted = await encryptIp(
    "2001:db8::1",
    oldKey,
    `${record.event_id}:${record.observed_at}:${record.expires_at}`
  );
  record.ip_ciphertext = encrypted.ciphertext;
  record.ip_iv = encrypted.iv;
  database.resultSets.push([record]);

  const response = await worker.fetch(makeAdminRequest("/v1/admin/visits?limit=1"), env);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).visits[0].ip_masked, "IPv6 (masked)");
});

test("encryption binds the IP to record metadata and expiry pruning covers events and audit records", async () => {
  const key = Buffer.alloc(32, 3).toString("base64");
  const encrypted = await encryptIp("2001:db8::1", key, "event-2:100:200");
  await assert.rejects(() => decryptIp(encrypted.ciphertext, encrypted.iv, key, "event-2:100:201"));
  assert.equal(maskIp("203.0.113.27"), "203.0.113.0");
  assert.equal(maskIp("::1"), "IPv6 (masked)");

  const database = new FakeDatabase();
  await pruneExpired(database, 12345);
  assert.equal(database.runs.length, 2);
  assert.equal(database.runs.every((entry) => entry.values[0] === 12345), true);
});
