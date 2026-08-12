# Raw-IP visitor collector

This Cloudflare Worker accepts a minimal visit event from
`https://wjxsec.github.io`, obtains the network source IP from Cloudflare's
request metadata, encrypts that raw IP with AES-GCM, and stores it in D1. The
application can return a record for **no more than 90 days**.

For each accepted event, it stores the encrypted IP and IP-derived country,
region code, city, ASN, page path, and referring hostname. It also stores a
separate keyed one-way IP digest only for aggregate unique-source counts. It
does not store cookies, URL query strings, URL fragments, page content, form
data, user-agent strings, or a client-supplied IP/location value. Only the raw
IP is encrypted; the listed analysis metadata remains queryable in D1.

The browser and the Worker both honor Do Not Track and Global Privacy Control.
The normal administrator list masks addresses; viewing one full address needs a
separate confirmed request and creates a short-lived audit record.

## Important scope

This is a cross-origin `workers.dev` access-sampling endpoint. CORS stops a
normal browser on another origin, but it cannot prevent a script or curl from
forging an `Origin` header. The Worker rate-limits writes before it reads a
request body, but that is mitigation rather than proof that an event was a real
homepage view. Do not treat this deployment as a complete or authoritative
request log. For trustworthy coverage, put a domain you control in front of the
site with a Worker as the request front door.

## Deploy

Use a Cloudflare account that owns the Worker. Never put account API tokens,
the administrator token, or encryption keys in Git or browser code. Wrangler
4.36.0 or newer is required for the Worker rate-limit bindings.

1. In the Cloudflare dashboard, set the account's `workers.dev` subdomain.
   Authenticate Wrangler on a trusted machine:

   ```sh
   npx wrangler login
   ```

2. Create the D1 database, then copy its returned `database_id` into
   `wrangler.jsonc`. The checked-in ID belongs to the current deployment and
   must be replaced when deploying in another Cloudflare account.

   ```sh
   npx wrangler d1 create wjxsec-visitor-analytics
   ```

   Before deploying, replace the two `namespace_id` values in
   `wrangler.jsonc` if either one is already used by another Worker in the same
   Cloudflare account. They must be distinct positive integers within that
   account.

3. Apply the versioned database migration to the remote D1 database:

   ```sh
   npx wrangler d1 migrations apply wjxsec-visitor-analytics --remote
   ```

4. Set the four secrets. Generate long random values and keep them outside
   Git:

   ```sh
   npx wrangler secret put IP_ENCRYPTION_KEY
   npx wrangler secret put IP_HMAC_KEY
   npx wrangler secret put ADMIN_TOKEN
   npx wrangler secret put PANEL_HMAC_KEY
   ```

   `IP_ENCRYPTION_KEY` must be a base64-encoded 32-byte AES key. For example,
   on a trusted machine: `openssl rand -base64 32`. `IP_HMAC_KEY` is a separate
   high-entropy secret for unique-source aggregation. `ADMIN_TOKEN` protects
   the fixed administrator API. `PANEL_HMAC_KEY` is shared only with the
   private admin Worker and authenticates its signed internal requests.

5. Deploy the Worker:

   ```sh
   npx wrangler deploy
   ```

6. Verify the public collector returns `204` for a normal test visit, then put
   its HTTPS URL with the `/v1/visit` suffix into
   `../assets/js/analytics-config.js` and publish the static homepage:

   ```js
   visitorCollectorUrl: "https://wjxsec-visitor-collector.<account-subdomain>.workers.dev/v1/visit"
   ```

The current deployment already has this public collector URL configured. Clear
the value before publishing if the Worker or its storage protections are not
available.

## Retention and key handling

The Worker and the database schema both cap a normal event's expiry at 90 days.
The administrator API filters out expired records immediately, and an hourly
UTC job deletes expired event and audit rows. A raw-IP reveal audit row expires
no later than the event it references.

Cloudflare D1 Time Travel can retain a Cloudflare service-level recovery
snapshot after application deletion (up to 7 days on Free or 30 days on paid
plans). It is not accessible through this site, but it means this design cannot
promise a strict physical-deletion deadline of exactly 90 days.

`IP_ENCRYPTION_KEY_VERSION` is `v1` initially. The Worker supports one previous
key through `IP_ENCRYPTION_KEY_PREVIOUS` and
`IP_ENCRYPTION_KEY_PREVIOUS_VERSION`. Keep the old key available until all
records carrying its version have expired; otherwise the site will safely show
their IP as unavailable rather than exposing it.

## Private administration

The administrator endpoints intentionally have no CORS headers. Aggregate and
masked-list endpoints can be used from a private terminal for emergency
diagnostics. Keep the bearer token out of URLs and shell history when practical,
and rotate it immediately if exposed.

The normal web control plane is the separate `analytics-admin/` Worker. It is
protected by Cloudflare Access, validates the Access JWT again inside the
Worker, and calls this collector's fixed production HTTPS endpoint with
server-only credentials. The browser never receives a bearer token. Full-IP
reveal is deliberately restricted to a signed request from that private panel,
so a bearer token alone cannot reveal it.

```sh
curl -H "Authorization: Bearer $ANALYTICS_ADMIN_TOKEN" \
  "https://<worker>.workers.dev/v1/admin/summary?days=30"

curl -H "Authorization: Bearer $ANALYTICS_ADMIN_TOKEN" \
  "https://<worker>.workers.dev/v1/admin/visits?limit=50"
```

The summary returns aggregate event, unique-source, country, region, city, and
ASN counts. The visits endpoint returns metadata plus masked IPs in pages of at
most 50 rows; pass the returned `next_before` value as `before` for the next
page. Use the Access-protected panel to reveal exactly one full IP and record
the associated audit event.

## Synthetic test records

Records with a `/__test__/` path, `synthetic-test.invalid` referrer, and
`synthetic-v1` key version are clearly marked test fixtures made from the
documentation address ranges `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, and `2001:db8::/32`. Their test key is intentionally public;
it is accepted only when all synthetic markers match and is never used for a
normal visit. The panel reports how many aggregate events and unique sources
are synthetic, and prefixes each test path with `[TEST]`. Geography and ASN
rankings deliberately include these clearly labeled fixtures during the
90-day test window. Production visitor IPs continue to use the private Worker
secret.

The four fixtures in the current production D1 database were inserted once for
this live demonstration. They are not a migration and will not be recreated
when the database is rebuilt; they expire normally after 90 days.

## Local verification

No package install is required for the included tests when Node.js is present:

```sh
npm test
```
