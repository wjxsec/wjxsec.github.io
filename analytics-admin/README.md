# Private visitor administration panel

This Worker serves a same-origin administration UI and fixed `/api/*` routes.
The browser never receives the collector bearer token, D1 binding, or IP
encryption key. Cloudflare Access protects the entire admin Worker, while the
existing collector Worker remains public for `POST /v1/visit`.

## Security boundary

- Enable Cloudflare Access on **this admin Worker only**. Enabling it on the
  collector would also block the public visit endpoint.
- Use an Access Allow policy restricted to the site owner's exact identity and
  select a short session duration. Prefer an MFA-capable identity provider if
  one is configured; the current deployment uses Cloudflare's email one-time
  PIN for the exact allowed address.
- The Worker verifies `Cf-Access-Jwt-Assertion` with the Access team's remote
  JWKS, expected issuer, and application audience. Access must be enabled before
  the panel is considered private.
- The normal list contains only masked IPs. A full IP requires a same-origin
  `POST`, an explicit confirmation, and creates an audit row.
- The panel contains no third-party scripts, analytics, local storage, raw-IP
  URL parameters, or CORS response headers. All responses are `no-store`.

## Deploy

The service binding targets the existing `wjxsec-visitor-collector` Worker.
The rate-limit namespace must remain unique within the Cloudflare account.

After the Access application exists, set these six values as Worker secrets;
never commit them:

```sh
npx wrangler secret put ACCESS_TEAM_DOMAIN
npx wrangler secret put ACCESS_AUD
npx wrangler secret put ACCESS_ALLOWED_EMAIL
npx wrangler secret put COLLECTOR_ADMIN_TOKEN
npx wrangler secret put COLLECTOR_PANEL_HMAC_KEY
npx wrangler secret put ADMIN_AUDIT_HMAC_KEY
```

`ACCESS_TEAM_DOMAIN` is the team's `<name>.cloudflareaccess.com` hostname or
HTTPS origin.
`ACCESS_AUD` is the audience tag shown in the Access application settings.
`ACCESS_ALLOWED_EMAIL` is the single normalized Access identity allowed by the
Worker as a defense-in-depth check beyond the Access policy.
`COLLECTOR_ADMIN_TOKEN` must equal the collector Worker's `ADMIN_TOKEN` secret.
`COLLECTOR_PANEL_HMAC_KEY` must equal the collector Worker's `PANEL_HMAC_KEY`
secret; it authenticates the Access actor attestation for raw-IP reveals.
`ADMIN_AUDIT_HMAC_KEY` is an independent random value of at least 32 characters.

Bootstrap the Worker, then enable Access for the production `workers.dev`
route. Run commands from this `analytics-admin` directory (or pass its config
explicitly):

```sh
npx wrangler deploy
```

In Cloudflare: Workers & Pages -> `wjxsec-visitor-admin` -> Domains -> change
the production Worker URL from **Public** to **Restricted**. Configure the
generated Access policy to allow only the intended identity and use a short
session. Prefer an MFA-capable identity provider when available.
Copy the resulting audience tag into the `ACCESS_AUD` secret, add all six
secrets in one Dashboard version, and verify that an unauthenticated browser is
rejected.

The collector's `0002_admin_actor.sql` migration must also be applied so a
successful raw-IP reveal can record the HMAC-pseudonymized Access actor.

## Test

The tests use Web Crypto and a generated RSA key pair; no network is required:

```sh
npm test
```
