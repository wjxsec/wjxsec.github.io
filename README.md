# wjxsec.github.io

Static academic homepage for Jiaxi Wang.

The site is intentionally lightweight: plain HTML, CSS, and small JavaScript
loaders, designed for GitHub Pages user-site hosting at:

https://wjxsec.github.io

## Contact

- Email: jiaxi.wang.research@gmail.com
- GitHub: https://github.com/wjxsec
- Google Scholar: https://scholar.google.com/citations?hl=zh-CN&user=foI99V4AAAAJ
- ORCID: https://orcid.org/0009-0001-6084-7698

## Structure

- `index.html` - homepage content
- `assets/css/styles.css` - responsive academic page styling
- `assets/js/` - privacy-respecting analytics configuration and loaders
- `assets/img/avatar.png` - profile photo
- `assets/papers/mmd-power-side-channel-leakage.pdf` - CCF-A paper PDF
- `analytics-worker/` - optional encrypted raw-IP collector and D1 migration
- `.nojekyll` - asks GitHub Pages to serve files as-is

## Publish

Create or open the GitHub repository `wjxsec/wjxsec.github.io`, then place these
files at the repository root and push to the default branch. GitHub Pages will
serve the site at `https://wjxsec.github.io`.

## Privacy-preserving traffic analytics

The site includes a disabled-by-default Cloudflare Web Analytics loader. When
configured, it provides aggregate page views, visits, referrer trends, and
country-level trends in the Cloudflare dashboard.

1. In Cloudflare, open **Web Analytics**, choose **Add a site**, and register
   `wjxsec.github.io` as the hostname.
2. Copy the site token that Cloudflare generates.
3. Set that value as `cloudflareWebAnalyticsToken` in
   `assets/js/analytics-config.js`, then publish the site.

The token is intended to be public in the page source; do not put account API
tokens or other secrets in this repository.

The GitHub Pages and Cloudflare Web Analytics integration itself does **not**
collect, store, or expose a visitor's raw IP address to the site owner. GitHub
Pages does not make its request IP logs available to a site owner. Country data
in the analytics dashboard is aggregate and approximate.

## Raw-IP visitor log (90-day retention)

The optional `analytics-worker/` project records raw source IP addresses and
IP-derived country, region, city, and ASN data for up to 90 days. It is kept
separate from the static site so that the storage, access controls, and
retention job are explicit. The homepage collector is disabled until its HTTPS
Worker URL is added to `visitorCollectorUrl` in `assets/js/analytics-config.js`.

Because this static GitHub Pages site cannot authenticate a cross-origin beacon,
a `workers.dev` collector is an access-sampling endpoint rather than a
cryptographically authoritative record of every homepage request. For stronger
source integrity and full request coverage, use a domain you control with the
Worker in front of the site.

See [`analytics-worker/README.md`](analytics-worker/README.md) for deployment,
administrator access, and data-handling instructions. Never put the Worker
administrator token, encryption key, or IP-hash secret in this repository.
