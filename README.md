# wjxsec.github.io

Static academic homepage for Jiaxi Wang.

The site is intentionally lightweight: plain HTML, CSS, and SVG assets only. It
is designed for GitHub Pages user-site hosting at:

https://wjxsec.github.io

## Contact

- Email: jiaxi.wang.research@gmail.com
- GitHub: https://github.com/wjxsec
- Google Scholar: https://scholar.google.com/citations?hl=zh-CN&user=foI99V4AAAAJ
- ORCID: https://orcid.org/0009-0001-6084-7698

## Structure

- `index.html` - homepage content
- `assets/css/styles.css` - responsive academic page styling
- `assets/img/avatar.png` - profile photo
- `assets/papers/mmd-power-side-channel-leakage.pdf` - CCF-A paper PDF
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

This implementation intentionally does **not** collect, store, or expose a
visitor's raw IP address. GitHub Pages does not make its request IP logs
available to a site owner. Raw-IP logging would require a domain and a
server-side endpoint or reverse proxy that you control, plus a privacy notice,
retention policy, and compliance review. Country data in the analytics
dashboard is aggregate and approximate.
