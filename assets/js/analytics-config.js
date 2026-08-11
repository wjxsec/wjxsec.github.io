/*
 * The Web Analytics site token is public by design. The visitorCollectorUrl
 * is a public collector endpoint, not a credential. It only works with the
 * separately deployed Worker, D1 database, and Cloudflare-side secrets.
 */
window.WJXSEC_ANALYTICS = Object.freeze({
  cloudflareWebAnalyticsToken: "7143d2b83aee4f8bbf49f655c8364aa4",
  visitorCollectorUrl: "https://wjxsec-visitor-collector.wjx15896427883.workers.dev/v1/visit"
});
