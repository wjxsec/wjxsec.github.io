/*
 * The Web Analytics site token is public by design. The visitorCollectorUrl
 * must remain blank until the separately deployed Worker and D1 database are
 * configured. It contains no secret when set.
 */
window.WJXSEC_ANALYTICS = Object.freeze({
  cloudflareWebAnalyticsToken: "7143d2b83aee4f8bbf49f655c8364aa4",
  visitorCollectorUrl: ""
});
