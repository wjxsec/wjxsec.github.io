(function () {
  "use strict";

  const token = window.WJXSEC_ANALYTICS?.cloudflareWebAnalyticsToken;

  if (typeof token !== "string" || token.trim() === "") {
    document.documentElement.dataset.analytics = "disabled";
    return;
  }

  const beacon = document.createElement("script");
  beacon.type = "module";
  beacon.src = "https://static.cloudflareinsights.com/beacon.min.js";
  beacon.dataset.cfBeacon = JSON.stringify({
    token: token.trim(),
    spa: false
  });
  beacon.addEventListener("error", () => {
    document.documentElement.dataset.analytics = "unavailable";
  });

  document.body.append(beacon);
})();
