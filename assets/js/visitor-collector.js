(function () {
  "use strict";

  const collectorUrl = window.WJXSEC_ANALYTICS?.visitorCollectorUrl;
  const doNotTrackValue = String(navigator.doNotTrack || window.doNotTrack || "").toLowerCase();
  const doNotTrack = doNotTrackValue === "1" || doNotTrackValue === "yes" || navigator.globalPrivacyControl === true;

  if (doNotTrack || typeof collectorUrl !== "string" || collectorUrl.trim() === "") {
    document.documentElement.dataset.rawIpCollector = "disabled";
    return;
  }

  let endpoint;
  try {
    endpoint = new URL(collectorUrl);
  } catch {
    document.documentElement.dataset.rawIpCollector = "invalid";
    return;
  }

  if (endpoint.protocol !== "https:") {
    document.documentElement.dataset.rawIpCollector = "invalid";
    return;
  }

  let referrerHost = null;
  if (document.referrer) {
    try {
      referrerHost = new URL(document.referrer).hostname || null;
    } catch {
      referrerHost = null;
    }
  }

  const payload = JSON.stringify({
    path: window.location.pathname || "/",
    referrerHost
  });

  fetch(endpoint.toString(), {
    method: "POST",
    mode: "cors",
    credentials: "omit",
    keepalive: true,
    referrerPolicy: "origin",
    headers: { "Content-Type": "text/plain;charset=UTF-8" },
    body: payload
  })
    .then((response) => {
      document.documentElement.dataset.rawIpCollector = response.ok ? "enabled" : "unavailable";
    })
    .catch(() => {
      document.documentElement.dataset.rawIpCollector = "unavailable";
    });
})();
