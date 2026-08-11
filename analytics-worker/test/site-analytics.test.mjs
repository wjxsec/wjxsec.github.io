import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const siteDirectory = path.resolve(testDirectory, "../..");
const [indexHtml, privacyHtml, analyticsConfig, analyticsLoader, visitorCollector] = await Promise.all([
  readFile(path.join(siteDirectory, "index.html"), "utf8"),
  readFile(path.join(siteDirectory, "privacy.html"), "utf8"),
  readFile(path.join(siteDirectory, "assets/js/analytics-config.js"), "utf8"),
  readFile(path.join(siteDirectory, "assets/js/analytics.js"), "utf8"),
  readFile(path.join(siteDirectory, "assets/js/visitor-collector.js"), "utf8")
]);

function makeBrowser({ doNotTrack = "0", globalPrivacyControl = false, referrer = "", pathname = "/", config } = {}) {
  const appended = [];
  const fetches = [];
  const document = {
    referrer,
    documentElement: { dataset: {} },
    body: { append: (node) => appended.push(node) },
    createElement: () => ({ dataset: {}, addEventListener() {} })
  };
  const window = {
    WJXSEC_ANALYTICS: config,
    location: { pathname }
  };
  const context = vm.createContext({
    URL,
    document,
    window,
    navigator: { doNotTrack, globalPrivacyControl },
    fetch: (...args) => {
      fetches.push(args);
      return Promise.resolve({ ok: true });
    }
  });
  return { appended, context, document, fetches, window };
}

test("both public pages load the analytics configuration and privacy-respecting collectors", () => {
  for (const html of [indexHtml, privacyHtml]) {
    assert.match(html, /assets\/js\/analytics-config\.js/);
    assert.match(html, /assets\/js\/analytics\.js/);
    assert.match(html, /assets\/js\/visitor-collector\.js/);
  }
  assert.match(privacyHtml, /no more than 90\s+days/);
  assert.match(privacyHtml, /Do Not Track and Global Privacy Control/);
});

test("aggregate analytics and raw collection disable themselves for Do Not Track", () => {
  const analyticsBrowser = makeBrowser({
    doNotTrack: "yes",
    config: { cloudflareWebAnalyticsToken: "public-token", visitorCollectorUrl: "" }
  });
  vm.runInContext(analyticsLoader, analyticsBrowser.context);
  assert.equal(analyticsBrowser.document.documentElement.dataset.analytics, "disabled");
  assert.equal(analyticsBrowser.appended.length, 0);

  const collectorBrowser = makeBrowser({
    doNotTrack: "1",
    config: { visitorCollectorUrl: "https://collector.example/v1/visit" }
  });
  vm.runInContext(visitorCollector, collectorBrowser.context);
  assert.equal(collectorBrowser.document.documentElement.dataset.rawIpCollector, "disabled");
  assert.equal(collectorBrowser.fetches.length, 0);

  const gpcBrowser = makeBrowser({
    globalPrivacyControl: true,
    config: { visitorCollectorUrl: "https://collector.example/v1/visit" }
  });
  vm.runInContext(visitorCollector, gpcBrowser.context);
  assert.equal(gpcBrowser.document.documentElement.dataset.rawIpCollector, "disabled");
  assert.equal(gpcBrowser.fetches.length, 0);
});

test("the raw-IP collector remains disabled until configured and sends only minimized metadata when enabled", async () => {
  const disabledBrowser = makeBrowser({ config: { visitorCollectorUrl: "" } });
  vm.runInContext(visitorCollector, disabledBrowser.context);
  assert.equal(disabledBrowser.document.documentElement.dataset.rawIpCollector, "disabled");
  assert.equal(disabledBrowser.fetches.length, 0);

  const enabledBrowser = makeBrowser({
    config: { visitorCollectorUrl: "https://collector.example/v1/visit" },
    pathname: "/privacy.html",
    referrer: "https://search.example/results?q=private"
  });
  vm.runInContext(visitorCollector, enabledBrowser.context);
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(enabledBrowser.document.documentElement.dataset.rawIpCollector, "enabled");
  assert.equal(enabledBrowser.fetches.length, 1);
  const [url, options] = enabledBrowser.fetches[0];
  assert.equal(url, "https://collector.example/v1/visit");
  assert.equal(options.credentials, "omit");
  assert.equal(options.referrerPolicy, "origin");
  assert.equal(options.headers["Content-Type"], "text/plain;charset=UTF-8");
  assert.deepEqual(JSON.parse(options.body), {
    path: "/privacy.html",
    referrerHost: "search.example"
  });
});

test("the checked-in analytics configuration leaves the raw collector off", () => {
  const browser = makeBrowser();
  vm.runInContext(analyticsConfig, browser.context);
  assert.equal(browser.window.WJXSEC_ANALYTICS.visitorCollectorUrl, "");
});
