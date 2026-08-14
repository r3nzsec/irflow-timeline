"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  redactAiSecretExportText,
  buildAiSecretPrintDocument,
  hardenAiSecretPdfWindow,
} = require("../electron/ipc/export-handlers");

const SECRET = "ghp_Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2";

test("AI Secret CSV, JSON, and HTML export boundary removes a synthetic secret", () => {
  for (const content of [
    `Secret,${SECRET}\n`,
    JSON.stringify({ accidentallyRevealed: SECRET }),
    `<html><body><code>${SECRET}</code></body></html>`,
  ]) {
    const exported = redactAiSecretExportText(content);
    assert.equal(exported.includes(SECRET), false);
    assert.match(exported, /ghp_.*•.*J3I2/);
  }
});

test("AI Secret PDF document is redacted and receives a deny-by-default CSP", () => {
  const document = buildAiSecretPrintDocument(`<html><head></head><body>${SECRET}<script>globalThis.pwned=true</script></body></html>`);
  assert.equal(document.includes(SECRET), false);
  assert.match(document, /Content-Security-Policy/);
  assert.match(document, /default-src 'none'/);
  assert.match(document, /frame-src 'none'/);
  assert.ok(document.indexOf("Content-Security-Policy") < document.indexOf("<script>"));
});

test("AI Secret PDF window denies popups, navigation, webviews, redirects, and outbound requests", () => {
  const listeners = {};
  let windowOpenHandler;
  let requestFilter;
  let requestHandler;
  const win = {
    webContents: {
      setWindowOpenHandler(handler) { windowOpenHandler = handler; },
      on(name, handler) { listeners[name] = handler; },
      session: {
        webRequest: {
          onBeforeRequest(filter, handler) { requestFilter = filter; requestHandler = handler; },
        },
      },
    },
  };
  const expectedUrl = "data:text/html,report";
  hardenAiSecretPdfWindow(win, expectedUrl);

  assert.deepEqual(windowOpenHandler(), { action: "deny" });
  for (const eventName of ["will-attach-webview", "will-redirect"]) {
    let prevented = false;
    listeners[eventName]({ preventDefault() { prevented = true; } });
    assert.equal(prevented, true, `${eventName} must be denied`);
  }
  let prevented = false;
  listeners["will-navigate"]({ preventDefault() { prevented = true; } }, "https://attacker.invalid/");
  assert.equal(prevented, true);
  prevented = false;
  listeners["will-navigate"]({ preventDefault() { prevented = true; } }, expectedUrl);
  assert.equal(prevented, false);
  assert.ok(requestFilter.urls.includes("https://*/*"));
  let decision;
  requestHandler({ url: "https://attacker.invalid/" }, (value) => { decision = value; });
  assert.deepEqual(decision, { cancel: true });
});

