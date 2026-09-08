"use strict";

const { test, before } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  isCodexDesktopAppDir,
  isChatgptAppDir,
  isChatgptAppDirQuick,
  isChatgptDataFile,
  chromeTimeToMs,
  extractChatgptDir,
  extractChatgptPath,
} = require("../electron/parsers/ai-history/chatgpt");
const { listChatgptCandidatePaths } = require("../electron/parsers/ai-history/artifact-paths");
const { detectAiHistoryImport } = require("../electron/parsers/ai-history-import");
const { scanAiArtifacts, classifyChatgptDir } = require("../electron/parsers/ai-artifacts");
const { isCodexDir } = require("../electron/parsers/ai-history/codex");

let sqliteAvailable = false;

before(() => {
  try {
    require("better-sqlite3");
    sqliteAvailable = true;
  } catch {
    sqliteAvailable = false;
  }
});

function chromeTimeFromIso(iso) {
  const unixMs = Date.parse(iso);
  return (unixMs + 11644473600000) * 1000;
}

function writeHistoryDb(dbPath, { url, title, iso }) {
  const Database = require("better-sqlite3");
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE urls (
      id INTEGER PRIMARY KEY,
      url TEXT,
      title TEXT,
      visit_count INTEGER,
      typed_count INTEGER,
      last_visit_time INTEGER,
      hidden INTEGER
    );
    CREATE TABLE visits (
      id INTEGER PRIMARY KEY,
      url INTEGER,
      visit_time INTEGER,
      from_visit INTEGER,
      transition INTEGER,
      segment_id INTEGER,
      visit_duration INTEGER
    );
    CREATE TABLE downloads (
      id INTEGER PRIMARY KEY,
      current_path TEXT,
      target_path TEXT,
      start_time INTEGER,
      end_time INTEGER,
      received_bytes INTEGER,
      total_bytes INTEGER,
      state INTEGER
    );
  `);
  const visitTime = chromeTimeFromIso(iso);
  db.prepare("INSERT INTO urls (id, url, title, visit_count, typed_count, last_visit_time, hidden) VALUES (1,?,?,1,0,?,0)")
    .run(url, title, visitTime);
  db.prepare("INSERT INTO visits (id, url, visit_time, from_visit, transition, segment_id, visit_duration) VALUES (1,1,?,0,0,0,0)")
    .run(visitTime);
  db.close();
}

test("chromeTimeToMs round-trips a known UTC instant", () => {
  const iso = "2026-03-01T12:00:00.000Z";
  const unixMs = Date.parse(iso);
  assert.equal(chromeTimeToMs(chromeTimeFromIso(iso)), unixMs);
  assert.equal(chromeTimeToMs(0), null);
  assert.equal(chromeTimeToMs(-1), null);
});

test("listChatgptCandidatePaths includes the merged Codex desktop profile", () => {
  const paths = listChatgptCandidatePaths();
  assert.ok(paths.some((p) => /[/\\]Codex$/.test(p)), "Codex app-support path is a candidate");
});

test("isCodexDesktopAppDir requires Chromium markers and does not claim ~/.codex", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-profile-"));
  try {
    const app = path.join(tmp, "Codex");
    fs.mkdirSync(app);
    assert.equal(isCodexDesktopAppDir(app), false, "empty Codex dir is not a profile");
    fs.mkdirSync(path.join(app, "Local Storage", "leveldb"), { recursive: true });
    fs.writeFileSync(path.join(app, "Local State"), "{}");
    assert.equal(isCodexDesktopAppDir(app), true);
    assert.equal(isChatgptAppDir(app), true);
    assert.equal(isChatgptAppDirQuick(app), true);
    assert.equal(classifyChatgptDir(app), true);

    const cli = path.join(tmp, ".codex");
    fs.mkdirSync(path.join(cli, "sessions"), { recursive: true });
    fs.writeFileSync(path.join(cli, "history.jsonl"), '{"session_id":"s","ts":1,"text":"x"}\n');
    assert.equal(isCodexDir(cli), true);
    assert.equal(isCodexDesktopAppDir(cli), false);
    assert.equal(isChatgptAppDir(cli), false, "Codex CLI home must not be claimed as ChatGPT");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("Login Data is not treated as a ChatGPT conversation store", () => {
  assert.equal(isChatgptDataFile("/tmp/Codex/Default/Login Data"), false);
  assert.equal(isChatgptDataFile("/tmp/Codex/Cookies"), false);
  assert.equal(isChatgptDataFile("/tmp/com.openai.chat/.tipkit/tips-store.db"), false);
});

test("extractChatgptDir reads Chromium History visits from a Codex desktop profile", {
  skip: !sqliteAvailable && "better-sqlite3 not available",
}, async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-hist-"));
  const app = path.join(tmp, "Codex");
  try {
    fs.mkdirSync(path.join(app, "artifact-sessions", "runtime-generations"), { recursive: true });
    fs.mkdirSync(path.join(app, "codex-browser-app"), { recursive: true });
    fs.writeFileSync(path.join(app, "Local State"), "{}");
    writeHistoryDb(path.join(app, "Default", "History"), {
      url: "https://chatgpt.com/c/demo",
      title: "Demo chat",
      iso: "2026-03-01T12:00:00.000Z",
    });

    assert.equal(detectAiHistoryImport(app)?.tool, "chatgpt");
    const rows = await extractChatgptDir(app, { user: "alice" });
    const visit = rows.find((r) => r.RecordType === "browser_visit");
    assert.ok(visit, "visit row present");
    assert.equal(visit.User, "alice");
    assert.equal(visit.Timestamp, "2026-03-01 12:00:00");
    assert.match(visit.Summary, /Demo chat/);
    assert.match(visit.FullText, /chatgpt\.com\/c\/demo/);
    assert.match(visit.FullText, /Chromium visits\.visit_time/);

    const profile = rows.find((r) => r.RecordType === "chatgpt_desktop_profile");
    assert.ok(profile);
    assert.match(profile.Summary, /merged desktop Chromium profile/);

    const artifacts = rows.find((r) => r.RecordType === "artifact_sessions");
    assert.ok(artifacts);

    const scanRoot = path.join(tmp, "Users", "bob", "Library", "Application Support");
    fs.mkdirSync(scanRoot, { recursive: true });
    fs.cpSync(app, path.join(scanRoot, "Codex"), { recursive: true });
    const scan = scanAiArtifacts(tmp);
    assert.ok(scan.chatgpt.some((h) => h.path.endsWith(`${path.sep}Codex`) && h.username === "bob"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("extractChatgptPath on a History sqlite file yields visit rows", {
  skip: !sqliteAvailable && "better-sqlite3 not available",
}, async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-hist-file-"));
  try {
    const hist = path.join(tmp, "History");
    writeHistoryDb(hist, {
      url: "https://example.invalid/x",
      title: "Example",
      iso: "2026-04-02T08:30:00.000Z",
    });
    const rows = await extractChatgptPath(hist);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].RecordType, "browser_visit");
    assert.equal(rows[0].Timestamp, "2026-04-02 08:30:00");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("sentry scope/session, Work-with-Apps pairings and credential stores become typed rows with URLs stripped", async () => {
  const {
    collectCodexDesktopSentryRows, collectAppPairingRows, collectChromiumCredentialStoreInventory, redactUrlsInText,
  } = require("../electron/parsers/ai-history/chatgpt");
  assert.equal(redactUrlsInText("POST https://chatgpt.com/ces/v1/rgstr?k=client-SECRET&t=1 failed"), "POST https://chatgpt.com/ces/v1/rgstr failed");

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-codex-sentry-"));
  const app = path.join(tmp, "Codex");
  const chat = path.join(tmp, "com.openai.chat");
  try {
    fs.mkdirSync(path.join(app, "sentry"), { recursive: true });
    fs.mkdirSync(path.join(app, "codex-browser-app"), { recursive: true });
    fs.mkdirSync(path.join(app, "Default"), { recursive: true });
    fs.writeFileSync(path.join(app, "Local State"), "{}");
    fs.writeFileSync(path.join(app, "codex-browser-app", "Login Data"), Buffer.alloc(4096));
    fs.writeFileSync(path.join(app, "Default", "Cookies"), Buffer.alloc(1024));
    fs.writeFileSync(path.join(app, "sentry", "scope_v3.json"), JSON.stringify({
      scope: {
        breadcrumbs: [
          { timestamp: 1788790839.283, type: "http", category: "electron.net", data: { url: "https://chatgpt.com/backend-api/automations?token=SHOULD-NEVER-APPEAR", method: "GET", status_code: 200 } },
          { timestamp: 1788790840.1, category: "ui.click", message: "button.send" },
          { timestamp: 1788790841.5, category: "console", level: "error", data: { arguments: ["[Statsig] error POST https://chatgpt.com/ces/v1/rgstr?k=client-SHOULD-NEVER-APPEAR&t=1"] } },
        ],
        tags: { sessionId: "sess-1", buildFlavor: "prod", bundle: "webview" },
        user: { id: "user-abc", authMethod: "chatgpt", account_id: "acct-9097" },
      },
      event: { release: "codex@26.901.51231", contexts: { app: { app_start_time: "2026-09-06T18:57:53.000Z", app_version: "26.901.51231" }, os: { name: "macOS", version: "26.6.2" } } },
    }));
    fs.writeFileSync(path.join(app, "sentry", "session.json"), JSON.stringify({ sid: "sid-1", started: 1788721073.95, timestamp: 1788721078.25, duration: 4.3, status: "ok", errors: 0, did: "user-abc", release: "codex@26.901.51231" }));
    fs.mkdirSync(path.join(chat, "app_pairing_extensions"), { recursive: true });
    fs.writeFileSync(path.join(chat, "app_pairing_extensions", "Cursor-502efd98"), JSON.stringify({
      appName: "Cursor", bundleID: "com.todesktop.230313mzl4w4u92", extensionVersion: "0.0.1731016154", marketplaceID: "openai.chatgpt",
      extensionName: "oai_pwai Cursor", workspaceName: "Agentic-IR", id: "Cursor-502efd98",
      capabilities: { content: 1, ping: 1, selections: 1, setContent: 1, replaceSelection: 1, highlight: 1 },
    }));
    fs.writeFileSync(path.join(chat, "app_pairing_extensions", "Xcode-1"), JSON.stringify({ appName: "Xcode", workspaceName: "App", capabilities: { content: 1, ping: 1 } }));

    const sentry = collectCodexDesktopSentryRows(app, { user: "subject" });
    const identity = sentry.find((r) => r.RecordType === "app_identity");
    assert.equal(identity.Summary, "ChatGPT/Codex desktop signed in as user-abc (account acct-9097), auth chatgpt, codex@26.901.51231 on macOS 26.6.2");
    assert.equal(identity.Timestamp, "2026-09-06 18:57:53");
    const crumbs = sentry.filter((r) => r.RecordType === "app_breadcrumb");
    assert.equal(crumbs.length, 3);
    assert.equal(crumbs[0].Summary, "GET https://chatgpt.com/backend-api/automations → 200");
    assert.equal(crumbs[0].Timestamp, "2026-09-07 14:20:39");
    assert.equal(crumbs[0].InvokedTool, "http");
    assert.match(crumbs[0].FullText, /"queryStripped":true/);
    assert.equal(crumbs[1].Summary, "UI click: button.send");
    assert.equal(crumbs[2].Summary, "Console: [Statsig] error POST https://chatgpt.com/ces/v1/rgstr");
    const session = sentry.find((r) => r.RecordType === "app_crash_reporter_session");
    assert.match(session.Summary, /session ok — codex@26\.901\.51231, last update 2026-09-06 18:57:58/);
    assert.equal(session.Timestamp, "2026-09-06 18:57:53");
    assert.ok(!/SHOULD-NEVER-APPEAR/.test(JSON.stringify(sentry)), "query strings with keys never reach a row");

    const pairings = collectAppPairingRows(chat, { user: "subject" });
    assert.equal(pairings.length, 2);
    assert.equal(pairings[0].Summary, 'ChatGPT paired with Cursor — workspace "Agentic-IR" (6 capabilities, WRITE access: setContent/replaceSelection)');
    assert.equal(pairings[0].Workspace, "Agentic-IR");
    assert.match(pairings[0].FullText, /"bundleID": "com\.todesktop\.230313mzl4w4u92"/);
    assert.equal(pairings[1].Summary, 'ChatGPT paired with Xcode — workspace "App" (2 capabilities, read-only)');

    const stores = collectChromiumCredentialStoreInventory(app, {});
    assert.deepEqual(stores.map((r) => r.Summary), [
      "Chromium credential store present (not read) — Default/Cookies (1024 bytes)",
      "Chromium credential store present (not read) — codex-browser-app/Login Data (4096 bytes)",
    ]);
    assert.match(stores[1].ToolDescription, /AGENT held web sessions/);

    // Directory extraction wires all three in.
    const rows = await extractChatgptDir(app, { user: "subject" });
    assert.ok(rows.some((r) => r.RecordType === "app_identity"));
    assert.ok(rows.some((r) => r.RecordType === "credential_store_inventory"));
    const chatRows = await extractChatgptDir(chat, { user: "subject" });
    assert.equal(chatRows.filter((r) => r.RecordType === "app_pairing").length, 2);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
