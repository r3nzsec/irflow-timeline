const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.join(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");

function luminance(hex) {
  const channels = hex.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16) / 255);
  const linear = channels.map((value) =>
    value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(foreground, background) {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function themeColor(section, key) {
  const match = section.match(new RegExp(`\\b${key}:\\s*"(#[0-9a-fA-F]{6})"`));
  assert.ok(match, `missing ${key} theme token`);
  return match[1];
}

test("search UI explains its minimum and exposes one match-mode control", () => {
  const source = read("src/components/FilterBar.jsx");
  const helper = read("src/utils/search.js");

  assert.match(helper, /MIN_SEARCH_LENGTH = 2/);
  assert.match(source, /Enter at least \{MIN_SEARCH_LENGTH\} characters/);
  assert.match(source, /Search is paused until you enter at least \{MIN_SEARCH_LENGTH\} characters/);
  assert.ok(source.includes("{searchBehavior.label}"));
  assert.equal(source.split("<select value={ct.searchMode").length - 1, 1);
  assert.doesNotMatch(source, />FL<|>HL</);
});

test("primary navigation and grid controls are keyboard-operable", () => {
  const tabs = read("src/components/TabBar.jsx");
  // Grid markup spans two files since the data row moved into the memoized GridRow.jsx.
  const grid = read("src/components/VirtualGrid.jsx") + "\n" + read("src/components/GridRow.jsx");
  const status = read("src/components/StatusBar.jsx");
  const overlays = read("src/components/InlineModals.jsx");

  assert.match(tabs, /role="tablist"/);
  assert.match(tabs, /role="tab"/);
  assert.ok(tabs.includes("onKeyDown={(event) => handleTabKeyDown(event, index)}"));
  assert.match(grid, /id="timeline-grid"/);
  assert.ok(grid.includes("tabIndex={selectedRow === ai"));
  assert.ok(grid.includes("onKeyDown={(e) => activateOnKey"));
  assert.ok(grid.includes('aria-label={`${sel ? "Deselect" : "Select"} row'));
  assert.ok(status.includes('aria-label={ct.filePath ? "Copy timeline file path"'));
  assert.match(overlays, /role="dialog" aria-modal="true"/);
  assert.match(overlays, /trapFocus/);
});

test("histogram and grid treat FILETIME epoch as an unset timestamp, not a real date", () => {
  const grid = read("src/components/VirtualGrid.jsx");
  const dt = read("src/utils/datetime.js");
  const app = read("src/App.jsx");
  assert.match(dt, /UNSET_TIMESTAMP_LABEL = "Unset"/);
  assert.match(grid, /omittedUnset/);
  assert.match(grid, /unset FILETIME \(1601-01-01\)/);
  assert.match(app, /Unset timestamp/);
  assert.match(app, /isUnsetWindowsTimestamp/);
});

test("column value filter is not hard-capped at a Top 1000 list", () => {
  const app = read("src/App.jsx");
  const store = read("electron/db/query-store.js");
  assert.doesNotMatch(app, /Top \$\{formatNumber\(fdValues\.length\)\} of/);
  assert.doesNotMatch(app, /search for more/);
  assert.match(store, /No default cap/);
  assert.match(store, /hasLimit = Number.isInteger\(limit\) && limit > 0/);
  assert.match(store, /BIND_IN_MAX/);
  assert.match(app, /FD_ROW_H/);
});

test("core theme text tokens meet WCAG AA contrast", () => {
  const source = read("src/constants/themes.js");
  const dark = source.split("dark: {")[1].split("light: {")[0];
  const light = source.split("light: {")[1];

  for (const section of [dark, light]) {
    const bg = themeColor(section, "bg");
    const headerBg = themeColor(section, "headerBg");
    assert.ok(contrast(themeColor(section, "textMuted"), bg) >= 4.5);
    assert.ok(contrast(themeColor(section, "textDim"), bg) >= 4.5);
    assert.ok(contrast(themeColor(section, "headerText"), headerBg) >= 4.5);
  }
});
