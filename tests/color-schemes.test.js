// Color schemes: the eight-scheme catalog, its WCAG contrast guarantees,
// the main-process mirror that paints the window and builds the native menu, the persisted
// preference store, and the source contracts that keep dark/light branching on `base`.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const root = path.join(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), "utf8");
const themesModule = () => import("../src/constants/themes.js");

const HEX = /^#[0-9a-f]{6}$/i;
const RGBA = /^rgba\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*(0|1|0?\.\d+)\s*\)$/;

function luminance(hex) {
  const channels = hex.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16) / 255);
  const linear = channels.map((value) => (value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4));
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}
function contrast(foreground, background) {
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}
const GROUPS = ["sev", "bars"];
function tokenKeys(theme) {
  return Object.keys(theme).sort().map((key) => (GROUPS.includes(key) ? `${key}{${Object.keys(theme[key]).sort().join(",")}}` : key));
}
// Every color in a token value: plain colors, the sev group, and the bars' top/bottom overrides.
function colorsOf(key, value) {
  if (key === "sev") return Object.values(value);
  if (key === "bars") return Object.values(value).flatMap((part) => Object.values(part));
  return [value];
}

test("the catalog lists the eight schemes in menu order and every scheme has a complete token set", async () => {
  const { THEMES, THEME_OPTIONS, THEME_IDS, DEFAULT_THEME } = await themesModule();
  assert.deepEqual(THEME_IDS, ["dark", "light", "spring", "sakura", "summer", "autumn", "winter", "christmas"]);
  assert.deepEqual(THEME_OPTIONS.map((o) => o.label), ["Dark Mode", "Light Mode", "Spring", "Sakura", "Summer", "Autumn", "Winter", "Christmas"]);
  assert.deepEqual(Object.keys(THEMES), THEME_IDS);
  assert.equal(DEFAULT_THEME, "dark");
  const reference = tokenKeys(THEMES.dark);
  for (const [name, theme] of Object.entries(THEMES)) {
    assert.deepEqual(tokenKeys(theme), reference, `${name} must define exactly the dark scheme's tokens`);
    assert.ok(["dark", "light"].includes(theme.base), `${name}.base`);
    for (const [key, value] of Object.entries(theme)) {
      if (key === "base") continue;
      const values = colorsOf(key, value);
      for (const color of values) assert.ok(HEX.test(color) || RGBA.test(color), `${name}.${key} = ${color}`);
    }
  }
  for (const option of THEME_OPTIONS) {
    assert.ok(option.icon && option.description, `${option.id} needs an icon and a description for the toolbar picker`);
  }
});

test("every scheme keeps readable text and distinct severity colors", async () => {
  const { THEMES } = await themesModule();
  for (const [name, th] of Object.entries(THEMES)) {
    const at = (fg, bg, min, what) => assert.ok(contrast(fg, bg) >= min, `${name}: ${what} ${contrast(fg, bg).toFixed(2)} < ${min}`);
    // The Autumn reference background targets AA; other palettes retain AAA.
    at(th.text, th.bg, name === "autumn" ? 4.5 : 7, "text on bg");
    at(th.textDim, th.bg, 4.5, "textDim on bg");
    at(th.textMuted, th.bg, 4.5, "textMuted on bg");
    at(th.textMuted, th.bgAlt, 4.5, "textMuted on bgAlt");
    at(th.headerText, th.headerBg, 4.5, "headerText on headerBg");
    for (const key of ["accent", "success", "warning", "danger"]) at(th[key], th.bg, 3, `${key} on bg`);
    for (const [key, color] of Object.entries(th.sev)) at(color, th.bg, 3, `sev.${key} on bg`);
    assert.equal(new Set(Object.values(th.sev)).size, 7, `${name}: severity colors must remain distinct`);
    // Choose the base that matches readable foregrounds. 0.179 is the crossover
    // where black and white have equal contrast, including saturated backgrounds.
    assert.equal(contrast("#000000", th.bg) < contrast("#ffffff", th.bg) ? "dark" : "light", th.base, `${name}.base disagrees with its background`);
  }
});

test("resolveTheme falls back to the default for unknown names and isDarkTheme follows base", async () => {
  const { THEMES, resolveTheme, isThemeName, isDarkTheme } = await themesModule();
  assert.equal(resolveTheme("no-such-scheme"), THEMES.dark);
  assert.equal(resolveTheme(undefined), THEMES.dark);
  assert.equal(resolveTheme("winter"), THEMES.winter);
  assert.equal(isThemeName("toString"), false);
  assert.equal(isThemeName("autumn"), true);
  assert.equal(isDarkTheme("summer"), false);
  assert.equal(isDarkTheme("christmas"), true);
  assert.equal(isThemeName("christmas-2"), false, "retired names must not be selectable");
  assert.equal(isDarkTheme("spring"), false);
  assert.equal(isDarkTheme("bogus"), true, "unknown names resolve to the dark default");
});

test("the main-process catalog mirrors the renderer catalog", async () => {
  const renderer = await themesModule();
  const main = require("../electron/themes");
  assert.deepEqual(main.THEME_OPTIONS.map((o) => o.id), renderer.THEME_IDS);
  assert.deepEqual(main.THEME_OPTIONS.map((o) => o.label), renderer.THEME_OPTIONS.map((o) => o.label));
  assert.equal(main.DEFAULT_THEME, renderer.DEFAULT_THEME);
  for (const option of main.THEME_OPTIONS) {
    assert.equal(option.windowBackground, renderer.THEMES[option.id].bg, `${option.id} window background must equal the scheme bg`);
  }
  assert.equal(main.windowBackgroundFor("summer"), renderer.THEMES.summer.bg);
  assert.equal(main.windowBackgroundFor("nope"), renderer.THEMES.dark.bg);
  assert.equal(main.isThemeId("winter"), true);
  assert.equal(main.isThemeId("constructor"), false);
  assert.equal(main.isThemeId("christmas-2"), false);
  assert.equal(main.windowBackgroundFor("christmas-2"), renderer.THEMES.christmas.bg);
});

test("ui-prefs store round-trips the scheme and sanitizes missing, corrupt and unknown values", () => {
  const { createUiPrefsStore, sanitizeUiPrefs } = require("../electron/ui-prefs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-ui-prefs-"));
  try {
    const file = path.join(dir, "nested", "ui-prefs.json");
    const store = createUiPrefsStore(file);
    assert.deepEqual(store.load(), { themeName: "dark" }, "missing file → defaults");
    assert.deepEqual(store.save({ themeName: "autumn" }), { themeName: "autumn" });
    assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), { themeName: "autumn" });
    assert.deepEqual(createUiPrefsStore(file).load(), { themeName: "autumn" }, "a fresh store reads it back");
    assert.deepEqual(store.save({ themeName: "christmas" }), { themeName: "christmas" });
    assert.deepEqual(createUiPrefsStore(file).load(), { themeName: "christmas" });
    fs.writeFileSync(file, JSON.stringify({ themeName: "christmas-2" }));
    assert.deepEqual(createUiPrefsStore(file).load(), { themeName: "christmas" }, "older Christmas-2 preferences select Christmas");
    assert.deepEqual(store.save({ themeName: "christmas-2" }), { themeName: "christmas" });
    assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), { themeName: "christmas" }, "subsequent saves use the canonical name");
    assert.deepEqual(store.save({ themeName: "sakura" }), { themeName: "sakura" });
    assert.deepEqual(createUiPrefsStore(file).load(), { themeName: "sakura" });
    assert.deepEqual(store.save({ themeName: "light" }), { themeName: "light" });
    assert.deepEqual(createUiPrefsStore(file).load(), { themeName: "light" });
    assert.deepEqual(store.save({ themeName: "neon" }), { themeName: "dark" }, "unknown schemes fall back to the default");
    fs.writeFileSync(file, "{ not json", "utf8");
    assert.deepEqual(store.load(), { themeName: "dark" }, "corrupt file → defaults");
    assert.deepEqual(sanitizeUiPrefs(null), { themeName: "dark" });
    assert.deepEqual(sanitizeUiPrefs({ themeName: "spring", extra: 1 }), { themeName: "spring" });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Color Scheme menu, toolbar picker, preload and main process are wired together", () => {
  const menu = read("electron/menu.js");
  assert.match(menu, /label: "Color Scheme"/);
  assert.match(menu, /THEME_OPTIONS\.map/);
  assert.match(menu, /type: "radio"/);
  assert.match(menu, /checked: option\.id === currentTheme/);
  assert.doesNotMatch(menu, /label: "Theme"/);

  const toolbar = read("src/components/MenuBar.jsx");
  assert.match(toolbar, /aria-label="Color scheme"/);
  assert.match(toolbar, /THEME_OPTIONS\.map\(\(t\) => <option/);
  assert.match(toolbar, /chooseTheme\(e\.target\.value\)/);
  assert.doesNotMatch(toolbar, /Toggle theme/);

  const preload = read("electron/preload.js");
  assert.match(preload, /getUiPrefs: \(\) => ipcRenderer\.invoke\("get-ui-prefs"\)/);
  assert.match(preload, /setThemePreference: \(themeName\) => ipcRenderer\.invoke\("set-theme-preference", \{ themeName \}\)/);

  const main = read("electron/main.js");
  assert.match(main, /safeHandle\("get-ui-prefs"/);
  assert.match(main, /safeHandle\("set-theme-preference"/);
  assert.match(main, /backgroundColor: windowBackgroundFor\(uiPrefs\.load\(\)\.themeName\)/);
  assert.match(main, /getCurrentTheme: \(\) => uiPrefs\.load\(\)\.themeName, applyTheme/);
  assert.match(menu, /const currentTheme = typeof getCurrentTheme === "function" \? getCurrentTheme\(\) : DEFAULT_THEME/);
  assert.match(main, /safeSend\("set-theme", prefs\.themeName\)/, "menu-initiated changes reach the renderer");

  const app = read("src/App.jsx");
  assert.match(app, /tle\.getUiPrefs\?\.\(\)/, "startup restores the persisted scheme");
  assert.match(app, /const isDark = th\.base === "dark"/);
  assert.match(app, /colorScheme: th\.base/);
});

test("no renderer code branches on the scheme name — only on base/isDark", () => {
  const offenders = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(jsx?|mjs)$/.test(entry.name)) {
        const text = fs.readFileSync(full, "utf8");
        if (/themeName\s*[!=]==?\s*["'](dark|light)["']/.test(text) || /colorScheme:\s*themeName\b/.test(text)) {
          offenders.push(path.relative(root, full));
        }
      }
    }
  };
  walk(path.join(root, "src"));
  assert.deepEqual(offenders, []);
  const html = read("index.html");
  for (const prop of ["--tle-bg", "--tle-scrollbar-thumb", "--tle-scrollbar-thumb-hover", "--tle-selection"]) {
    assert.ok(html.includes(`var(${prop}`), `index.html must read ${prop}`);
  }
});


test("light and seasonal text stays readable on panels, controls and selected/bookmarked rows", async () => {
  const { THEMES } = await themesModule();
  const composite = (rgba, background) => {
    const [r, g, b, a] = rgba.match(/[\d.]+/g).map(Number);
    const under = background.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16));
    return "#" + [r, g, b].map((v, i) => Math.round(v * a + under[i] * (1 - a)).toString(16).padStart(2, "0")).join("");
  };
  for (const name of ["light", "spring", "sakura", "summer", "autumn", "winter", "christmas"]) {
    const th = THEMES[name];
    for (const surface of ["bg", "bgAlt", "bgInput", "modalBg", "rowOdd", "rowEven", "panelBg", "btnBg"]) {
      for (const foreground of ["text", "textDim", "textMuted", "accent"]) {
        const ratio = contrast(th[foreground], th[surface]);
        assert.ok(ratio >= 4.5, `${name}: ${foreground} on ${surface}: ${ratio.toFixed(2)}`);
      }
    }
    assert.ok(contrast(th.headerText, th.headerBg) >= 4.5, `${name}: header foreground on its own surface`);
    for (const foreground of ["text", "textDim", "textMuted", "accent"]) {
      const ratio = contrast(th[foreground], composite(th.toolbarBg, th.bg));
      assert.ok(ratio >= 4.5, `${name}: ${foreground} on toolbar: ${ratio.toFixed(2)}`);
    }
    for (const row of [th.rowOdd, th.rowEven]) {
      for (const highlight of [th.selection, th.bookmark]) {
        assert.ok(contrast(th.text, composite(highlight, row)) >= (name === "autumn" ? 4.5 : 7), `${name}: highlighted row text`);
      }
    }
  }
});

test("bar overrides: Autumn's, Spring's and Christmas's bars, the other schemes override nothing", async () => {
  const { THEMES, barTheme } = await themesModule();
  const PARTS = ["top", "menu", "dropdown", "group", "search", "header", "inputs", "filters", "bottom"];
  for (const [name, th] of Object.entries(THEMES)) {
    assert.deepEqual(Object.keys(th.bars), PARTS, `${name}.bars parts`);
    for (const part of PARTS) {
      const overrides = th.bars[part];
      for (const key of Object.keys(overrides)) {
        assert.ok(key in th && !GROUPS.includes(key) && key !== "base", `${name}.bars.${part}.${key} must override a plain color token`);
      }
      // The sticky column header row needs an opaque background.
      if ("headerBg" in overrides) assert.match(overrides.headerBg, HEX, `${name}.bars.${part}.headerBg must be opaque`);
      assert.deepEqual(barTheme(th, part), { ...th, ...overrides }, `${name}: barTheme ${part}`);
    }
    assert.deepEqual(barTheme(th, "top", "group"), { ...th, ...th.bars.top, ...th.bars.group }, `${name}: later parts win`);
    if (!["autumn", "spring", "christmas"].includes(name)) {
      for (const part of PARTS) assert.deepEqual(th.bars[part], {}, `${name}.bars.${part}`);
      assert.equal(barTheme(th, "top", "group"), th, `${name}: no overrides, same theme object`);
    }
  }
  const TEXT = ["text", "textDim", "textMuted", "accent", "success", "warning", "danger"];

  // Christmas: the search conditions bar is red, like the column headers; the group strip is not.
  const christmas = THEMES.christmas;
  const christmasSearch = barTheme(christmas, "top", "group", "search");
  assert.equal(christmasSearch.panelBg, christmas.headerBg);
  assert.equal(barTheme(christmas, "top", "group").panelBg, christmas.panelBg);
  for (const key of ["text", "textDim", "accent"]) assert.ok(contrast(christmasSearch[key], christmasSearch.panelBg) >= 4.5, `christmas search ${key}`);
  assert.ok(contrast(christmasSearch.textMuted, christmasSearch.panelBg) >= 4.4, "christmas search textMuted");
  // "Clear All" in the group strip and the status bar is vermillion.
  assert.equal(barTheme(christmas, "top", "group").danger, "#ea4630");
  assert.equal(barTheme(christmas, "bottom").danger, "#ea4630");

  const autumn = THEMES.autumn;
  const YELLOW = "#eac910";
  for (const key of ["bg", "bgAlt", "rowOdd", "rowEven"]) assert.equal(autumn[key], "#6b3c2c", `autumn.${key}`);
  // Red-brown menu bar, tab bar; red menus, as before.
  const top = barTheme(autumn, "top", "menu");
  assert.equal(top.toolbarBg, "rgba(107,60,44,0.98)");
  assert.equal(top.modalBg, "#c93036");
  for (const key of TEXT) assert.equal(top[key], YELLOW, `autumn top ${key}`);
  for (const key of ["border", "borderAccent", "btnBorder", "glassBorder"]) assert.equal(top[key], "#ff8c00", `autumn top ${key}`);
  // Red search conditions bar and group strip; "N filters active" is yellow too.
  const group = barTheme(autumn, "top", "group");
  assert.equal(group.panelBg, "#c93036");
  assert.equal(group.borderAccent, YELLOW);
  for (const key of TEXT) assert.equal(group[key], YELLOW, `autumn group ${key}`);
  assert.equal(group.border, "#ff8c00");
  // Red column headers with orange lines; the column names keep the cream header text.
  const header = barTheme(autumn, "top", "header");
  assert.equal(header.headerBg, "#c93036");
  assert.equal(header.headerText, "#fff8ed");
  assert.equal(header.borderAccent, "#ff8c00");
  // Light green text in the dropdowns (toolbar and match mode) and the search box.
  for (const base of [top, group]) {
    const inputs = barTheme(base, "inputs");
    for (const key of ["text", "textDim", "textMuted"]) assert.equal(inputs[key], "#a6b784", `autumn inputs ${key}`);
    assert.equal(inputs.btnBg, "#6b3c2c");
  }
  // Red status bar with yellow text.
  const bottom = barTheme(autumn, "bottom");
  assert.equal(bottom.toolbarBg, "rgba(201,48,54,0.98)");
  for (const key of [...TEXT, "borderAccent"]) assert.equal(bottom[key], YELLOW, `autumn bottom ${key}`);
  // Yellow is 5.6:1 on the red-brown and 3.3:1 on the red; the light green input text 4.2:1 on the red-brown.
  assert.ok(contrast(YELLOW, "#6b3c2c") >= 4.5, "yellow on the red-brown bars");
  assert.ok(contrast(YELLOW, "#c93036") >= 3, "yellow on the red bars");
  assert.ok(contrast("#a6b784", "#6b3c2c") >= 3, "light green on the red-brown dropdowns");
  assert.ok(contrast(header.headerText, header.headerBg) >= 4.5, "column names on the red header row");

  const spring = THEMES.spring;
  const PALE_YELLOW = "#fae3a0";
  const PURPLE = "#6f5497";
  const BLACK = { text: "#010500", textDim: "#040602", textMuted: "#070803", accent: "#0f060a", success: "#27462e", warning: "#604c0f", danger: "#732f4b" };
  // Near-black text on the light green timeline, menus, dialogs, search conditions bar, group
  // strip and column headers.
  for (const [key, value] of Object.entries(BLACK)) {
    assert.equal(spring[key], value, `spring.${key}`);
    assert.equal(barTheme(spring, "top", "dropdown")[key], value, `spring dropdown ${key}`);
    assert.equal(barTheme(spring, "top", "group")[key], value, `spring group ${key}`);
    assert.equal(barTheme(spring, "top", "header")[key], value, `spring header ${key}`);
  }
  assert.equal(barTheme(spring, "top", "group").borderAccent, "#010500", "spring: N filters active");
  assert.equal(spring.headerText, "#102015");
  // Pale-yellow text on the dark green top row, tab bar and status bar.
  for (const part of [["top"], ["top", "menu"], ["bottom"]]) {
    const bar = barTheme(spring, ...part);
    for (const key of TEXT) assert.equal(bar[key], PALE_YELLOW, `spring ${part.join("+")} ${key}`);
  }
  // Pale-yellow dropdowns with purple text; the search box text stays pale yellow.
  const springInputs = barTheme(barTheme(spring, "top", "menu"), "inputs");
  assert.equal(springInputs.btnBg, PALE_YELLOW);
  assert.equal(springInputs.textDim, PURPLE);
  assert.equal(springInputs.text, PALE_YELLOW);
  // Pale-yellow filter boxes with purple text; other text boxes are pale yellow with black text.
  const filters = barTheme(spring, "filters");
  assert.equal(filters.bgInput, PALE_YELLOW);
  assert.equal(filters.text, PURPLE);
  assert.equal(spring.bgInput, PALE_YELLOW);
  // Filled controls are pale yellow with purple text; plain buttons are the bar green.
  for (const key of ["primaryBtn", "primaryBtnHover", "fillAccent", "fillAccentHover", "fillWarning", "fillDanger"]) assert.equal(spring[key], PALE_YELLOW, `spring.${key}`);
  for (const key of ["onPrimary", "onAccent"]) assert.equal(spring[key], PURPLE, `spring.${key}`);
  assert.equal(spring.btnBg, "#678215");
  assert.ok(contrast(PURPLE, PALE_YELLOW) >= 4.5, "purple on the pale-yellow filter boxes");
  assert.ok(contrast(PURPLE, PALE_YELLOW) >= 4.5, "purple on pale yellow");
  assert.ok(contrast(PALE_YELLOW, "#678215") >= 3, "pale yellow on the dark green bars");
});

test("filled controls pair the foreground with the actual accent or primary surface", async () => {
  const { THEMES } = await themesModule();
  const { buttonStyles } = await import("../src/components/primitives/buttonStyles.js");
  for (const [name, th] of Object.entries(THEMES)) {
    for (const [fg, bg] of [["onAccent", "fillAccent"], ["onAccent", "fillAccentHover"], ["onAccent", "fillWarning"], ["onAccent", "fillDanger"], ["onPrimary", "primaryBtn"], ["onPrimary", "primaryBtnHover"]]) {
      assert.ok(contrast(th[fg], th[bg]) >= 4.5, `${name}: ${fg} on ${bg}`);
    }
    const style = buttonStyles(th);
    assert.ok(contrast(style.color, style.background) >= 4.5, `${name}: rendered primary button`);
    assert.equal(buttonStyles(th, { disabled: true }).color, th.textMuted);
  }
});

test("histogram density colors follow the selected theme, including endpoints and clamping", async () => {
  const { THEMES, createHistogramColorScale } = await themesModule();
  const rgb = (hex) => `rgb(${hex.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16)).join(",")})`;
  for (const th of Object.values(THEMES)) {
    const scale = createHistogramColorScale(th);
    assert.equal(scale(0), rgb(th.histBar));
    assert.equal(scale(1), rgb(th.histBarHover));
    assert.equal(scale(-1), scale(0));
    assert.equal(scale(2), scale(1));
    const lo = th.histBar.match(/[0-9a-f]{2}/gi).map((p) => parseInt(p, 16));
    const hi = th.histBarHover.match(/[0-9a-f]{2}/gi).map((p) => parseInt(p, 16));
    assert.equal(scale(0.5), `rgb(${lo.map((n, i) => Math.round((n + hi[i]) / 2)).join(",")})`);
  }
});
