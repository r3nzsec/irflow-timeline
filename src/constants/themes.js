/**
 * Color schemes.
 *
 * Every scheme defines the same token set. `base` says whether the scheme is a dark or a
 * light design — components that only know two moods (context-menu glass, the
 * `color-scheme` CSS property, the timeline palettes) branch on `base`, never on the name.
 *
 * Palette text-contrast guarantees, enforced by tests/color-schemes.test.js (WCAG 2.x ratios):
 *   text, textDim and textMuted / bg ≥ 4.5, headerText / headerBg ≥ 4.5,
 *   accent, success, warning, danger and every severity color / bg ≥ 3.
 * Autumn targets 4.5:1 for main text; the other schemes target 7:1.
 * Reference header and control fills use their own contrasting foregrounds.
 *
 * `bars` overrides tokens for the bars around the timeline. `top` applies to everything above the
 * timeline; on top of it, `menu` to the top row (menu bar, search box), `dropdown` to the menus and
 * the command palette, `group` to the search conditions bar and the group strip (`search`, on top of
 * `group`, to the search conditions bar alone), `header` to the
 * column headers, and `inputs` to the dropdown lists and the search box's text. `filters` applies to
 * the text boxes under the column headers, and `bottom` to the status bar. Most schemes override
 * nothing. Autumn's and Spring's bar text is below the contrast targets above in places; the docs
 * give the ratios.
 */
// Spring's text colors: its near-black main text, and the pale yellow used on its dark green bars.
const SPRING_TEXT = { text: "#010500", textDim: "#040602", textMuted: "#070803", accent: "#0f060a", success: "#27462e", warning: "#604c0f", danger: "#732f4b" };
const SPRING_BAR_TEXT = { text: "#fae3a0", textDim: "#fae3a0", textMuted: "#fae3a0", accent: "#fae3a0", success: "#fae3a0", warning: "#fae3a0", danger: "#fae3a0" };

export const THEMES = {
  dark: {
    base: "dark",
    bg: "#0f1114", bgAlt: "#181b20", bgInput: "#12151a", border: "#2a2d33", borderAccent: "#E85D2A",
    text: "#e0ddd8", textDim: "#b0aaa4", textMuted: "#948e88", accent: "#E85D2A", accentHover: "#F47B50", onAccent: "#151311",
    rowOdd: "#141720", rowEven: "#0f1114", headerBg: "#181b20", headerText: "#E85D2A",
    selection: "rgba(232,93,42,0.14)", bookmark: "rgba(232,93,42,0.06)",
    modalBg: "#181b20", modalBorder: "#333639", overlay: "rgba(5,5,8,0.85)",
    success: "#4ade80", warning: "#F5A623", danger: "#f85149",
    btnBg: "#22252a", btnBorder: "#333639",
    // Unit 42 extended palette
    panelBg: "#0b0d10", cellBorder: "#12151a", accentSubtle: "rgba(232,93,42,0.12)",
    histBar: "#E85D2A", histBarHover: "#F47B50", histGrid: "#1e2028",
    primaryBtn: "#E85D2A", primaryBtnHover: "#F47B50", onPrimary: "#151311",
    toolbarBg: "rgba(24,27,32,0.82)", glassBg: "rgba(255,255,255,0.05)", glassBorder: "rgba(255,255,255,0.08)", glassHover: "rgba(255,255,255,0.10)",
    // Severity palette — used by SUS_COLORS, INT_COLOR, PI_SEV_COLORS, IOC verdicts.
    // Distinct from brand `accent` (which is #E85D2A): severity needs cooler reds, deeper amber, etc.
    sev: { critical: "#f85149", high: "#f0883e", med: "#d29922", low: "#8b949e", custom: "#a371f7", clean: "#3fb950", info: "#58a6ff" },
    bars: { top: {}, menu: {}, dropdown: {}, group: {}, search: {}, header: {}, inputs: {}, filters: {}, bottom: {} },
  },
  light: {
    base: "light",
    // A neutral workspace: soft gray chrome, white paper, navy ink and restrained
    // teal/blue controls. Amber bookmarks stay distinct from blue selections.
    bg: "#f5f7fa", bgAlt: "#edf2f7", bgInput: "#ffffff", border: "#c4cfdc", borderAccent: "#2563a6",
    text: "#172536", textDim: "#34465b", textMuted: "#506176", accent: "#0b6274", accentHover: "#084b5c", onAccent: "#ffffff",
    rowOdd: "#f4f7fb", rowEven: "#ffffff", headerBg: "#e2eaf3", headerText: "#233e5b",
    selection: "rgba(37,99,166,0.14)", bookmark: "rgba(210,144,24,0.13)",
    modalBg: "#ffffff", modalBorder: "#b7c5d5", overlay: "rgba(19,35,54,0.42)",
    success: "#187345", warning: "#925800", danger: "#c12c3e",
    btnBg: "#f8fafc", btnBorder: "#aebed0",
    panelBg: "#eaf0f6", cellBorder: "#e1e7ef", accentSubtle: "rgba(11,98,116,0.08)",
    histBar: "#337f9a", histBarHover: "#175c7a", histGrid: "#c4d0de",
    primaryBtn: "#2563a6", primaryBtnHover: "#1c4e86", onPrimary: "#ffffff",
    toolbarBg: "rgba(237,242,247,0.97)", glassBg: "rgba(255,255,255,0.55)", glassBorder: "rgba(48,74,105,0.16)", glassHover: "rgba(37,99,166,0.08)",
    sev: { critical: "#bd2035", high: "#b04b0a", med: "#895900", low: "#506176", custom: "#7045a2", clean: "#187345", info: "#2563a6" },
    bars: { top: {}, menu: {}, dropdown: {}, group: {}, search: {}, header: {}, inputs: {}, filters: {}, bottom: {} },
  },
  // ── Seasonal schemes ─────────────────────────────────────────────────────────
  // Spring reference: https://stitchpalettes.com/palette/uplifting-spring-spa1006/
  // Light Forest Green and the requested #678215 green dominate; floral accents remain.
  spring: {
    base: "light",
    bg: "#a6b784", bgAlt: "#678215", bgInput: "#fae3a0", border: "#678215", borderAccent: "#6f5497",
    text: "#010500", textDim: "#040602", textMuted: "#070803", accent: "#0f060a", accentHover: "#010500", onAccent: "#6f5497",
    rowOdd: "#a6b784", rowEven: "#a6b784", headerBg: "#a6b784", headerText: "#102015",
    selection: "rgba(178,165,205,0.22)", bookmark: "rgba(226,166,190,0.20)",
    modalBg: "#a6b784", modalBorder: "#6f5497", overlay: "rgba(36,51,41,0.55)",
    success: "#27462e", warning: "#604c0f", danger: "#732f4b",
    btnBg: "#678215", btnBorder: "#6f5497",
    panelBg: "#a6b784", cellBorder: "#678215", accentSubtle: "rgba(111,84,151,0.10)",
    histBar: "#6f5497", histBarHover: "#6f5497", histGrid: "#678215",
    primaryBtn: "#fae3a0", primaryBtnHover: "#fae3a0", onPrimary: "#6f5497",
    fillAccent: "#fae3a0", fillAccentHover: "#fae3a0", fillWarning: "#fae3a0", fillDanger: "#fae3a0",
    toolbarBg: "rgba(103,130,21,0.98)", glassBg: "rgba(166,183,132,0.30)", glassBorder: "rgba(111,84,151,0.30)", glassHover: "rgba(250,227,160,0.10)",
    sev: { critical: "#732f4b", high: "#7e3e19", med: "#604c0f", low: "#142017", custom: "#614786", clean: "#27462e", info: "#24475c" },
    // Pale-yellow text on the dark green bars (top row, tab bar, status bar); black text on the
    // light green menus, search conditions bar, group strip and column headers; pale-yellow
    // dropdowns and filter boxes with purple text.
    bars: {
      top: SPRING_BAR_TEXT,
      menu: {},
      dropdown: SPRING_TEXT,
      group: { ...SPRING_TEXT, borderAccent: "#010500" },
      search: {},
      header: SPRING_TEXT,
      inputs: { btnBg: "#fae3a0", textDim: "#6f5497" },
      filters: { text: "#6f5497" },
      bottom: { ...SPRING_BAR_TEXT, borderAccent: "#fae3a0" },
    },
  },
  // Sakura reference: https://img.magnific.com/premium-vector/color-element-trendy-pallete-color-sakura-color-pallete-swatch-summer-shade-tone-with-hex-code_615232-1235.jpg
  // Exact reference surfaces and accents, with plum foregrounds for readability.
  sakura: {
    base: "light",
    bg: "#fff4f3", bgAlt: "#ffdbdb", bgInput: "#fff4f3", border: "#d4e0ee", borderAccent: "#ec275f",
    text: "#432336", textDim: "#563647", textMuted: "#634153", accent: "#84264d", accentHover: "#70203f", onAccent: "#100810",
    rowOdd: "#ffdbdb", rowEven: "#fff4f3", headerBg: "#ffa7a6", headerText: "#432336",
    selection: "rgba(212,224,238,0.72)", bookmark: "rgba(255,167,166,0.28)",
    modalBg: "#fff4f3", modalBorder: "#f25477", overlay: "rgba(58,22,43,0.45)",
    success: "#286b4c", warning: "#8c5900", danger: "#ac294d",
    btnBg: "#ffdbdb", btnBorder: "#f25477",
    panelBg: "#fff4f3", cellBorder: "#d4e0ee", accentSubtle: "rgba(236,39,95,0.10)",
    histBar: "#f25477", histBarHover: "#ec275f", histGrid: "#d4e0ee",
    primaryBtn: "#ec275f", primaryBtnHover: "#f25477", onPrimary: "#100810",
    fillAccent: "#ec275f", fillAccentHover: "#f25477", fillWarning: "#ffa7a6", fillDanger: "#f25477",
    toolbarBg: "rgba(255,219,219,0.98)", glassBg: "rgba(255,244,243,0.30)", glassBorder: "rgba(236,39,95,0.18)", glassHover: "rgba(236,39,95,0.08)",
    sev: { critical: "#b32445", high: "#ab4c16", med: "#856000", low: "#634153", custom: "#81509b", clean: "#286b4c", info: "#37628c" },
    bars: { top: {}, menu: {}, dropdown: {}, group: {}, search: {}, header: {}, inputs: {}, filters: {}, bottom: {} },
  },
  // Summer reference: https://avemateiu.com/wp-content/uploads/2019/06/summer-color-palette-6.png
  // Aqua and sunny yellow dominate; citrus red, leaf green and sand are accents.
  summer: {
    base: "light",
    bg: "#a2eeeb", bgAlt: "#a2eeeb", bgInput: "#edc02c", border: "#6ebebd", borderAccent: "#f03613",
    text: "#101b24", textDim: "#304e5c", textMuted: "#3b535b", accent: "#005166", accentHover: "#004355", onAccent: "#0a1017",
    rowOdd: "#a2eeeb", rowEven: "#d1f6f4", headerBg: "#f3e2b3", headerText: "#23474d",
    selection: "rgba(39,180,110,0.16)", bookmark: "rgba(240,54,19,0.16)",
    modalBg: "#edc02c", modalBorder: "#6ebebd", overlay: "rgba(8,36,54,0.48)",
    success: "#196b47", warning: "#795000", danger: "#bb2a12",
    btnBg: "#f3e2b3", btnBorder: "#27b46e",
    panelBg: "#edc02c", cellBorder: "#8bd4d1", accentSubtle: "rgba(0,93,116,0.10)",
    histBar: "#007fba", histBarHover: "#005f98", histGrid: "#d5c593",
    primaryBtn: "#f3e2b3", primaryBtnHover: "#edc02c", onPrimary: "#0a1017",
    fillAccent: "#f3e2b3", fillAccentHover: "#edc02c", fillWarning: "#f3e2b3", fillDanger: "#f03613",
    toolbarBg: "rgba(243,226,179,0.98)", glassBg: "rgba(237,192,44,0.30)", glassBorder: "rgba(0,93,116,0.20)", glassHover: "rgba(240,54,19,0.10)",
    sev: { critical: "#bb2a12", high: "#ad420c", med: "#795000", low: "#3b535b", custom: "#74519b", clean: "#196b47", info: "#005d74" },
    bars: { top: {}, menu: {}, dropdown: {}, group: {}, search: {}, header: {}, inputs: {}, filters: {}, bottom: {} },
  },
  // Autumn reference: https://branding-lab.net/wp-content/uploads/2026/11/japanese-fall-color-palette.jpg
  // Momiji red, orange, yellow, leaf green, plum and brown, with cream text.
  autumn: {
    base: "dark",
    bg: "#6b3c2c", bgAlt: "#6b3c2c", bgInput: "#4b2a1f", border: "#a34c66", borderAccent: "#e9b626",
    text: "#fff8ed", textDim: "#fff1d8", textMuted: "#ffedd0", accent: "#fff4de", accentHover: "#fff8ed", onAccent: "#21120b",
    rowOdd: "#6b3c2c", rowEven: "#6b3c2c", headerBg: "#c93036", headerText: "#fff8ed",
    selection: "rgba(240,131,0,0.12)", bookmark: "rgba(131,163,60,0.13)",
    modalBg: "#c93036", modalBorder: "#f08300", overlay: "rgba(15,8,5,0.83)",
    success: "#d9e7b8", warning: "#ffdd7c", danger: "#ffb2a6",
    btnBg: "#a34c66", btnBorder: "#e9b626",
    panelBg: "#3b2018", cellBorder: "#a34c66", accentSubtle: "rgba(240,131,0,0.12)",
    histBar: "#c93036", histBarHover: "#f08300", histGrid: "#6b3c2c",
    primaryBtn: "#f08300", primaryBtnHover: "#e9b626", onPrimary: "#21120b",
    fillAccent: "#f08300", fillAccentHover: "#e9b626", fillWarning: "#e9b626", fillDanger: "#f08300",
    toolbarBg: "rgba(201,48,54,0.98)", glassBg: "rgba(233,182,38,0.06)", glassBorder: "rgba(233,182,38,0.25)", glassHover: "rgba(240,131,0,0.12)",
    sev: { critical: "#ffb2a6", high: "#ffd0a0", med: "#ffdd7c", low: "#ffedd0", custom: "#f1d7e0", clean: "#d9e7b8", info: "#d4e0ee" },
    // Red-brown bars above the timeline; red search conditions bar, group strip and column
    // headers; yellow text and dark orange lines on all of them (column names keep the cream
    // headerText); light green text in the dropdowns and search box; red status bar, yellow text.
    bars: {
      top: {
        toolbarBg: "rgba(107,60,44,0.98)", panelBg: "#6b3c2c",
        border: "#ff8c00", borderAccent: "#ff8c00", btnBorder: "#ff8c00", glassBorder: "#ff8c00",
        text: "#eac910", textDim: "#eac910", textMuted: "#eac910", accent: "#eac910", success: "#eac910", warning: "#eac910", danger: "#eac910",
      },
      menu: {},
      dropdown: {},
      group: { panelBg: "#c93036", borderAccent: "#eac910" },
      search: {},
      header: {},
      inputs: { text: "#a6b784", textDim: "#a6b784", textMuted: "#a6b784", btnBg: "#6b3c2c" },
      filters: {},
      bottom: { text: "#eac910", textDim: "#eac910", textMuted: "#eac910", accent: "#eac910", success: "#eac910", warning: "#eac910", danger: "#eac910", borderAccent: "#eac910" },
    },
  },
  // Winter — blue ice, snow-white rows and pale glacier-blue controls. Christmas
  // has its own scheme below; red and green here are reserved for status meanings.
  winter: {
    base: "light",
    bg: "#f4fbff", bgAlt: "#e3f3fc", bgInput: "#ffffff", border: "#b1cedf", borderAccent: "#6baccd",
    text: "#183749", textDim: "#365568", textMuted: "#456478", accent: "#16678d", accentHover: "#0a5276", onAccent: "#ffffff",
    rowOdd: "#ecf7fd", rowEven: "#ffffff", headerBg: "#d0eafa", headerText: "#24536e",
    selection: "rgba(66,139,185,0.18)", bookmark: "rgba(120,187,227,0.18)",
    modalBg: "#f8fcff", modalBorder: "#a6c8dc", overlay: "rgba(19,46,66,0.43)",
    success: "#276f62", warning: "#856000", danger: "#b33445",
    btnBg: "#ebf8ff", btnBorder: "#a6c8dc",
    panelBg: "#dff2ff", cellBorder: "#d5e9f5", accentSubtle: "rgba(65,141,183,0.10)",
    histBar: "#418db7", histBarHover: "#22688c", histGrid: "#b6d6e9",
    primaryBtn: "#b8e5fa", primaryBtnHover: "#9ddaf5", onPrimary: "#163e52",
    toolbarBg: "rgba(218,239,252,0.96)", glassBg: "rgba(255,255,255,0.42)", glassBorder: "rgba(37,95,132,0.16)", glassHover: "rgba(77,153,199,0.12)",
    sev: { critical: "#b33445", high: "#ad4c17", med: "#856000", low: "#456478", custom: "#685895", clean: "#276f62", info: "#16678d" },
    bars: { top: {}, menu: {}, dropdown: {}, group: {}, search: {}, header: {}, inputs: {}, filters: {}, bottom: {} },
  },
  // Christmas reference: https://www.schemecolor.com/christmas-hex-color-codes.php
  // Both greens frame the workspace; red headers/actions and vermillion/gold bars add contrast.
  christmas: {
    base: "dark",
    bg: "#165b33", bgAlt: "#146b3a", bgInput: "#0d371f", border: "#367c4e", borderAccent: "#f8b229",
    text: "#fff8ed", textDim: "#f2e3d1", textMuted: "#e7d9c3", accent: "#ffe2a1", accentHover: "#fff0cd", onAccent: "#fff8ed",
    rowOdd: "#165b33", rowEven: "#14532f", headerBg: "#bb2528", headerText: "#fff8ed",
    selection: "rgba(248,178,41,0.04)", bookmark: "rgba(234,70,48,0.12)",
    modalBg: "#165b33", modalBorder: "#f8b229", overlay: "rgba(6,26,15,0.82)",
    success: "#a5e5b3", warning: "#f8b229", danger: "#ffaaa0",
    btnBg: "#104829", btnBorder: "#367c4e",
    panelBg: "#0d371f", cellBorder: "#146b3a", accentSubtle: "rgba(248,178,41,0.10)",
    histBar: "#ea4630", histBarHover: "#f8b229", histGrid: "#367c4e",
    primaryBtn: "#bb2528", primaryBtnHover: "#9e1f23", onPrimary: "#fff8ed",
    fillAccent: "#bb2528", fillAccentHover: "#9e1f23", fillWarning: "#bb2528", fillDanger: "#bb2528",
    toolbarBg: "rgba(20,107,58,0.98)", glassBg: "rgba(255,248,237,0.06)", glassBorder: "rgba(248,178,41,0.25)", glassHover: "rgba(248,178,41,0.10)",
    sev: { critical: "#ffaaa0", high: "#ffc087", med: "#f8b229", low: "#e7d9c3", custom: "#dfc3ee", clean: "#a5e5b3", info: "#b8e5fa" },
    // The search conditions bar is red while a search is typed, like the column headers; "Clear All"
    // in the group strip and the status bar is vermillion.
    bars: { top: {}, menu: {}, dropdown: {}, group: { danger: "#ea4630" }, search: { panelBg: "#bb2528" }, header: {}, inputs: {}, filters: {}, bottom: { danger: "#ea4630" } },
  },
};

// Separate foreground accents from opaque control fills. Existing palettes keep
// their original fills; reference palettes may need a different button background.
for (const th of Object.values(THEMES)) {
  th.fillAccent ??= th.accent;
  th.fillAccentHover ??= th.accentHover;
  th.fillWarning ??= th.warning;
  th.fillDanger ??= th.danger;
}

export const DEFAULT_THEME = "dark";

/**
 * The schemes in menu order, with the labels the Color Scheme menus show.
 * `icon` is only used by the in-app toolbar picker; the native macOS menu shows `label`.
 */
export const THEME_OPTIONS = [
  { id: "dark", label: "Dark Mode", icon: "🌙", description: "Charcoal with the orange accent (default)" },
  { id: "light", label: "Light Mode", icon: "☀️", description: "Soft gray and white, navy text, teal and blue accents" },
  { id: "spring", label: "Spring", icon: "🌱", description: "Light forest green, fresh #678215 green bars with pale-yellow text, purple text in the filter boxes" },
  { id: "sakura", label: "Sakura", icon: "🌸", description: "Reference Sakura pinks, cream, pale blue and plum text" },
  { id: "summer", label: "Summer", icon: "🌊", description: "Aqua blue, pale-yellow headers and sunny-yellow chart panels" },
  { id: "autumn", label: "Autumn", icon: "🍂", description: "Japanese autumn: red-brown timeline and toolbar, red headers and status bar, yellow text" },
  { id: "winter", label: "Winter", icon: "❄️", description: "Snow white and pale glacier blue" },
  { id: "christmas", label: "Christmas", icon: "🎄", description: "Forest and jewel greens, festive red headers and controls, vermillion and gold charts" },
];

export const THEME_IDS = THEME_OPTIONS.map((option) => option.id);

/** True for the id of a known color scheme (and nothing else — `toString` is not a scheme). */
export function isThemeName(name) {
  return typeof name === "string" && Object.prototype.hasOwnProperty.call(THEMES, name);
}

/** The theme object for `name`, or the default scheme when `name` is unknown or stale. */
export function resolveTheme(name) {
  return THEMES[isThemeName(name) ? name : DEFAULT_THEME];
}

/** The theme with the scheme's `bars` overrides for the given parts applied in order (later parts win). */
export function barTheme(theme, ...parts) {
  const overrides = Object.assign({}, ...parts.map((part) => theme.bars?.[part] || {}));
  return Object.keys(overrides).length ? { ...theme, ...overrides } : theme;
}

/** Whether `name` resolves to a dark-based scheme. */
export function isDarkTheme(name) {
  return resolveTheme(name).base === "dark";
}

/** Build once per histogram render; interpolate the theme's two density endpoints. */
export function createHistogramColorScale(theme) {
  const rgb = (hex) => hex.match(/[0-9a-f]{2}/gi).map((part) => parseInt(part, 16));
  const low = rgb(theme.histBar);
  const high = rgb(theme.histBarHover);
  return (ratio) => {
    const t = Math.max(0, Math.min(1, ratio));
    return `rgb(${low.map((channel, i) => Math.round(channel + (high[i] - channel) * t)).join(",")})`;
  };
}
