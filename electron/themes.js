/**
 * themes.js — Color-scheme catalog for the main process.
 *
 * The renderer owns the full token sets in
 * src/constants/themes.js; the main process only needs each scheme's id, menu label and
 * window background (painted before the renderer loads, so a light scheme does not flash
 * dark on launch). tests/color-schemes.test.js fails if the two files drift apart.
 */
const THEME_OPTIONS = Object.freeze([
  Object.freeze({ id: "dark", label: "Dark Mode", windowBackground: "#0f1114" }),
  Object.freeze({ id: "light", label: "Light Mode", windowBackground: "#f5f7fa" }),
  Object.freeze({ id: "spring", label: "Spring", windowBackground: "#a6b784" }),
  Object.freeze({ id: "sakura", label: "Sakura", windowBackground: "#fff4f3" }),
  Object.freeze({ id: "summer", label: "Summer", windowBackground: "#a2eeeb" }),
  Object.freeze({ id: "autumn", label: "Autumn", windowBackground: "#6b3c2c" }),
  Object.freeze({ id: "winter", label: "Winter", windowBackground: "#f4fbff" }),
  Object.freeze({ id: "christmas", label: "Christmas", windowBackground: "#165b33" }),
]);

const DEFAULT_THEME = "dark";

// Older previews stored the surviving palette as `christmas-2`.
function normalizeThemeId(value) {
  return value === "christmas-2" ? "christmas" : value;
}

function isThemeId(value) {
  return typeof value === "string" && THEME_OPTIONS.some((option) => option.id === value);
}

function windowBackgroundFor(themeId) {
  const option = THEME_OPTIONS.find((o) => o.id === normalizeThemeId(themeId)) || THEME_OPTIONS.find((o) => o.id === DEFAULT_THEME);
  return option.windowBackground;
}

module.exports = { THEME_OPTIONS, DEFAULT_THEME, normalizeThemeId, isThemeId, windowBackgroundFor };
