/**
 * ui-prefs.js — Small JSON store for display preferences that must survive a restart.
 *
 * Today it holds the color scheme. The store is
 * created with an explicit file path (main.js passes <userData>/ui-prefs.json) so it has
 * no Electron dependency and the tests can point it at a temp directory. Every read is
 * sanitized: unknown or corrupt values fall back to the defaults instead of throwing.
 */
const fs = require("fs");
const path = require("path");
const { DEFAULT_THEME, normalizeThemeId, isThemeId } = require("./themes");

function sanitizeUiPrefs(raw) {
  const source = raw && typeof raw === "object" ? raw : {};
  const themeName = normalizeThemeId(source.themeName);
  return {
    themeName: isThemeId(themeName) ? themeName : DEFAULT_THEME,
  };
}

function createUiPrefsStore(filePath) {
  function load() {
    try {
      return sanitizeUiPrefs(JSON.parse(fs.readFileSync(filePath, "utf8")));
    } catch {
      return sanitizeUiPrefs({});
    }
  }

  /** Merge `patch` into the stored preferences and return the sanitized result. */
  function save(patch) {
    const next = sanitizeUiPrefs({ ...load(), ...(patch || {}) });
    try {
      fs.mkdirSync(path.dirname(filePath), { recursive: true });
      fs.writeFileSync(filePath, JSON.stringify(next, null, 2), "utf8");
    } catch {
      // A read-only or missing profile directory must never take the UI down with it.
    }
    return next;
  }

  return { load, save, filePath };
}

module.exports = { createUiPrefsStore, sanitizeUiPrefs };
