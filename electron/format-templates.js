/**
 * format-templates.js — Known CSV output formats whose timestamp columns are declared, not guessed.
 *
 * Templates for every Juntei CSV output (electron/juntei-templates.json). When a file's header
 * row is a template's columns, the template's timestampColumns are the tab's timestamp columns,
 * exactly: no other column is formatted, converted, sorted or filtered as a date, whatever its
 * name or values look like.
 *
 * The renderer reads the same JSON (src/utils/dataset-detect.js) and must pick the same
 * template; tests/juntei-templates.test.js checks both.
 */

const JUNTEI = require("./juntei-templates.json");

const TEMPLATES = JUNTEI.templates;

/**
 * Whether `headers` is the output a template describes: every one of its columns is there, and
 * no other column is, except its optionalColumns (or any column, with allowExtraColumns).
 */
function matchesTemplate(t, present) {
  if (!t.columns.every((c) => present.has(c))) return false;
  if (t.allowExtraColumns) return true;
  const known = new Set([...t.columns, ...(t.optionalColumns || [])]);
  for (const h of present) if (!known.has(h)) return false;
  return true;
}

/**
 * The template that matches `headers`. When several do, the one with the most columns wins, so
 * an output whose columns contain another output's columns is still told apart.
 * @param {string[]} headers
 * @returns {{ name: string, columns: string[], timestampColumns: string[] } | null}
 */
function detectFormatTemplate(headers) {
  const present = new Set(headers || []);
  let best = null;
  for (const t of TEMPLATES) {
    if (!matchesTemplate(t, present)) continue;
    if (!best || t.columns.length > best.columns.length) best = t;
  }
  return best;
}

module.exports = { detectFormatTemplate, FORMAT_TEMPLATES: TEMPLATES };
