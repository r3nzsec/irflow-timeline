// The filters set under the column headers, as Edit Filter
// lists and saves them (src/components/modals/EditFilterModal.jsx).
import { normalizeCheckboxFilterValues } from "./ai-history-profile.js";

// Internal names of the special columns' filters under the headers.
const SPECIAL_COLUMNS = { __tags__: "Tags", __vt__: "VT" };
export const headerFilterColumnLabel = (column) => SPECIAL_COLUMNS[column] || column;

/**
 * The filters set under the column headers, in column order: the text box (contains), the ▼ value
 * list and the date range. A header filter turned off with its toggle isn't listed (it isn't
 * filtering) and is left as it is.
 */
export function headerFilterRows(ct) {
  const off = ct.disabledFilters || new Set();
  const rows = [];
  for (const [column, value] of Object.entries(ct.columnFilters || {})) {
    if (value && !off.has(column)) rows.push({ kind: "text", column, value });
  }
  for (const [column, raw] of Object.entries(ct.checkboxFilters || {})) {
    const values = normalizeCheckboxFilterValues(raw);
    if (values.length && !off.has(column)) rows.push({ kind: "values", column, values });
  }
  for (const [column, range] of Object.entries(ct.dateRangeFilters || {})) {
    if (range && (range.from || range.to)) rows.push({ kind: "date", column, from: range.from || "", to: range.to || "" });
  }
  const order = new Map(["__tags__", "__vt__", ...(ct.headers || [])].map((h, i) => [h, i]));
  const kinds = { text: 0, values: 1, date: 2 };
  rows.sort((a, b) => ((order.get(a.column) ?? 1e9) - (order.get(b.column) ?? 1e9)) || (kinds[a.kind] - kinds[b.kind]));
  return rows.map((r) => ({ ...r, key: `${r.kind}\u0000${r.column}` }));
}

/**
 * The header filters after the dialog: rows still listed keep their (edited) text; rows removed,
 * or whose text was emptied, are cleared. Filters the dialog didn't list are kept.
 */
export function applyHeaderFilterRows(ct, shownRows, rows) {
  const columnFilters = { ...(ct.columnFilters || {}) };
  const checkboxFilters = { ...(ct.checkboxFilters || {}) };
  const dateRangeFilters = { ...(ct.dateRangeFilters || {}) };
  const kept = new Map(rows.map((r) => [r.key, r]));
  for (const shown of shownRows) {
    const r = kept.get(shown.key);
    if (shown.kind === "text") {
      if (r && r.value) columnFilters[shown.column] = r.value;
      else delete columnFilters[shown.column];
    } else if (!r) {
      if (shown.kind === "values") delete checkboxFilters[shown.column];
      else delete dateRangeFilters[shown.column];
    }
  }
  return { columnFilters, checkboxFilters, dateRangeFilters };
}
