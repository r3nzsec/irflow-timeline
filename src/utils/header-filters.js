// The filters set under the column headers, as Edit Filter
// lists and saves them (src/components/modals/EditFilterModal.jsx), and the operators a header
// text filter can use (the grid's filter row, src/components/VirtualGrid.jsx).
import { normalizeCheckboxFilterValues } from "./ai-history-profile.js";

/** Filter operators, as Edit Filter and the header filters offer them. `symbol` labels the header filter's button. */
export const FILTER_OPERATORS = [
  { value: "contains", label: "Contains", symbol: "~" },
  { value: "not_contains", label: "Does not contain", symbol: "!~" },
  { value: "equals", label: "Equals", symbol: "=" },
  { value: "not_equals", label: "Does not equal", symbol: "≠" },
  { value: "starts_with", label: "Starts with", symbol: "a…" },
  { value: "ends_with", label: "Ends with", symbol: "…a" },
  { value: "greater_than", label: "Greater than", symbol: ">" },
  { value: "less_than", label: "Less than", symbol: "<" },
  { value: "is_empty", label: "Is empty", symbol: "∅" },
  { value: "is_not_empty", label: "Is not empty", symbol: "!∅" },
  { value: "regex", label: "Matches regex", symbol: ".*" },
];
export const NO_VALUE_OPERATORS = new Set(["is_empty", "is_not_empty"]);
export const filterOperator = (op) => FILTER_OPERATORS.find((o) => o.value === op) || FILTER_OPERATORS[0];

/**
 * A header text filter is stored as a string (Contains, as before) or as { op, value } for
 * another operator, so every query that passes the tab's column filters keeps the operator.
 */
export function columnFilterParts(raw) {
  if (raw && typeof raw === "object") return { op: raw.op || "contains", value: raw.value == null ? "" : String(raw.value) };
  return { op: "contains", value: raw == null ? "" : String(raw) };
}

export function encodeColumnFilter(op, value) {
  if (!op || op === "contains") return value || "";
  return { op, value: NO_VALUE_OPERATORS.has(op) ? "" : (value || "") };
}

/** Whether a stored header text filter filters anything. */
export function isActiveColumnFilter(raw) {
  const { op, value } = columnFilterParts(raw);
  return NO_VALUE_OPERATORS.has(op) || value !== "";
}

// Internal names of the special columns' filters under the headers.
const SPECIAL_COLUMNS = { __tags__: "Tags", __vt__: "VT" };
export const headerFilterColumnLabel = (column) => SPECIAL_COLUMNS[column] || column;

/**
 * The filters set under the column headers, in column order: the text box (with its operator), the ▼ value
 * list and the date range. A header filter turned off with its toggle isn't listed (it isn't
 * filtering) and is left as it is.
 */
export function headerFilterRows(ct) {
  const off = ct.disabledFilters || new Set();
  const rows = [];
  for (const [column, raw] of Object.entries(ct.columnFilters || {})) {
    const { op, value } = columnFilterParts(raw);
    if (isActiveColumnFilter(raw) && !off.has(column)) rows.push({ kind: "text", column, op, value });
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
      if (r && (r.value || NO_VALUE_OPERATORS.has(r.op))) columnFilters[shown.column] = encodeColumnFilter(r.op, r.value);
      else delete columnFilters[shown.column];
    } else if (!r) {
      if (shown.kind === "values") delete checkboxFilters[shown.column];
      else delete dateRangeFilters[shown.column];
    }
  }
  return { columnFilters, checkboxFilters, dateRangeFilters };
}
