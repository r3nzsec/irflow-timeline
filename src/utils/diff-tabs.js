/**
 * Renderer helpers for View → Diff Tabs.
 * Matching itself lives in electron/db/diff-tabs.js (CJS). Keep identity scoring
 * here in sync with `scoreIdentityColumn` / `suggestMatchKeys` in that file.
 */

export const DIFF_META_COLUMNS = [
  "_Diff",
  "_Baseline",
  "_Compare",
  "_MatchKey",
  "_ChangedFields",
  "_DiffSummary",
  "_DiffDetail",
];

export const DIFF_COLUMN_ORDER = [
  "_Diff",
  "_ChangedFields",
  "_DiffSummary",
  "datetime",
  "_MatchKey",
  "_Baseline",
  "_Compare",
];

export const DIFF_STATUSES = ["Added", "Removed", "Changed", "Unchanged"];

export function isDiffTab(tab) {
  return tab?.sourceFormat === "tab-diff" || tab?.diffMeta?.kind === "tab-diff";
}

export function isDiffMetaColumn(name) {
  const n = String(name || "");
  return n === "datetime" || DIFF_META_COLUMNS.includes(n);
}

export function scoreIdentityColumn(name) {
  const n = String(name || "").toLowerCase();
  if (!n || n.startsWith("_")) return 0;
  if (n === "eventrecordid" || n === "recordnumber" || n === "recordid" || n === "event_record_id") return 100;
  if (n === "uuid" || n === "guid" || n.endsWith("uuid") || n.endsWith("guid")) return 95;
  if (/(^|_)(sha-?1|sha-?256|md5)$/.test(n) || n.endsWith("hash")) return 88;
  if (n === "sourcefile" || n === "fullpath" || n === "filepath" || n === "path") return 72;
  if (/(message|payload|content|summary|fulltext|description|commandline|command)$/.test(n)) return 8;
  if (n === "eventkind" || n === "recordtype" || n === "artifactname" || n === "sourcetype") return 58;
  if (n === "activity" || n === "action" || n === "operation") return 52;
  if (n === "eventid" || n === "event_id" || n === "eid") return 48;
  if (n === "computer" || n === "hostname" || n === "host") return 45;
  if (n === "filename" || n === "name") return 40;
  if (/(time|date|timestamp|created|modified|accessed)/i.test(n) && !/id$/.test(n)) return 42;
  if (/id$/i.test(n)) return 70;
  return 12;
}

export function suggestMatchKeys(headersA, headersB) {
  const a = new Set(headersA || []);
  const common = (headersB || []).filter((h) => a.has(h) && !isDiffMetaColumn(h));
  const scored = common
    .map((h) => ({ h, s: scoreIdentityColumn(h) }))
    .sort((x, y) => y.s - x.s || x.h.localeCompare(y.h));

  const strong = scored.filter((x) => x.s >= 88).map((x) => x.h);
  if (strong.length) return [...new Set(strong.slice(0, 4))];

  const auto = [];
  const pick = (name) => {
    if (common.includes(name) && !auto.includes(name)) auto.push(name);
  };
  const idish = scored.find((x) => x.s >= 70);
  if (idish) auto.push(idish.h);

  pick("EventRecordId");
  pick("RecordNumber");
  pick("SourceFile");
  pick("Timestamp");
  pick("TimeCreated");
  pick("DateTime");
  pick("EventKind");
  pick("Activity");
  pick("EventId");
  pick("Computer");

  if (auto.length) return auto.slice(0, 6);
  return scored.filter((x) => x.s >= 40).slice(0, 4).map((x) => x.h);
}

export function schemaDelta(headersA, headersB) {
  const a = new Set(headersA || []);
  const b = new Set(headersB || []);
  const onlyA = [...a].filter((h) => !b.has(h) && !isDiffMetaColumn(h)).sort();
  const onlyB = [...b].filter((h) => !a.has(h) && !isDiffMetaColumn(h)).sort();
  const common = [...a].filter((h) => b.has(h) && !isDiffMetaColumn(h)).sort();
  return { onlyA, onlyB, common };
}

export function parseDiffDetail(raw) {
  if (Array.isArray(raw)) return raw.filter((p) => p && p.f);
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((p) => p && p.f) : [];
  } catch {
    return [];
  }
}

export function diffStatusColor(status, th) {
  switch (status) {
    case "Added": return th.success;
    case "Removed": return th.danger;
    case "Changed": return th.warning;
    default: return th.textMuted;
  }
}

export function buildDiffColorRules(th) {
  const rule = (value, color) => ({
    column: "_Diff",
    condition: "equals",
    value,
    bgColor: `${color}28`,
    fgColor: color,
  });
  return [
    rule("Added", th.success),
    rule("Removed", th.danger),
    rule("Changed", th.warning),
    rule("Unchanged", th.textMuted),
  ];
}

export function diffStatusFilter(checkboxFilters) {
  const list = checkboxFilters?._Diff;
  if (!Array.isArray(list) || list.length === 0) return null;
  return list;
}
