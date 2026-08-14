/**
 * analyzers/ai-history — AI-specific secret / credential / PII leak detector.
 *
 * Scans AI-assistant query history (prompts the subject typed + model responses) for leaked
 * secrets — API keys, tokens, private keys, hardcoded credentials — and, in Deep mode, PII and
 * high-entropy "unknown" secrets. Emits findings with a MITRE ATT&CK mapping. Same analyzer
 * contract as the others: analyzeAiHistory(meta, opts) receives the tab DB meta (meta.db
 * better-sqlite3 handle + meta.colMap name->c0..cN) and returns { findings, summary }. The core
 * (analyzeAiHistoryRows) is pure and unit-testable without a SQLite binding.
 *
 * Two-stage detection:
 *   1. catalog regex (detection-rules.js), each run through compileSafeRegex (ReDoS guard + 64KB
 *      per-value cap) so a malformed/expensive rule is dropped rather than hanging the process;
 *   2. precision layer (validators.js): structural validators (Luhn/IBAN/entropy) + a placeholder
 *      allow-list drop false matches; a Deep-mode entropy pass catches secrets no named rule knows.
 *
 * Findings are permanently redacted (first4…last4 + length) and fingerprinted (salted SHA-256).
 * Cleartext never crosses the normal worker/main/renderer result path. A reveal must re-read and
 * verify one requested span from source evidence in the main process.
 */

const crypto = require("crypto");
const { dbg } = require("../../logger");
const { compileSafeRegex, MAX_VALUE_LEN } = require("../../utils/safe-regex");
const { AI_DETECTION_RULES } = require("./detection-rules");
const {
  isPlaceholderValue,
  isKnownExampleValue,
  isPublicTestCardNumber,
  scanEntropyCandidates,
  classifyEntropyCandidate,
  redactValue,
  fingerprint,
} = require("./validators");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const SNIPPET_PAD = 48; // chars of context around a match
const MAX_MATCHES_PER_RULE_PER_TEXT = 100;
const SCAN_CHUNK_LEN = MAX_VALUE_LEN;
// The largest catalog match is a 12 KiB PEM block. An overlap larger than that ensures a match
// crossing a chunk boundary is wholly present in at least one chunk.
const SCAN_CHUNK_OVERLAP = 16 * 1024;
const MAX_IN_MEMORY_FINDINGS = 10_000;
const MAX_AGGREGATE_KEYS = 100_000;
const EVIDENCE_FIELDS = Object.freeze(["FullText", "ToolInput", "ToolCommand", "ToolDescription"]);

/** Compile + safety-gate the raw rule catalog once at load. Unsafe/invalid rules are skipped. */
function compileRules(rawRules) {
  const out = [];
  for (const r of rawRules || []) {
    // flags default to "i", but "" must stay case-sensitive (token formats) — nullish, not ||.
    const compiled = compileSafeRegex(r.regex, r.flags != null ? r.flags : "i");
    if (compiled.error) {
      dbg("AIHIST", "skip unsafe AI detection rule", { id: r.id, error: compiled.error });
      continue;
    }
    out.push({ ...r, _test: compiled.test, _re: compiled.re });
  }
  return out;
}

const COMPILED_RULES = compileRules(AI_DETECTION_RULES);

function roleMatches(scope, role) {
  if (!scope || scope === "any") return true;
  return scope === String(role || "").toLowerCase();
}

/** Keep the most specific detector when several match the same span; the rest become alsoMatched. */
function rulePriority(r) {
  switch (r.category) {
    case "private-key": return 5;
    case "secret-cloud":
    case "secret-scm":
    case "secret-ai":
    case "secret-payment":
    case "secret-messaging": return 4;
    case "secret-generic": return 3;
    case "pii": return 2;
    case "high-entropy": return 1;
    default: return 0;
  }
}

function spansOverlap(i1, l1, i2, l2) {
  return i1 < i2 + l2 && i2 < i1 + l1;
}

/** Inline mask for snippet display (no length suffix — that lives in `redacted`). */
function maskInline(value) {
  const s = String(value || "");
  if (s.length <= 8) return "•".repeat(Math.max(1, s.length));
  return `${s.slice(0, 4)}${"•".repeat(Math.min(8, s.length - 8))}${s.slice(-4)}`;
}

function adjustedRuleForValue(rule, value) {
  if (rule.id === "pii-credit-card" && isPublicTestCardNumber(value)) {
    return {
      ...rule,
      title: "Credit Card Number (public test number)",
      severity: "low",
      confidence: "informational",
      publicTestValue: true,
    };
  }
  return rule;
}

function validatedConfidence(rule) {
  return rule.validatedConfidence || "verified";
}

/**
 * Catalog matches for one text/role. Pure. Returns
 * [{ rule, value, matchText, index, confidence }] after validators + placeholder filtering.
 */
function findMatchesInBoundedText(text, role, rules = COMPILED_RULES, baseOffset = 0, counts = new Map()) {
  if (!text) return [];
  const s = typeof text === "string" ? text : String(text);
  const bounded = s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s;
  const out = [];
  for (const r of rules) {
    if (!roleMatches(r.roleScope, role)) continue;
    // Fresh global clone so every same-rule secret in the message is reported without leaking
    // lastIndex state across rows. The per-rule cap bounds pathological high-density rows.
    const flags = r._re.flags.includes("g") ? r._re.flags : `${r._re.flags}g`;
    const probe = new RegExp(r._re.source, flags);
    let m;
    let seenForRule = counts.get(r.id) || 0;
    while ((m = probe.exec(bounded)) !== null) {
      if (++seenForRule > MAX_MATCHES_PER_RULE_PER_TEXT) break;
      let value = r.valueGroup && m[r.valueGroup] != null ? String(m[r.valueGroup]) : m[0];
      let matchText = m[0];
      let valIdx = r.valueGroup && m[r.valueGroup] != null
        ? (bounded.indexOf(m[r.valueGroup], m.index) >= 0 ? bounded.indexOf(m[r.valueGroup], m.index) : m.index)
        : m.index;
      if (typeof r.extract === "function") {
        try {
          const extracted = r.extract(bounded, m, { value, matchText, index: valIdx });
          if (extracted?.value) {
            value = String(extracted.value);
            matchText = String(extracted.matchText || extracted.value);
            valIdx = extracted.index != null ? Number(extracted.index) : valIdx;
          }
        } catch {
          value = r.valueGroup && m[r.valueGroup] != null ? String(m[r.valueGroup]) : m[0];
          matchText = m[0];
          valIdx = r.valueGroup && m[r.valueGroup] != null
            ? (bounded.indexOf(m[r.valueGroup], m.index) >= 0 ? bounded.indexOf(m[r.valueGroup], m.index) : m.index)
            : m.index;
        }
      }
      if (!isPlaceholderValue(value) && !isKnownExampleValue(value)) {
        let confidence = r.confidence || "suspicious";
        let rule = r;
        let ok = true;
        if (typeof r.validate === "function") {
          ok = false;
          try { ok = !!r.validate(value, m, bounded); } catch { ok = false; }
          if (ok) confidence = validatedConfidence(r);
        }
        if (ok) {
          rule = adjustedRuleForValue(r, value);
          if (rule.publicTestValue) confidence = rule.confidence || "informational";
          out.push({ rule, value, matchText, index: baseOffset + valIdx, confidence, priority: rulePriority(rule) });
        }
      }
      if (m.index === probe.lastIndex) probe.lastIndex++;
    }
    counts.set(r.id, Math.min(seenForRule, MAX_MATCHES_PER_RULE_PER_TEXT));
  }
  return out;
}

/** Catalog matches over the complete value using bounded, overlapping regex windows. */
function findMatchesInText(text, role, rules = COMPILED_RULES) {
  const s = typeof text === "string" ? text : String(text || "");
  if (!s) return [];
  const counts = new Map();
  const hits = [];
  const seen = new Set();
  const step = SCAN_CHUNK_LEN - SCAN_CHUNK_OVERLAP;
  for (let start = 0; start < s.length; start += step) {
    const chunk = s.slice(start, start + SCAN_CHUNK_LEN);
    for (const hit of findMatchesInBoundedText(chunk, role, rules, start, new Map())) {
      const key = `${hit.rule.id}\u0000${hit.index}\u0000${hit.value.length}`;
      if (seen.has(key)) continue;
      const count = counts.get(hit.rule.id) || 0;
      if (count >= MAX_MATCHES_PER_RULE_PER_TEXT) continue;
      seen.add(key);
      counts.set(hit.rule.id, count + 1);
      hits.push(hit);
    }
    if (start + SCAN_CHUNK_LEN >= s.length) break;
  }
  return hits;
}

/** Deep-mode entropy pass — catches high-entropy secrets no named rule matched. */
function findEntropyHitsBounded(text, existing, baseOffset = 0) {
  const s = typeof text === "string" ? text : String(text || "");
  const bounded = s.length > MAX_VALUE_LEN ? s.slice(0, MAX_VALUE_LEN) : s;
  const out = [];
  for (const c of scanEntropyCandidates(bounded)) {
    const globalIndex = baseOffset + c.index;
    if (existing.some((h) => spansOverlap(h.index, h.matchText.length, globalIndex, c.value.length))) continue;
    const cls = classifyEntropyCandidate(c, bounded);
    if (!cls) continue;
    out.push({
      rule: {
        id: "high-entropy", title: "High-entropy string (possible secret)", category: "high-entropy",
        severity: cls.severity, mitreId: "T1552.001", mitreName: "Unsecured Credentials: Credentials In Files",
      },
      value: c.value, matchText: c.value, index: globalIndex, confidence: cls.confidence, priority: 1,
    });
  }
  return out;
}

function findEntropyHits(text, existing) {
  const s = typeof text === "string" ? text : String(text || "");
  if (!s) return [];
  const hits = [];
  const seen = new Set();
  const step = SCAN_CHUNK_LEN - SCAN_CHUNK_OVERLAP;
  for (let start = 0; start < s.length; start += step) {
    const chunk = s.slice(start, start + SCAN_CHUNK_LEN);
    for (const hit of findEntropyHitsBounded(chunk, [...existing, ...hits], start)) {
      const key = `${hit.index}\u0000${hit.value.length}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hits.push(hit);
      if (hits.length >= 200) return hits;
    }
    if (start + SCAN_CHUNK_LEN >= s.length) break;
  }
  return hits;
}

/** Resolve overlapping spans to the highest-priority detector; fold the rest into alsoMatched. */
function dedupeOverlaps(hits) {
  const sorted = [...hits].sort((a, b) =>
    b.priority - a.priority
    || (SEVERITY_RANK[b.rule.severity] || 0) - (SEVERITY_RANK[a.rule.severity] || 0));
  const kept = [];
  for (const h of sorted) {
    const owner = kept.find((k) => spansOverlap(k.index, k.matchText.length, h.index, h.matchText.length));
    if (owner) {
      if (owner.rule.id !== h.rule.id) (owner.alsoMatched = owner.alsoMatched || []).push(h.rule.id);
      continue;
    }
    kept.push(h);
  }
  return kept;
}

function leakDirectionFor(role) {
  const r = String(role || "").toLowerCase();
  if (r === "user") return "user→service";
  if (r === "assistant") return "service→user";
  return "";
}

function buildFinding(hit, row, ctx) {
  const r = hit.rule;
  const role = row.role || "";
  const text = ctx.text;
  const start = Math.max(0, hit.index - SNIPPET_PAD);
  const end = Math.min(text.length, hit.index + hit.matchText.length + SNIPPET_PAD);
  let seg = text.slice(start, end);
  seg = seg.split(hit.value).join(maskInline(hit.value));
  if (hit.matchText !== hit.value) seg = seg.split(hit.matchText).join(maskInline(hit.matchText));
  const snippet = `${start > 0 ? "…" : ""}${seg}${end < text.length ? "…" : ""}`.replace(/\s+/g, " ").trim();

  const finding = {
    ruleId: r.id,
    category: r.category,
    title: r.title,
    severity: r.severity,
    confidence: hit.confidence,
    mitreId: r.mitreId || "",
    mitreName: r.mitreName || "",
    rowId: row.rowId != null ? String(row.rowId) : "",
    recordId: row.recordId != null ? String(row.recordId) : "",
    timestamp: row.timestamp || "",
    tool: row.tool || "",
    role,
    sessionId: row.sessionId || "",
    sourceFile: row.sourceFile || "",
    lineNumber: row.lineNumber || "",
    workspace: row.workspace || "",
    messageId: row.messageId || "",
    evidenceField: ctx.evidenceField || "FullText",
    startOffset: hit.index,
    endOffset: hit.index + hit.value.length,
    leakDirection: leakDirectionFor(role),
    redacted: redactValue(hit.value),
    fingerprint: fingerprint(hit.value, ctx.salt),
    alsoMatched: hit.alsoMatched || [],
    snippet,
  };
  return finding;
}

class SummaryAccumulator {
  constructor(maxKeys = MAX_AGGREGATE_KEYS) {
    this.maxKeys = maxKeys;
    this.total = 0;
    this.bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    this.byCategory = {};
    this.byConfidence = {};
    this.mitreMap = new Map();
    this.rowKeys = new Set();
    this.fingerprints = new Set();
    this.rowKeysCapped = false;
    this.fingerprintsCapped = false;
  }

  add(f) {
    this.total++;
    this.bySeverity[f.severity] = (this.bySeverity[f.severity] || 0) + 1;
    this.byCategory[f.category] = (this.byCategory[f.category] || 0) + 1;
    this.byConfidence[f.confidence] = (this.byConfidence[f.confidence] || 0) + 1;
    const rowKey = f.rowId || f.recordId;
    if (rowKey != null && String(rowKey) !== "") {
      if (this.rowKeys.size < this.maxKeys || this.rowKeys.has(String(rowKey))) this.rowKeys.add(String(rowKey));
      else this.rowKeysCapped = true;
    }
    if (f.fingerprint) {
      if (this.fingerprints.size < this.maxKeys || this.fingerprints.has(f.fingerprint)) this.fingerprints.add(f.fingerprint);
      else this.fingerprintsCapped = true;
    }
    if (f.mitreId) {
      const e = this.mitreMap.get(f.mitreId) || { id: f.mitreId, name: f.mitreName || "", count: 0 };
      e.count += 1;
      this.mitreMap.set(f.mitreId, e);
    }
  }

  value() {
    let severity = "info";
    if (this.bySeverity.critical) severity = "critical";
    else if (this.bySeverity.high) severity = "high";
    else if (this.bySeverity.medium) severity = "medium";
    else if (this.bySeverity.low) severity = "low";
    return {
      severity,
      total: this.total,
      flaggedRows: this.rowKeys.size,
      flaggedRowsExact: !this.rowKeysCapped,
      uniqueSecrets: this.fingerprints.size,
      uniqueSecretsExact: !this.fingerprintsCapped,
      bySeverity: this.bySeverity,
      byCategory: this.byCategory,
      byConfidence: this.byConfidence,
      mitre: [...this.mitreMap.values()].sort((a, b) => b.count - a.count),
    };
  }
}

function summarize(findings) {
  const accumulator = new SummaryAccumulator();
  for (const f of findings || []) accumulator.add(f);
  return accumulator.value();
}

function buildScanContext(opts = {}) {
  const mode = opts.mode === "deep" ? "deep" : "quick";
  return {
    mode,
    salt: opts.salt != null ? String(opts.salt) : crypto.randomBytes(8).toString("hex"),
    rules: (opts.rules || COMPILED_RULES).filter((r) => mode === "deep" || r.mode !== "deep"),
  };
}

function scanTextField(row, ctx, text, evidenceField) {
  const role = String(row.role || "").toLowerCase();
  const value = typeof text === "string" ? text : String(text || "");
  if (!value) return [];
  const hits = findMatchesInText(value, role, ctx.rules);
  if (ctx.mode === "deep") hits.push(...findEntropyHits(value, hits));
  if (!hits.length) return [];
  return dedupeOverlaps(hits).map((hit) => buildFinding(hit, row, {
    salt: ctx.salt,
    text: value,
    evidenceField,
  }));
}

function scanRow(row, ctx) {
  const fields = row.fields && typeof row.fields === "object"
    ? row.fields
    : { FullText: row.text };
  const findings = [];
  for (const [evidenceField, text] of Object.entries(fields)) {
    for (const finding of scanTextField(row, ctx, text, evidenceField)) findings.push(finding);
  }
  return findings;
}

function sortFindings(findings) {
  findings.sort((a, b) =>
    (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0)
    || (a.timestamp < b.timestamp ? -1 : a.timestamp > b.timestamp ? 1 : 0));
  return findings;
}

/**
 * Core: scan an array of normalized AI rows.
 * @param {Array<{recordId,timestamp,tool,role,sessionId,sourceFile,workspace,messageId,text}>} rows
 * @param {{ rules?:Array, mode?:"quick"|"deep", redact?:boolean, salt?:string }} [opts]
 * @returns {{ findings: Array, summary: object }}
 */
function analyzeAiHistoryRows(rows, opts = {}) {
  const ctx = buildScanContext(opts);
  const findings = [];
  const aggregate = new SummaryAccumulator();
  const maxFindings = Number.isFinite(opts.maxFindings)
    ? Math.max(0, Math.min(MAX_IN_MEMORY_FINDINGS, Math.floor(opts.maxFindings)))
    : MAX_IN_MEMORY_FINDINGS;
  for (const row of rows || []) {
    const rowFindings = scanRow(row, ctx);
    for (const finding of rowFindings) {
      aggregate.add(finding);
      if (findings.length < maxFindings) findings.push(finding);
    }
  }
  sortFindings(findings);
  return {
    findings,
    summary: aggregate.value(),
    storedFindings: findings.length,
    resultsTruncated: aggregate.total > findings.length,
  };
}

const EMPTY = Object.freeze({
  findings: [],
  summary: { severity: "info", total: 0, flaggedRows: 0, flaggedRowsExact: true, uniqueSecrets: 0, uniqueSecretsExact: true, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, byCategory: {}, byConfidence: {}, mitre: [] },
});

/**
 * Tab-DB entry point (mirrors analyzeADS(meta)). Scans the complete FullText (or Summary fallback)
 * plus ToolInput, ToolCommand, and ToolDescription with per-field provenance.
 */
function analyzeAiHistory(meta, opts = {}) {
  if (!meta || !meta.db || !meta.colMap) return { ...EMPTY, error: "No timeline data for this tab." };
  const col = (name) => meta.colMap[name];
  const cSummary = col("Summary");
  const cFull = col("FullText");
  if (!cSummary && !cFull) return { ...EMPTY, error: "Not an AI history tab (no Summary/FullText column)." };

  const cRecord = col("RecordId");
  const cRole = col("Role");
  const cTool = col("Tool");
  const cTs = col("Timestamp");
  const cSession = col("SessionId");
  const cSource = col("SourceFile");
  const cLine = col("LineNumber");
  const cWorkspace = col("Workspace");
  const cMessage = col("MessageId");
  const cToolInput = col("ToolInput");
  const cToolCommand = col("ToolCommand");
  const cToolDescription = col("ToolDescription");

  const selCols = [...new Set([
    cSummary, cFull, cRecord, cRole, cTool, cTs, cSession, cSource, cLine, cWorkspace,
    cMessage, cToolInput, cToolCommand, cToolDescription,
  ].filter(Boolean))];
  let stmt;
  let total = 0;
  try {
    total = meta.db.prepare(`SELECT COUNT(*) AS n FROM data`).get().n;
    stmt = meta.db.prepare(`SELECT data.rowid AS _rowid, ${selCols.join(", ")} FROM data`);
  } catch (e) {
    return { ...EMPTY, error: `AI history scan failed: ${e.message}` };
  }

  const progressCb = typeof opts.progressCb === "function" ? opts.progressCb : null;
  const checkAbort = typeof opts.checkAbort === "function" ? opts.checkAbort : null;
  const findingSink = typeof opts.findingSink === "function" ? opts.findingSink : null;
  const ctx = buildScanContext(opts);
  const findings = [];
  const aggregate = new SummaryAccumulator();
  const maxFindings = Number.isFinite(opts.maxFindings)
    ? Math.max(0, Math.min(MAX_IN_MEMORY_FINDINGS, Math.floor(opts.maxFindings)))
    : MAX_IN_MEMORY_FINDINGS;
  let rowsWithFullText = 0;
  let rowsSummaryOnly = 0;
  let maxScannedChars = 0;
  let totalScannedChars = 0;
  let scanned = 0;
  const fieldCoverage = Object.fromEntries(
    [...EVIDENCE_FIELDS, "Summary"].map((field) => [field, { rows: 0, characters: 0 }]),
  );
  for (const rec of stmt.iterate()) {
    if (checkAbort && scanned % 250 === 0) checkAbort();
    const full = cFull && rec[cFull] != null ? String(rec[cFull]) : "";
    const summaryText = cSummary && rec[cSummary] != null ? String(rec[cSummary]) : "";
    const hasFullText = !!(cFull && full.trim());
    if (hasFullText) rowsWithFullText++;
    else if (summaryText.trim()) rowsSummaryOnly++;

    const fields = {};
    const addField = (field, value) => {
      const text = value != null ? String(value) : "";
      if (!text.trim()) return;
      fields[field] = text;
      fieldCoverage[field].rows++;
      fieldCoverage[field].characters += text.length;
      totalScannedChars += text.length;
      maxScannedChars = Math.max(maxScannedChars, text.length);
    };
    if (hasFullText) addField("FullText", full);
    else addField("Summary", summaryText);
    if (cToolInput) addField("ToolInput", rec[cToolInput]);
    if (cToolCommand) addField("ToolCommand", rec[cToolCommand]);
    if (cToolDescription) addField("ToolDescription", rec[cToolDescription]);

    const row = {
      rowId: rec._rowid,
      recordId: cRecord ? rec[cRecord] : "",
      timestamp: cTs ? rec[cTs] : "",
      tool: cTool ? rec[cTool] : "",
      role: cRole ? rec[cRole] : "",
      sessionId: cSession ? rec[cSession] : "",
      sourceFile: cSource ? rec[cSource] : "",
      lineNumber: cLine ? rec[cLine] : "",
      workspace: cWorkspace ? rec[cWorkspace] : "",
      messageId: cMessage ? rec[cMessage] : "",
      fields,
    };
    for (const finding of scanRow(row, ctx)) {
      aggregate.add(finding);
      if (findingSink) findingSink(finding);
      if (!findingSink && findings.length < maxFindings) findings.push(finding);
    }
    scanned++;
    if (progressCb && scanned % 1000 === 0) progressCb({ phase: "ai-secrets", processed: scanned, total });
  }
  if (checkAbort) checkAbort();
  if (progressCb) progressCb({ phase: "ai-secrets", processed: total, total });

  sortFindings(findings);
  const result = {
    findings,
    summary: aggregate.value(),
    storedFindings: findingSink ? undefined : findings.length,
    resultsTruncated: !findingSink && aggregate.total > findings.length,
  };
  // Surface the FullText-coverage caveat so the UI can warn when scanning a slimmed merged tab.
  result.fullTextAvailable = rowsWithFullText > 0;
  result.rowsWithFullText = rowsWithFullText;
  result.rowsSummaryOnly = rowsSummaryOnly;
  result.maxScannedChars = maxScannedChars;
  result.scanChunkChars = SCAN_CHUNK_LEN;
  result.scanChunkOverlap = SCAN_CHUNK_OVERLAP;
  result.coverage = {
    complete: scanned === total && rowsSummaryOnly === 0,
    rowsScanned: scanned,
    totalRows: total,
    totalCharacters: totalScannedChars,
    fields: fieldCoverage,
    limitations: rowsSummaryOnly > 0
      ? [`${rowsSummaryOnly} row${rowsSummaryOnly === 1 ? "" : "s"} lacked FullText and were limited to Summary.`]
      : [],
  };
  return result;
}

module.exports = {
  analyzeAiHistory,
  analyzeAiHistoryRows,
  findMatchesInText,
  compileRules,
  COMPILED_RULES,
  SEVERITY_RANK,
  MAX_MATCHES_PER_RULE_PER_TEXT,
  MAX_IN_MEMORY_FINDINGS,
  SCAN_CHUNK_LEN,
  SCAN_CHUNK_OVERLAP,
  EVIDENCE_FIELDS,
  SummaryAccumulator,
};
