/**
 * codex-local-evidence.js — Codex evidence held in flat files under `~/.codex`.
 *
 *   memories/rollout_summaries/<ts>-<4char>-<slug>.md
 *     A model-written summary of one finished thread. Two properties make these worth collecting
 *     independently of the rollouts they describe:
 *       - They outlive the transcript. On a live host these reached back months further than the
 *         retained rollout set, so on a stale image they may be the only account of a thread.
 *       - Each carries a `rollout_path:` header naming the transcript it came from. When that file
 *         is absent the summary is evidence a thread existed and its transcript is gone — a
 *         deletion signal the rollout directory cannot produce on its own.
 *     Because the body is model-written interpretation, rows are tagged `thread_summary` so an
 *     analyst never mistakes them for verbatim transcript content.
 *
 *   hooks.json
 *     Commands Codex executes on lifecycle events (`SessionStart`, `PreToolUse`, `Stop`,
 *     `PermissionRequest`, …). Each entry is an arbitrary local command line that runs whenever the
 *     event fires, so this file is both an execution-persistence mechanism and a supply-chain
 *     surface. It is configuration rather than activity, so rows are timestamped from the file
 *     mtime and marked `hook_config`.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, sortAndNumberRows } = require("./row-utils");

const ROLLOUT_SUMMARY_REL = ["memories", "rollout_summaries"];
const HOOKS_FILE = "hooks.json";

/** `2026-05-27T18-30-10-WBmr-<slug>.md` */
const SUMMARY_NAME_RE = /^(\d{4}-\d{2}-\d{2})T(\d{2})-(\d{2})-(\d{2})-([A-Za-z0-9]{4})-(.*)\.md$/;

const DEFAULT_MAX_SUMMARY_FILES = 500;
// Summaries are prose; a whole file is legitimate evidence, but cap the read so a pathological
// file cannot be pulled into heap in full. makeRow caps FullText separately.
const MAX_SUMMARY_BYTES = 512 * 1024;

function localRow(fields) {
  return makeRow({ ...fields, tool: TOOL_CODEX, role: fields.role || "system" }, TOOL_CODEX);
}

function serializeSafe(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try { return JSON.stringify(value); } catch { return String(value); }
}

function readTextCapped(filePath, maxBytes) {
  const fd = fs.openSync(filePath, "r");
  try {
    const size = fs.fstatSync(fd).size;
    const len = Math.min(size, maxBytes);
    const buf = Buffer.allocUnsafe(len);
    fs.readSync(fd, buf, 0, len, 0);
    const text = buf.toString("utf8");
    return size > maxBytes
      ? `${text}\n…[truncated ${size - maxBytes} bytes over ${maxBytes}-byte read cap]`
      : text;
  } finally {
    try { fs.closeSync(fd); } catch { /* ignore */ }
  }
}

/* ------------------------------------------------------------------ *
 * memories/rollout_summaries
 * ------------------------------------------------------------------ */

/** Timestamp encoded in the filename, which uses `-` separators in the time component. */
function timestampFromSummaryName(fileName) {
  const m = SUMMARY_NAME_RE.exec(fileName);
  if (!m) return null;
  return parseIsoTimestamp(`${m[1]}T${m[2]}:${m[3]}:${m[4]}Z`);
}

function slugFromSummaryName(fileName) {
  const m = SUMMARY_NAME_RE.exec(fileName);
  if (!m) return "";
  return m[6].replace(/_/g, " ").trim();
}

/**
 * Split the leading `key: value` header block from the markdown body.
 *
 * The block is bare `key: value` lines (no `---` fences) terminated by a blank line, so parsing
 * stops at the first line that is blank or is not a header pair.
 *
 * @returns {{ headers: Record<string,string>, title: string, body: string }}
 */
function parseRolloutSummary(content) {
  const text = String(content ?? "").replace(/\r\n/g, "\n");
  const lines = text.split("\n");
  const headers = {};
  let i = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) { i += 1; break; }
    const m = /^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/.exec(line);
    if (!m) break;
    headers[m[1].toLowerCase()] = m[2].trim();
  }
  const rest = lines.slice(i).join("\n").trim();
  const titleMatch = /^#\s+(.+)$/m.exec(rest);
  return { headers, title: titleMatch ? titleMatch[1].trim() : "", body: rest };
}

function listRolloutSummaryFiles(summariesDir) {
  let entries;
  try { entries = fs.readdirSync(summariesDir, { withFileTypes: true }); } catch { return []; }
  return entries
    .filter((e) => e.isFile() && e.name.toLowerCase().endsWith(".md"))
    .map((e) => path.join(summariesDir, e.name))
    .sort();
}

/**
 * @param {string} codexRoot
 * @returns {{ rows: object[], files: number, orphaned: number }}
 */
function extractRolloutSummaryRows(codexRoot, attribution, options) {
  const summariesDir = path.join(codexRoot, ...ROLLOUT_SUMMARY_REL);
  const files = listRolloutSummaryFiles(summariesDir);
  if (!files.length) return { rows: [], files: 0, orphaned: 0 };

  const maxFiles = options.maxRolloutSummaryFiles ?? DEFAULT_MAX_SUMMARY_FILES;
  const selected = files.slice(0, maxFiles);
  const rows = [];
  let orphaned = 0;

  for (const filePath of selected) {
    let content;
    try {
      content = readTextCapped(filePath, MAX_SUMMARY_BYTES);
    } catch (e) {
      dbg("AIHIST", "codex rollout summary read failed", { path: filePath, err: e.message });
      continue;
    }

    const { headers, title, body } = parseRolloutSummary(content);
    const fileName = path.basename(filePath);
    const rolloutPath = headers.rollout_path || "";
    // An absent transcript is the finding. Only claim it when a path was actually recorded.
    const rolloutMissing = !!rolloutPath && !fs.existsSync(rolloutPath);
    if (rolloutMissing) orphaned += 1;

    const tsMs = parseIsoTimestamp(headers.updated_at) ?? timestampFromSummaryName(fileName);
    const heading = title || slugFromSummaryName(fileName) || fileName;

    rows.push(localRow({
      timestamp: formatTimestampUtc(tsMs),
      recordType: rolloutMissing ? "thread_summary_orphaned" : "thread_summary",
      summary: `${heading}${rolloutMissing ? " [rollout deleted]" : ""}`,
      fullText: body || content,
      sessionId: headers.thread_id || "",
      workspace: headers.cwd || "",
      toolDescription: rolloutPath,
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }

  return { rows, files: selected.length, orphaned, truncated: files.length - selected.length };
}

/* ------------------------------------------------------------------ *
 * hooks.json
 * ------------------------------------------------------------------ */

/**
 * Flatten `{ hooks: { <Event>: [ { matcher, hooks: [ { type, command } ] } ] } }` into one row per
 * configured command.
 *
 * @returns {{ rows: object[], hooks: number }}
 */
function extractHookRows(codexRoot, attribution) {
  const hooksPath = path.join(codexRoot, HOOKS_FILE);
  if (!fs.existsSync(hooksPath)) return { rows: [], hooks: 0 };

  let parsed;
  let mtimeMs = 0;
  try {
    parsed = JSON.parse(fs.readFileSync(hooksPath, "utf8"));
    mtimeMs = fs.statSync(hooksPath).mtimeMs;
  } catch (e) {
    dbg("AIHIST", "codex hooks.json read failed", { path: hooksPath, err: e.message });
    return { rows: [], hooks: 0 };
  }

  const byEvent = parsed && typeof parsed === "object" ? (parsed.hooks || parsed) : null;
  if (!byEvent || typeof byEvent !== "object") return { rows: [], hooks: 0 };

  const timestamp = formatTimestampUtc(mtimeMs);
  const rows = [];
  for (const [event, groups] of Object.entries(byEvent)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      const matcher = group && typeof group === "object" ? String(group.matcher ?? "") : "";
      const entries = group && Array.isArray(group.hooks) ? group.hooks : [];
      for (const entry of entries) {
        if (!entry || typeof entry !== "object") continue;
        const command = String(entry.command ?? "").trim();
        if (!command) continue;
        rows.push(localRow({
          timestamp,
          recordType: "hook_config",
          summary: `Hook on ${event}${matcher && matcher !== ".*" ? ` [${matcher}]` : ""} → ${command}`,
          fullText: serializeSafe({ event, matcher, ...entry }),
          toolName: event,
          toolCommand: command,
          toolInput: matcher,
          toolDescription: String(entry.type ?? ""),
          sourceFile: hooksPath,
          user: attribution.user || "",
          host: attribution.host || "",
        }));
      }
    }
  }
  return { rows, hooks: rows.length };
}

/* ------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------ */

/**
 * @returns {{ rows: object[], stats: object|null }}
 */
function supplementCodexFromLocalEvidence(codexRoot, attribution = {}, options = {}) {
  const summaries = extractRolloutSummaryRows(codexRoot, attribution, options);
  const hooks = extractHookRows(codexRoot, attribution);

  const all = [...summaries.rows, ...hooks.rows];
  if (!all.length) return { rows: [], stats: null };

  return {
    rows: sortAndNumberRows(all),
    stats: {
      totalRows: all.length,
      summaryFiles: summaries.files,
      orphanedSummaries: summaries.orphaned,
      summaryFilesSkipped: summaries.truncated || 0,
      hookCommands: hooks.hooks,
    },
  };
}

function buildCodexLocalEvidenceNotice(stats) {
  if (!stats?.totalRows) return "";
  const parts = [];
  if (stats.summaryFiles) {
    parts.push(`${stats.summaryFiles} thread summary file(s)`
      + (stats.orphanedSummaries ? `, ${stats.orphanedSummaries} whose rollout is deleted` : ""));
  }
  if (stats.hookCommands) parts.push(`${stats.hookCommands} configured hook command(s)`);
  const skipped = stats.summaryFilesSkipped
    ? ` ${stats.summaryFilesSkipped} summary file(s) beyond the cap were not read.`
    : "";
  return `OpenAI Codex: +${stats.totalRows} row(s) from local evidence`
    + `${parts.length ? ` — ${parts.join("; ")}` : ""}.${skipped}`;
}

module.exports = {
  ROLLOUT_SUMMARY_REL,
  HOOKS_FILE,
  timestampFromSummaryName,
  parseRolloutSummary,
  listRolloutSummaryFiles,
  extractRolloutSummaryRows,
  extractHookRows,
  supplementCodexFromLocalEvidence,
  buildCodexLocalEvidenceNotice,
};
