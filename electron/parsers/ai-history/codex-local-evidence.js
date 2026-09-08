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
 *
 *   rules/*.rules
 *     The execpolicy allow-list: `prefix_rule(pattern=[...], decision="allow")` lines. Every
 *     matching command prefix runs WITHOUT an approval prompt, so this file is the authorization
 *     posture of the host (the Codex counterpart of Grok Bot's localToolPermission). `exec_policy_rule`.
 *
 *   shell_snapshots/<thread-id>.<epoch-ns>.sh
 *     A dump of the exported shell environment taken when a thread started, world-readable. On a
 *     live host it exported `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_ID` and similar in cleartext.
 *     Rows carry the thread id, the nanosecond capture time, the variable NAMES and which of them
 *     look credential-bearing; values are never copied. `shell_snapshot`.
 *
 *   memories/{MEMORY.md,raw_memories.md,memory_summary.md}, memories/extensions/ad_hoc/*
 *     The model's persistent memory of the user and their projects. Model-written interpretation
 *     that outlives the rollouts; emitted per section as `agent_memory`.
 *
 *   ambient-suggestions/<hash>/ambient-suggestions.json
 *     Project roots the desktop app was watching, with generated follow-up prompts. `ambient_suggestions`.
 *
 *   .codex-global-state.json
 *     Desktop app state: Codex-managed SSH hosts (hostname, port, identity file), remote projects,
 *     which hosts may be driven by Remote Control, whether a mobile device has paired, local
 *     project roots. The push deregistration token in this file is never read. `remote_control_state`.
 *
 *   dictation-history/, transcription-history.jsonl
 *     Voice input. Parsed when they carry text; ignored when empty.
 */

const fs = require("fs");
const path = require("path");

const { dbg } = require("../../logger");
const { TOOL_CODEX } = require("./schema");
const { formatTimestampUtc, parseIsoTimestamp, makeRow, sortAndNumberRows } = require("./row-utils");

const ROLLOUT_SUMMARY_REL = ["memories", "rollout_summaries"];
const HOOKS_FILE = "hooks.json";
const RULES_DIR = "rules";
const SHELL_SNAPSHOT_DIR = "shell_snapshots";
const AMBIENT_DIR = "ambient-suggestions";
const GLOBAL_STATE_FILE = ".codex-global-state.json";
const TRANSCRIPTION_FILE = "transcription-history.jsonl";
const DICTATION_DIR = "dictation-history";
const MEMORY_FILES = [
  ["memories", "MEMORY.md"],
  ["memories", "raw_memories.md"],
  ["memories", "memory_summary.md"],
  ["memories", "extensions", "ad_hoc", "notes"],
  ["memories", "extensions", "ad_hoc", "instructions.md"],
];
/** `<thread-uuid>.<epoch-nanoseconds>.sh` */
const SNAPSHOT_NAME_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(\d{16,19})\.sh$/i;
const CREDENTIAL_NAME_RE = /(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_KEY|ACCESS_KEY|PRIVATE|BEARER|COOKIE)/i;
/** Names that match the credential pattern but are plainly not secrets. */
const CREDENTIAL_NAME_ALLOW = /^(SSH_AUTH_SOCK|GPG_TTY|TERM_SESSION_ID|SECURITYSESSIONID|XPC_[A-Z_]+|LC_[A-Z_]+|KEYBOARD[A-Z_]*|HOMEBREW_[A-Z_]+|[A-Z_]*KEYMAP[A-Z_]*|LESSKEY|[A-Z_]*_KEY_PATH|[A-Z_]*_KEYRING)$/;
const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;
const MAX_SNAPSHOT_FILES = 500;
const MAX_MEMORY_BYTES = 1024 * 1024;
const MAX_MEMORY_SECTIONS = 300;
const MAX_AMBIENT_FILES = 200;
const MAX_VOICE_LINES = 5000;

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
 * rules/*.rules — execpolicy allow-list
 * ------------------------------------------------------------------ */

/**
 * Parse execpolicy lines. The common form is
 *   prefix_rule(pattern=["docker", "run"], decision="allow")
 * The pattern array is JSON-compatible; `.*` is greedy on purpose because a pattern element can
 * itself contain `]` (a `node -e` one-liner did on a live host) and `, decision=` is always last.
 * @returns {{ line: number, kind: string, pattern: string[], decision: string, raw: string }[]}
 */
function parseExecPolicyRules(text) {
  const out = [];
  const lines = String(text ?? "").replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const prefix = /^prefix_rule\(\s*pattern\s*=\s*(\[.*\])\s*,\s*decision\s*=\s*"([^"]*)"\s*\)\s*$/.exec(line);
    if (prefix) {
      let pattern;
      try { pattern = JSON.parse(prefix[1]); } catch { pattern = null; }
      if (!Array.isArray(pattern)) pattern = [prefix[1]];
      out.push({ line: i + 1, kind: "prefix_rule", pattern: pattern.map((p) => String(p)), decision: prefix[2], raw: line });
      continue;
    }
    const generic = /^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*$/.exec(line);
    if (generic) {
      const decision = /decision\s*=\s*"([^"]*)"/.exec(generic[2])?.[1] || "";
      out.push({ line: i + 1, kind: generic[1], pattern: [generic[2]], decision, raw: line });
    }
  }
  return out;
}

function extractExecPolicyRows(codexRoot, attribution) {
  const dir = path.join(codexRoot, RULES_DIR);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return { rows: [], rules: 0 }; }
  const rows = [];
  for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!e.isFile() || !/\.rules$/i.test(e.name)) continue;
    const filePath = path.join(dir, e.name);
    let text;
    let mtimeMs = 0;
    try {
      text = readTextCapped(filePath, MAX_MEMORY_BYTES);
      mtimeMs = fs.statSync(filePath).mtimeMs;
    } catch (err) {
      dbg("AIHIST", "codex rules read failed", { path: filePath, err: err.message });
      continue;
    }
    for (const rule of parseExecPolicyRules(text)) {
      const command = rule.pattern.join(" ");
      rows.push(localRow({
        timestamp: formatTimestampUtc(mtimeMs),
        recordType: "exec_policy_rule",
        summary: `Exec policy ${rule.decision || rule.kind}: ${command}`,
        fullText: rule.raw,
        toolName: rule.decision || rule.kind,
        toolCommand: command,
        toolInput: serializeSafe(rule.pattern),
        toolDescription: rule.decision === "allow"
          ? "Any command starting with this prefix runs WITHOUT an approval prompt. The rule is written "
            + "when the user chooses \"always allow\", so it also records a past approval decision."
          : `execpolicy ${rule.kind} with decision "${rule.decision || "?"}".`,
        sourceFile: filePath,
        lineNumber: rule.line,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    }
  }
  return { rows, rules: rows.length };
}

/* ------------------------------------------------------------------ *
 * shell_snapshots/<thread>.<ns>.sh — exported environment, values never copied
 * ------------------------------------------------------------------ */

function nsToMs(ns) {
  const n = Number(ns);
  return Number.isFinite(n) && n > 1e15 ? Math.floor(n / 1e6) : null;
}

/** @returns {{ exported: string[], credentialLike: {name:string,valueLength:number}[], functions: number, aliases: number }} */
function summarizeShellSnapshot(text) {
  const exported = [];
  const credentialLike = [];
  const seen = new Set();
  let functions = 0;
  let aliases = 0;
  for (const rawLine of String(text ?? "").split("\n")) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^alias\s/.test(line)) { aliases += 1; continue; }
    if (/^(function\s+[A-Za-z_][\w-]*|[A-Za-z_][\w-]*\s*\(\)\s*\{)/.test(line)) { functions += 1; continue; }
    const m = /^(?:export\s+|typeset\s+-x\s+|declare\s+-x\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!m || !/^(export|typeset|declare)\s/.test(line)) continue;
    const name = m[1];
    if (seen.has(name)) continue;
    seen.add(name);
    exported.push(name);
    const value = m[2].replace(/^['"]|['"]$/g, "");
    if (value && CREDENTIAL_NAME_RE.test(name) && !CREDENTIAL_NAME_ALLOW.test(name)) {
      credentialLike.push({ name, valueLength: value.length });
    }
  }
  return { exported, credentialLike, functions, aliases };
}

function extractShellSnapshotRows(codexRoot, attribution) {
  const dir = path.join(codexRoot, SHELL_SNAPSHOT_DIR);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return { rows: [], snapshots: 0, exposures: 0 }; }
  const files = entries.filter((e) => e.isFile() && SNAPSHOT_NAME_RE.test(e.name)).map((e) => e.name).sort().slice(0, MAX_SNAPSHOT_FILES);
  const rows = [];
  let exposures = 0;
  for (const name of files) {
    const filePath = path.join(dir, name);
    const m = SNAPSHOT_NAME_RE.exec(name);
    let text;
    let size = 0;
    try {
      text = readTextCapped(filePath, MAX_SNAPSHOT_BYTES);
      size = fs.statSync(filePath).size;
    } catch (err) {
      dbg("AIHIST", "codex shell snapshot read failed", { path: filePath, err: err.message });
      continue;
    }
    const info = summarizeShellSnapshot(text);
    const tsMs = nsToMs(m[2]);
    if (info.credentialLike.length) exposures += 1;
    const credNames = info.credentialLike.map((c) => c.name);
    rows.push(localRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      recordType: "shell_snapshot",
      summary: `Shell environment snapshot for thread ${m[1]} — ${info.exported.length} exported variable(s)`
        + `${credNames.length ? `, ${credNames.length} credential-like value(s) present in cleartext (${credNames.slice(0, 6).join(", ")}${credNames.length > 6 ? ", …" : ""})` : ""}`,
      fullText: serializeSafe({
        threadId: m[1],
        capturedAt: tsMs == null ? null : formatTimestampUtc(tsMs),
        fileBytes: size,
        exportedVariableCount: info.exported.length,
        exportedVariableNames: info.exported.slice(0, 400),
        credentialLikeVariables: info.credentialLike,
        functionCount: info.functions,
        aliasCount: info.aliases,
        valuesRedacted: true,
      }),
      sessionId: m[1],
      toolInput: credNames.join("\n"),
      toolDescription: "Codex dumps the user's exported shell environment to this world-readable file when a "
        + "thread starts, so every API key or password exported in the shell profile is on disk in "
        + "cleartext for the life of the file. Variable NAMES and value lengths are recorded; values are "
        + "never read into the timeline. Treat the file as a credential store during acquisition.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return { rows, snapshots: rows.length, exposures };
}

/* ------------------------------------------------------------------ *
 * memories/*.md — the model's persistent memory (model-written)
 * ------------------------------------------------------------------ */

/** Split markdown at `#`/`##` headings; a file with no headings is one section. */
function splitMarkdownSections(text) {
  const lines = String(text ?? "").replace(/\r\n/g, "\n").split("\n");
  const sections = [];
  let current = { heading: "", lines: [] };
  for (const line of lines) {
    const h = /^(#{1,2})\s+(.+)$/.exec(line);
    if (h) {
      if (current.heading || current.lines.some((l) => l.trim())) sections.push(current);
      current = { heading: h[2].trim(), lines: [line] };
    } else {
      current.lines.push(line);
    }
  }
  if (current.heading || current.lines.some((l) => l.trim())) sections.push(current);
  return sections.map((s) => ({ heading: s.heading, body: s.lines.join("\n").trim() })).filter((s) => s.body);
}

function extractMemoryRows(codexRoot, attribution) {
  const rows = [];
  let files = 0;
  for (const rel of MEMORY_FILES) {
    const filePath = path.join(codexRoot, ...rel);
    let st;
    try { st = fs.statSync(filePath); } catch { continue; }
    if (!st.isFile() || !st.size) continue;
    let text;
    try { text = readTextCapped(filePath, MAX_MEMORY_BYTES); } catch (err) {
      dbg("AIHIST", "codex memory read failed", { path: filePath, err: err.message });
      continue;
    }
    files += 1;
    const label = rel.slice(1).join("/");
    const sections = splitMarkdownSections(text).slice(0, MAX_MEMORY_SECTIONS);
    sections.forEach((section, idx) => {
      rows.push(localRow({
        timestamp: formatTimestampUtc(st.mtimeMs),
        recordType: "agent_memory",
        summary: `[Codex memory: ${label}] ${section.heading || label}`,
        fullText: section.body,
        toolDescription: "Model-written memory about the user and their projects, consolidated from past "
          + "threads. It outlives the rollouts it was distilled from, but it is interpretation, not a "
          + "verbatim record. Dated from the file mtime.",
        sourceFile: filePath,
        lineNumber: idx + 1,
        user: attribution.user || "",
        host: attribution.host || "",
      }));
    });
  }
  return { rows, files };
}

/* ------------------------------------------------------------------ *
 * ambient-suggestions/<hash>/ambient-suggestions.json
 * ------------------------------------------------------------------ */

function extractAmbientSuggestionRows(codexRoot, attribution) {
  const dir = path.join(codexRoot, AMBIENT_DIR);
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return { rows: [], files: 0 }; }
  const rows = [];
  for (const e of entries.filter((d) => d.isDirectory()).sort((a, b) => a.name.localeCompare(b.name)).slice(0, MAX_AMBIENT_FILES)) {
    const filePath = path.join(dir, e.name, "ambient-suggestions.json");
    let parsed;
    let mtimeMs = 0;
    try {
      parsed = JSON.parse(readTextCapped(filePath, MAX_MEMORY_BYTES));
      mtimeMs = fs.statSync(filePath).mtimeMs;
    } catch { continue; }
    if (!parsed || typeof parsed !== "object") continue;
    const suggestions = Array.isArray(parsed.suggestions) ? parsed.suggestions.filter((x) => x && typeof x === "object") : [];
    const tsMs = Number(parsed.generatedAtMs);
    const projectRoot = parsed.projectRoot != null ? String(parsed.projectRoot) : "";
    rows.push(localRow({
      timestamp: Number.isFinite(tsMs) && tsMs > 1e12 ? formatTimestampUtc(tsMs) : formatTimestampUtc(mtimeMs),
      recordType: "ambient_suggestions",
      summary: `Codex watched project ${projectRoot || e.name} — ${suggestions.length} ambient suggestion(s)`
        + `${suggestions.length ? `: ${suggestions.slice(0, 3).map((x) => String(x.title ?? "")).filter(Boolean).join(" | ")}` : ""}`,
      fullText: serializeSafe({
        projectRoot,
        generatedAt: Number.isFinite(tsMs) && tsMs > 1e12 ? formatTimestampUtc(tsMs) : null,
        suggestions: suggestions.slice(0, 50).map((x) => ({
          id: x.id ?? null,
          title: x.title ?? null,
          description: x.description ?? null,
          prompt: x.prompt ?? null,
          status: x.status ?? null,
          createdAt: Number(x.createdAtMs) > 1e12 ? formatTimestampUtc(Number(x.createdAtMs)) : null,
        })),
      }),
      workspace: projectRoot,
      toolDescription: "The desktop app generated follow-up prompts for this project root, which proves the "
        + "root was open in Codex at generatedAt and summarises the work the model saw there.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return { rows, files: rows.length };
}

/* ------------------------------------------------------------------ *
 * .codex-global-state.json — remote hosts, remote control, projects
 * ------------------------------------------------------------------ */

function extractGlobalStateRows(codexRoot, attribution) {
  const filePath = path.join(codexRoot, GLOBAL_STATE_FILE);
  let state;
  let mtimeMs = 0;
  try {
    state = JSON.parse(readTextCapped(filePath, 8 * 1024 * 1024));
    mtimeMs = fs.statSync(filePath).mtimeMs;
  } catch { return { rows: [], remoteHosts: 0 }; }
  if (!state || typeof state !== "object") return { rows: [], remoteHosts: 0 };

  const connections = Array.isArray(state["codex-managed-remote-connections"])
    ? state["codex-managed-remote-connections"].filter((c) => c && typeof c === "object") : [];
  const remoteProjects = Array.isArray(state["remote-projects"])
    ? state["remote-projects"].filter((p) => p && typeof p === "object") : [];
  const localProjects = state["local-projects"] && typeof state["local-projects"] === "object"
    ? Object.values(state["local-projects"]).filter((p) => p && typeof p === "object") : [];
  const allowed = Array.isArray(state["host-id-remote-control-allowed"]) ? state["host-id-remote-control-allowed"].map(String) : [];
  const timestamp = formatTimestampUtc(mtimeMs);
  const rows = [];

  const hostSummary = connections.map((c) => String(c.hostname ?? c.displayName ?? c.hostId ?? "?"));
  rows.push(localRow({
    timestamp,
    recordType: "remote_control_state",
    summary: `Codex desktop remote state — ${connections.length} managed SSH host(s)`
      + `${hostSummary.length ? ` (${hostSummary.slice(0, 4).join(", ")})` : ""}`
      + `, Remote Control allowed for ${allowed.length} host(s)`
      + `, mobile device paired: ${state["codex-mobile-has-connected-device"] === true ? "yes" : "no"}`
      + `, ${localProjects.length} local project(s)`,
    fullText: serializeSafe({
      remoteControlInstallationId: state["electron-local-remote-control-installation-id"] ?? null,
      remoteControlEnvironmentId: state["electron-local-remote-control-environment-id"] ?? null,
      remoteControlAllowedHostIds: allowed,
      selectedRemoteHostId: state["selected-remote-host-id"] ?? null,
      mobileDeviceConnected: state["codex-mobile-has-connected-device"] === true,
      managedRemoteConnections: connections.slice(0, 100).map((c) => ({
        hostId: c.hostId ?? null,
        displayName: c.displayName ?? null,
        hostname: c.hostname ?? null,
        sshPort: c.sshPort ?? null,
        identity: c.identity ?? null,
        source: c.source ?? null,
        alias: c.alias ?? null,
      })),
      remoteProjects: remoteProjects.slice(0, 200).map((p) => ({ id: p.id ?? null, hostId: p.hostId ?? null, remotePath: p.remotePath ?? null, label: p.label ?? null })),
      localProjects: localProjects.slice(0, 300).map((p) => ({
        id: p.id ?? null,
        name: p.name ?? null,
        rootPaths: Array.isArray(p.rootPaths) ? p.rootPaths : [],
        createdAt: Number(p.createdAt) > 1e12 ? formatTimestampUtc(Number(p.createdAt)) : null,
        updatedAt: Number(p.updatedAt) > 1e12 ? formatTimestampUtc(Number(p.updatedAt)) : null,
      })),
      savedWorkspaceRoots: Array.isArray(state["electron-saved-workspace-roots"]) ? state["electron-saved-workspace-roots"].slice(0, 200) : [],
      activeWorkspaceRoots: Array.isArray(state["active-workspace-roots"]) ? state["active-workspace-roots"].slice(0, 200) : [],
      pinnedProjectCount: Array.isArray(state["pinned-project-ids"]) ? state["pinned-project-ids"].length : 0,
      completedLocalDataMigrations: Array.isArray(state["electron-completed-local-data-migration-ids"]) ? state["electron-completed-local-data-migration-ids"] : [],
      neverRead: ["electron-mac-push-deregistration-token"],
      timeSource: "file mtime",
    }),
    toolDescription: "Desktop app state. Managed SSH hosts are machines Codex can run threads on over SSH "
      + "with the listed identity key; Remote Control allowed hosts can be driven from a phone or "
      + "browser; the mobile flag records that a device paired. Local projects are the roots opened "
      + "in the app with creation times. The push deregistration token is never read.",
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
  }));

  for (const c of connections.slice(0, 100)) {
    const hostname = String(c.hostname ?? "");
    rows.push(localRow({
      timestamp,
      recordType: "remote_ssh_host",
      summary: `Codex-managed SSH host "${c.displayName ?? c.hostId ?? "?"}" — ${hostname || "?"}`
        + `${c.sshPort != null ? `:${c.sshPort}` : ""}${c.identity ? ` (key ${c.identity})` : ""}`
        + `${allowed.includes(String(c.hostId)) ? "; Remote Control allowed" : ""}`,
      fullText: serializeSafe({
        hostId: c.hostId ?? null,
        displayName: c.displayName ?? null,
        hostname,
        sshPort: c.sshPort ?? null,
        identity: c.identity ?? null,
        source: c.source ?? null,
        remoteControlAllowed: allowed.includes(String(c.hostId)),
        remoteProjects: remoteProjects.filter((p) => p.hostId === c.hostId).map((p) => ({ label: p.label ?? null, remotePath: p.remotePath ?? null })),
      }),
      sessionId: c.hostId != null ? String(c.hostId) : "",
      workspace: hostname,
      toolDescription: "A remote machine the desktop app connects to over SSH so agents can run there. "
        + "The identity path names the private key used; the host is a lateral-movement path from this Mac.",
      sourceFile: filePath,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
  return { rows, remoteHosts: connections.length };
}

/* ------------------------------------------------------------------ *
 * Voice input — dictation-history/, transcription-history.jsonl
 * ------------------------------------------------------------------ */

function voiceRowsFromJsonl(filePath, attribution, rows) {
  let text;
  try { text = readTextCapped(filePath, MAX_MEMORY_BYTES); } catch { return; }
  let lineNo = 0;
  for (const line of text.split("\n")) {
    if (rows.length >= MAX_VOICE_LINES) break;
    lineNo += 1;
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let obj;
    try { obj = JSON.parse(trimmed); } catch { continue; }
    const body = String(obj.text ?? obj.transcript ?? obj.transcription ?? obj.content ?? "").trim();
    if (!body) continue;
    const tsMs = parseIsoTimestamp(obj.ts ?? obj.timestamp ?? obj.created_at ?? obj.createdAt)
      ?? (Number(obj.ts ?? obj.timestamp ?? obj.created_at_ms) > 1e12 ? Number(obj.ts ?? obj.timestamp ?? obj.created_at_ms) : null);
    rows.push(localRow({
      timestamp: tsMs == null ? "" : formatTimestampUtc(tsMs),
      role: "user",
      recordType: "voice_transcription",
      summary: body,
      fullText: body,
      sessionId: obj.session_id != null ? String(obj.session_id) : obj.thread_id != null ? String(obj.thread_id) : "",
      toolDescription: "Prompt entered by voice (dictation / transcription history).",
      sourceFile: filePath,
      lineNumber: lineNo,
      user: attribution.user || "",
      host: attribution.host || "",
    }));
  }
}

function extractVoiceInputRows(codexRoot, attribution) {
  const rows = [];
  const transcription = path.join(codexRoot, TRANSCRIPTION_FILE);
  try { if (fs.statSync(transcription).size > 0) voiceRowsFromJsonl(transcription, attribution, rows); } catch { /* absent */ }
  const dir = path.join(codexRoot, DICTATION_DIR);
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { /* absent */ }
  for (const e of entries) {
    if (!e.isFile() || !/\.jsonl?$/i.test(e.name)) continue;
    voiceRowsFromJsonl(path.join(dir, e.name), attribution, rows);
  }
  return { rows, lines: rows.length };
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
  const run = (label, fn, empty) => {
    try { return fn(); } catch (e) {
      dbg("AIHIST", `codex local evidence ${label} failed`, { err: e.message });
      return empty;
    }
  };
  const policy = run("exec policy", () => extractExecPolicyRows(codexRoot, attribution), { rows: [], rules: 0 });
  const snapshots = run("shell snapshots", () => extractShellSnapshotRows(codexRoot, attribution), { rows: [], snapshots: 0, exposures: 0 });
  const memory = run("memory", () => extractMemoryRows(codexRoot, attribution), { rows: [], files: 0 });
  const ambient = run("ambient suggestions", () => extractAmbientSuggestionRows(codexRoot, attribution), { rows: [], files: 0 });
  const globalState = run("global state", () => extractGlobalStateRows(codexRoot, attribution), { rows: [], remoteHosts: 0 });
  const voice = run("voice input", () => extractVoiceInputRows(codexRoot, attribution), { rows: [], lines: 0 });

  const all = [
    ...summaries.rows, ...hooks.rows, ...policy.rows, ...snapshots.rows,
    ...memory.rows, ...ambient.rows, ...globalState.rows, ...voice.rows,
  ];
  if (!all.length) return { rows: [], stats: null };

  return {
    rows: sortAndNumberRows(all),
    stats: {
      totalRows: all.length,
      summaryFiles: summaries.files,
      orphanedSummaries: summaries.orphaned,
      summaryFilesSkipped: summaries.truncated || 0,
      hookCommands: hooks.hooks,
      execPolicyRules: policy.rules,
      shellSnapshots: snapshots.snapshots,
      shellSnapshotsWithCredentials: snapshots.exposures,
      memoryFiles: memory.files,
      memoryRows: memory.rows.length,
      ambientSuggestionFiles: ambient.files,
      remoteSshHosts: globalState.remoteHosts,
      voiceRows: voice.lines,
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
  if (stats.execPolicyRules) parts.push(`${stats.execPolicyRules} exec-policy allow rule(s)`);
  if (stats.shellSnapshots) {
    parts.push(`${stats.shellSnapshots} shell environment snapshot(s)`
      + (stats.shellSnapshotsWithCredentials ? `, ${stats.shellSnapshotsWithCredentials} exposing credential-like variables in cleartext` : ""));
  }
  if (stats.memoryRows) parts.push(`${stats.memoryRows} agent-memory section(s) from ${stats.memoryFiles} file(s)`);
  if (stats.ambientSuggestionFiles) parts.push(`${stats.ambientSuggestionFiles} watched project root(s)`);
  if (stats.remoteSshHosts) parts.push(`${stats.remoteSshHosts} Codex-managed SSH host(s)`);
  if (stats.voiceRows) parts.push(`${stats.voiceRows} voice transcription(s)`);
  const skipped = stats.summaryFilesSkipped
    ? ` ${stats.summaryFilesSkipped} summary file(s) beyond the cap were not read.`
    : "";
  return `OpenAI Codex: +${stats.totalRows} row(s) from local evidence`
    + `${parts.length ? ` — ${parts.join("; ")}` : ""}.${skipped}`;
}

module.exports = {
  ROLLOUT_SUMMARY_REL,
  HOOKS_FILE,
  RULES_DIR,
  SHELL_SNAPSHOT_DIR,
  GLOBAL_STATE_FILE,
  timestampFromSummaryName,
  parseRolloutSummary,
  listRolloutSummaryFiles,
  extractRolloutSummaryRows,
  extractHookRows,
  parseExecPolicyRules,
  extractExecPolicyRows,
  summarizeShellSnapshot,
  extractShellSnapshotRows,
  splitMarkdownSections,
  extractMemoryRows,
  extractAmbientSuggestionRows,
  extractGlobalStateRows,
  extractVoiceInputRows,
  supplementCodexFromLocalEvidence,
  buildCodexLocalEvidenceNotice,
};
