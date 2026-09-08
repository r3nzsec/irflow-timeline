"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { extractClaudeContext, isClaudeCliConfigRoot } = require("../electron/parsers/ai-history/claude-code-context");
const { extractCodexContext } = require("../electron/parsers/ai-history/codex-context");
const { extractGrokBuildContext } = require("../electron/parsers/ai-history/grok-build-context");
const { extractCursorContext } = require("../electron/parsers/ai-history/cursor-context");
const { inventoryAiHistorySources } = require("../electron/parsers/ai-history/source-coverage");

function tempRoot(t, prefix) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("Claude relocated context extracts policy while credential bodies remain unread", (t) => {
  const root = tempRoot(t, "irflow-claude-context-");
  fs.writeFileSync(path.join(root, "settings.json"), JSON.stringify({
    model: "claude-sonnet",
    permissions: { defaultMode: "ask", allow: ["Read"], deny: ["Bash(rm:*)"] },
    env: { API_TOKEN: "CLAUDE-SECRET" },
    hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "audit-hook" }] }] },
  }));
  fs.writeFileSync(path.join(root, ".mcp.json"), JSON.stringify({ mcpServers: {
    triage: { command: "node", args: ["server.js", "--token", "CLAUDE-MCP-SECRET"], env: { API_KEY: "SECRET" } },
  } }));
  fs.writeFileSync(path.join(root, ".credentials.json"), "CLAUDE-CREDENTIAL-BODY");
  fs.mkdirSync(path.join(root, "file-history", "session-1"), { recursive: true });
  fs.writeFileSync(path.join(root, "file-history", "session-1", "content@v2"), "physical historical bytes");
  fs.mkdirSync(path.join(root, "backups"));
  fs.writeFileSync(path.join(root, "backups", ".claude.json.backup.1788840000000"), "backup bytes");

  assert.equal(isClaudeCliConfigRoot(root), true);
  const { rows, stats } = extractClaudeContext(root);
  assert.ok(rows.some((r) => r.RecordType === "cli_settings"));
  assert.ok(rows.some((r) => r.RecordType === "hook_config" && r.ToolCommand === "audit-hook"));
  assert.ok(rows.some((r) => r.RecordType === "mcp_server_config" && r.InvokedTool === "triage"));
  assert.ok(rows.some((r) => r.RecordType === "file_history_backup"));
  const backup = rows.find((r) => r.RecordType === "claude_state_backup_inventory");
  assert.match(backup.FullText, /linkedCurrentSource/);
  const credential = rows.find((r) => r.RecordType === "credential_inventory");
  assert.match(credential.FullText, /excluded_credential/);
  assert.equal(stats.credentialExcluded, 1);
  const all = rows.map((r) => `${r.FullText}\n${r.ToolInput}`).join("\n");
  assert.doesNotMatch(all, /CLAUDE-SECRET|CLAUDE-MCP-SECRET|CLAUDE-CREDENTIAL-BODY/);
});

test("Codex config emits trust/MCP/plugin context and redacts sensitive values", (t) => {
  const root = tempRoot(t, "irflow-codex-context-");
  fs.writeFileSync(path.join(root, "config.toml"), [
    'model = "gpt-6"',
    '[projects."/evidence/case"]',
    'trust_level = "trusted"',
    '[mcp_servers.timeline]',
    'command = "node"',
    'args = ["server.js", "--token", "CODEX-ARG-SECRET"]',
    'env = { API_TOKEN = "CODEX-INLINE-SECRET" }',
    'url = "https://mcp.invalid/connect?api_key=CODEX-URL-SECRET"',
    'authorization_token = "CODEX-SECRET"',
    '[plugins.forensics]',
    'enabled = true',
  ].join("\n"));
  fs.writeFileSync(path.join(root, "AGENTS.md"), "# Evidence instruction\nPreserve original files.");
  fs.writeFileSync(path.join(root, "auth.json"), "CODEX-AUTH-BODY");
  fs.mkdirSync(path.join(root, "plugins", "forensics"), { recursive: true });
  fs.writeFileSync(path.join(root, "plugins", "forensics", "plugin.json"), '{"name":"forensics"}');

  const { rows, stats } = extractCodexContext(root);
  assert.ok(rows.some((r) => r.RecordType === "project_trust_config" && r.Workspace === "/evidence/case"));
  assert.ok(rows.some((r) => r.RecordType === "mcp_server_config" && r.ToolCommand === "node"));
  assert.ok(rows.some((r) => r.RecordType === "plugin_config"));
  assert.ok(rows.some((r) => r.RecordType === "instruction_context" && /Preserve original files/.test(r.FullText)));
  assert.ok(rows.some((r) => r.RecordType === "credential_inventory" && /excluded_credential/.test(r.FullText)));
  assert.ok(stats.configRows >= 4);
  const all = rows.map((r) => r.FullText).join("\n");
  assert.doesNotMatch(all, /CODEX-SECRET|CODEX-ARG-SECRET|CODEX-INLINE-SECRET|CODEX-URL-SECRET|CODEX-AUTH-BODY/);
});

test("Grok Build context keeps trust, prompt hashes, terminal output, worktrees, and task provenance", (t) => {
  const root = tempRoot(t, "irflow-grok-context-");
  fs.writeFileSync(path.join(root, "config.toml"), 'yolo = false\npermission_mode = "ask"\nenv = { API_TOKEN = "GROK-INLINE-SECRET" }\nauth_token = "GROK-SECRET"\n');
  fs.writeFileSync(path.join(root, "trusted_folders.toml"), '["/evidence/case"]\ntrusted = true\ndecided_at = "2026-09-08T01:00:00Z"\n');
  fs.writeFileSync(path.join(root, "version.json"), '{"version":"1.0.13"}');
  fs.writeFileSync(path.join(root, "agent_id"), "agent-123");
  const session = path.join(root, "sessions", "workspace", "session-1");
  fs.mkdirSync(path.join(session, "terminal"), { recursive: true });
  fs.writeFileSync(path.join(session, "prompt_context.json"), JSON.stringify({
    prompt_mode: "build", cwd: "/evidence/case", prompt_body: "SYSTEM-PROMPT-BODY",
    agents_md_files: [{ path: "/evidence/case/AGENTS.md", prompt_body: "NESTED-INSTRUCTION-BODY" }],
    persona_summaries: ["NESTED-PERSONA-SUMMARY"],
  }));
  fs.writeFileSync(path.join(session, "terminal", "call-11111111-1111-4111-8111-111111111111-7.log"), "uid=501 analyst\n");
  fs.mkdirSync(path.join(root, "long-running-background-tasks"));
  fs.writeFileSync(path.join(root, "long-running-background-tasks", "watch.sh"), "#!/bin/sh\necho watch\n");

  let sqliteBuilt = false;
  try {
    const Database = require("better-sqlite3");
    const db = new Database(path.join(root, "worktrees.db"));
    db.exec("CREATE TABLE worktrees (id TEXT, path TEXT, source_repo TEXT, status TEXT, session_id TEXT, git_ref TEXT, created_at TEXT, last_accessed_at TEXT)");
    db.prepare("INSERT INTO worktrees VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run("wt-1", "/tmp/wt", "/repo", "active", "session-1", "main", "2026-09-08T01:00:00Z", "2026-09-08T01:01:00Z");
    db.close();
    sqliteBuilt = true;
  } catch { /* ABI-dependent test lane */ }

  const { rows } = extractGrokBuildContext(root);
  assert.ok(rows.some((r) => r.RecordType === "cli_settings"));
  assert.ok(rows.some((r) => r.RecordType === "trusted_folder_config" && r.Timestamp === "2026-09-08 01:00:00"));
  const prompt = rows.find((r) => r.RecordType === "prompt_context");
  assert.match(prompt.FullText, /"sha256": "[0-9a-f]{64}"/);
  assert.doesNotMatch(prompt.FullText, /SYSTEM-PROMPT-BODY|NESTED-INSTRUCTION-BODY|NESTED-PERSONA-SUMMARY/);
  const terminal = rows.find((r) => r.RecordType === "terminal_output_log");
  assert.equal(terminal.MessageId, "11111111-1111-4111-8111-111111111111");
  assert.match(terminal.FullText, /uid=501/);
  assert.ok(rows.some((r) => r.RecordType === "background_task_definition"));
  if (sqliteBuilt) assert.ok(rows.some((r) => r.RecordType === "worktree_state" && r.MessageId === "wt-1"));
  assert.doesNotMatch(rows.map((r) => r.FullText).join("\n"), /GROK-SECRET|GROK-INLINE-SECRET/);
});

test("Cursor context inventories raw indexes and parses hook/MCP configuration", (t) => {
  const root = tempRoot(t, "irflow-cursor-context-");
  fs.mkdirSync(path.join(root, "plans"), { recursive: true });
  fs.mkdirSync(path.join(root, "ai-tracking"), { recursive: true });
  fs.writeFileSync(path.join(root, "hooks.json"), JSON.stringify({ hooks: { PreToolUse: [{ command: "cursor-audit" }] } }));
  fs.writeFileSync(path.join(root, "mcp.json"), JSON.stringify({ mcpServers: { case: { command: "case-server", env: { TOKEN: "CURSOR-SECRET" } } } }));
  fs.writeFileSync(path.join(root, "plans", "case.md"), "# Plan");
  fs.writeFileSync(path.join(root, "AGENTS.md"), "Preserve evidence");
  fs.writeFileSync(path.join(root, "ai-tracking", "ai-tracking.db"), "raw-index");

  const { rows } = extractCursorContext(root);
  assert.ok(rows.some((r) => r.RecordType === "hook_config" && r.ToolCommand === "cursor-audit"));
  assert.ok(rows.some((r) => r.RecordType === "mcp_server_config" && r.InvokedTool === "case"));
  assert.ok(rows.some((r) => r.RecordType === "plan_inventory"));
  assert.ok(rows.some((r) => r.RecordType === "instruction_inventory"));
  assert.ok(rows.some((r) => r.RecordType === "raw_index_inventory" && /computed/.test(r.FullText)));
  assert.doesNotMatch(rows.map((r) => r.FullText).join("\n"), /CURSOR-SECRET/);

  const sources = inventoryAiHistorySources("cursor", root);
  assert.ok(sources.some((p) => p.endsWith("ai-tracking.db")));
});
