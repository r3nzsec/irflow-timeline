/**
 * ai-history/import-meta.js — import notices and extraction stats for AI history tabs.
 */

const { formatChatgptImportNotice, buildChatgptExtractionStats } = require("./chatgpt");
const { buildClaudeDesktopImportNotice } = require("./claude-desktop");
const { buildCursorComposerImportNotice } = require("./cursor-composer");
const { buildCodexStateSqliteNotice } = require("./codex-state-sqlite");
const { buildWindsurfCascadeNotice } = require("./windsurf-cascade");

function buildCopilotExtractionStats(rows, sessionStats = {}) {
  const rowMessageCount = rows.filter((r) => r.Role === "user" || r.Role === "assistant").length;
  const {
    cli = false,
    sessionsScanned = 0,
    sessionsWithMessages = 0,
    emptySessions = 0,
    jsonlFiles = 0,
    jsonFiles = 0,
    jsonlSiblingFallback = 0,
    kind1Lines = 0,
    kind1Bodies = 0,
    emptyAfterJsonlReplay = 0,
    vscdbSupplement = 0,
    alternateAgentSessions = 0,
    eventFiles = 0,
    eventRows = 0,
    messageRows: streamedMessageRows = 0,
    planRows = 0,
    checkpointRows = 0,
    trackedFileRows = 0,
    commandHistoryRows = 0,
    sessionStoreTables = 0,
    sessionStoreRows = 0,
    logInventoryRows = 0,
    parseErrors = 0,
    excludedSensitiveStores = [],
  } = sessionStats;

  const messageRows = rowMessageCount || streamedMessageRows;
  const metadataOnly = sessionsScanned > 0 && messageRows === 0;
  return {
    cli,
    messageRows,
    sessionsScanned,
    sessionsWithMessages,
    emptySessions,
    jsonlFiles,
    jsonFiles,
    jsonlSiblingFallback,
    kind1Lines,
    kind1Bodies,
    emptyAfterJsonlReplay,
    vscdbSupplement,
    alternateAgentSessions,
    eventFiles,
    eventRows,
    planRows,
    checkpointRows,
    trackedFileRows,
    commandHistoryRows,
    sessionStoreTables,
    sessionStoreRows,
    logInventoryRows,
    parseErrors,
    excludedSensitiveStores,
    metadataOnly,
  };
}

function formatCopilotImportNotice(stats) {
  if (!stats) return "";
  const {
    messageRows,
    sessionsScanned,
    sessionsWithMessages,
    emptySessions,
    metadataOnly,
  } = stats;

  if (stats.cli) {
    const parts = [
      `GitHub Copilot CLI: ${messageRows} message row(s) from ${sessionsWithMessages}/${sessionsScanned} session(s)`,
    ];
    if (stats.eventRows) parts.push(`${stats.eventRows} event rows`);
    if (stats.commandHistoryRows) parts.push(`${stats.commandHistoryRows} command-history rows`);
    if (stats.planRows) parts.push(`${stats.planRows} plan`);
    if (stats.checkpointRows) parts.push(`${stats.checkpointRows} checkpoint(s)`);
    if (stats.trackedFileRows) parts.push(`${stats.trackedFileRows} tracked-file inventory row(s)`);
    if (stats.sessionStoreRows) parts.push(`${stats.sessionStoreRows} session-store row(s)`);
    if (stats.logInventoryRows) parts.push(`${stats.logInventoryRows} log inventory row(s)`);
    parts.push("authentication and MCP secret stores excluded");
    return `${parts.join("; ")}.`;
  }

  if (metadataOnly) {
    let msg = `GitHub Copilot: scanned ${sessionsScanned} session file(s) but found no message bodies `
      + `(${emptySessions} empty shell(s)).`;
    if (stats.emptyAfterJsonlReplay > 0) {
      msg += ` ${stats.emptyAfterJsonlReplay} JSONL replay(s) had kind:1 UI state only — export chats from VS Code or check emptyWindowChatSessions.`;
    } else {
      msg += " Session JSON may be metadata-only; pair with .jsonl or use Export Chat.";
    }
    if (stats.alternateAgentSessions > 0) {
      msg += ` Found ${stats.alternateAgentSessions} VS Code Codex/agent session(s) in state.vscdb — use Tools → AI Artifacts → AI Apps → OpenAI Codex (or ~/.codex), not GitHub Copilot.`;
    }
    if (stats.vscdbSupplement > 0) {
      msg += ` Recovered ${stats.vscdbSupplement} message(s) from state.vscdb supplement.`;
    }
    return msg;
  }

  const parts = [`GitHub Copilot: ${messageRows} message row(s) from ${sessionsWithMessages}/${sessionsScanned} session(s)`];
  if (emptySessions > 0) parts.push(`${emptySessions} empty`);
  if (stats.jsonlSiblingFallback) parts.push(`${stats.jsonlSiblingFallback} via .jsonl sibling`);
  if (stats.kind1Lines > 0) parts.push(`kind:1 lines ${stats.kind1Lines} (${stats.kind1Bodies} with bodies)`);
  if (stats.jsonlFiles) parts.push(`${stats.jsonlFiles} JSONL`);
  if (stats.jsonFiles) parts.push(`${stats.jsonFiles} JSON`);
  return `${parts.join("; ")}.`;
}

function buildCopilotEmptyExtractError(stats) {
  if (!stats?.metadataOnly) return "";
  const notice = formatCopilotImportNotice(stats);
  return notice || "Sources were found but contained no message rows.";
}

function formatContextNotice(label, stats) {
  if (!stats) return "";
  const files = Number(stats.files || stats.selected || stats.taskInventory?.files || 0);
  const typed = Number(stats.typedRows || stats.configRows || 0);
  const omitted = Number(stats.omitted || stats.taskOmitted || 0);
  const credentialExcluded = Number(stats.credentialExcluded || 0);
  return `${label} context: ${typed} typed configuration row(s), ${files} inventoried file(s)`
    + `${credentialExcluded ? `, ${credentialExcluded} credential store(s) excluded from reading/hashing` : ""}`
    + `${omitted ? `, ${omitted} eligible file(s) omitted by the explicit context cap` : ", no eligible context file omitted"}.`;
}

function buildAiHistoryImportNotice(meta) {
  const parts = [];
  if (Array.isArray(meta?.sourceCoverage) && meta.sourceCoverage.length) {
    const counts = {};
    for (const entry of meta.sourceCoverage) counts[entry.status] = (counts[entry.status] || 0) + 1;
    const details = Object.entries(counts)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([status, count]) => `${count} ${status}`)
      .join(", ");
    parts.push(`Source coverage v1: ${meta.sourceCoverage.length} source(s) accounted for (${details}).`);
  }
  if (meta?.claudeDesktop) {
    const s = buildClaudeDesktopImportNotice(meta.claudeDesktop);
    if (s) parts.push(s);
  }
  if (meta?.claudeContext) parts.push(formatContextNotice("Claude Code", meta.claudeContext));
  if (meta?.chatgpt) {
    const s = formatChatgptImportNotice(meta.chatgpt);
    if (s) parts.push(s);
  }
  if (meta?.copilot) {
    const s = formatCopilotImportNotice(meta.copilot);
    if (s) parts.push(s);
    if (meta.copilot.vscdbSupplement > 0) {
      parts.push(`GitHub Copilot: +${meta.copilot.vscdbSupplement} row(s) from workspace state.vscdb supplement.`);
    }
  }
  if (meta?.cursor?.composer) {
    const s = buildCursorComposerImportNotice(meta.cursor.composer);
    if (s) parts.push(s);
  }
  if (meta?.cursor?.context) parts.push(formatContextNotice("Cursor", meta.cursor.context));
  if (meta?.windsurf) {
    const { buildVsCodeChatImportNotice } = require("./vscode-chat-db");
    const s = buildVsCodeChatImportNotice("Windsurf", meta.windsurf);
    if (s) parts.push(s);
  }
  if (meta?.codexStateSqlite) {
    const s = buildCodexStateSqliteNotice(meta.codexStateSqlite);
    if (s) parts.push(s);
  }
  if (meta?.codexAuxSqlite) {
    const { buildCodexAuxSqliteNotice } = require("./codex-aux-sqlite");
    const s = buildCodexAuxSqliteNotice(meta.codexAuxSqlite);
    if (s) parts.push(s);
  }
  if (meta?.codexThreadHistory) {
    const { buildCodexThreadHistoryNotice } = require("./codex-thread-history-sqlite");
    const s = buildCodexThreadHistoryNotice(meta.codexThreadHistory);
    if (s) parts.push(s);
  }
  if (meta?.codexLocalEvidence) {
    const { buildCodexLocalEvidenceNotice } = require("./codex-local-evidence");
    const s = buildCodexLocalEvidenceNotice(meta.codexLocalEvidence);
    if (s) parts.push(s);
  }
  if (meta?.codexContext) parts.push(formatContextNotice("OpenAI Codex", meta.codexContext));
  if (meta?.grokContext) {
    const independent = meta.grokContext.independent || {};
    const worktrees = meta.grokContext.worktrees || {};
    parts.push(`Grok Build context: ${Number(meta.grokContext.typedRows || 0)} typed row(s); `
      + `${Number(independent.terminalRows || 0)} independent terminal log(s), ${Number(independent.promptRows || 0)} prompt context(s), `
      + `${Number(worktrees.records || 0)} worktree record(s)`
      + `${Number(independent.oversized || 0) ? `; ${independent.oversized} oversized source(s) inventoried instead of body-decoded` : ""}`
      + `${Number(independent.omitted || 0) ? `; ${independent.omitted} independent source(s) omitted by cap` : "; no independent source omitted"}.`);
  }
  if (meta?.geminiHistory) {
    parts.push(`Gemini CLI immutable history: ${Number(meta.geminiHistory.currentMessageRows || 0)} current row(s), `
      + `${Number(meta.geminiHistory.historyRows || 0)} history row(s), ${Number(meta.geminiHistory.operations || 0)} rewind/replacement operation(s).`);
  }
  if (meta?.windsurfCascade) {
    const s = buildWindsurfCascadeNotice(meta.windsurfCascade);
    if (s) parts.push(s);
  }
  if (meta?.grokBot) {
    const { buildGrokBotImportNotice } = require("./grok-bot");
    const s = buildGrokBotImportNotice(meta.grokBot);
    if (s) parts.push(s);
  }
  if (meta?.browserAgentHints?.length) {
    parts.push(`Browser AI paths detected (${meta.browserAgentHints.length}) — web-only usage may not appear in CLI/desktop stores.`);
  }
  if (meta?.cursor?.syntheticTimestamps) {
    parts.push("Cursor: some agent-transcript times are estimated from file timestamps; composer DB and JSONL createdAt are used when present.");
  }
  if (meta?.parseErrors > 0) {
    parts.push(`${meta.parseErrors.toLocaleString()} malformed JSONL line(s) were skipped during parsing.`);
  }
  if (meta?.capped) {
    parts.push(`Row cap of ${Number(meta.capped.maxRows).toLocaleString()} reached — the timeline was truncated to the earliest ${Number(meta.capped.rowCount).toLocaleString()} messages.`);
  }
  if (meta?.fullTextTruncated?.rows > 0) {
    const kb = Math.round(Number(meta.fullTextTruncated.maxChars || 0) / 1024);
    parts.push(`${Number(meta.fullTextTruncated.rows).toLocaleString()} message bod${meta.fullTextTruncated.rows === 1 ? "y" : "ies"} longer than ${kb} KB were stored truncated in this merged import (secret scan and search see the first ${kb} KB). Open that tool's folder on its own to keep the complete body.`);
  }
  return parts.join(" ");
}

function buildAiHistoryImportWarning(meta) {
  if (meta?.chatgpt?.encryptedBundleCount > 0 && !meta?.chatgpt?.messageCount) {
    return formatChatgptImportNotice(meta.chatgpt);
  }
  if (meta?.chatgpt?.leveldbMetadataOnly) {
    return formatChatgptImportNotice(meta.chatgpt);
  }
  if (meta?.claudeDesktop?.danglingCli > 0 || meta?.claudeDesktop?.metadataOnly > 0) {
    return buildClaudeDesktopImportNotice(meta.claudeDesktop);
  }
  if (meta?.copilot?.metadataOnly) {
    return formatCopilotImportNotice(meta.copilot);
  }
  if (meta?.copilot?.vscdbSupplement > 0) {
    return `GitHub Copilot: supplemented ${meta.copilot.vscdbSupplement} message(s) from workspace state.vscdb (chatSessions were empty or sparse).`;
  }
  return null;
}

module.exports = {
  buildCopilotExtractionStats,
  formatCopilotImportNotice,
  buildCopilotEmptyExtractError,
  buildChatgptExtractionStats,
  formatChatgptImportNotice,
  buildAiHistoryImportNotice,
  buildAiHistoryImportWarning,
};
