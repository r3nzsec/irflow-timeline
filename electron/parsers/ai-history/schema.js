/**
 * ai-history/schema.js — unified column schema for AI assistant timeline rows.
 */

const AI_HISTORY_COLUMNS = [
  "Timestamp",
  "TimestampBasis",
  "Role",
  "RecordType",
  "Summary",
  "FullText",
  "InvokedTool",
  "ToolCommand",
  "ToolInput",
  "ToolDescription",
  "SessionId",
  "MessageId",
  "ParentId",
  "Workspace",
  "IsSidechain",
  "GitBranch",
  "Tool",
  "Model",
  "InputTokens",
  "OutputTokens",
  "SourceFile",
  "LineNumber",
  "SourceOffset",
  "User",
  "Host",
  "AlsoInTools",
  "Description",
  "RecordId",
];

const SUMMARY_MAX_LEN = 500;
/** Allows DB sinks to omit FullText when explicitly requested; AI history imports retain it. */
const AI_HISTORY_DB_OMIT_FULLTEXT = true;
const TOOL_CLAUDE_CODE = "Claude Code";
const TOOL_CHATGPT = "ChatGPT";
const TOOL_GEMINI_CLI = "Gemini CLI";
const TOOL_CODEX = "OpenAI Codex";
const TOOL_GROK_BUILD = "Grok Build";
const TOOL_GROK_BOT = "Grok Bot";
const TOOL_CURSOR = "Cursor";
const TOOL_COPILOT = "GitHub Copilot";
const TOOL_WINDSURF = "Windsurf";
const TOOL_CONTINUE = "Continue";

const AI_HISTORY_TOOLS = {
  "claude-code": { label: TOOL_CLAUDE_CODE, tabPrefix: "Claude Code AI History" },
  chatgpt: { label: TOOL_CHATGPT, tabPrefix: "ChatGPT AI History" },
  "gemini-cli": { label: TOOL_GEMINI_CLI, tabPrefix: "Gemini CLI AI History" },
  codex: { label: TOOL_CODEX, tabPrefix: "OpenAI Codex AI History" },
  "grok-build": { label: TOOL_GROK_BUILD, tabPrefix: "Grok Build AI History" },
  "grok-bot": { label: TOOL_GROK_BOT, tabPrefix: "Grok Bot AI History" },
  cursor: { label: TOOL_CURSOR, tabPrefix: "Cursor AI History" },
  copilot: { label: TOOL_COPILOT, tabPrefix: "GitHub Copilot AI History" },
  windsurf: { label: TOOL_WINDSURF, tabPrefix: "Windsurf AI History" },
  continue: { label: TOOL_CONTINUE, tabPrefix: "Continue AI History" },
};

module.exports = {
  AI_HISTORY_COLUMNS,
  SUMMARY_MAX_LEN,
  AI_HISTORY_DB_OMIT_FULLTEXT,
  TOOL_CLAUDE_CODE,
  TOOL_CHATGPT,
  TOOL_GEMINI_CLI,
  TOOL_CODEX,
  TOOL_GROK_BUILD,
  TOOL_GROK_BOT,
  TOOL_CURSOR,
  TOOL_COPILOT,
  TOOL_WINDSURF,
  TOOL_CONTINUE,
  AI_HISTORY_TOOLS,
};
