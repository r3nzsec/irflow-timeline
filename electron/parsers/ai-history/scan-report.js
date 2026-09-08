/**
 * scan-report.js — actionable report when AI artifact discovery finds nothing.
 */

const fs = require("fs");
const path = require("path");

const { FORENSIC_AI_PATH_HINTS } = require("./artifact-paths");
const { scanBrowserAgentHints, buildBrowserAgentReportLines } = require("./browser-agents");

function pathExists(p) {
  try { return fs.existsSync(p); } catch { return false; }
}

function probeCollectionLayout(scanRoot) {
  const resolved = path.resolve(scanRoot);
  const probe = {
    hasUsersDir: false,
    userSample: [],
    hasHomeLinux: false,
    homeSample: [],
    hasAppData: false,
    depth: 0,
  };

  const usersWin = path.join(resolved, "Users");
  const usersMac = path.join(resolved, "Users");
  if (pathExists(usersWin)) {
    try {
      const entries = fs.readdirSync(usersWin, { withFileTypes: true });
      probe.hasUsersDir = entries.some((e) => e.isDirectory() && !/^\.|\$|Default|Public|All Users/i.test(e.name));
      probe.userSample = entries
        .filter((e) => e.isDirectory() && !/^(Default|Public|All Users|\.)$/i.test(e.name))
        .slice(0, 5)
        .map((e) => e.name);
    } catch { /* ignore */ }
  }

  const homeDir = path.join(resolved, "home");
  if (pathExists(homeDir)) {
    try {
      const entries = fs.readdirSync(homeDir, { withFileTypes: true });
      probe.hasHomeLinux = entries.some((e) => e.isDirectory());
      probe.homeSample = entries.filter((e) => e.isDirectory()).slice(0, 5).map((e) => e.name);
    } catch { /* ignore */ }
  }

  const appData = path.join(resolved, "Users", probe.userSample[0] || "", "AppData");
  if (probe.userSample[0] && pathExists(path.join(resolved, "Users", probe.userSample[0], "AppData"))) {
    probe.hasAppData = true;
  }

  let depth = 0;
  let p = resolved;
  while (p !== path.dirname(p) && depth < 8) {
    depth += 1;
    p = path.dirname(p);
  }
  probe.depth = depth;

  return probe;
}

function formatHintList(platform) {
  const hints = FORENSIC_AI_PATH_HINTS[platform] || [];
  return hints.slice(0, 6).map((h) => `  • ${h}`).join("\n");
}

const PLATFORM_LABELS = { windows: "Windows", linux: "Linux", macos: "macOS" };

/** Structured checklist for the profile-scan modal (folder mode empty results). */
function buildExpectedPathsChecklist(probe) {
  const platforms = [];
  if (probe?.hasUsersDir || probe?.hasAppData) {
    platforms.push("windows", "macos");
  }
  if (probe?.hasHomeLinux) platforms.push("linux");
  if (!platforms.length) platforms.push("windows", "linux", "macos");

  const seen = new Set();
  const checklist = [];
  for (const platform of platforms) {
    if (seen.has(platform)) continue;
    seen.add(platform);
    checklist.push({
      platform,
      label: PLATFORM_LABELS[platform] || platform,
      paths: (FORENSIC_AI_PATH_HINTS[platform] || []).slice(0, 8),
    });
  }
  return checklist;
}

/**
 * @param {{ scanRoot?: string, scanMode?: string, scanned?: number, hitsFound?: number }} ctx
 */
function buildEmptyAiScanReport(ctx = {}) {
  const { scanRoot, scanMode, scanned = 0, hitsFound = 0 } = ctx;
  const isFolder = scanMode === "folder" && scanRoot;
  const lines = [];
  const probe = isFolder ? probeCollectionLayout(scanRoot) : null;
  const collectionIncomplete = !!(isFolder && probe
    && (probe.hasUsersDir || probe.hasHomeLinux)
    && hitsFound === 0);

  if (isFolder) {
    lines.push(`No AI assistant artifacts were found under this collection (${Number(scanned).toLocaleString()} directories checked).`);
    if (probe.hasUsersDir) {
      lines.push(`A Users\\ folder is present (${probe.userSample.join(", ") || "profiles detected"}) — standard AI paths may not have been collected by KAPE.`);
    } else if (probe.hasHomeLinux) {
      lines.push(`A home/ tree is present (${probe.homeSample.join(", ")}) — look for .claude, .cursor, .codex, .grok, .grokbot, .gemini under each user.`);
    } else {
      lines.push("No Users\\ or home/ layout detected at this path — try the KAPE output root or a per-user profile folder.");
    }
    lines.push("");
    lines.push("Expected paths (partial list):");
    lines.push(formatHintList("windows"));
    lines.push(formatHintList("macos"));
    lines.push("");
    lines.push("Next step: add the expected AI assistant folders to the collection, then run Scan AI Artifacts on the collection root again.");
    const browserHits = ctx.browserAgentHints?.length
      ? ctx.browserAgentHints.slice(0, 12)
      : scanBrowserAgentHints(scanRoot, { maxDepth: 10, maxHits: 12 });
    if (browserHits.length) {
      lines.push("");
      lines.push(...buildBrowserAgentReportLines(browserHits));
    }
  } else {
    lines.push("No readable AI history was found at standard locations on this machine.");
    lines.push("Install paths are probed for Claude Code, Codex, Grok Build, Grok Bot, ChatGPT, Gemini CLI, Cursor, GitHub Copilot, Windsurf, and Continue.");
    lines.push("");
    lines.push("If tools were used in-browser only, local desktop/CLI stores may be empty.");
  }

  const browserAgentHints = ctx.browserAgentHints?.length
    ? ctx.browserAgentHints
    : (isFolder ? scanBrowserAgentHints(scanRoot, { maxDepth: 10, maxHits: 16 }) : []);

  return {
    summary: lines[0],
    detail: lines.join("\n"),
    scanned,
    hitsFound,
    probe,
    collectionIncomplete,
    suggestAiRescan: !!isFolder,
    checklist: isFolder ? buildExpectedPathsChecklist(probe) : [],
    browserAgentHints,
  };
}

module.exports = {
  buildEmptyAiScanReport,
  buildExpectedPathsChecklist,
  probeCollectionLayout,
};
