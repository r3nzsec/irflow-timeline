/**
 * ai-history/skysight-git-recovery.js — recover cleared Computer History summaries from git.
 *
 * `~/.codex/memories/` is a git repository. The ChatGPT docs advertise "clear the last 10 minutes /
 * hour / day / all history", and clearing deletes the derived summary files under
 * `extensions/skysight/resources/` — but the repository still holds their content, and the commit
 * that removed them is timestamped. That makes this the highest-value recovery path the feature has:
 * on a host where the ~48h raw event purge has already run AND the user cleared their history, the
 * git object store can be the only surviving record of the activity.
 *
 * Recovery is read-only and best-effort. `git` is invoked with `--git-dir` against the acquired
 * repository (never a checkout, never a write), with execFile — no shell — and a bounded output
 * buffer. If git is unavailable, the path is not a repository, or any command fails, the caller gets
 * an empty list and the import proceeds without recovery.
 *
 * CAVEAT for the analyst: a recovered summary is still LLM-generated interpretation, exactly like a
 * live one. Recovery proves the summary EXISTED and was REMOVED at the commit's timestamp; it does
 * not upgrade the summary's own evidentiary weight.
 */

const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

const { dbg } = require("../../logger");

const GIT_TIMEOUT_MS = 20000;
const GIT_MAX_BUFFER = 32 * 1024 * 1024;
/** Guardrail: a memories repo holds a handful of summaries, not thousands. */
const MAX_RECOVERED_FILES = 500;
const SKYSIGHT_PATHSPEC = "extensions/skysight";

/** Promise wrapper over execFile — array args only, no shell, bounded time and output. */
function runGit(gitDir, args) {
  return new Promise((resolve) => {
    execFile(
      "git",
      ["--git-dir", gitDir, ...args],
      { timeout: GIT_TIMEOUT_MS, maxBuffer: GIT_MAX_BUFFER, encoding: "utf8", windowsHide: true },
      (err, stdout) => {
        if (err) { resolve({ ok: false, err, out: "" }); return; }
        resolve({ ok: true, err: null, out: String(stdout || "") });
      },
    );
  });
}

/**
 * Locate the git directory governing a Skysight resources path.
 * Walks up from the resources dir looking for a `.git` directory (typically `~/.codex/memories/.git`).
 */
function findMemoriesGitDir(resourcesDir) {
  if (!resourcesDir) return null;
  let p = resourcesDir;
  try {
    if (fs.statSync(p).isFile()) p = path.dirname(p);
  } catch { return null; }

  for (let i = 0; i < 16; i++) {
    const candidate = path.join(p, ".git");
    try {
      if (fs.statSync(candidate).isDirectory()) return candidate;
    } catch { /* keep walking */ }
    const parent = path.dirname(p);
    if (parent === p) break;
    p = parent;
  }
  return null;
}

/** `<sha>\x1f<iso>` header lines followed by name-only paths, per `--pretty` below. */
function parseLogOutput(out) {
  const commits = [];
  let current = null;
  for (const raw of String(out || "").split("\n")) {
    const line = raw.trimEnd();
    if (!line) continue;
    if (line.includes("\x1f")) {
      const [sha, iso] = line.split("\x1f");
      current = { sha: (sha || "").trim(), iso: (iso || "").trim(), files: [] };
      commits.push(current);
      continue;
    }
    if (current && line.startsWith(SKYSIGHT_PATHSPEC)) current.files.push(line);
  }
  return commits.filter((c) => c.sha && c.files.length);
}

/**
 * Find summaries removed from the repository, newest commit first.
 * Returns `[{ sha, iso, filePath, content }]`; `content` is "" when the blob could not be read.
 */
async function findDeletedSummaries(gitDir, options = {}) {
  const withContent = options.withContent !== false;
  const log = await runGit(gitDir, [
    "log", "--diff-filter=D", "--name-only", "--pretty=format:%H\x1f%aI",
    "--", SKYSIGHT_PATHSPEC,
  ]);
  if (!log.ok) {
    dbg("AIHIST", "skysight git log failed", { gitDir, err: log.err?.message });
    return [];
  }

  const out = [];
  for (const commit of parseLogOutput(log.out)) {
    for (const filePath of commit.files) {
      if (out.length >= MAX_RECOVERED_FILES) return out;
      let content = "";
      if (withContent) {
        // The parent commit still has the blob; the deleting commit does not.
        const show = await runGit(gitDir, ["show", `${commit.sha}^:${filePath}`]);
        if (show.ok) content = show.out;
      }
      out.push({ sha: commit.sha, iso: commit.iso, filePath, content });
    }
  }
  return out;
}

/** True when the repository has at least one commit — an empty repo recovers nothing. */
async function isUsableRepo(gitDir) {
  if (!gitDir) return false;
  const head = await runGit(gitDir, ["rev-parse", "--verify", "HEAD"]);
  return head.ok && head.out.trim().length > 0;
}

module.exports = {
  findMemoriesGitDir,
  findDeletedSummaries,
  isUsableRepo,
  parseLogOutput,
  MAX_RECOVERED_FILES,
  SKYSIGHT_PATHSPEC,
};
