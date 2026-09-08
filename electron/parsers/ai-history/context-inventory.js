/**
 * Bounded, content-safe inventory helpers for AI application context artifacts.
 *
 * These artifacts often influence what an agent may do without being conversation events:
 * instructions, plans, skills, plugins, configuration backups, and physical file-history copies.
 * The default representation records path, size, mtime and a SHA-256 for ordinary files. Files
 * whose names indicate credentials are never opened, including for hashing.
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { formatTimestampUtc, makeRow } = require("./row-utils");
const { pageDiscoveryInventory } = require("./discovery-inventory");

const MAX_CONTEXT_HASH_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_CONTEXT_FILES = 5000;
const CREDENTIAL_PATH_RE = /(?:^|[._-])(auth|credential|credentials|oauth|token|tokens|secret|secrets|cookie|cookies|keychain|api[_-]?key)(?:[._-]|$)/i;

function safeStat(filePath) {
  try { return fs.statSync(filePath); } catch { return null; }
}

function isCredentialLikePath(filePath) {
  return String(filePath || "").split(/[\\/]+/).some((part) => CREDENTIAL_PATH_RE.test(part));
}

function sha256FileBounded(filePath, maxBytes = MAX_CONTEXT_HASH_BYTES, checkAbort = () => {}) {
  const st = safeStat(filePath);
  if (!st || !st.isFile()) return { sha256: null, hashStatus: "unavailable" };
  if (isCredentialLikePath(filePath)) return { sha256: null, hashStatus: "excluded_credential" };
  if (st.size > maxBytes) return { sha256: null, hashStatus: "omitted_size_limit" };

  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.allocUnsafe(256 * 1024);
  let offset = 0;
  try {
    while (offset < st.size) {
      checkAbort();
      const read = fs.readSync(fd, buffer, 0, Math.min(buffer.length, st.size - offset), offset);
      if (!read) break;
      hash.update(buffer.subarray(0, read));
      offset += read;
    }
  } finally {
    try { fs.closeSync(fd); } catch { /* ignore */ }
  }
  if (offset !== st.size) return { sha256: null, hashStatus: "read_incomplete" };
  return { sha256: hash.digest("hex"), hashStatus: "computed" };
}

function walkContextFiles(rootDir, options = {}) {
  const maxDepth = Math.max(0, Number(options.maxDepth ?? 8));
  const maxFiles = Math.max(1, Number(options.maxFiles ?? DEFAULT_MAX_CONTEXT_FILES));
  const maxInventoryFiles = Math.max(maxFiles, Number(options.maxInventoryFiles ?? 100000));
  const checkAbort = typeof options.checkAbort === "function" ? options.checkAbort : () => {};
  const accept = typeof options.accept === "function" ? options.accept : () => true;
  const skipDir = typeof options.skipDir === "function" ? options.skipDir : () => false;
  const eligibleFiles = [];
  let eligible = 0;
  let directories = 0;
  const stack = [{ dir: rootDir, depth: 0 }];

  while (stack.length) {
    checkAbort();
    const { dir, depth } = stack.pop();
    directories += 1;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!entry.isSymbolicLink() && depth < maxDepth && !skipDir(full, entry, depth + 1)) {
          stack.push({ dir: full, depth: depth + 1 });
        }
        continue;
      }
      if (!entry.isFile() || !accept(full, entry)) continue;
      eligible += 1;
      if (eligibleFiles.length < maxInventoryFiles) eligibleFiles.push(full);
    }
  }
  const page = pageDiscoveryInventory(eligibleFiles, { limit: maxFiles, cursor: options.cursor });
  return {
    files: page.paths,
    remainingFiles: page.remainingPaths,
    nextCursor: page.nextCursor,
    fingerprintSha256: page.fingerprintSha256,
    stats: {
      eligible,
      selected: page.paths.length,
      omitted: page.remainingPaths.length,
      directories,
      maxFiles,
      maxInventoryFiles,
      inventoryTruncated: eligible > eligibleFiles.length,
      nextCursor: page.nextCursor,
      inventoryFingerprintSha256: page.fingerprintSha256,
    },
  };
}

function contextInventoryRow({
  tool,
  rootPath,
  filePath,
  family,
  recordType = "context_inventory",
  summaryLabel,
  toolDescription,
  attribution = {},
  sessionId = "",
  messageId = "",
  parentId = "",
  workspace = "",
  extra = {},
  maxHashBytes = MAX_CONTEXT_HASH_BYTES,
  checkAbort = () => {},
  credentialExcluded = isCredentialLikePath(filePath),
}) {
  const st = safeStat(filePath);
  if (!st || !st.isFile()) return null;
  const hash = credentialExcluded
    ? { sha256: null, hashStatus: "excluded_credential" }
    : sha256FileBounded(filePath, maxHashBytes, checkAbort);
  const relativePath = rootPath ? path.relative(rootPath, filePath) : path.basename(filePath);
  const details = {
    family,
    relativePath,
    fileName: path.basename(filePath),
    sizeBytes: st.size,
    modifiedAtMs: Math.trunc(st.mtimeMs),
    sha256: hash.sha256,
    hashStatus: hash.hashStatus,
    contentsRead: false,
    credentialExcluded,
    ...extra,
  };
  return makeRow({
    timestamp: formatTimestampUtc(st.mtimeMs),
    timestampBasis: "source file mtime",
    role: "metadata",
    recordType,
    summary: `${summaryLabel || family} — ${relativePath} (${st.size} bytes)`,
    fullText: JSON.stringify(details, null, 2),
    toolDescription: toolDescription || "Inventory metadata for an agent context artifact. The body was not copied into the timeline row.",
    sessionId,
    messageId: messageId || relativePath,
    parentId,
    workspace,
    sourceFile: filePath,
    user: attribution.user || "",
    host: attribution.host || "",
    tool,
  }, tool);
}

function inventoryContextFiles({ tool, rootPath, files, classify, attribution = {}, maxHashBytes, checkAbort = () => {} }) {
  const rows = [];
  const stats = {
    files: 0,
    bytes: 0,
    hashed: 0,
    credentialExcluded: 0,
    hashOmitted: 0,
    byFamily: {},
  };
  for (const filePath of [...new Set(files || [])].sort()) {
    checkAbort();
    const spec = classify(filePath);
    if (!spec) continue;
    const row = contextInventoryRow({
      tool,
      rootPath,
      filePath,
      attribution,
      maxHashBytes,
      checkAbort,
      ...spec,
    });
    if (!row) continue;
    rows.push(row);
    const data = JSON.parse(row.FullText);
    stats.files += 1;
    stats.bytes += Number(data.sizeBytes) || 0;
    stats.byFamily[data.family] = (stats.byFamily[data.family] || 0) + 1;
    if (data.hashStatus === "computed") stats.hashed += 1;
    else stats.hashOmitted += 1;
    if (data.credentialExcluded) stats.credentialExcluded += 1;
  }
  return { rows, stats };
}

module.exports = {
  MAX_CONTEXT_HASH_BYTES,
  DEFAULT_MAX_CONTEXT_FILES,
  CREDENTIAL_PATH_RE,
  safeStat,
  isCredentialLikePath,
  sha256FileBounded,
  walkContextFiles,
  contextInventoryRow,
  inventoryContextFiles,
};
