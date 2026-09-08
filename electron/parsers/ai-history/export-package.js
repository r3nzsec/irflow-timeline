/**
 * ai-history/export-package.js — forensic export bundle (CSV + source manifest).
 */

const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const MAX_HASH_FILES = 250;

function sanitizeExportBaseName(name) {
  const base = String(name || "ai-query-history").replace(/\.[^.]+$/, "");
  return base.replace(/[^\w.-]+/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "").slice(0, 80) || "ai-query-history";
}

async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

/**
 * @param {{ value: string, count: number }[]} sourceGroups
 */
async function enrichSourceManifest(sourceGroups, opts = {}) {
  const maxHash = opts.maxHashFiles ?? MAX_HASH_FILES;
  const coverage = Array.isArray(opts.sourceCoverage) ? opts.sourceCoverage : [];
  const coverageByPath = new Map();
  for (const item of coverage) {
    if (!item?.sourceFile) continue;
    coverageByPath.set(path.resolve(String(item.sourceFile)), item);
  }
  const groupByPath = new Map();
  for (const group of sourceGroups || []) {
    if (!group?.value) continue;
    const sourcePath = path.resolve(String(group.value));
    const current = groupByPath.get(sourcePath) || 0;
    groupByPath.set(sourcePath, current + Number(group.count || 0));
  }
  for (const sourcePath of coverageByPath.keys()) {
    if (!groupByPath.has(sourcePath)) groupByPath.set(sourcePath, 0);
  }
  const sources = [];
  let hashed = 0;
  let hashTruncated = false;

  for (const [filePath, count] of [...groupByPath.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const coverageItem = coverageByPath.get(filePath) || null;
    const entry = {
      path: filePath,
      rowCount: count,
      exists: false,
    };
    if (coverageItem) {
      entry.coverage = Object.fromEntries(Object.entries(coverageItem)
        .filter(([key, value]) => key !== "sourceFile" && value !== undefined));
    }
    try {
      const st = await fsp.stat(filePath);
      entry.exists = true;
      entry.sizeBytes = st.size;
      entry.mtime = st.mtime.toISOString();
      const status = coverageItem?.status || "";
      const omitHash = status === "excluded" || status === "unavailable" || status === "unsupported";
      if (omitHash) {
        entry.sha256 = null;
        entry.sha256Skipped = true;
        entry.sha256SkippedReason = `source coverage status: ${status}`;
      } else if (hashed < maxHash) {
        entry.sha256 = await sha256File(filePath);
        hashed += 1;
      } else {
        hashTruncated = true;
        entry.sha256 = null;
        entry.sha256Skipped = true;
      }
    } catch {
      entry.exists = false;
    }
    sources.push(entry);
  }

  return { sources, hashedFileCount: hashed, hashTruncated };
}

function buildExtractionReport(importMeta = null, failures = []) {
  if (!importMeta && !(failures || []).length) return null;
  const sourceCoverage = Array.isArray(importMeta?.sourceCoverage) ? importMeta.sourceCoverage : [];
  const statusCounts = {};
  for (const entry of sourceCoverage) {
    const status = entry?.status || "unknown";
    statusCounts[status] = (statusCounts[status] || 0) + 1;
  }
  const incompleteStatuses = new Set(["partial", "malformed", "unsupported", "excluded", "unavailable"]);
  const incompleteSources = sourceCoverage.filter((entry) => incompleteStatuses.has(entry?.status));
  const normalizedFailures = (failures || []).map((failure) => ({
    tool: failure?.tool || "",
    label: failure?.label || "",
    path: failure?.path || "",
    error: failure?.error || String(failure || ""),
  }));
  return {
    version: 1,
    complete: !importMeta?.capped && incompleteSources.length === 0 && normalizedFailures.length === 0,
    statusCounts,
    sourceCoverage,
    failures: normalizedFailures,
    discoveryInventory: importMeta?.discoveryInventory || null,
    capped: importMeta?.capped || null,
    parseErrors: Number(importMeta?.parseErrors || 0),
    fullTextTruncated: importMeta?.fullTextTruncated || null,
    performance: importMeta?.performance || null,
  };
}

function buildPackageManifest({
  tabName,
  sourceFormat,
  totalRows,
  exportedRows,
  filtersApplied,
  sources,
  hashedFileCount,
  hashTruncated,
  toolBreakdown,
  extractionReport,
}) {
  return {
    format: "irflow-ai-history-package",
    formatVersion: 2,
    exportedAt: new Date().toISOString(),
    tabName: tabName || "",
    sourceFormat: sourceFormat || "",
    rowCount: {
      totalInTab: totalRows,
      exported: exportedRows,
    },
    filtersApplied: !!filtersApplied,
    sourceFileCount: sources.length,
    hashedFileCount,
    hashTruncated,
    toolBreakdown: toolBreakdown || [],
    extraction: extractionReport || null,
    sources,
  };
}

function buildReadmeText({ tabName, exportedRows, sourceFileCount, hashTruncated, dirPath }) {
  const lines = [
    "IRFlow Timeline — AI Query History export package",
    "",
    `Tab: ${tabName || "AI Query History"}`,
    `Exported rows: ${exportedRows.toLocaleString()}`,
    `Source files referenced: ${sourceFileCount}`,
    hashTruncated ? "Note: SHA-256 computed for the first 250 source files only (remaining paths listed without hash)." : "",
    "",
    "Contents:",
    "  * *_timeline.csv — timeline rows (respects active filters and sort; always includes FullText when present)",
    "  * manifest.json — SourceFile paths, row counts, file size, mtime, SHA-256",
    "",
    `Folder: ${dirPath}`,
  ];
  return lines.filter(Boolean).join("\n");
}

/** Counsel-friendly slice: source paths and hashes only (no timeline CSV). */
function buildSourcesOnlyManifest({
  tabName,
  sourceFormat,
  totalRows,
  filtersApplied,
  sources,
  hashedFileCount,
  hashTruncated,
  toolBreakdown,
  extractionReport,
}) {
  return {
    format: "irflow-ai-history-sources-only",
    formatVersion: 2,
    exportedAt: new Date().toISOString(),
    tabName: tabName || "",
    sourceFormat: sourceFormat || "",
    rowCountInScope: totalRows,
    filtersApplied: !!filtersApplied,
    sourceFileCount: sources.length,
    hashedFileCount,
    hashTruncated,
    toolBreakdown: toolBreakdown || [],
    extraction: extractionReport || null,
    sources,
  };
}

function buildSourcesOnlyReadmeText({ tabName, sourceFileCount, hashTruncated, dirPath }) {
  const lines = [
    "IRFlow Timeline — AI Query History source manifest (sources only)",
    "",
    `Tab: ${tabName || "AI Query History"}`,
    `Source files referenced: ${sourceFileCount}`,
    hashTruncated ? "Note: SHA-256 computed for the first 250 source files only (remaining paths listed without hash)." : "",
    "",
    "Contents:",
    "  * sources_manifest.json — SourceFile paths, row counts, file size, mtime, SHA-256 (no message bodies)",
    "",
    "This export omits timeline CSV rows for counsel or chain-of-custody handoff when only artifact paths are needed.",
    "",
    `Folder: ${dirPath}`,
  ];
  return lines.filter(Boolean).join("\n");
}

module.exports = {
  MAX_HASH_FILES,
  sanitizeExportBaseName,
  sha256File,
  enrichSourceManifest,
  buildExtractionReport,
  buildPackageManifest,
  buildReadmeText,
  buildSourcesOnlyManifest,
  buildSourcesOnlyReadmeText,
};
