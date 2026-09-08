/** Deterministic paging for bounded AI-artifact discovery inventories. */

const crypto = require("crypto");

const INVENTORY_VERSION = 1;

function encodeCursor(sourcePath) {
  return Buffer.from(String(sourcePath || ""), "utf8").toString("base64url");
}

function decodeCursor(cursor) {
  if (!cursor) return "";
  try { return Buffer.from(String(cursor), "base64url").toString("utf8"); } catch { return ""; }
}

function inventoryFingerprint(paths) {
  const hash = crypto.createHash("sha256");
  for (const sourcePath of paths) hash.update(sourcePath).update("\0");
  return hash.digest("hex");
}

/**
 * Page a complete path inventory without making the processing cap part of discovery.
 * A cursor names the last emitted path, so inserting an earlier source does not repeat later ones.
 */
function pageDiscoveryInventory(sourcePaths, options = {}) {
  const paths = [...new Set((sourcePaths || []).filter(Boolean).map(String))].sort();
  const requestedLimit = Number(options.limit);
  const limit = Number.isFinite(requestedLimit) && requestedLimit > 0
    ? Math.max(1, Math.floor(requestedLimit))
    : paths.length || 1;
  const afterPath = decodeCursor(options.cursor);
  let startIndex = 0;
  if (afterPath) {
    while (startIndex < paths.length && paths[startIndex] <= afterPath) startIndex += 1;
  }
  const selected = paths.slice(startIndex, startIndex + limit);
  const remainingPaths = paths.slice(startIndex + selected.length);
  return {
    version: INVENTORY_VERSION,
    paths: selected,
    allPaths: paths,
    remainingPaths,
    eligible: paths.length,
    selected: selected.length,
    omitted: remainingPaths.length,
    startIndex,
    nextCursor: remainingPaths.length && selected.length
      ? encodeCursor(selected[selected.length - 1])
      : null,
    fingerprintSha256: inventoryFingerprint(paths),
  };
}

module.exports = {
  INVENTORY_VERSION,
  encodeCursor,
  decodeCursor,
  inventoryFingerprint,
  pageDiscoveryInventory,
};
