const crypto = require("crypto");
const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");

const SESSION_VERSION = 1;

function assertValidSessionPayload(session) {
  if (!session || typeof session !== "object" || Array.isArray(session)) {
    throw new Error("Session payload must be an object");
  }
  if (session.version !== SESSION_VERSION) {
    throw new Error(`Unsupported session version: ${session.version ?? "missing"}`);
  }
  if (!Array.isArray(session.tabs)) {
    throw new Error("Session payload is missing its tabs array");
  }
  if (!Number.isInteger(session.activeTabIndex) || session.activeTabIndex < -1) {
    throw new Error("Session payload has an invalid active tab index");
  }
  if (typeof session.savedAt !== "string" || !Number.isFinite(Date.parse(session.savedAt))) {
    throw new Error("Session payload has an invalid savedAt timestamp");
  }
  for (let i = 0; i < session.tabs.length; i++) {
    const tab = session.tabs[i];
    if (!tab || typeof tab !== "object" || Array.isArray(tab)) {
      throw new Error(`Session tab ${i + 1} must be an object`);
    }
    if (typeof tab.filePath !== "string" || typeof tab.name !== "string") {
      throw new Error(`Session tab ${i + 1} is missing its file path or name`);
    }
    if (!Array.isArray(tab.bookmarkedRowIds)) {
      throw new Error(`Session tab ${i + 1} is missing bookmarked row IDs`);
    }
    if (!tab.tags || typeof tab.tags !== "object" || Array.isArray(tab.tags)) {
      throw new Error(`Session tab ${i + 1} is missing tag data`);
    }
  }
  return session;
}

function _tempPathFor(filePath) {
  const token = crypto.randomBytes(8).toString("hex");
  return `${filePath}.${process.pid}.${token}.tmp`;
}

async function _syncDirectory(dirPath) {
  let handle;
  try {
    handle = await fsp.open(dirPath, "r");
    await handle.sync();
  } catch {
    // Directory fsync is not available on every platform/filesystem. The file
    // itself has already been synced, so this is best-effort durability only.
  } finally {
    try { await handle?.close(); } catch {}
  }
}

async function writeSessionAtomic(filePath, session, { backupPath = null, pretty = false } = {}) {
  assertValidSessionPayload(session);
  const json = JSON.stringify(session, null, pretty ? 2 : 0);
  const dirPath = path.dirname(filePath);
  const tempPath = _tempPathFor(filePath);
  let handle;
  let primaryMovedToBackup = false;

  await fsp.mkdir(dirPath, { recursive: true });
  try {
    handle = await fsp.open(tempPath, "wx", 0o600);
    await handle.writeFile(json, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;

    if (backupPath && fs.existsSync(filePath)) {
      await fsp.rm(backupPath, { force: true });
      await fsp.rename(filePath, backupPath);
      primaryMovedToBackup = true;
    }

    try {
      await fsp.rename(tempPath, filePath);
    } catch (err) {
      if (primaryMovedToBackup && !fs.existsSync(filePath) && fs.existsSync(backupPath)) {
        try { await fsp.rename(backupPath, filePath); } catch {}
      }
      throw err;
    }

    await _syncDirectory(dirPath);
    return { path: filePath, bytes: Buffer.byteLength(json, "utf8") };
  } finally {
    try { await handle?.close(); } catch {}
    try { await fsp.rm(tempPath, { force: true }); } catch {}
  }
}

async function readSessionWithBackup(filePath, backupPath = null) {
  const candidates = [filePath, ...(backupPath ? [backupPath] : [])];
  const failures = [];
  let found = false;

  for (const candidate of candidates) {
    try {
      const raw = await fsp.readFile(candidate, "utf8");
      found = true;
      const session = assertValidSessionPayload(JSON.parse(raw));
      return {
        session,
        sourcePath: candidate,
        recoveredFromBackup: candidate !== filePath,
      };
    } catch (err) {
      if (err?.code === "ENOENT") continue;
      found = true;
      failures.push(`${path.basename(candidate)}: ${err?.message || String(err)}`);
    }
  }

  if (!found) return null;
  throw new Error(`No valid session snapshot was found (${failures.join("; ")})`);
}

module.exports = {
  SESSION_VERSION,
  assertValidSessionPayload,
  writeSessionAtomic,
  readSessionWithBackup,
};
