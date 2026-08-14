"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

const {
  assertValidSessionPayload,
  writeSessionAtomic,
  readSessionWithBackup,
} = require("../electron/utils/session-persistence");

function session(savedAt, name = "Evidence") {
  return {
    version: 1,
    savedAt,
    activeTabIndex: 0,
    tabs: [{
      filePath: "/evidence/timeline.csv",
      name,
      bookmarkedRowIds: [4, 9],
      tags: { 4: ["review"] },
    }],
  };
}

test("atomic session writes rotate the previous valid snapshot to backup", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-atomic-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  const first = session("2026-08-11T00:00:00.000Z", "First");
  const second = session("2026-08-11T00:01:00.000Z", "Second");

  await writeSessionAtomic(primary, first, { backupPath: backup });
  await writeSessionAtomic(primary, second, { backupPath: backup });

  assert.deepEqual(JSON.parse(await fsp.readFile(primary, "utf8")), second);
  assert.deepEqual(JSON.parse(await fsp.readFile(backup, "utf8")), first);
  assert.deepEqual(fs.readdirSync(tmp).sort(), ["autosave.tle", "autosave.tle.bak"]);
});

test("autosave recovery falls back to the last valid backup", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-recovery-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  const first = session("2026-08-11T00:00:00.000Z", "Recover Me");
  const second = session("2026-08-11T00:01:00.000Z", "Corrupt Me");

  await writeSessionAtomic(primary, first, { backupPath: backup });
  await writeSessionAtomic(primary, second, { backupPath: backup });
  await fsp.writeFile(primary, '{"version":1,"tabs":[', "utf8");

  const loaded = await readSessionWithBackup(primary, backup);
  assert.equal(loaded.recoveredFromBackup, true);
  assert.equal(loaded.sourcePath, backup);
  assert.deepEqual(loaded.session, first);
});

test("session validation rejects malformed recovery data before it is written", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-invalid-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const good = session("2026-08-11T00:00:00.000Z");

  await writeSessionAtomic(primary, good);
  await assert.rejects(
    writeSessionAtomic(primary, { version: 1, savedAt: "invalid", activeTabIndex: 0, tabs: [] }),
    /invalid savedAt timestamp/,
  );
  assert.deepEqual(JSON.parse(await fsp.readFile(primary, "utf8")), good);
  assert.throws(() => assertValidSessionPayload({ version: 1 }), /tabs array/);
});

test("session recovery reports corruption when neither snapshot is valid", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-session-both-corrupt-"));
  t.after(() => { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ } });
  const primary = path.join(tmp, "autosave.tle");
  const backup = `${primary}.bak`;
  await fsp.writeFile(primary, "not-json", "utf8");
  await fsp.writeFile(backup, JSON.stringify({ version: 1, tabs: [] }), "utf8");

  await assert.rejects(readSessionWithBackup(primary, backup), /No valid session snapshot/);
});
