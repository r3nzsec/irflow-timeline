#!/usr/bin/env node
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { Worker } = require("node:worker_threads");

const ROOT = path.resolve(__dirname, "..");
const WORKER = path.join(__dirname, "ai-history-phase4-worker.cjs");
const DEFAULT_OUTPUT = path.join(ROOT, "internal-docs", "audits", "2026-09-08-ai-apps", "evidence", "phase-4-benchmark-report.json");
const args = process.argv.slice(2);
const valueAfter = (flag, fallback = null) => {
  const index = args.indexOf(flag);
  return index >= 0 && args[index + 1] ? args[index + 1] : fallback;
};
const isElectronChild = args.includes("--electron-child");
const quick = args.includes("--quick");
const largeMiB = Number(valueAfter("--large-mib", quick ? "64" : "1024"));
const outputPath = path.resolve(valueAfter("--output", DEFAULT_OUTPUT));
const suppliedCorpus = valueAfter("--corpus");

function hashFile(filePath) {
  const hash = crypto.createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    while (true) {
      const read = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (!read) break;
      hash.update(buffer.subarray(0, read));
    }
  } finally { fs.closeSync(fd); }
  return hash.digest("hex");
}

function listFiles(rootPath) {
  let st;
  try { st = fs.statSync(rootPath); } catch { return []; }
  if (st.isFile()) return [rootPath];
  const out = [];
  const stack = [rootPath];
  while (stack.length) {
    const dir = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !entry.isSymbolicLink()) stack.push(full);
      else if (entry.isFile()) out.push(full);
    }
  }
  return out.sort();
}

function copyDir(source, destination) {
  fs.cpSync(source, destination, { recursive: true });
}

function generateLargeRollout(root, sizeMiB) {
  const sessionDir = path.join(root, ".codex", "sessions", "2026", "09", "08");
  fs.mkdirSync(sessionDir, { recursive: true });
  const filePath = path.join(sessionDir, "rollout-phase4-large.jsonl");
  const targetBytes = sizeMiB * 1024 * 1024;
  const fd = fs.openSync(filePath, "w");
  const hash = crypto.createHash("sha256");
  let bytes = 0;
  let index = 0;
  try {
    while (bytes < targetBytes) {
      const payload = {
        timestamp: `2026-09-08T08:${String(Math.floor(index / 60) % 60).padStart(2, "0")}:${String(index % 60).padStart(2, "0")}.000Z`,
        type: "response_item",
        payload: {
          type: "message",
          role: index % 2 ? "assistant" : "user",
          content: [{ type: "output_text", text: `phase4-${index}-` + "x".repeat(32 * 1024) }],
        },
      };
      const line = Buffer.from(`${JSON.stringify(payload)}\n`);
      fs.writeSync(fd, line);
      hash.update(line);
      bytes += line.length;
      index += 1;
    }
  } finally { fs.closeSync(fd); }
  return { filePath, sha256: hash.digest("hex"), sizeBytes: bytes, records: index };
}

function generateCorpus(corpusRoot) {
  fs.mkdirSync(corpusRoot, { recursive: true });
  const fixtures = path.join(ROOT, "tests", "fixtures", "ai-history");
  const malformedRoot = path.join(corpusRoot, "malformed", ".codex", "sessions", "2026", "09", "08");
  fs.mkdirSync(malformedRoot, { recursive: true });
  const malformedPath = path.join(malformedRoot, "rollout-malformed.jsonl");
  const malformedFd = fs.openSync(malformedPath, "w");
  try {
    fs.writeSync(malformedFd, `${JSON.stringify({ timestamp: "2026-09-08T00:00:00Z", type: "event_msg", payload: { type: "user_message", message: "before" } })}\n`);
    fs.writeSync(malformedFd, "{malformed\n");
    fs.writeSync(malformedFd, `{"body":"${"z".repeat(34 * 1024 * 1024)}"}\n`);
    fs.writeSync(malformedFd, `${JSON.stringify({ timestamp: "2026-09-08T00:00:01Z", type: "event_msg", payload: { type: "user_message", message: "after" } })}\n`);
  } finally { fs.closeSync(malformedFd); }

  const cursorMany = path.join(corpusRoot, "cursor-many", ".cursor");
  fs.mkdirSync(path.join(cursorMany, "projects"), { recursive: true });
  const { buildCursorComposerFixture } = require("../tests/helpers/vscdb-builder");
  for (let i = 0; i < 30; i++) {
    buildCursorComposerFixture(path.join(cursorMany, "chats", `store-${String(i).padStart(2, "0")}`, "state.vscdb"));
  }

  const grokMulti = path.join(corpusRoot, "grokbot-multi");
  copyDir(path.join(fixtures, "grok-bot"), path.join(grokMulti, "account-a"));
  copyDir(path.join(fixtures, "grok-bot"), path.join(grokMulti, "account-b"));
  const staged = path.join(grokMulti, "account-a", ".grokbot", "attachment-staging", "large-evidence.bin");
  fs.mkdirSync(path.dirname(staged), { recursive: true });
  fs.writeFileSync(staged, "");
  fs.truncateSync(staged, 128 * 1024 * 1024);

  const activeWal = path.join(corpusRoot, "active-wal", ".cursor", "chats", "active", "state.vscdb");
  fs.mkdirSync(path.join(corpusRoot, "active-wal", ".cursor", "projects"), { recursive: true });
  fs.mkdirSync(path.dirname(activeWal), { recursive: true });
  const Database = require("better-sqlite3");
  const writer = new Database(activeWal);
  writer.pragma("journal_mode = WAL");
  writer.pragma("wal_autocheckpoint = 0");
  writer.exec("CREATE TABLE cursorDiskKV(key TEXT UNIQUE, value BLOB)");
  const insert = writer.prepare("INSERT INTO cursorDiskKV(key,value) VALUES (?,?)");
  insert.run("composerData:active", JSON.stringify({ composerId: "active", fullConversationHeadersOnly: [{ bubbleId: "b1", type: 1 }] }));
  insert.run("bubbleId:active:b1", JSON.stringify({ type: 1, text: "active WAL message", createdAt: 1788854400000 }));
  writer.close();

  const large = generateLargeRollout(path.join(corpusRoot, "large-rollout"), largeMiB);
  return { large };
}

function definitions(corpusRoot) {
  const fixtures = path.join(ROOT, "tests", "fixtures", "ai-history");
  return {
    tiny: [{ tool: "codex", target: path.join(fixtures, "codex", ".codex") }],
    representative_multi_app: [
      { tool: "claude-code", target: path.join(fixtures, "claude", ".claude") },
      { tool: "codex", target: path.join(fixtures, "codex", ".codex") },
      { tool: "grok-build", target: path.join(fixtures, "grok", ".grok") },
      { tool: "grok-bot", target: path.join(fixtures, "grok-bot") },
      { tool: "gemini-cli", target: path.join(fixtures, "gemini", ".gemini") },
      { tool: "cursor", target: path.join(fixtures, "cursor", ".cursor") },
    ],
    large_rollout: [{ tool: "codex", target: path.join(corpusRoot, "large-rollout", ".codex") }],
    malformed_oversized_line: [{ tool: "codex", target: path.join(corpusRoot, "malformed", ".codex") }],
    cursor_30_sqlite_stores: [{ tool: "cursor", target: path.join(corpusRoot, "cursor-many", ".cursor") }],
    grokbot_multi_account_replicas: [
      { tool: "grok-bot", target: path.join(corpusRoot, "grokbot-multi", "account-a") },
      { tool: "grok-bot", target: path.join(corpusRoot, "grokbot-multi", "account-b") },
    ],
    grokbot_large_attachment: [{ tool: "grok-bot", target: path.join(corpusRoot, "grokbot-multi", "account-a") }],
    active_wal_writer: [{ tool: "cursor", target: path.join(corpusRoot, "active-wal", ".cursor") }],
  };
}

function runWorker(cases, { cancelAfterMs = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const cancelBuffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const cancelView = new Int32Array(cancelBuffer);
    const worker = new Worker(WORKER, {
      workerData: { cases, cancelBuffer },
      resourceLimits: { maxOldGenerationSizeMb: 512 },
    });
    let cancelRequestedAt = 0;
    let timer = null;
    if (cancelAfterMs > 0) {
      timer = setTimeout(() => {
        cancelRequestedAt = performance.now();
        Atomics.store(cancelView, 0, 1);
      }, cancelAfterMs);
    }
    worker.once("message", (message) => {
      if (timer) clearTimeout(timer);
      resolve({
        ...message,
        resourceLimitMb: 512,
        cancellationLatencyMs: cancelRequestedAt ? performance.now() - cancelRequestedAt : null,
      });
      worker.terminate().catch(() => {});
    });
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code !== 0 && !cancelRequestedAt) reject(new Error(`benchmark worker exited ${code}`));
    });
  });
}

async function runRuntime(corpusRoot) {
  const casesByName = definitions(corpusRoot);
  const benchmarks = {};
  const Database = require("better-sqlite3");
  const activeWalPath = path.join(corpusRoot, "active-wal", ".cursor", "chats", "active", "state.vscdb");
  const activeWriter = new Database(activeWalPath);
  activeWriter.pragma("journal_mode = WAL");
  activeWriter.pragma("wal_autocheckpoint = 0");
  activeWriter.prepare("INSERT OR REPLACE INTO cursorDiskKV(key,value) VALUES (?,?)").run(
    "phase4:writer-heartbeat",
    JSON.stringify({ updatedAt: Date.now(), state: "writer connection held open during acquisition" }),
  );
  try {
    for (const [name, cases] of Object.entries(casesByName)) {
      benchmarks[name] = {
        cold: await runWorker(cases),
        warm: await runWorker(cases),
        cacheLabels: {
          cold: "new worker; operating-system cache state uncontrolled",
          warm: "new worker immediately after cold run against identical sources",
        },
      };
    }
  } finally {
    activeWriter.close();
  }
  const cancellation = await runWorker(casesByName.large_rollout, { cancelAfterMs: 100 });
  const runtime = process.versions.electron ? `electron-${process.versions.electron}` : `node-${process.versions.node}`;
  const gates = {
    completedWithin512MiBWorkerHeap: Object.values(benchmarks).every((entry) => entry.cold.ok && entry.warm.ok),
    cancellationAcknowledgedWithin2s: cancellation.canceled === true && cancellation.cancellationLatencyMs < 2000,
    noSilentSourceOmission: Object.values(benchmarks).every((entry) => {
      const run = entry.warm;
      return run.ok && Number(run.coverageCount || 0) > 0
        && Number(run.coverageStatusCounts?.excluded || 0) === 0;
    }),
    activeWalSnapshotParsed: benchmarks.active_wal_writer.warm.ok
      && benchmarks.active_wal_writer.warm.rowCount > 0
      && benchmarks.active_wal_writer.warm.acquisitions?.some((item) => (
        item.method === "sqlite_vacuum_into"
        && item.integrityCheck === "ok"
        && item.originalIdentity?.some((identity) => identity.path.endsWith("-wal") && identity.sha256)
        && /^[0-9a-f]{64}$/.test(item.snapshotIdentity?.sha256 || "")
      )),
  };
  return { runtime, benchmarks, cancellation, gates };
}

function corpusManifest(casesByName, knownLarge, corpusRoot) {
  const roots = [...new Set(Object.values(casesByName).flat().map((entry) => entry.target))];
  const files = [...new Set(roots.flatMap(listFiles))].sort();
  return files.map((filePath) => {
    const st = fs.statSync(filePath);
    const relativePath = filePath.startsWith(ROOT)
      ? path.relative(ROOT, filePath)
      : path.relative(corpusRoot, filePath);
    const credentialExcluded = /(?:^|[._-])(auth|credential|credentials|oauth|token|tokens|secret|secrets|cookie|cookies|keychain|api[_-]?key)(?:[._-]|$)/i
      .test(path.basename(filePath));
    return {
      path: relativePath,
      sizeBytes: st.size,
      sha256: credentialExcluded ? null : (filePath === knownLarge.filePath ? knownLarge.sha256 : hashFile(filePath)),
      hashStatus: credentialExcluded ? "excluded_credential" : "computed",
    };
  });
}

(async () => {
  const ownsCorpus = !suppliedCorpus;
  const corpusRoot = suppliedCorpus ? path.resolve(suppliedCorpus) : fs.mkdtempSync(path.join(os.tmpdir(), "irflow-phase4-corpus-"));
  let generated;
  try {
    const generatedMetaPath = path.join(corpusRoot, "generated-meta.json");
    if (ownsCorpus) {
      generated = generateCorpus(corpusRoot);
      fs.writeFileSync(generatedMetaPath, JSON.stringify(generated, null, 2));
    } else {
      generated = JSON.parse(fs.readFileSync(generatedMetaPath, "utf8"));
    }

    if (isElectronChild) {
      const electronResult = await runRuntime(corpusRoot);
      fs.mkdirSync(path.dirname(outputPath), { recursive: true });
      fs.writeFileSync(outputPath, JSON.stringify(electronResult, null, 2));
      try { require("electron").app.exit(0); } catch { process.exit(0); }
      return;
    }

    const nodeResult = await runRuntime(corpusRoot);
    const electronOutput = path.join(corpusRoot, "electron-result.json");
    const electron = path.join(ROOT, "node_modules", ".bin", "electron");
    const child = spawnSync(electron, [__filename, "--electron-child", "--corpus", corpusRoot, "--output", electronOutput, "--large-mib", String(largeMiB)], {
      cwd: ROOT,
      encoding: "utf8",
      timeout: 30 * 60 * 1000,
      env: { ...process.env, ELECTRON_DISABLE_SECURITY_WARNINGS: "1" },
    });
    if (child.status !== 0) {
      throw new Error(`Electron benchmark failed (${child.status}): ${child.stderr || child.stdout}`);
    }
    const electronResult = JSON.parse(fs.readFileSync(electronOutput, "utf8"));
    const casesByName = definitions(corpusRoot);
    const manifest = corpusManifest(casesByName, generated.large, corpusRoot);
    const report = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      referenceHost: {
        platform: process.platform,
        arch: process.arch,
        cpu: os.cpus()[0]?.model || "unknown",
        logicalCpus: os.cpus().length,
        totalMemoryBytes: os.totalmem(),
      },
      corpus: {
        requestedLargeMiB: largeMiB,
        largeRollout: {
          ...generated.large,
          filePath: path.relative(corpusRoot, generated.large.filePath),
        },
        fileCount: manifest.length,
        totalBytes: manifest.reduce((sum, entry) => sum + entry.sizeBytes, 0),
        manifestSha256: crypto.createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
        files: manifest,
      },
      runtimes: [nodeResult, electronResult],
      gates: {
        node: nodeResult.gates,
        electron: electronResult.gates,
        allPassed: Object.values(nodeResult.gates).every(Boolean) && Object.values(electronResult.gates).every(Boolean),
      },
      qualificationNotes: [
        "The 512 MiB gate is a V8 worker old-generation limit; peak RSS is reported separately.",
        "Cold means a new worker with uncontrolled operating-system cache state. Warm immediately repeats identical input in a new worker.",
        "The 20 percent regression gate requires a checked-in baseline from an earlier qualified release; this first Phase 4 report establishes that baseline.",
      ],
    };
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(report, null, 2));
    process.stdout.write(`${JSON.stringify({ outputPath, gates: report.gates, runtimes: report.runtimes.map((item) => item.runtime) }, null, 2)}\n`);
    if (!report.gates.allPassed) process.exitCode = 2;
  } finally {
    if (ownsCorpus) fs.rmSync(corpusRoot, { recursive: true, force: true });
  }
})().catch((error) => {
  process.stderr.write(`${error.stack || error.message || error}\n`);
  process.exitCode = 1;
});
