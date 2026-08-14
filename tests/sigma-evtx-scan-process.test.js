// Hayabusa subprocess lifecycle: spawn / crash / cancel + binary self-test.
//
// Drives the real subprocess code in scan-process.js against a *fake* hayabusa
// (a tiny shell script), so we exercise spawn, exit-code handling, the partial-
// output-on-crash path, and cancellation without a real binary or better-sqlite3.
// scan-process.js depends only on Node core + the pure progress parser, so this
// runs under plain `node --test`.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  MAX_CAPTURED_STDERR_BYTES,
  runScanProcess,
  cancelScan,
  registerScanProc,
  isCancelled,
  unregisterScanProc,
  isAbnormalExit,
} = require("../electron/analyzers/sigma/evtx-scanner/scan-process");
const { verifyHayabusaBinary } = require("../electron/analyzers/sigma/evtx-scanner/binary-manager");
const {
  scanEvtxDirectory,
  _activeProcs,
} = require("../electron/analyzers/sigma/evtx-scanner/scan-runner");

const POSIX = process.platform !== "win32";

// A fake "hayabusa" executable: parses -o / --mode and behaves per mode.
const FAKE_HAYABUSA = `#!/bin/sh
out=""
mode="success"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2;;
    --mode) mode="$2"; shift 2;;
    *) shift;;
  esac
done
echo "Loading detection rules..." 1>&2
case "$mode" in
  success) [ -n "$out" ] && printf 'Timestamp,RuleTitle\\n2026,Test\\n' > "$out"; exit 0;;
  crash-with-output) [ -n "$out" ] && printf 'Timestamp,RuleTitle\\npartial' > "$out"; echo "[ERROR] boom" 1>&2; exit 3;;
  crash-no-output) echo "[ERROR] cannot read evtx" 1>&2; exit 3;;
  noisy-crash-with-output)
    [ -n "$out" ] && printf 'Timestamp,RuleTitle\\npartial' > "$out"
    i=0
    while [ "$i" -lt 20000 ]; do
      echo "[ERROR] noisy failure line $i 012345678901234567890123456789" 1>&2
      i=$((i + 1))
    done
    exit 3;;
  # exec so the spawned process *becomes* sleep — killing it directly closes the
  # stderr pipe and fires 'close' immediately (no orphaned child holding the fd).
  hang) exec sleep 10;;
  # Ignore TERM so the cancellation test proves SIGKILL escalation is based on
  # actual exit state, not ChildProcess.killed (which becomes true after TERM).
  ignore-term)
    [ -n "$out" ] && printf 'Timestamp,RuleTitle\\npartial' > "$out"
    trap '' TERM
    while :; do :; done;;
esac
`;

function makeWorkspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-scan-proc-"));
  t.after(() => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} });
  const bin = path.join(dir, "fake-hayabusa.sh");
  fs.writeFileSync(bin, FAKE_HAYABUSA, { mode: 0o755 });
  return { dir, bin };
}

function progressStub() {
  let stderr = "";
  return {
    handleChunk: (chunk) => { stderr += chunk.toString(); },
    startTicker: () => null,
    getStderr: () => stderr,
  };
}

function progressDiscardStub() {
  return {
    handleChunk: () => {},
    startTicker: () => null,
  };
}

test("runScanProcess: clean exit resolves exitCode 0 and produces output", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "success"],
    cwd: dir,
    scanJobId: null,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  assert.equal(result.cancelled, false);
  assert.equal(result.exitCode, 0);
  assert.equal(result.signal, null);
  assert.equal(isAbnormalExit(result), false);
  assert.ok(fs.existsSync(out));
});

test("runScanProcess: crash WITH partial output resolves with the non-zero code (not a hard failure)", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "crash-with-output"],
    cwd: dir,
    scanJobId: null,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  // The key behavior: a crash that left output is NOT silently treated as success.
  assert.equal(result.cancelled, false);
  assert.equal(result.exitCode, 3);
  assert.equal(isAbnormalExit(result), true, "non-zero exit must be flagged abnormal so results read as partial");
  assert.ok(result.errorLines.some((l) => /\[ERROR\]/.test(l)), "stderr [ERROR] lines are surfaced");
  assert.ok(fs.existsSync(out), "partial output is preserved for inspection");
});

test("runScanProcess: crash with NO output rejects (hard failure)", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "never-written.csv");

  await assert.rejects(
    runScanProcess({
      hayabusaPath: bin,
      args: ["-o", out, "--mode", "crash-no-output"],
      cwd: dir,
      scanJobId: null,
      progressParser: progressStub(),
      tempFiles: [out],
      actualOutput: out,
    }),
    /exited with code 3/
  );
});

test("runScanProcess: cancellation kills the process and resolves cancelled", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");
  const jobId = "test-cancel-job";
  t.after(() => unregisterScanProc(jobId));

  const promise = runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "hang"],
    cwd: dir,
    scanJobId: jobId,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  // Give the process a moment to actually start, then cancel it.
  await new Promise((r) => setTimeout(r, 150));
  const cancel = await cancelScan(jobId);
  assert.equal(cancel.cancelled, true);
  assert.equal(cancel.terminated, true, "cancel does not resolve until the process close event");
  assert.equal(isCancelled(jobId), true);

  const result = await promise;
  assert.equal(result.cancelled, true, "a cancelled scan resolves cancelled, not as an error or success");
});

test("cancelScan: escalates to SIGKILL when Hayabusa ignores SIGTERM and cleans output after close", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "partial.csv");
  const jobId = "test-force-cancel-job";
  t.after(() => unregisterScanProc(jobId));

  const promise = runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "ignore-term"],
    cwd: dir,
    scanJobId: jobId,
    progressParser: progressStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  await new Promise((r) => setTimeout(r, 100));
  assert.ok(fs.existsSync(out), "fixture output exists before cancellation");

  const cancel = await cancelScan(jobId, { graceMs: 50, killWaitMs: 1000 });
  assert.equal(cancel.cancelled, true);
  assert.equal(cancel.terminated, true, "SIGKILL path waits for close");
  assert.equal(cancel.forced, true, "a TERM-resistant process receives SIGKILL");
  assert.equal(cancel.signal, "SIGKILL");
  assert.equal(fs.existsSync(out), false, "temporary output is deleted only after close");

  assert.deepEqual(await promise, { cancelled: true });
});

test("runScanProcess: a cancel-before-spawn race terminates the process on registration", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const jobId = "test-cancel-before-spawn";
  t.after(() => unregisterScanProc(jobId));

  registerScanProc(jobId, null, []);
  const earlyCancel = await cancelScan(jobId);
  assert.equal(earlyCancel.cancelled, true);

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["--mode", "hang"],
    cwd: dir,
    scanJobId: jobId,
    progressParser: progressStub(),
    tempFiles: [],
    actualOutput: null,
  });

  assert.deepEqual(result, { cancelled: true });
});

test("runScanProcess: captured stderr is capped while retaining error diagnostics", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "partial.csv");

  const result = await runScanProcess({
    hayabusaPath: bin,
    args: ["-o", out, "--mode", "noisy-crash-with-output"],
    cwd: dir,
    scanJobId: null,
    progressParser: progressDiscardStub(),
    tempFiles: [out],
    actualOutput: out,
  });

  assert.equal(result.stderrTruncated, true, `stderr over ${MAX_CAPTURED_STDERR_BYTES} bytes is capped`);
  assert.equal(result.errorLines.length, 5, "only a bounded diagnostic sample is returned");
  assert.ok(result.errorLines.every((line) => /\[ERROR\]/.test(line)));
});

test("runScanProcess: progress callback failures reject safely after closing the child", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);
  const out = path.join(dir, "result.csv");

  await assert.rejects(
    runScanProcess({
      hayabusaPath: bin,
      args: ["-o", out, "--mode", "hang"],
      cwd: dir,
      scanJobId: null,
      progressParser: {
        handleChunk: () => { throw new Error("progress exploded"); },
        startTicker: () => null,
      },
      tempFiles: [out],
      actualOutput: out,
    }),
    /Failed to process Hayabusa progress: progress exploded/
  );
});

test("runScanProcess: asynchronous progress ticker failures are contained", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir, bin } = makeWorkspace(t);

  await assert.rejects(
    runScanProcess({
      hayabusaPath: bin,
      args: ["--mode", "hang"],
      cwd: dir,
      scanJobId: null,
      progressParser: {
        handleChunk: () => {},
        startTicker: (onError) => setTimeout(() => onError(new Error("ticker exploded")), 5),
      },
      tempFiles: [],
      actualOutput: null,
    }),
    /Failed to process Hayabusa progress: ticker exploded/
  );
});

test("scanEvtxDirectory: unregisters the scan in finally after a subprocess failure", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir } = makeWorkspace(t);
  fs.writeFileSync(path.join(dir, "fixture.evtx"), "not parsed because the subprocess fails first");
  const failingBin = path.join(dir, "always-fail-hayabusa.sh");
  fs.writeFileSync(failingBin, '#!/bin/sh\necho "[ERROR] forced failure" 1>&2\nexit 9\n', { mode: 0o755 });
  const jobId = "test-finally-unregister";

  await assert.rejects(
    scanEvtxDirectory(dir, null, () => "unused", {
      scanJobId: jobId,
      hayabusaPath: failingBin,
      hayabusaStatus: { installed: true, version: "test" },
      hayabusaRuleState: { hayabusaRuleCount: 1 },
    }),
    /exited with code 9/
  );
  assert.equal(_activeProcs.has(jobId), false, "the scan registry is cleared on every thrown path");
});

test("runScanProcess: a non-existent binary rejects with a start failure", async (t) => {
  const { dir } = makeWorkspace(t);
  await assert.rejects(
    runScanProcess({
      hayabusaPath: path.join(dir, "does-not-exist"),
      args: [],
      cwd: dir,
      scanJobId: null,
      progressParser: progressStub(),
      tempFiles: [],
      actualOutput: null,
    }),
    /Failed to start Hayabusa/
  );
});

// ───────────────────────── binary self-test ─────────────────────────

test("verifyHayabusaBinary: accepts a binary that prints a Hayabusa banner", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir } = makeWorkspace(t);
  const good = path.join(dir, "good");
  fs.writeFileSync(good, '#!/bin/sh\necho "Hayabusa v3.9.0"\n', { mode: 0o755 });
  const out = await verifyHayabusaBinary(good);
  assert.match(out, /hayabusa/i);
});

test("verifyHayabusaBinary: rejects a binary that runs but isn't Hayabusa", async (t) => {
  if (!POSIX) return t.skip("POSIX-only fake binary");
  const { dir } = makeWorkspace(t);
  const wrong = path.join(dir, "wrong");
  fs.writeFileSync(wrong, '#!/bin/sh\necho "some other tool"\nexit 0\n', { mode: 0o755 });
  await assert.rejects(verifyHayabusaBinary(wrong), /self-test failed/i);
});

test("verifyHayabusaBinary: rejects a binary that cannot execute", async (t) => {
  const { dir } = makeWorkspace(t);
  await assert.rejects(verifyHayabusaBinary(path.join(dir, "missing")), /failed to execute/i);
});
