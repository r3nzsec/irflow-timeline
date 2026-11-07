"use strict";

// Starts the DuckDB engine inside Electron (host thread, a worker thread on the same host, the
// app's SQL functions) next to the better-sqlite3 readers that remain for SQLite evidence files.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { Worker } = require("worker_threads");
const { app } = require("electron");

function duckdbSmoke() {
  const Database = require("../electron/db/duckdb");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-smoke-"));
  const dbPath = path.join(dir, "smoke.db");
  const db = new Database(dbPath);
  db.exec("CREATE TABLE data (rowid BIGINT, c0 VARCHAR)");
  db.appendRows("data", [["2024-01-02 03:04:05 +09:00"], ["PowerShell -enc"]], { firstRowid: 1 });
  const row = db.prepare("SELECT COUNT(*) AS n, MIN(sort_datetime(c0)) AS k FROM data").get();
  const like = db.prepare("SELECT COUNT(*) AS n FROM data WHERE c0 LIKE ?").get("%POWERSHELL%").n;
  const result = { rows: row.n, sortKey: row.k, like };
  return new Promise((resolve, reject) => {
    // A worker thread reaches the same DuckDB host through a port, as the job workers do.
    const { createWorkerPort, WORKER_DATA_KEY } = require("../electron/db/duckdb");
    const port = createWorkerPort();
    const worker = new Worker(
      `const { parentPort, workerData } = require("worker_threads");
       const Database = require(${JSON.stringify(path.join(__dirname, "..", "electron", "db", "duckdb"))});
       const db = new Database(workerData.dbPath);
       parentPort.postMessage(db.prepare("SELECT COUNT(*) AS n FROM data WHERE c0 ILIKE 'powershell%'").get().n);
       db.close();`,
      { eval: true, workerData: { dbPath, [WORKER_DATA_KEY]: port.data }, transferList: port.transfer },
    );
    worker.once("message", (n) => {
      db.close();
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({ ...result, workerRows: n });
    });
    worker.once("error", reject);
  });
}

app.whenReady().then(async () => {
  const Database = require("better-sqlite3");
  const db = new Database(":memory:");
  db.exec("CREATE TABLE smoke (value INTEGER); INSERT INTO smoke VALUES (1)");
  const row = db.prepare("SELECT value FROM smoke").get();
  db.close();

  const { SqliteMessageProvider } = await import("@ts-evtx/messages");
  const messageDbPath = path.join(
    process.cwd(),
    "node_modules",
    "@ts-evtx",
    "messages",
    "assets",
    "merged-messages.db",
  );
  const provider = new SqliteMessageProvider(messageDbPath);
  provider.close();

  const duck = await duckdbSmoke();
  const duckOk = duck.rows === 2 && duck.sortKey === "2024-01-01 18:04:05.000" && duck.like === 1 && duck.workerRows === 1;

  console.log(JSON.stringify({
    electron: process.versions.electron,
    node: process.versions.node,
    sqlite: row.value === 1 ? "ok" : "failed",
    evtxMessages: "ok",
    duckdb: duckOk ? "ok" : `failed ${JSON.stringify(duck)}`,
  }));
  if (!duckOk) app.exit(1);
  else app.quit();
}).catch((err) => {
  console.error(err);
  app.exit(1);
});
