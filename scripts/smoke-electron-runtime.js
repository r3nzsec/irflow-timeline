"use strict";

const path = require("path");
const { app } = require("electron");

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

  console.log(JSON.stringify({
    electron: process.versions.electron,
    node: process.versions.node,
    sqlite: row.value === 1 ? "ok" : "failed",
    evtxMessages: "ok",
  }));
  app.quit();
}).catch((err) => {
  console.error(err);
  app.exit(1);
});
