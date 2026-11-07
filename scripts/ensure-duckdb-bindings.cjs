#!/usr/bin/env node
// Puts both macOS DuckDB bindings into node_modules.
//
// DuckDB's Node package ships its native library as one optional package per platform, and
// npm installs only the one for the machine it runs on. A universal macOS build packs the
// same node_modules into its x64 and arm64 halves, so both @duckdb/node-bindings-darwin-x64
// and -darwin-arm64 must be present. This fetches whichever is missing, at the exact
// version and SHA-512 recorded in package-lock.json, and unpacks it in place.
//
// Runs on macOS only (other platforms build their own installers); --force runs it anywhere.
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const ARCHS = ["x64", "arm64"];

async function main() {
  if (process.platform !== "darwin" && !process.argv.includes("--force")) {
    console.log("ensure-duckdb-bindings: not macOS, nothing to do");
    return;
  }
  const lock = JSON.parse(fs.readFileSync(path.join(ROOT, "package-lock.json"), "utf8"));
  for (const arch of ARCHS) {
    const rel = `node_modules/@duckdb/node-bindings-darwin-${arch}`;
    const entry = lock.packages?.[rel];
    if (!entry?.resolved || !entry?.integrity) throw new Error(`package-lock.json has no ${rel} entry`);
    const dir = path.join(ROOT, rel);
    const pkgJson = path.join(dir, "package.json");
    if (fs.existsSync(pkgJson) && JSON.parse(fs.readFileSync(pkgJson, "utf8")).version === entry.version
      && fs.existsSync(path.join(dir, "duckdb.node"))) {
      console.log(`ensure-duckdb-bindings: ${rel}@${entry.version} present`);
      continue;
    }
    const [algo, expected] = entry.integrity.split("-", 2);
    if (algo !== "sha512") throw new Error(`${rel}: unexpected integrity algorithm ${algo}`);
    console.log(`ensure-duckdb-bindings: fetching ${entry.resolved}`);
    const res = await fetch(entry.resolved);
    if (!res.ok) throw new Error(`${entry.resolved}: HTTP ${res.status}`);
    const tgz = Buffer.from(await res.arrayBuffer());
    const actual = crypto.createHash("sha512").update(tgz).digest("base64");
    if (actual !== expected) throw new Error(`${rel}: SHA-512 mismatch (expected ${expected}, got ${actual})`);
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "duckdb-bindings-"));
    try {
      const file = path.join(tmp, "pkg.tgz");
      fs.writeFileSync(file, tgz);
      fs.rmSync(dir, { recursive: true, force: true });
      fs.mkdirSync(dir, { recursive: true });
      // npm tarballs keep everything under package/
      execFileSync("tar", ["-xzf", file, "-C", dir, "--strip-components=1"], { stdio: "inherit" });
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    if (!fs.existsSync(path.join(dir, "duckdb.node"))) throw new Error(`${rel}: duckdb.node missing after unpacking`);
    console.log(`ensure-duckdb-bindings: installed ${rel}@${entry.version}`);
  }
}

main().catch((err) => {
  console.error(`ensure-duckdb-bindings: ${err.message}`);
  process.exit(1);
});
