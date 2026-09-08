const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { verifyAppUpdateConfig } = require("../scripts/verify-app-update-config.cjs");
const { verifyPublishedUpdateFeed } = require("../scripts/verify-published-update-feed.cjs");

function sha512(value) {
  return crypto.createHash("sha512").update(value).digest("base64");
}

test("release app embeds the configured generic HTTPS updater feed", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-app-update-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const config = path.join(dir, "app-update.yml");
  fs.writeFileSync(config, [
    "provider: generic",
    "url: https://updates.example.test/irflow-timeline",
    "channel: latest",
    "useMultipleRangeRequest: false",
    "",
  ].join("\n"));

  const result = verifyAppUpdateConfig(config, "https://updates.example.test/irflow-timeline/", "latest");
  assert.equal(result.provider, "generic");
  assert.equal(result.useMultipleRangeRequest, false);
  assert.throws(
    () => verifyAppUpdateConfig(config, "https://wrong.example.test/irflow-timeline", "latest"),
    /does not match/,
  );
});

test("public updater verification checks exact metadata, sizes, and byte ranges", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-public-update-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const names = [
    "IRFlow-Timeline-9.9.9-universal.zip",
    "IRFlow-Timeline-9.9.9-universal.dmg",
    "IRFlow-Timeline-9.9.9-universal.zip.blockmap",
    "IRFlow-Timeline-9.9.9-universal.dmg.blockmap",
  ];
  const files = new Map();
  for (const name of names) {
    const body = Buffer.from(`published-${name}`);
    fs.writeFileSync(path.join(dir, name), body);
    files.set(`/${name}`, body);
  }

  const zip = files.get(`/${names[0]}`);
  const dmg = files.get(`/${names[1]}`);
  const metadata = Buffer.from([
    "version: 9.9.9",
    "files:",
    `  - url: ${names[0]}`,
    `    sha512: ${sha512(zip)}`,
    `    size: ${zip.length}`,
    `  - url: ${names[1]}`,
    `    sha512: ${sha512(dmg)}`,
    `    size: ${dmg.length}`,
    `path: ${names[0]}`,
    `sha512: ${sha512(zip)}`,
    "",
  ].join("\n"));
  const metadataPath = path.join(dir, "latest-mac.yml");
  fs.writeFileSync(metadataPath, metadata);
  files.set("/latest-mac.yml", metadata);

  const server = http.createServer((request, response) => {
    const pathname = new URL(request.url, "http://127.0.0.1").pathname;
    const body = files.get(pathname);
    if (!body) {
      response.writeHead(404).end();
      return;
    }
    response.setHeader("Accept-Ranges", "bytes");
    response.setHeader("Content-Length", body.length);
    if (request.method === "HEAD") {
      response.writeHead(200).end();
      return;
    }
    if (request.headers.range === "bytes=0-0") {
      response.setHeader("Content-Length", 1);
      response.setHeader("Content-Range", `bytes 0-0/${body.length}`);
      response.writeHead(206).end(body.subarray(0, 1));
      return;
    }
    response.writeHead(200).end(body);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();

  const result = await verifyPublishedUpdateFeed({
    baseUrl: `http://127.0.0.1:${address.port}`,
    metadataPath,
    artifactPaths: names.map((name) => path.join(dir, name)),
    attempts: 1,
    delayMs: 0,
  });
  assert.equal(result.version, "9.9.9");
  assert.equal(result.artifacts.length, 4);
});
