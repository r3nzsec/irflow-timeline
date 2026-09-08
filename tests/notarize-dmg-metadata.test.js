const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { refreshDmgUpdateInfo } = require("../scripts/notarize-dmg.js");
const { sha512Base64, verifyUpdateMetadata } = require("../scripts/verify-update-metadata.cjs");
const builderConfig = require("../electron-builder.config.cjs");

test("DMG hook runs before updater metadata is written", () => {
  assert.equal(builderConfig.artifactBuildCompleted, "scripts/notarize-dmg.js");
  assert.equal(builderConfig.afterAllArtifactBuild, undefined);
});

test("post-staple DMG bytes replace electron-builder updateInfo and blockmap", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-dmg-update-info-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const file = path.join(dir, "IRFlow-Timeline-test.dmg");
  const bytes = Buffer.concat([
    Buffer.from("post-staple-ticket\n"),
    crypto.randomBytes(128 * 1024),
  ]);
  fs.writeFileSync(file, bytes);

  const event = {
    file,
    updateInfo: { sha512: "pre-staple", size: 1 },
  };
  const info = await refreshDmgUpdateInfo(event);

  assert.equal(event.updateInfo, info);
  assert.equal(info.size, bytes.length);
  assert.equal(info.sha512, crypto.createHash("sha512").update(bytes).digest("base64"));
  assert.ok(fs.statSync(`${file}.blockmap`).size > 0);
});

test("release verification rejects updater metadata from pre-staple bytes", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "irflow-update-yml-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));

  const artifact = path.join(dir, "IRFlow-Timeline-test.dmg");
  fs.writeFileSync(artifact, "signed-dmg-before-staple");
  const yml = path.join(dir, "latest-mac.yml");
  fs.writeFileSync(yml, [
    "version: 1.0.13",
    "files:",
    `  - url: ${path.basename(artifact)}`,
    `    sha512: ${sha512Base64(artifact)}`,
    `    size: ${fs.statSync(artifact).size}`,
    "",
  ].join("\n"));

  assert.equal(verifyUpdateMetadata(yml, [artifact]).length, 1);
  fs.appendFileSync(artifact, "\nstapled-ticket");
  assert.throws(() => verifyUpdateMetadata(yml, [artifact]), /does not match/);
});
