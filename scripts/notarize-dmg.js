/**
 * electron-builder `afterAllArtifactBuild` hook — sign, notarize and staple the DMG.
 *
 * Why this exists separately from scripts/notarize.js:
 *
 *   `afterSign` runs on the .app, before any DMG exists, so it can only notarize
 *   and staple the app bundle. electron-builder then wraps that (already stapled)
 *   app in a DMG and never signs or notarizes the DMG itself. The result passes
 *   Gatekeeper once the app is on disk, but the downloaded disk image does not:
 *
 *     spctl -a -t open --context context:primary-signature <dmg>
 *     → rejected  (source=no usable signature)
 *
 *   which is the "Apple could not verify..." dialog users see on first open.
 *
 * Stapling rewrites the DMG *after* electron-builder has already hashed it for
 * latest-mac.yml and built the .blockmap, so both are stale the moment we staple.
 * This hook therefore regenerates them, using electron-builder's own blockmap
 * builder so the numbers match exactly what it would have written itself.
 */
const fs = require("fs");
const path = require("path");
const { execFileSync, spawnSync } = require("child_process");

const IDENTITY_PREFIX = "Developer ID Application";

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
}

/** Developer ID signing identity: CSC_NAME wins, else the one in the keychain. */
function resolveIdentity() {
  if (process.env.CSC_NAME) return process.env.CSC_NAME;
  let out = "";
  try {
    out = run("security", ["find-identity", "-v", "-p", "codesigning"]);
  } catch {
    return null;
  }
  const match = out.split("\n").map((l) => l.match(/"([^"]+)"/)).find((m) => m && m[1].startsWith(IDENTITY_PREFIX));
  return match ? match[1] : null;
}

/**
 * Recompute the DMG's sha512/size and rewrite them into latest-mac.yml, and
 * rebuild the .blockmap. Called after stapling has changed the file.
 *
 * The entry is replaced by a targeted text edit rather than a parse-and-dump so
 * the rest of the file keeps electron-builder's exact formatting and key order.
 */
async function repairUpdateMetadata(dmgPath) {
  const { buildBlockMap } = require("app-builder-lib/out/targets/blockmap/blockmap");
  const blockMapFile = `${dmgPath}.blockmap`;
  const info = await buildBlockMap(dmgPath, "gzip", blockMapFile);

  const ymlPath = path.join(path.dirname(dmgPath), "latest-mac.yml");
  if (!fs.existsSync(ymlPath)) return info;

  const name = path.basename(dmgPath);
  const yml = fs.readFileSync(ymlPath, "utf8");
  // Match the `- url: <dmg>` block and replace only its sha512 and size lines.
  const block = new RegExp(
    `(- url: ${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\n\\s+sha512: )[^\\n]+(\\n\\s+size: )\\d+`,
  );
  if (!block.test(yml)) {
    console.warn(`notarize-dmg: no ${name} entry in latest-mac.yml — hashes NOT updated`);
    return info;
  }
  fs.writeFileSync(ymlPath, yml.replace(block, `$1${info.sha512}$2${info.size}`));
  console.log(`notarize-dmg: refreshed latest-mac.yml + blockmap for ${name}`);
  return info;
}

exports.default = async function afterAllArtifactBuild(context) {
  const dmgs = (context.artifactPaths || []).filter((p) => p.endsWith(".dmg"));
  if (dmgs.length === 0) return [];

  if (process.env.SKIP_NOTARIZE === "1") {
    console.log("notarize-dmg: skipping because SKIP_NOTARIZE=1.");
    return [];
  }
  const appleId = process.env.APPLE_ID;
  const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
  const teamId = process.env.APPLE_TEAM_ID;
  if (!appleId || !appleIdPassword || !teamId) {
    console.log("notarize-dmg: skipping, Apple notarization credentials are not set.");
    return [];
  }
  const identity = resolveIdentity();
  if (!identity) {
    console.log(`notarize-dmg: skipping, no "${IDENTITY_PREFIX}" identity found in the keychain.`);
    return [];
  }

  for (const dmg of dmgs) {
    console.log(`notarize-dmg: signing ${path.basename(dmg)}`);
    run("codesign", ["--sign", identity, "--timestamp", "--force", dmg]);

    console.log("notarize-dmg: submitting to Apple (this waits for the result)...");
    // Credentials go through argv here because notarytool has no env-var form.
    // Nothing in this function logs argv, and the password is never echoed.
    run("xcrun", [
      "notarytool", "submit", dmg,
      "--apple-id", appleId,
      "--password", appleIdPassword,
      "--team-id", teamId,
      "--wait",
    ], { stdio: ["ignore", "inherit", "inherit"] });

    console.log("notarize-dmg: stapling ticket");
    run("xcrun", ["stapler", "staple", dmg]);

    // Prove it, rather than assuming the staple took. spctl writes its verdict to
    // STDERR and exits non-zero on rejection, so this needs spawnSync and both
    // streams — execFileSync would hand back an empty stdout, or throw before the
    // verdict could be read.
    const check = spawnSync("spctl", ["-a", "-t", "open", "--context", "context:primary-signature", "-vv", dmg], {
      encoding: "utf8",
    });
    const assessment = `${check.stdout || ""}${check.stderr || ""}`.trim();
    if (!/: accepted/.test(assessment)) {
      throw new Error(`notarize-dmg: Gatekeeper still rejects ${path.basename(dmg)}:\n${assessment || "(no output)"}`);
    }
    console.log(`notarize-dmg: ${path.basename(dmg)} accepted by Gatekeeper`);

    await repairUpdateMetadata(dmg);
  }
  return [];
};
