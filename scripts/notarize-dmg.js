/**
 * electron-builder `artifactBuildCompleted` hook — sign, notarize and staple the DMG.
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
 * Stapling rewrites the DMG after electron-builder has built its first blockmap.
 * This hook therefore rebuilds that blockmap and replaces event.updateInfo before
 * electron-builder writes latest-mac.yml. Running this as afterAllArtifactBuild is
 * too late: the publish manager has already captured the pre-staple hash by then.
 */
const fs = require("fs");
const path = require("path");
const { execFileSync, spawnSync } = require("child_process");

const IDENTITY_PREFIX = "Developer ID Application";

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
}

/**
 * Developer ID signing identity, in order of reliability:
 *   1. CSC_NAME, if the build set it explicitly.
 *   2. The Authority already recorded in the signed .app. afterSign has always run
 *      by this point, so this is the identity that actually signed this build —
 *      and it works even when the key lives in a keychain we cannot enumerate.
 *   3. The keychain search list.
 *
 * (2) exists because CI hands the certificate over as CSC_LINK and lets
 * electron-builder import it into a keychain it owns and tears down. Relying on
 * `security find-identity` alone made this return null on CI, the hook skip, and
 * v1.0.12 ship an unsigned disk image.
 */
function resolveIdentity(outDir) {
  if (process.env.CSC_NAME) return process.env.CSC_NAME;

  if (outDir) {
    for (const dir of fs.existsSync(outDir) ? fs.readdirSync(outDir) : []) {
      if (!dir.startsWith("mac")) continue;
      const appDir = path.join(outDir, dir);
      const app = (fs.existsSync(appDir) ? fs.readdirSync(appDir) : []).find((f) => f.endsWith(".app"));
      if (!app) continue;
      const probe = spawnSync("codesign", ["-dvv", path.join(appDir, app)], { encoding: "utf8" });
      const authority = `${probe.stdout || ""}${probe.stderr || ""}`
        .split("\n").map((l) => l.match(/^Authority=(.+)$/)).find((m) => m && m[1].startsWith(IDENTITY_PREFIX));
      if (authority) return authority[1];
    }
  }

  const found = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });
  const match = `${found.stdout || ""}`.split("\n")
    .map((l) => l.match(/"([^"]+)"/)).find((m) => m && m[1].startsWith(IDENTITY_PREFIX));
  return match ? match[1] : null;
}

/**
 * Recompute the DMG's sha512/size and blockmap after stapling changes the file.
 * Mutating event.updateInfo is the supported handoff to electron-builder's publish
 * manager, which writes latest-mac.yml only after artifact hooks have completed.
 */
async function refreshDmgUpdateInfo(event) {
  const dmgPath = event.file;
  const { buildBlockMap } = require("app-builder-lib/out/targets/blockmap/blockmap");
  const blockMapFile = `${dmgPath}.blockmap`;
  const info = await buildBlockMap(dmgPath, "gzip", blockMapFile);
  event.updateInfo = info;
  console.log(`notarize-dmg: refreshed updater hash + blockmap for ${path.basename(dmgPath)}`);
  return info;
}

exports.default = async function artifactBuildCompleted(event) {
  const dmg = event && typeof event.file === "string" && event.file.endsWith(".dmg")
    ? event.file
    : null;
  if (!dmg) return;

  if (process.env.SKIP_NOTARIZE === "1") {
    console.log("notarize-dmg: skipping because SKIP_NOTARIZE=1.");
    return;
  }
  const appleId = process.env.APPLE_ID;
  const appleIdPassword = process.env.APPLE_APP_SPECIFIC_PASSWORD;
  const teamId = process.env.APPLE_TEAM_ID;
  if (!appleId || !appleIdPassword || !teamId) {
    console.log("notarize-dmg: skipping, Apple notarization credentials are not set.");
    return;
  }
  // Credentials being present means a real signed release was intended, so a
  // missing identity is a build failure — not something to skip past quietly.
  // Skipping is what let an unsigned DMG reach the v1.0.12 release.
  const identity = resolveIdentity(path.dirname(dmg));
  if (!identity) {
    throw new Error(
      `notarize-dmg: Apple credentials are set but no "${IDENTITY_PREFIX}" identity could be resolved `
      + "(checked CSC_NAME, the signed .app's Authority, and the keychain search list). "
      + "Refusing to publish an unsigned DMG.",
    );
  }

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

  await refreshDmgUpdateInfo(event);
};

exports.refreshDmgUpdateInfo = refreshDmgUpdateInfo;
