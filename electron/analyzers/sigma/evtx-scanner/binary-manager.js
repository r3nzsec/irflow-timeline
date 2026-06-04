const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn, spawnSync } = require("child_process");
const { app } = require("electron");
const { dbg } = require("../../../logger");
const { ensureDefaultNoisyRules } = require("./default-tuning");
const {
  copyDirectoryContents,
  downloadFile,
  extractTarGzBuffer,
  extractZip,
  fetchJson,
  findExecutableOnPath,
  normalizeSha256,
  runProcessCapture,
} = require("../node-io-utils");

const HAYABUSA_DIR = "hayabusa";

function getHayabusaDir() {
  return path.join(app.getPath("userData"), HAYABUSA_DIR);
}

function ensureWritableHayabusa() {
  const binName = process.platform === "win32" ? "hayabusa.exe" : "hayabusa";
  const userDir = getHayabusaDir();
  const userBin = path.join(userDir, binName);

  if (fs.existsSync(userBin)) return userBin;

  let bundledDir;
  try {
    bundledDir = path.join(process.resourcesPath, "hayabusa");
  } catch {
    return null;
  }
  const bundledBin = path.join(bundledDir, binName);
  if (!fs.existsSync(bundledBin)) return null;

  dbg("HAYABUSA", `Copying bundled Hayabusa to writable location: ${userDir}`);
  try {
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
    copyDirectoryContents(bundledDir, userDir);
  } catch (err) {
    // A failed/partial copy must NOT make Hayabusa look uninstalled (which would push
    // the user into a network download). Remove the partial dir and return null so
    // findHayabusa() falls back to running the bundled binary in place.
    dbg("HAYABUSA", "bundled->writable copy failed; will use bundled binary in place", { err: err?.message });
    try { fs.rmSync(userDir, { recursive: true, force: true }); } catch {}
    return null;
  }
  try { fs.chmodSync(userBin, 0o755); } catch {}
  try { ensureDefaultNoisyRules(userBin); } catch {}
  if (!fs.existsSync(userBin)) return null;
  return userBin;
}

function isAppManagedHayabusa(binPath) {
  try {
    return !!binPath && binPath.startsWith(getHayabusaDir());
  } catch {
    return false;
  }
}

function prepareManagedHayabusa(binPath) {
  if (isAppManagedHayabusa(binPath)) ensureDefaultNoisyRules(binPath);
  return binPath;
}

function findExtractedHayabusaBin(rootDir, isWin) {
  const stack = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!["__MACOSX", ".git"].includes(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!entry.name.startsWith("hayabusa")) continue;
      if (/\.(zip|tar|gz|pdf|txt|csv|md|yaml|yml|css|png|jpg|json)$/i.test(entry.name)) continue;
      try {
        const size = fs.statSync(full).size;
        if (isWin ? entry.name.endsWith(".exe") && size > 1000000 : size > 1000000) return full;
      } catch {}
    }
  }
  return null;
}

function findHayabusa() {
  const binName = process.platform === "win32" ? "hayabusa.exe" : "hayabusa";

  const userDataBin = path.join(getHayabusaDir(), binName);
  if (fs.existsSync(userDataBin)) {
    try {
      fs.accessSync(userDataBin, fs.constants.X_OK);
      return prepareManagedHayabusa(userDataBin);
    } catch {}
    try {
      fs.chmodSync(userDataBin, 0o755);
      return prepareManagedHayabusa(userDataBin);
    } catch {}
  }

  // Bundled binary (extraResources) — always preferred for fresh installs. Ships
  // inside the .app so no network/copy is required. ensureWritableHayabusa() copies
  // it to a writable userData location so Hayabusa can write its own config; if that
  // copy fails (permissions, disk space, corporate write-restrictions) we fall back to
  // running the bundled binary in place rather than reporting "not installed" and
  // pushing the user into a network download (which fails on TLS-intercepting proxies).
  try {
    const bundledAppBin = path.join(process.resourcesPath, "hayabusa", binName);
    if (fs.existsSync(bundledAppBin)) {
      const writable = ensureWritableHayabusa();
      if (writable) return writable;
      // Copy failed or skipped — use the bundled binary directly.
      try { fs.accessSync(bundledAppBin, fs.constants.X_OK); return bundledAppBin; } catch {}
      try { fs.chmodSync(bundledAppBin, 0o755); return bundledAppBin; } catch {}
    }
  } catch (err) {
    dbg("HAYABUSA", "bundled binary lookup failed", { err: err?.message });
  }

  const pathMatch = findExecutableOnPath([binName]);
  if (pathMatch) return pathMatch;

  const common = process.platform === "darwin"
    ? ["/usr/local/bin/hayabusa", "/opt/homebrew/bin/hayabusa", path.join(os.homedir(), "hayabusa/hayabusa")]
    : process.platform === "win32"
      ? [path.join(os.homedir(), "hayabusa", "hayabusa.exe"), "C:\\Tools\\hayabusa\\hayabusa.exe"]
      : ["/usr/local/bin/hayabusa", "/usr/bin/hayabusa", path.join(os.homedir(), "hayabusa/hayabusa")];

  for (const candidate of common) {
    if (fs.existsSync(candidate)) return candidate;
  }

  return null;
}

// Maps a Node platform/arch to the Yamato-Security/hayabusa release asset pattern.
// MUST stay in sync with scripts/bundle-hayabusa.sh and the real release asset names
// (verified against the live GitHub API): mac-aarch64, mac-x64, lin-x64-gnu,
// lin-aarch64-gnu, win-x64, win-aarch64. Returns null for unsupported platforms.
function hayabusaAssetPattern(platform, arch) {
  if (platform === "darwin") return arch === "arm64" ? "mac-aarch64" : "mac-x64";
  if (platform === "win32") return arch === "arm64" ? "win-aarch64" : "win-x64";
  if (platform === "linux") return arch === "arm64" ? "lin-aarch64-gnu" : "lin-x64-gnu";
  return null;
}

// Wrap a TLS / network error in a clear, actionable message. "Self-signed cert" errors
// are common on enterprise/DFIR networks with TLS-intercepting proxies (Zscaler, etc.)
function wrapDownloadError(err) {
  const msg = err?.message || String(err);
  if (/self.signed|DEPTH_ZERO_SELF_SIGNED|CERT_|unable to verify|certificate/i.test(msg)) {
    // The hand-off path the user is told to drop the manual binary into is
    // app.getPath("userData") on every platform; the OS-prefix string below just
    // describes where that lands in human-readable form. Keeping it platform-aware
    // means an analyst on Linux doesn't get told to look in ~/Library.
    let userDataHint;
    try { userDataHint = app.getPath("userData"); } catch { userDataHint = "<userData>"; }
    return new Error(
      "Failed to download Hayabusa: your network uses TLS inspection (self-signed certificate in chain). " +
      "Hayabusa is bundled with the app — if you see this the bundled binary could not be located. " +
      "Try restarting the app; if the problem persists, manually install Hayabusa from " +
      "https://github.com/Yamato-Security/hayabusa/releases and place it at " +
      `${userDataHint}/hayabusa/hayabusa${process.platform === "win32" ? ".exe" : ""}.`
    );
  }
  if (/ENOTFOUND|ECONNREFUSED|ETIMEDOUT|network/i.test(msg)) {
    return new Error(`Failed to download Hayabusa: no internet access (${msg}). The bundled binary should work — try restarting the app.`);
  }
  return err;
}

async function downloadHayabusa(onProgress) {
  const destDir = getHayabusaDir();
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });

  const platform = process.platform;
  const arch = process.arch;
  const assetPattern = hayabusaAssetPattern(platform, arch);
  if (!assetPattern) throw new Error(`Unsupported platform: ${platform}/${arch}`);

  onProgress?.("fetching", "Fetching latest Hayabusa release info...");

  const apiUrl = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest";
  let releaseData;
  try {
    releaseData = await fetchJson(apiUrl);
  } catch (err) {
    throw wrapDownloadError(err);
  }

  const asset = releaseData.assets?.find((candidate) =>
    candidate.name.includes(assetPattern)
    && candidate.name.endsWith(".zip")
    && !candidate.name.includes("live-response")
    && !candidate.name.includes("all-platforms")
  );
  if (!asset) {
    throw new Error(`No Hayabusa release found for ${assetPattern}. Available: ${releaseData.assets?.map((candidate) => candidate.name).join(", ") || "none"}`);
  }

  const version = releaseData.tag_name || "unknown";
  onProgress?.("release", `Latest Hayabusa release: ${version} (${asset.name})`, {
    releaseVersion: version,
    assetName: asset.name,
    assetSize: asset.size,
  });
  onProgress?.("downloading", `Downloading Hayabusa ${version} (${(asset.size / 1048576).toFixed(1)} MB)...`);
  dbg("HAYABUSA", `Downloading ${asset.name} (${asset.size} bytes)`);

  const downloadUrl = asset.browser_download_url;
  const archivePath = path.join(destDir, asset.name);

  // GitHub now publishes a per-asset SHA-256 ("sha256:<hex>") in the release API
  // we already fetched. Verify the download against it — no extra request, works
  // with the "latest" model, and detects corruption/truncation/tampering.
  const expectedSha256 = normalizeSha256(asset.digest);
  if (expectedSha256) {
    dbg("HAYABUSA", `Expecting SHA-256 ${expectedSha256} for ${asset.name}`);
  } else {
    dbg("HAYABUSA", `GitHub provided no SHA-256 digest for ${asset.name}; integrity will not be verified`);
    onProgress?.("downloading", "Note: GitHub published no checksum for this release; skipping integrity verification.");
  }

  try {
    let lastPct = -1;
    const { sha256 } = await downloadFile(downloadUrl, archivePath, {
      totalBytes: asset.size,
      timeoutMs: 30000,
      expectedSha256,
      onProgress: ({ downloadedBytes, totalBytes }) => {
        const pct = totalBytes > 0 ? Math.floor((downloadedBytes / totalBytes) * 100) : null;
        if (pct != null && pct === lastPct) return;
        if (pct != null) lastPct = pct;
        onProgress?.("downloading", pct != null
          ? `Downloading Hayabusa ${version}: ${pct}% (${(downloadedBytes / 1048576).toFixed(1)} / ${(totalBytes / 1048576).toFixed(1)} MB)`
          : `Downloading Hayabusa ${version}: ${(downloadedBytes / 1048576).toFixed(1)} MB`, {
          downloadedBytes,
          totalBytes,
          pct,
        });
      },
    });
    if (expectedSha256) {
      onProgress?.("verifying", "Download integrity verified (SHA-256).");
      dbg("HAYABUSA", `Integrity verified: SHA-256 ${sha256}`);
    }
  } catch (err) {
    if (/SHA-256 mismatch/i.test(err.message)) {
      throw new Error(`Hayabusa integrity check failed — the download was corrupted or tampered with and has been discarded. ${err.message}`);
    }
    throw wrapDownloadError(err);
  }

  if (!fs.existsSync(archivePath)) throw new Error("Download failed: file not created");
  const dlSize = fs.statSync(archivePath).size;
  if (dlSize < 1000000) {
    try { fs.unlinkSync(archivePath); } catch {}
    throw new Error(`Download failed: received ${dlSize} bytes (expected ~${(asset.size / 1048576).toFixed(0)} MB)`);
  }
  dbg("HAYABUSA", `Downloaded ${(dlSize / 1048576).toFixed(1)} MB`);

  onProgress?.("extracting", "Extracting Hayabusa...");
  try {
    if (archivePath.endsWith(".zip")) {
      extractZip(archivePath, destDir);
    } else if (/\.tar\.gz$|\.tgz$/i.test(archivePath)) {
      extractTarGzBuffer(fs.readFileSync(archivePath), destDir);
    } else {
      throw new Error(`Unsupported archive type: ${path.basename(archivePath)}`);
    }
  } catch (err) {
    throw new Error(`Failed to extract: ${err.message}`);
  }

  const isWin = process.platform === "win32";
  const expectedBin = path.join(destDir, isWin ? "hayabusa.exe" : "hayabusa");
  let foundBin = null;

  if (fs.existsSync(expectedBin)) {
    foundBin = expectedBin;
  } else {
    foundBin = findExtractedHayabusaBin(destDir, isWin);
  }

  if (!foundBin) throw new Error("Hayabusa binary not found after extraction");

  if (foundBin !== expectedBin) {
    fs.renameSync(foundBin, expectedBin);
    foundBin = expectedBin;
  }
  try { fs.chmodSync(foundBin, 0o755); } catch {}
  try { fs.unlinkSync(archivePath); } catch {}

  // Self-test: confirm the extracted binary actually runs. Previously this was a
  // swallowed try/catch, so a corrupt or arch-incompatible binary would be marked
  // "installed" and only fail on the first real scan. Now a failure removes the
  // bad binary and aborts so the caller can surface a clear error.
  onProgress?.("verifying", "Verifying Hayabusa binary...");
  try {
    await verifyHayabusaBinary(foundBin);
  } catch (err) {
    try { fs.unlinkSync(foundBin); } catch {}
    throw err;
  }

  onProgress?.("done", `Hayabusa ${version} installed`);
  ensureDefaultNoisyRules(foundBin);
  dbg("HAYABUSA", `Installed at ${foundBin}`);
  return foundBin;
}

// Runs `hayabusa help` and confirms the binary executes and identifies itself.
// Throws a descriptive error if the binary cannot run or produces no Hayabusa
// banner (corrupted download, wrong architecture, missing libs, etc.).
async function verifyHayabusaBinary(binPath) {
  let result;
  try {
    result = await runProcessCapture(binPath, ["help"], { timeoutMs: 15000 });
  } catch (err) {
    throw new Error(`Hayabusa binary failed to execute (${err.message}). The download may be corrupted or incompatible with this system.`);
  }
  const out = `${result.stdout || ""}\n${result.stderr || ""}`;
  if (!/hayabusa/i.test(out)) {
    throw new Error("Hayabusa binary self-test failed: 'hayabusa help' did not produce the expected output. The download may be corrupted.");
  }
  return out;
}

function getHayabusaStatus() {
  const binPath = findHayabusa();
  if (!binPath) return { installed: false, path: null, version: null, source: null };

  let version = null;
  try {
    const result = spawnSync(binPath, ["help"], { encoding: "utf8", timeout: 5000, shell: false });
    const out = `${result.stdout || ""}\n${result.stderr || ""}`;
    const match = out.match(/Hayabusa\s+(v[\d.]+)/i);
    version = match ? match[1] : null;
  } catch {}

  let source = "system";
  try {
    if (binPath.startsWith(process.resourcesPath)) source = "bundled";
    else if (binPath.startsWith(getHayabusaDir())) source = "downloaded";
  } catch {}

  return { installed: true, path: binPath, version, source };
}

async function updateHayabusa(onProgress) {
  const before = getHayabusaStatus();
  onProgress?.("checking", `Current Hayabusa version: ${before.version || "not installed"}`, {
    oldVersion: before.version || null,
  });

  const destDir = getHayabusaDir();
  const binName = process.platform === "win32" ? "hayabusa.exe" : "hayabusa";
  const oldBin = path.join(destDir, binName);
  if (fs.existsSync(oldBin)) {
    try { fs.unlinkSync(oldBin); } catch {}
  }

  const binPath = await downloadHayabusa(onProgress);
  const after = getHayabusaStatus();
  onProgress?.("done", `Hayabusa update complete: ${before.version || "not installed"} -> ${after.version || "unknown"}`, {
    oldVersion: before.version || null,
    newVersion: after.version || null,
    path: after.path || binPath,
  });
  return {
    success: true,
    oldVersion: before.version || null,
    newVersion: after.version || null,
    upgraded: before.version !== after.version,
    previous: before,
    current: after,
    path: after.path || binPath,
  };
}

function getGeoIpDir() {
  return path.join(getHayabusaDir(), "geoip");
}

function getGeoIpStatus() {
  const dir = getGeoIpDir();
  if (!fs.existsSync(dir)) return { available: false, dir, files: [] };
  try {
    const files = fs.readdirSync(dir).filter((file) => file.endsWith(".mmdb"));
    return { available: files.length > 0, dir, files };
  } catch {
    return { available: false, dir, files: [] };
  }
}

async function downloadGeoIp(onProgress) {
  let binPath = findHayabusa();
  if (!binPath) {
    onProgress?.("installing", "Downloading Hayabusa first...");
    binPath = await downloadHayabusa(onProgress);
  }

  const geoDir = getGeoIpDir();
  if (!fs.existsSync(geoDir)) fs.mkdirSync(geoDir, { recursive: true });

  onProgress?.("downloading", "Downloading GeoIP databases...");
  dbg("HAYABUSA", "Downloading GeoIP databases via Hayabusa geo-ip command");

  try {
    await new Promise((resolve, reject) => {
      const proc = spawn(binPath, ["geo-ip", "-q"], {
        cwd: path.dirname(binPath),
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 120000,
      });
      let stderrBuf = "";
      proc.stderr.on("data", (chunk) => { stderrBuf += chunk.toString(); });
      proc.on("close", (code) => {
        if (code === 0) resolve();
        else reject(new Error(`geo-ip exited ${code}: ${stderrBuf.slice(0, 200)}`));
      });
      proc.on("error", (err) => reject(err));
    });

    const hayabusaGeoDir = path.join(path.dirname(binPath), "geoip");
    if (fs.existsSync(hayabusaGeoDir)) {
      const mmdbFiles = fs.readdirSync(hayabusaGeoDir).filter((file) => file.endsWith(".mmdb"));
      if (mmdbFiles.length > 0) {
        if (hayabusaGeoDir !== geoDir) {
          for (const file of mmdbFiles) {
            fs.copyFileSync(path.join(hayabusaGeoDir, file), path.join(geoDir, file));
          }
        }
        onProgress?.("done", `GeoIP databases downloaded (${mmdbFiles.length} files)`);
        return { path: hayabusaGeoDir, files: mmdbFiles };
      }
    }

    const status = getGeoIpStatus();
    if (status.available) {
      onProgress?.("done", `GeoIP databases ready (${status.files.length} files)`);
      return { path: geoDir, files: status.files };
    }

    throw new Error("geo-ip command succeeded but no .mmdb files found");
  } catch (err) {
    dbg("HAYABUSA", `geo-ip command failed: ${err.message}. GeoIP databases may need to be downloaded manually.`);
    onProgress?.("error", `GeoIP download failed: ${err.message}. You can manually place MaxMind GeoLite2 .mmdb files in: ${geoDir}`);
    return { path: geoDir, files: [], error: err.message };
  }
}

async function runLevelTuning(tunings, onProgress) {
  let binPath = findHayabusa();
  if (!binPath) {
    onProgress?.({ phase: "installing", text: "Downloading Hayabusa..." });
    binPath = await downloadHayabusa(onProgress);
  }

  const hayabusaDir = path.dirname(binPath);
  const configDir = path.join(hayabusaDir, "rules", "config");
  if (!fs.existsSync(configDir)) fs.mkdirSync(configDir, { recursive: true });

  const configPath = path.join(configDir, "level_tuning.yml");
  dbg("HAYABUSA", `Level tuning config: ${configPath}`);

  if (fs.existsSync(configPath)) {
    fs.readFileSync(configPath, "utf8").split("\n");
  }

  onProgress?.({ phase: "done", text: `Level tuning config at: ${configPath}` });
  return { success: true, configPath };
}

function getLevelTuningPath() {
  const binPath = findHayabusa();
  if (!binPath) return null;
  return path.join(path.dirname(binPath), "rules", "config", "level_tuning.yml");
}

function getRulesConfigDir() {
  const binPath = findHayabusa();
  if (!binPath) return null;
  return path.join(path.dirname(binPath), "rules", "config");
}

module.exports = {
  getHayabusaDir,
  ensureWritableHayabusa,
  ensureDefaultNoisyRules,
  findHayabusa,
  hayabusaAssetPattern,
  downloadHayabusa,
  verifyHayabusaBinary,
  getHayabusaStatus,
  updateHayabusa,
  getGeoIpDir,
  getGeoIpStatus,
  downloadGeoIp,
  runLevelTuning,
  getLevelTuningPath,
  getRulesConfigDir,
};
