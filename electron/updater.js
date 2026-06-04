const fs = require("fs");
const path = require("path");
const electron = require("electron");
const { dbg } = require("./logger");

let _autoUpdater = null;

function getAutoUpdater() {
  if (_autoUpdater) return _autoUpdater;
  ({ autoUpdater: _autoUpdater } = require("electron-updater"));
  return _autoUpdater;
}

function getElectronApp() {
  return electron && typeof electron === "object" ? electron.app || null : null;
}

function getElectronDialog() {
  return electron && typeof electron === "object" ? electron.dialog || null : null;
}

function getCurrentVersion() {
  const electronApp = getElectronApp();
  if (electronApp?.getVersion) return electronApp.getVersion();
  try {
    return require("../package.json").version || "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function getUpdateConfigPath() {
  const electronApp = getElectronApp();
  if (!electronApp) return path.join(process.cwd(), "dev-app-update.yml");
  return electronApp.isPackaged
    ? path.join(process.resourcesPath, "app-update.yml")
    : path.join(electronApp.getAppPath(), "dev-app-update.yml");
}

function getReleaseNotesText(info) {
  const notes = info?.releaseNotes;
  if (!notes) return "";
  if (Array.isArray(notes)) {
    return notes
      .map((item) => `${item.version ? `${item.version}\n` : ""}${String(item.note || "").trim()}`.trim())
      .filter(Boolean)
      .join("\n\n")
      .slice(0, 4000);
  }
  return String(notes).trim().slice(0, 4000);
}

const DEFAULT_CHECK_OPTIONS = Object.freeze({
  showNotConfiguredMessage: true,
  showBusyMessage: true,
  promptOnAvailable: true,
  showNoUpdateMessage: true,
  showErrors: true,
  emitStatus: false,
  autoDownload: false,
});

const STARTUP_CHECK_OPTIONS = Object.freeze({
  showNotConfiguredMessage: false,
  showBusyMessage: false,
  promptOnAvailable: true,
  showNoUpdateMessage: false,
  showErrors: false,
  emitStatus: false,
  autoDownload: false,
});

const RENDERER_CHECK_OPTIONS = Object.freeze({
  showNotConfiguredMessage: false,
  showBusyMessage: false,
  promptOnAvailable: false,
  showNoUpdateMessage: false,
  showErrors: false,
  emitStatus: true,
  autoDownload: true,
});

function createUpdateController({ getWindow, sendStatus }) {
  let initialized = false;
  let checkInFlight = null;
  let downloadInFlight = null;
  let activeCheckOptions = null;
  let errorPromptHandled = false;
  let startupCheckScheduled = false;
  let currentUpdateInfo = null;
  let currentDownloadProgress = null;
  let downloadedUpdateInfo = null;

  const activeWindow = () => {
    try {
      return getWindow ? getWindow() : null;
    } catch {
      return null;
    }
  };

  const setProgress = (value) => {
    try {
      activeWindow()?.setProgressBar(value);
    } catch {}
  };

  const isConfigured = () => fs.existsSync(getUpdateConfigPath());

  const normalizeCheckOptions = (options = {}) => ({
    ...DEFAULT_CHECK_OPTIONS,
    ...options,
  });

  const getCheckOptions = () => activeCheckOptions || DEFAULT_CHECK_OPTIONS;
  const clearCheckOptions = () => { activeCheckOptions = null; };

  const emitStatus = (payload) => {
    if (!payload) return;
    try {
      sendStatus?.({ ts: Date.now(), ...payload });
    } catch {}
  };

  const showNotConfiguredMessage = async () => {
    const dialog = getElectronDialog();
    if (!dialog?.showMessageBox) return;
    await dialog.showMessageBox(activeWindow(), {
      type: "info",
      title: "Updates Not Configured",
      message: "This build does not have an update feed configured.",
      detail: [
        `Expected config: ${getUpdateConfigPath()}`,
        "",
        "To enable in-app updates, publish a signed build with a platform-appropriate",
        "target (mac: zip + app-update.yml/latest-mac.yml, win: nupkg + latest.yml,",
        "linux: AppImage + latest-linux.yml) and point this build at its feed URL.",
      ].join("\n"),
      buttons: ["OK"],
    });
  };

  const ensureInitialized = () => {
    if (initialized) return;
    initialized = true;
    const autoUpdater = getAutoUpdater();
    const electronApp = getElectronApp();

    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = true;
    autoUpdater.allowPrerelease = /-/.test(getCurrentVersion());
    autoUpdater.logger = {
      info: (msg) => dbg("UPDATER", String(msg)),
      warn: (msg) => dbg("UPDATER", `WARN: ${String(msg)}`),
      error: (msg) => dbg("UPDATER", `ERROR: ${String(msg)}`),
      debug: (msg) => dbg("UPDATER", `DEBUG: ${String(msg)}`),
    };

    if (!electronApp?.isPackaged && isConfigured()) {
      autoUpdater.forceDevUpdateConfig = true;
    }

    autoUpdater.on("checking-for-update", () => {
      dbg("UPDATER", "Checking for updates");
    });

    autoUpdater.on("update-available", async (info) => {
      const options = getCheckOptions();
      const releaseNotes = getReleaseNotesText(info);
      currentUpdateInfo = { version: info?.version || null, releaseNotes };
      downloadedUpdateInfo = null;
      currentDownloadProgress = {
        percent: 0,
        transferred: 0,
        total: 0,
        bytesPerSecond: 0,
      };
      dbg("UPDATER", "Update available", { version: info?.version });
      if (options.emitStatus) {
        emitStatus({
          phase: options.autoDownload ? "downloading" : "available",
          version: currentUpdateInfo.version,
          releaseNotes,
          percent: 0,
          transferred: 0,
          total: 0,
          bytesPerSecond: 0,
          message: options.autoDownload
            ? `IRFlow Timeline ${info.version} is available. Downloading now.`
            : `IRFlow Timeline ${info.version} is available.`,
        });
      }

      if (options.autoDownload) {
        if (downloadInFlight) return;
        try {
          setProgress(0.01);
          downloadInFlight = autoUpdater.downloadUpdate();
          await downloadInFlight;
        } catch (err) {
          setProgress(-1);
          dbg("UPDATER", "Download failed", { message: err?.message, stack: err?.stack });
          if (options.emitStatus) {
            emitStatus({
              phase: "error",
              message: err?.message || "The update could not be downloaded.",
            });
          } else {
            const dialog = getElectronDialog();
            if (dialog?.showMessageBox) {
              await dialog.showMessageBox(activeWindow(), {
                type: "error",
                title: "Update Download Failed",
                message: err?.message || "The update could not be downloaded.",
                buttons: ["OK"],
              });
            }
          }
          clearCheckOptions();
          currentDownloadProgress = null;
        } finally {
          downloadInFlight = null;
        }
        return;
      }

      if (!options.promptOnAvailable) {
        clearCheckOptions();
        return;
      }
      const dialog = getElectronDialog();
      if (!dialog?.showMessageBox) return;

      const detailLines = [`Version ${info.version} is available.`];
      if (releaseNotes) detailLines.push("", releaseNotes);

      const { response } = await dialog.showMessageBox(activeWindow(), {
        type: "info",
        title: "Update Available",
        message: `IRFlow Timeline ${info.version} is available`,
        detail: detailLines.join("\n"),
        buttons: ["Download Update", "Later"],
        defaultId: 0,
        cancelId: 1,
      });

      if (response !== 0) {
        clearCheckOptions();
        currentDownloadProgress = null;
        return;
      }
      if (downloadInFlight) {
        await dialog.showMessageBox(activeWindow(), {
          type: "info",
          title: "Update Downloading",
          message: "The update is already downloading.",
        buttons: ["OK"],
      });
        return;
      }

      try {
        setProgress(0.01);
        downloadInFlight = autoUpdater.downloadUpdate();
        await downloadInFlight;
      } catch (err) {
        setProgress(-1);
        dbg("UPDATER", "Download failed", { message: err?.message, stack: err?.stack });
        await dialog.showMessageBox(activeWindow(), {
          type: "error",
          title: "Update Download Failed",
          message: err?.message || "The update could not be downloaded.",
          buttons: ["OK"],
        });
        clearCheckOptions();
        currentDownloadProgress = null;
      } finally {
        downloadInFlight = null;
      }
    });

    autoUpdater.on("update-not-available", async () => {
      const options = getCheckOptions();
      clearCheckOptions();
      currentUpdateInfo = null;
      currentDownloadProgress = null;
      dbg("UPDATER", "No update available");
      if (options.emitStatus) {
        emitStatus({
          phase: "no-update",
          version: getCurrentVersion(),
          message: `You already have the latest version (${getCurrentVersion()}).`,
        });
      }
      if (!options.showNoUpdateMessage) return;
      const dialog = getElectronDialog();
      if (!dialog?.showMessageBox) return;
      await dialog.showMessageBox(activeWindow(), {
        type: "info",
        title: "No Updates Available",
        message: `You already have the latest version (${getCurrentVersion()}).`,
        buttons: ["OK"],
      });
    });

    autoUpdater.on("download-progress", (progress) => {
      const fraction = Number.isFinite(progress?.percent) ? Math.max(0, Math.min(1, progress.percent / 100)) : 0;
      currentDownloadProgress = {
        percent: Number.isFinite(progress?.percent) ? progress.percent : 0,
        transferred: Number.isFinite(progress?.transferred) ? progress.transferred : 0,
        total: Number.isFinite(progress?.total) ? progress.total : 0,
        bytesPerSecond: Number.isFinite(progress?.bytesPerSecond) ? progress.bytesPerSecond : 0,
      };
      setProgress(fraction);
      if (getCheckOptions().emitStatus) {
        emitStatus({
          phase: "downloading",
          version: currentUpdateInfo?.version || null,
          releaseNotes: currentUpdateInfo?.releaseNotes || "",
          ...currentDownloadProgress,
          message: currentUpdateInfo?.version
            ? `Downloading IRFlow Timeline ${currentUpdateInfo.version}...`
            : "Downloading update...",
        });
      }
    });

    autoUpdater.on("update-downloaded", async (info) => {
      const options = getCheckOptions();
      downloadedUpdateInfo = {
        version: info?.version || currentUpdateInfo?.version || null,
        releaseNotes: currentUpdateInfo?.releaseNotes || getReleaseNotesText(info),
      };
      currentDownloadProgress = {
        percent: 100,
        transferred: currentDownloadProgress?.total || currentDownloadProgress?.transferred || 0,
        total: currentDownloadProgress?.total || currentDownloadProgress?.transferred || 0,
        bytesPerSecond: 0,
      };
      clearCheckOptions();
      setProgress(-1);
      dbg("UPDATER", "Update downloaded", { version: info?.version });
      if (options.emitStatus) {
        emitStatus({
          phase: "downloaded",
          version: downloadedUpdateInfo.version,
          releaseNotes: downloadedUpdateInfo.releaseNotes,
          message: `IRFlow Timeline ${downloadedUpdateInfo.version || ""} has been downloaded.`.trim(),
          detail: "Restart the app to apply the update to the app currently open.",
        });
        return;
      }
      const dialog = getElectronDialog();
      if (!dialog?.showMessageBox) return;
      const { response } = await dialog.showMessageBox(activeWindow(), {
        type: "info",
        title: "Update Ready",
        message: `IRFlow Timeline ${info.version} has been downloaded.`,
        detail: "Restart the app now to install the update.",
        buttons: ["Restart and Install", "Later"],
        defaultId: 0,
        cancelId: 1,
      });
      if (response === 0) {
        autoUpdater.quitAndInstall();
      }
    });

    autoUpdater.on("error", async (err) => {
      const options = getCheckOptions();
      clearCheckOptions();
      setProgress(-1);
      currentDownloadProgress = null;
      dbg("UPDATER", "Updater error", { message: err?.message, stack: err?.stack });
      if (options.emitStatus) {
        emitStatus({
          phase: "error",
          message: err?.message || "The update check failed.",
        });
      }
      if (!options.showErrors) return;
      const dialog = getElectronDialog();
      if (!dialog?.showMessageBox) return;
      errorPromptHandled = true;
      await dialog.showMessageBox(activeWindow(), {
        type: "error",
        title: "Update Check Failed",
        message: err?.message || "The update check failed.",
        buttons: ["OK"],
      });
    });
  };

  const checkForUpdates = async (options = {}) => {
    const checkOptions = normalizeCheckOptions(options);
    if (!isConfigured()) {
      if (checkOptions.emitStatus) {
        emitStatus({
          phase: "not-configured",
          message: "This build does not have an update feed configured.",
          detail: `Expected config: ${getUpdateConfigPath()}`,
        });
      }
      if (checkOptions.showNotConfiguredMessage) await showNotConfiguredMessage();
      return { ok: false, reason: "not-configured" };
    }
    ensureInitialized();
    const autoUpdater = getAutoUpdater();
    if (downloadedUpdateInfo) {
      if (checkOptions.emitStatus) {
        emitStatus({
          phase: "downloaded",
          version: downloadedUpdateInfo.version,
          releaseNotes: downloadedUpdateInfo.releaseNotes,
          message: `IRFlow Timeline ${downloadedUpdateInfo.version || ""} has already been downloaded.`.trim(),
          detail: "Restart the app to apply the update to the app currently open.",
        });
      }
      return { ok: false, reason: "downloaded" };
    }
    if (downloadInFlight) {
      if (checkOptions.emitStatus) {
        emitStatus({
          phase: "downloading",
          version: currentUpdateInfo?.version || null,
          releaseNotes: currentUpdateInfo?.releaseNotes || "",
          percent: currentDownloadProgress?.percent || 0,
          transferred: currentDownloadProgress?.transferred || 0,
          total: currentDownloadProgress?.total || 0,
          bytesPerSecond: currentDownloadProgress?.bytesPerSecond || 0,
          message: currentUpdateInfo?.version
            ? `Downloading IRFlow Timeline ${currentUpdateInfo.version}...`
            : "Downloading update...",
        });
      }
      if (checkOptions.showBusyMessage) {
        const dialog = getElectronDialog();
        if (dialog?.showMessageBox) {
          await dialog.showMessageBox(activeWindow(), {
            type: "info",
            title: "Update Downloading",
            message: "An update is already downloading.",
            buttons: ["OK"],
          });
        }
      }
      return { ok: false, reason: "downloading" };
    }
    if (checkInFlight) {
      if (checkOptions.emitStatus) {
        emitStatus({
          phase: "checking",
          message: "Checking for updates...",
        });
      }
      if (checkOptions.showBusyMessage) {
        const dialog = getElectronDialog();
        if (dialog?.showMessageBox) {
          await dialog.showMessageBox(activeWindow(), {
            type: "info",
            title: "Update Check In Progress",
            message: "An update check is already running.",
            buttons: ["OK"],
          });
        }
      }
      return { ok: false, reason: "busy" };
    }

    activeCheckOptions = checkOptions;
    currentUpdateInfo = null;
    currentDownloadProgress = null;
    errorPromptHandled = false;
    if (checkOptions.emitStatus) {
      emitStatus({
        phase: "checking",
        message: "Checking for updates...",
      });
    }
    try {
      checkInFlight = autoUpdater.checkForUpdates();
      await checkInFlight;
      return { ok: true };
    } catch (err) {
      clearCheckOptions();
      dbg("UPDATER", "checkForUpdates threw", { message: err?.message, stack: err?.stack });
      currentDownloadProgress = null;
      if (checkOptions.emitStatus) {
        emitStatus({
          phase: "error",
          message: err?.message || "The update check failed.",
        });
      }
      if (checkOptions.showErrors && !errorPromptHandled) {
        const dialog = getElectronDialog();
        if (dialog?.showMessageBox) {
          await dialog.showMessageBox(activeWindow(), {
            type: "error",
            title: "Update Check Failed",
            message: err?.message || "The update check failed.",
            buttons: ["OK"],
          });
        }
      }
      return { ok: false, reason: "error", error: err };
    } finally {
      checkInFlight = null;
    }
  };

  const checkForUpdatesFromRenderer = async () => checkForUpdates(RENDERER_CHECK_OPTIONS);

  const installUpdate = async () => {
    ensureInitialized();
    if (!downloadedUpdateInfo) {
      emitStatus({
        phase: "error",
        message: "No downloaded update is ready to install.",
      });
      return { ok: false, reason: "no-downloaded-update" };
    }
    getAutoUpdater().quitAndInstall();
    return { ok: true };
  };

  const scheduleStartupCheck = ({ delayMs = 5000 } = {}) => {
    const electronApp = getElectronApp();
    if (startupCheckScheduled || !electronApp?.isPackaged || !isConfigured()) return false;
    startupCheckScheduled = true;
    const timer = setTimeout(() => {
      checkForUpdates(STARTUP_CHECK_OPTIONS);
    }, delayMs);
    if (typeof timer?.unref === "function") timer.unref();
    return true;
  };

  return {
    checkForUpdates,
    checkForUpdatesFromRenderer,
    isConfigured,
    installUpdate,
    scheduleStartupCheck,
  };
}

module.exports = { createUpdateController, getUpdateConfigPath };
