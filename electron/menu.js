/**
 * menu.js — Native macOS menu builder
 *
 *
 * Extracted from main.js. Builds the application menu template
 * with recent files, keyboard shortcuts, and all menu actions.
 */

const { Menu, dialog, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const { planImportPaths } = require("./parsers/ai-history-import");
const { loadTempDirSetting, saveTempDirSetting, isUsable } = require("./utils/temp-dir");
const { openDialogOptions } = require("./utils/open-dialog");
const { THEME_OPTIONS, DEFAULT_THEME } = require("./themes");

/**
 * Build and set the native application menu.
 *
 * @param {object} deps - Dependencies from main.js
 * @param {BrowserWindow} deps.mainWindow
 * @param {Function} deps.loadRecentFiles
 * @param {Function} deps.saveRecentFiles
 * @param {Function} deps.enqueueImport
 * @param {Function} deps.safeSend
 * @param {Function} deps.activeWindow
 * @param {object} deps.updateController
 * @param {Function} [deps.getCurrentTheme] - Returns the color scheme id to show as checked
 * @param {Function} [deps.applyTheme] - Persists + applies a color scheme id
 */
function buildMenu(deps) {
  const { mainWindow, loadRecentFiles, saveRecentFiles, enqueueImport, safeSend, activeWindow, updateController, onTempDirChanged, getCurrentTheme, applyTheme } = deps;
  // Read the active scheme on every build: this function re-invokes itself with the same deps
  // (Clear Recent, temp-folder changes), so a captured value would leave the check mark stale.
  const currentTheme = typeof getCurrentTheme === "function" ? getCurrentTheme() : DEFAULT_THEME;

  // Build recent files submenu
  const recentFiles = loadRecentFiles();
  const recentSubmenu = recentFiles.length > 0
    ? [
        ...recentFiles.map((fp) => ({
          label: path.basename(fp),
          toolTip: fp,
          click: () => {
            if (fs.existsSync(fp)) {
              for (const item of planImportPaths([fp])) {
                enqueueImport(item.path, item.opts || {});
              }
            } else {
              const files = loadRecentFiles().filter((f) => f !== fp);
              saveRecentFiles(files);
              buildMenu(deps);
              safeSend("recent-files-updated", files);
              dialog.showMessageBox(activeWindow(), { type: "warning", title: "File Not Found", message: `The file no longer exists at this location.`, detail: fp, buttons: ["OK"] }).catch(() => {});
            }
          },
        })),
        { type: "separator" },
        { label: "Clear Recent", click: () => { saveRecentFiles([]); buildMenu(deps); } },
      ]
    : [{ label: "No Recent Files", enabled: false }];

  const template = [
    {
      label: "IRFlow Timeline",
      submenu: [
        { role: "about" },
        { type: "separator" },
        { role: "services" },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit" },
      ],
    },
    {
      label: "File",
      submenu: [
        {
          label: "Open...",
          accelerator: "CmdOrCtrl+O",
          click: () => mainWindow?.webContents.send("trigger-open"),
        },
        {
          label: "Open Recent",
          submenu: recentSubmenu,
        },
        { type: "separator" },
        {
          label: "Save Session...",
          accelerator: "CmdOrCtrl+S",
          click: () => mainWindow?.webContents.send("trigger-save-session"),
        },
        {
          label: "Open Session...",
          accelerator: "CmdOrCtrl+Shift+O",
          click: () => mainWindow?.webContents.send("trigger-load-session"),
        },
        { type: "separator" },
        {
          label: "Export Filtered View...",
          accelerator: "CmdOrCtrl+E",
          click: () => mainWindow?.webContents.send("trigger-export"),
        },
        {
          label: "Generate Report...",
          accelerator: "CmdOrCtrl+Shift+R",
          click: () => mainWindow?.webContents.send("trigger-generate-report"),
        },
        { type: "separator" },
        {
          label: "Close Tab",
          accelerator: "CmdOrCtrl+W",
          click: () => mainWindow?.webContents.send("trigger-close-tab"),
        },
        {
          label: "Close All Tabs",
          accelerator: "CmdOrCtrl+Shift+Q",
          click: () => mainWindow?.webContents.send("trigger-close-all-tabs"),
        },
        { type: "separator" },
        { role: "close" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" }, { role: "redo" }, { type: "separator" },
        { role: "cut" }, { role: "copy" }, { role: "paste" }, { role: "selectAll" },
        { type: "separator" },
        {
          label: "Find...",
          accelerator: "CmdOrCtrl+F",
          click: () => mainWindow?.webContents.send("trigger-search"),
        },
        {
          label: "Find in All Tabs...",
          accelerator: "CmdOrCtrl+Shift+F",
          click: () => mainWindow?.webContents.send("trigger-crossfind"),
        },
      ],
    },
    {
      label: "Tools",
      submenu: [
        {
          label: "Datetime Format",
          submenu: [
            { label: "Default (raw)", click: () => mainWindow?.webContents.send("set-datetime-format", "") },
            { label: "yyyy-MM-dd HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss") },
            { label: "yyyy-MM-dd HH:mm:ss.fff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fff") },
            { label: "yyyy-MM-dd HH:mm:ss.fffffff", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd HH:mm:ss.fffffff") },
            { label: "MM/dd/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "MM/dd/yyyy HH:mm:ss") },
            { label: "dd/MM/yyyy HH:mm:ss", click: () => mainWindow?.webContents.send("set-datetime-format", "dd/MM/yyyy HH:mm:ss") },
            { label: "yyyy-MM-dd", click: () => mainWindow?.webContents.send("set-datetime-format", "yyyy-MM-dd") },
          ],
        },
        {
          label: "Timezone",
          submenu: [
            { label: "UTC", click: () => mainWindow?.webContents.send("set-timezone", "UTC") },
            { label: "US/Eastern (EST/EDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/New_York") },
            { label: "US/Central (CST/CDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Chicago") },
            { label: "US/Mountain (MST/MDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Denver") },
            { label: "US/Pacific (PST/PDT)", click: () => mainWindow?.webContents.send("set-timezone", "America/Los_Angeles") },
            { label: "Europe/London (GMT/BST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/London") },
            { label: "Europe/Berlin (CET/CEST)", click: () => mainWindow?.webContents.send("set-timezone", "Europe/Berlin") },
            { label: "Asia/Tokyo (JST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Tokyo") },
            { label: "Asia/Shanghai (CST)", click: () => mainWindow?.webContents.send("set-timezone", "Asia/Shanghai") },
            { label: "Australia/Sydney (AEST/AEDT)", click: () => mainWindow?.webContents.send("set-timezone", "Australia/Sydney") },
            { label: "Local (system)", click: () => mainWindow?.webContents.send("set-timezone", "local") },
          ],
        },
        { type: "separator" },
        {
          label: "Font Size",
          submenu: [
            { label: "Increase", accelerator: "CmdOrCtrl+Plus", click: () => mainWindow?.webContents.send("set-font-size", "increase") },
            { label: "Decrease", accelerator: "CmdOrCtrl+-", click: () => mainWindow?.webContents.send("set-font-size", "decrease") },
            { type: "separator" },
            ...[9, 10, 11, 12, 13, 14, 16, 18].map((s) => ({
              label: `${s}px`, click: () => mainWindow?.webContents.send("set-font-size", s),
            })),
          ],
        },
        { type: "separator" },
        {
          label: "Reset Column Widths",
          accelerator: "CmdOrCtrl+R",
          click: () => mainWindow?.webContents.send("trigger-reset-columns"),
        },
        {
          label: "Toggle Histogram",
          click: () => mainWindow?.webContents.send("trigger-histogram"),
        },
        { type: "separator" },
        {
          // Radio items mirror the toolbar picker; applyTheme (main.js) persists the choice,
          // tells the renderer and rebuilds this menu so the check mark follows.
          label: "Color Scheme",
          submenu: THEME_OPTIONS.map((option) => ({
            label: option.label,
            type: "radio",
            checked: option.id === currentTheme,
            click: () => {
              if (applyTheme) applyTheme(option.id);
              else mainWindow?.webContents.send("set-theme", option.id);
            },
          })),
        },
        { type: "separator" },
        {
          label: "VirusTotal API Key...",
          click: () => mainWindow?.webContents.send("trigger-vt-settings"),
        },
        { type: "separator" },
        {
          // Where large imports build their temp DB + indexes. Redirect to a scratch/external
          // volume so 30-50GB ingests don't fill the boot disk. Applies to the NEXT import.
          label: `Temp Storage: ${loadTempDirSetting() || "Default (system temp)"}`,
          enabled: false,
        },
        {
          label: "Set Temp Storage Folder…",
          click: async () => {
            const res = await dialog.showOpenDialog(activeWindow(), openDialogOptions({
              title: "Choose Temp Storage Folder",
              message: "Large imports build their database and indexes here. Pick a folder on a volume with plenty of free space.",
              properties: ["openDirectory", "createDirectory"],
            })).catch(() => null);
            if (!res || res.canceled || !res.filePaths?.[0]) return;
            const dir = res.filePaths[0];
            if (!isUsable(dir)) {
              dialog.showMessageBox(activeWindow(), { type: "error", title: "Folder Not Writable", message: "That folder isn't writable. Please choose another.", detail: dir, buttons: ["OK"] }).catch(() => {});
              return;
            }
            saveTempDirSetting(dir);
            onTempDirChanged?.();
            buildMenu(deps); // refresh the label
            dialog.showMessageBox(activeWindow(), { type: "info", title: "Temp Storage Folder Set", message: "New imports will use this folder for their database and indexes.", detail: dir, buttons: ["OK"] }).catch(() => {});
          },
        },
        {
          label: "Use Default Temp Folder",
          enabled: !!loadTempDirSetting(),
          click: () => { saveTempDirSetting(null); onTempDirChanged?.(); buildMenu(deps); },
        },
      ],
    },
    {
      label: "View",
      submenu: [
        {
          label: "Toggle Bookmarked Only",
          accelerator: "CmdOrCtrl+B",
          click: () => mainWindow?.webContents.send("trigger-bookmark-toggle"),
        },
        {
          label: "Column Manager",
          accelerator: "CmdOrCtrl+Shift+C",
          click: () => mainWindow?.webContents.send("trigger-column-manager"),
        },
        {
          label: "Conditional Formatting",
          accelerator: "CmdOrCtrl+Shift+L",
          click: () => mainWindow?.webContents.send("trigger-color-rules"),
        },
        { type: "separator" },
        { role: "togglefullscreen" },
        { type: "separator" },
        { role: "zoomIn" }, { role: "zoomOut" }, { role: "resetZoom" },
        { type: "separator" },
        { role: "toggleDevTools" },
      ],
    },
    {
      label: "Window",
      submenu: [{ role: "minimize" }, { role: "zoom" }, { type: "separator" }, { role: "front" }],
    },
    {
      label: "Help",
      submenu: [
        {
          label: "Keyboard Shortcuts",
          accelerator: "CmdOrCtrl+/",
          click: () => mainWindow?.webContents.send("trigger-shortcuts"),
        },
        {
          label: "Check for Updates...",
          click: () => {
            if (activeWindow()) safeSend("trigger-check-for-updates");
            else updateController.checkForUpdates();
          },
        },
        { type: "separator" },
        {
          label: "EZ Tools Website",
          click: () => shell.openExternal("https://ericzimmerman.github.io/"),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

module.exports = { buildMenu };
