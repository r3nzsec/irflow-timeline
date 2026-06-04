/**
 * menu.js — Native macOS menu builder
 *
 * Extracted from main.js. Builds the application menu template
 * with recent files, keyboard shortcuts, and all menu actions.
 */

const { Menu, dialog, shell } = require("electron");
const path = require("path");
const fs = require("fs");
const { loadTempDirSetting, saveTempDirSetting, isUsable } = require("./utils/temp-dir");

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
 */
function buildMenu(deps) {
  const { mainWindow, loadRecentFiles, saveRecentFiles, enqueueImport, safeSend, activeWindow, updateController, onTempDirChanged } = deps;

  // On macOS the first menu is the application menu (with `about`, `services`, `hide`,
  // `hideOthers`, `unhide`, `quit` roles that are darwin-only). On Linux/Windows those
  // roles are invalid; the conventional alternative is to surface About/Quit inside the
  // File menu. Keeping the per-platform split in one place keeps the rest of the
  // template (File / Edit / Tools / View / Window / Help) shared.
  const IS_MAC = process.platform === "darwin";
  const appMenu = IS_MAC
    ? {
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
      }
    : null;

  // Build recent files submenu
  const recentFiles = loadRecentFiles();
  const recentSubmenu = recentFiles.length > 0
    ? [
        ...recentFiles.map((fp) => ({
          label: path.basename(fp),
          toolTip: fp,
          click: () => {
            if (fs.existsSync(fp)) {
              enqueueImport(fp);
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
    ...(appMenu ? [appMenu] : []),
    {
      label: "File",
      submenu: [
        ...(IS_MAC
          ? []
          : [
              { role: "about" },
              { type: "separator" },
            ]),
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
        ...(IS_MAC
          ? []
          : [
              { type: "separator" },
              { role: "quit" },
            ]),
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
          label: "Theme",
          submenu: [
            { label: "Dark", click: () => mainWindow?.webContents.send("set-theme", "dark") },
            { label: "Light", click: () => mainWindow?.webContents.send("set-theme", "light") },
          ],
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
            const res = await dialog.showOpenDialog(activeWindow(), {
              title: "Choose Temp Storage Folder",
              message: "Large imports build their database and indexes here. Pick a folder on a volume with plenty of free space.",
              properties: ["openDirectory", "createDirectory"],
            }).catch(() => null);
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
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        ...(IS_MAC ? [{ type: "separator" }, { role: "front" }] : []),
      ],
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
