const updateBaseUrlRaw =
  process.env.IRFLOW_UPDATE_BASE_URL ||
  process.env.TLE_UPDATE_BASE_URL ||
  "";

const updateBaseUrl = updateBaseUrlRaw.replace(/\/+$/, "");
const updateChannel =
  process.env.IRFLOW_UPDATE_CHANNEL ||
  process.env.TLE_UPDATE_CHANNEL ||
  "latest";

const config = {
  appId: "com.dfir.irflow-timeline",
  productName: "IRFlow Timeline",
  mac: {
    category: "public.app-category.developer-tools",
    icon: "assets/icon.icns",
    // The bundled Hayabusa binary (extraResources) is a universal (arm64+x86_64)
    // Mach-O, identical in both the x64 and arm64 sub-builds. @electron/universal
    // refuses to merge an identical Mach-O unless it's explicitly allowed here, so
    // this tells it to copy the (already-fat) binary through as-is. Without this the
    // universal build fails with "not covered by the x64ArchFiles rule".
    x64ArchFiles: "**/hayabusa/hayabusa",
    target: [
      {
        target: "dmg",
        arch: ["universal"],
      },
      {
        target: "zip",
        arch: ["universal"],
      },
    ],
    darkModeSupport: true,
    hardenedRuntime: true,
    gatekeeperAssess: false,
    entitlements: "entitlements.mac.plist",
    entitlementsInherit: "entitlements.mac.plist",
  },
  linux: {
    // Distribute as a portable AppImage (no install required, runs on most modern
    // distros) plus a .deb for Debian/Ubuntu/Mint/Pop!_OS installs. The userData
    // directory is system-standard (XDG ~/.config), and the Hayabusa binary bundled
    // into extraResources needs +x (asarUnpack handles the native module).
    // electron-builder's `linux.icon` only accepts a single string — the filename
    // MUST contain the icon size (e.g. 512x512.png) so the builder can pick the
    // right size per target (AppImage squashfs wants 256+, deb wants 256+).
    icon: "assets/512x512.png",
    category: "Development",
    target: [
      { target: "AppImage", arch: ["x64", "arm64"] },
      { target: "deb", arch: ["x64", "arm64"] },
    ],
    // Make the AppImage and deb self-contained: the bundled Hayabusa binary writes
    // its config / rule cache under userData, so it needs rwx on its own dir, not
    // the read-only /opt tree. extraResources is unpacked by default on Linux.
    executableName: "irflow-timeline",
    artifactName: "IRFlow-Timeline-${version}-${arch}.${ext}",
    synopsis: "DFIR Timeline Analysis",
    description: "High-performance DFIR timeline viewer for CSV, TSV, XLSX, EVTX, Plaso, $MFT, and $J files.",
  },
  afterSign: "scripts/notarize.js",
  electronUpdaterCompatibility: ">=2.16",
  dmg: {
    title: "IRFlow Timeline",
    contents: [
      { x: 130, y: 220 },
      { x: 410, y: 220, type: "link", path: "/Applications" },
    ],
  },
  files: [
    "dist/**/*",
    "electron/**/*",
    "assets/**/*",
  ],
  extraResources: [
    {
      from: "hayabusa",
      to: "hayabusa",
      filter: ["**/*", "!logs/**"],
    },
    {
      from: "tools/bmc-tools",
      to: "tools/bmc-tools",
      filter: ["**/*"],
    },
  ],
  asarUnpack: [
    "node_modules/better-sqlite3/**",
  ],
  directories: {
    output: "release",
  },
  fileAssociations: [
    { ext: "csv", name: "CSV File", role: "Viewer" },
    { ext: "tsv", name: "TSV File", role: "Viewer" },
    { ext: "xlsx", name: "Excel File", role: "Viewer" },
    { ext: "plaso", name: "Plaso File", role: "Viewer" },
    { ext: "evtx", name: "EVTX File", role: "Viewer" },
    { ext: "mft", name: "MFT File", role: "Viewer" },
  ],
};

if (updateBaseUrl) {
  config.publish = [
    {
      provider: "generic",
      url: updateBaseUrl,
      channel: updateChannel,
    },
  ];
}

module.exports = config;
