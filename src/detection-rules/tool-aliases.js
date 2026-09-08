// Canonical alias table for RMM, exfil, and tunnel tooling.
//
// One source of truth — used by:
//   • detection-rules.js to derive RMM_TOOLS, EXFIL_TOOLS, TUNNEL_TOOLS regexes
//   • process-inspector.js to seed PI_ALLOWLIST entries (so the same name set
//     drives both "looks like RMM" detection and "sanctioned vendor path" suppression)
//   • UI labels in the Process Inspector evidence pills
//
// Why this exists (Finding #5): the same tool was modeled three different ways
// — bare name in standalone regex (`screenconnect`), full executable in chain
// rules (`screenconnect.clientservice.exe`), allowlist key under yet another
// spelling (`screenconnect.windowsclient`). A process named
// `screenconnect.clientservice.exe` matched the chain rule but missed the
// standalone "RMM context" check entirely, weakening hands-on-keyboard detection.
//
// Each tool entry:
//   canonical:  short label used in UI / chain rules / messages
//   aliases:    [string] of every executable basename (without .exe) the tool ships
//               under. Used to build regexes and to look up category for an arbitrary
//               process name. The first alias is treated as the "primary" name.
//   category:   "rmm" | "exfil" | "tunnel"
//   technique:  MITRE ATT&CK ID(s) typically associated
//   sanctionedPaths: [string] of vendor install path fragments (lowercased,
//               with leading + trailing backslash) that mark a sanctioned install.
//               PI_ALLOWLIST uses these to suppress context-only hits when the
//               tool is running from its expected location.

export const TOOL_ENTRIES = [
  // ---- RMM / remote access ----
  {
    canonical: "ScreenConnect",
    aliases: [
      "screenconnect.clientservice",
      "screenconnect.windowsclient",
      "screenconnect.clientsetup",
      "screenconnect",
    ],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\screenconnect client\\", "\\connectwise\\"],
  },
  {
    canonical: "TeamViewer",
    aliases: [
      "teamviewer_service",
      "teamviewer",
      "tv_w32",
      "tv_x64",
    ],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\teamviewer\\"],
  },
  {
    canonical: "AnyDesk",
    aliases: ["anydesk"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\anydesk\\"],
  },
  {
    canonical: "Splashtop",
    aliases: ["splashtop", "srservice", "srfeature", "srmanager"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\splashtop\\"],
  },
  {
    canonical: "RustDesk",
    aliases: ["rustdesk"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\rustdesk\\"],
  },
  {
    canonical: "Supremo",
    aliases: ["supremo", "supremoremotedesktop"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\supremo\\"],
  },
  {
    canonical: "Atera",
    aliases: ["ateraagent", "atera_agent", "atera"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\atera\\"],
  },
  {
    canonical: "BeyondTrust",
    aliases: ["bomgar-scc", "bomgar"],
    category: "rmm",
    techniques: ["T1219"],
    sanctionedPaths: ["\\bomgar\\", "\\beyondtrust\\"],
  },
  // ---- Exfil ----
  {
    canonical: "rclone",
    aliases: ["rclone"],
    category: "exfil",
    techniques: ["T1567.002"],
  },
  {
    canonical: "FileZilla",
    aliases: ["filezilla"],
    category: "exfil",
    techniques: ["T1048"],
  },
  {
    canonical: "WinSCP",
    aliases: ["winscp"],
    category: "exfil",
    techniques: ["T1048"],
  },
  {
    canonical: "MEGAsync",
    aliases: ["megasync", "megacmd"],
    category: "exfil",
    techniques: ["T1567.002"],
  },
  // ---- Tunnel / proxy ----
  // Tunnel binaries are almost always shipped with the Go release-artifact name
  // still attached (frpc_windows_amd64.exe, cloudflared-windows-amd64.exe,
  // chisel_1.9.1_windows_amd64.exe), and the bare canonical name that used to be
  // the only alias matched none of them.
  {
    canonical: "ngrok",
    aliases: ["ngrok", "ngrok-windows-amd64", "ngrok_windows_amd64"],
    category: "tunnel",
    techniques: ["T1572"],
  },
  {
    canonical: "Chisel",
    aliases: ["chisel", "chisel_windows_amd64", "chisel-windows-amd64", "chisel_windows_386", "chiselc"],
    category: "tunnel",
    techniques: ["T1572"],
  },
  {
    canonical: "frp",
    aliases: ["frpc", "frps", "frpc_windows_amd64", "frps_windows_amd64", "frpc-windows-amd64", "frps-windows-amd64"],
    category: "tunnel",
    techniques: ["T1572"],
  },
  {
    canonical: "Cloudflared",
    aliases: ["cloudflared", "cloudflared-windows-amd64", "cloudflared_windows_amd64", "cloudflared-windows-386"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "Plink",
    aliases: ["plink"],
    category: "tunnel",
    techniques: ["T1572"],
  },
  {
    canonical: "Ligolo-ng",
    aliases: ["ligolo", "ligolo-ng", "agent_windows_amd64", "proxy_windows_amd64"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "gost",
    aliases: ["gost", "gost-windows-amd64"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "NPS",
    aliases: ["npc", "nps", "npc_windows_amd64"],
    category: "tunnel",
    techniques: ["T1572"],
  },
  {
    canonical: "Iox",
    aliases: ["iox"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "revsocks",
    aliases: ["revsocks", "rsockstun"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "EarthWorm",
    aliases: ["ew", "earthworm", "ew_for_win"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "Stowaway",
    aliases: ["stowaway", "stowaway_agent", "stowaway_admin"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
  {
    canonical: "socat",
    aliases: ["socat"],
    category: "tunnel",
    techniques: ["T1572", "T1090"],
  },
];

// Build a name → entry lookup. Aliases are matched case-insensitively against
// the basename of an image path (no .exe suffix).
export const TOOL_BY_ALIAS = (() => {
  const m = new Map();
  for (const e of TOOL_ENTRIES) {
    for (const a of e.aliases) m.set(a.toLowerCase(), e);
  }
  return m;
})();

// Normalize a process name for alias lookup: strip path + .exe + lowercase.
export function _toolAliasKey(name) {
  return String(name || "")
    .toLowerCase()
    .replace(/^.*[\\/]/, "")
    .replace(/\.exe$/i, "")
    .trim();
}

// Build a regex matching any alias of a given category. Anchored ^...(\.exe)?$.
export function buildCategoryRegex(category) {
  const aliases = [];
  for (const e of TOOL_ENTRIES) {
    if (e.category !== category) continue;
    for (const a of e.aliases) {
      // Escape regex meta in alias names
      aliases.push(a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    }
  }
  if (aliases.length === 0) return /(?!)/; // never matches
  return new RegExp(`^(${aliases.join("|")})(\\.exe)?$`, "i");
}

// Resolve a process name (any form) to its canonical entry, or null.
export function lookupTool(processName) {
  return TOOL_BY_ALIAS.get(_toolAliasKey(processName)) || null;
}
