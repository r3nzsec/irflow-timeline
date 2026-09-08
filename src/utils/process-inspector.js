import { CHAIN_RULE_MAP, resolveChainRule, SUS_PATHS, USER_WRITABLE_PATH, BENIGN_INSTALL_PATH, SAFE_PROCS, ENCODED_PS, CRED_DUMP_CMD, NTDS_EXTRACT, LSASS_TOOLS, LSASS_TARGET_CMD, ACCOUNT_MANIP, DEFENSE_EVASION, NETWORK_SCANNERS, AD_RECON_TOOLS, RMM_TOOLS, EXFIL_TOOLS, TUNNEL_TOOLS, ARCHIVE_SUSPECT, TOOL_ENTRIES } from "../detection-rules.js";
import { PI_ANALYST_PROFILE_DEFAULT } from "../constants/presets.js";

// Process Inspector allowlist — known-good EDR/AV/RMM/update agents by exact name + expected vendor path
// Suppresses Suspicious-path and RMM-presence context hits; dampens other detections
// Entries may include `cmdTest` for command-line-aware matching (e.g. offline collectors)
export const PI_ALLOWLIST = (() => {
  const entries = [
    // EDR agents — Cortex XDR: current installs use Palo Alto Networks paths,
    // while protected payloads may be staged below the legacy Cyvera vendor
    // root in ProgramData. The exact process-name + trusted-root requirement
    // still prevents a same-named copy from inheriting this baseline.
    { n: "cortex-xdr-payload", paths: ["\\palo alto networks\\", "\\cyvera\\"], cat: "edr" },
    { n: "cortex-xdr-payload", paths: null, cat: "edr",
      cmdTest: /offline_collector_config\.json|--offline-collector|--collect-artifacts|XDR_Collector/i },
    { n: "cyserver", paths: ["\\palo alto networks\\"], cat: "edr" },
    { n: "trapsagent", paths: ["\\palo alto networks\\traps\\"], cat: "edr" },
    { n: "cytool", paths: ["\\palo alto networks\\"], cat: "edr" },
    { n: "mssense", paths: ["\\windows defender advanced threat protection\\"], cat: "edr" },
    { n: "senseir", paths: ["\\windows defender advanced threat protection\\"], cat: "edr" },
    { n: "sensecncproxy", paths: ["\\windows defender advanced threat protection\\"], cat: "edr" },
    { n: "csfalconservice", paths: ["\\crowdstrike\\"], cat: "edr" },
    { n: "csfalconcontainer", paths: ["\\crowdstrike\\"], cat: "edr" },
    { n: "csagent", paths: ["\\crowdstrike\\"], cat: "edr" },
    { n: "cbdefense", paths: ["\\confer\\"], cat: "edr" },
    { n: "repux", paths: ["\\carbon black\\"], cat: "edr" },
    { n: "cb", paths: ["\\carbon black\\", "\\carbonblack\\"], cat: "edr" },
    { n: "taniumclient", paths: ["\\tanium\\"], cat: "edr" },
    { n: "taniumendpointindex", paths: ["\\tanium\\"], cat: "edr" },
    { n: "sentinelagent", paths: ["\\sentinelone\\"], cat: "edr" },
    { n: "sentinelctl", paths: ["\\sentinelone\\"], cat: "edr" },
    { n: "sentinelservicehost", paths: ["\\sentinelone\\"], cat: "edr" },
    { n: "xagt", paths: ["\\fireeye\\", "\\trellix\\"], cat: "edr" },
    { n: "firetray", paths: ["\\fireeye\\", "\\trellix\\"], cat: "edr" },
    { n: "clowd", paths: ["\\trellix\\"], cat: "edr" },
    { n: "cylanceprotect", paths: ["\\cylance\\"], cat: "edr" },
    { n: "cylanceui", paths: ["\\cylance\\"], cat: "edr" },
    { n: "cyoptics", paths: ["\\cylance\\"], cat: "edr" },
    // AV agents
    { n: "msmpeng", paths: ["\\windows defender\\", "\\microsoft antimalware\\"], cat: "av" },
    // mpcmdrun.exe is a documented LOLBin: it can download arbitrary files
    // and act as a download/proxy stager even when launched from its sanctioned
    // install path. cmdUntrust strips allowlist status when the cmdline matches
    // any of the known abuse shapes, so the standalone download/decode rules
    // (pi-22) and any analyst custom rules still see the row.
    { n: "mpcmdrun", paths: ["\\windows defender\\", "\\microsoft antimalware\\"], cat: "av",
      cmdUntrust: /-DownloadFile\b|-EncodedCommand\b|\bcom_threats\b/i },
    { n: "nissrv", paths: ["\\windows defender\\"], cat: "av" },
    { n: "avp", paths: ["\\kaspersky lab\\"], cat: "av" },
    { n: "kavfs", paths: ["\\kaspersky lab\\"], cat: "av" },
    { n: "savservice", paths: ["\\sophos\\"], cat: "av" },
    { n: "sophossps", paths: ["\\sophos\\"], cat: "av" },
    { n: "hmpalert", paths: ["\\sophos\\"], cat: "av" },
    { n: "ccsvchst", paths: ["\\symantec\\", "\\norton\\"], cat: "av" },
    { n: "rtvscan", paths: ["\\symantec\\"], cat: "av" },
    { n: "ekrn", paths: ["\\eset\\"], cat: "av" },
    { n: "egui", paths: ["\\eset\\"], cat: "av" },
    { n: "bdagent", paths: ["\\bitdefender\\"], cat: "av" },
    { n: "epintegrationservice", paths: ["\\bitdefender\\"], cat: "av" },
    { n: "epconsole", paths: ["\\bitdefender\\"], cat: "av" },
    { n: "clamav", paths: ["\\clamav\\"], cat: "av" },
    // Sanctioned RMM — seeded from the canonical tool alias table (Finding #5).
    // Adding a new RMM variant means editing src/detection-rules/tool-aliases.js;
    // both the standalone RMM_TOOLS regex and this allowlist pick it up automatically.
    ...TOOL_ENTRIES
      .filter((e) => e.category === "rmm" && e.sanctionedPaths && e.sanctionedPaths.length > 0)
      .flatMap((e) => e.aliases.map((a) => ({ n: a, paths: e.sanctionedPaths, cat: "rmm" }))),
    // Update / system agents
    { n: "googleupdate", paths: ["\\google\\"], cat: "update" },
    { n: "microsoftedgeupdate", paths: ["\\microsoft\\edgeupdate\\", "\\microsoft\\edge\\"], cat: "update" },
    { n: "wuauclt", paths: ["\\windows\\"], cat: "update" },
    { n: "musnotification", paths: ["\\windows\\"], cat: "update" },
    { n: "tiworker", paths: ["\\windows\\"], cat: "update" },
    { n: "trustedinstaller", paths: ["\\windows\\"], cat: "update" },
    { n: "onedrive", paths: ["\\microsoft onedrive\\", "\\onedrive\\"], cat: "update" },
    { n: "onedriveupdater", paths: ["\\microsoft onedrive\\", "\\onedrive\\"], cat: "update" },
    // DFIR / forensic tools
    { n: "kape", paths: ["\\kape\\"], cat: "dfir" },
    { n: "gkape", paths: ["\\kape\\"], cat: "dfir" },
  ];
  // Build name -> entries[] Map (multiple entries per name for cmdTest variants)
  const m = new Map();
  for (const e of entries) {
    let arr = m.get(e.n);
    if (!arr) { arr = []; m.set(e.n, arr); }
    arr.push(e);
  }
  return m;
})();

// Trusted system root prefixes for the allowlist path check. The original
// implementation matched vendor fragments anywhere in the path, so an
// attacker who controlled a folder name could plant `mssense.exe` inside
// `c:\users\public\windows defender advanced threat protection\` and pick up
// EDR allowlisting. We now require the path to:
//   1. start (after the drive letter) with one of these trusted roots, AND
//   2. contain no user-writable segment between the root and the binary.
// Both conditions must hold AND the vendor fragment from PI_ALLOWLIST must
// still match — making the allowlist a pure narrowing on top of "this image
// lives somewhere only an admin/installer should be able to write".
const _PI_TRUSTED_ROOT_PREFIXES = [
  ":\\program files\\",
  ":\\program files (x86)\\",
  ":\\programdata\\",
  ":\\windows\\",
];
// NOT the canonical USER_WRITABLE_PATH: this one answers a different question —
// "is this path under a writable SUBDIRECTORY of a trusted root" — and must not
// list the trusted roots themselves (\ProgramData\, \Users\ appear in
// _PI_TRUSTED_ROOT_PREFIXES), or every path under them would reject itself.
const _RX_PI_USER_WRITABLE_SEGMENT = /\\(users|temp|tmp|appdata|downloads|public|recycle|perflogs)\\/i;

// Canonicalise an image path ONCE so every path anchor compares the same shape.
// Windows hands the same binary to different providers in at least five forms:
//   C:\Windows\System32\svchost.exe      (Sysmon Image)
//   \??\C:\Windows\System32\svchost.exe  (native object-manager form, 4688/EID 10)
//   \SystemRoot\System32\smss.exe        (boot-time processes)
//   \Device\HarddiskVolume3\Windows\...  (kernel/device form)
//   "C:/Windows/System32/svchost.exe"     (quoted / forward slashes from some exporters)
// The masquerade anchors were written against the first form only, so the others
// looked like "a system binary running from an unexpected path" — a critical
// finding on the most normal processes on the machine. Trailing NUL/whitespace and
// wrapping quotes are stripped for the same reason.
const _canonImagePath = (img) => {
  let p = String(img == null ? "" : img).trim().toLowerCase();
  if (!p) return "";
  p = p.replace(/^["']+|["']+$/g, "").replace(/\0+$/g, "").trim();
  p = p.replace(/\//g, "\\");
  p = p.replace(/^\\\\\?\\/, "").replace(/^\\\?\?\\/, "");
  p = p.replace(/^\\device\\harddiskvolume\d+\\/, "c:\\");
  p = p.replace(/^(\\systemroot|%systemroot%|%windir%)\\/, "c:\\windows\\");
  p = p.replace(/^system32\\/, "c:\\windows\\system32\\");
  return p;
};
const _isUnderTrustedRoot = (lowerImg) => {
  if (!lowerImg) return false;
  const colon = lowerImg.indexOf(":\\");
  if (colon < 0) return false; // UNC paths and bare names are not trusted
  const fromColon = lowerImg.slice(colon);
  let underRoot = false;
  for (const p of _PI_TRUSTED_ROOT_PREFIXES) {
    if (fromColon.startsWith(p)) { underRoot = true; break; }
  }
  if (!underRoot) return false;
  // Reject anything sitting under a writable subdirectory (e.g.
  // c:\programdata\public\evil\… would pass step 1 but fail here)
  if (_RX_PI_USER_WRITABLE_SEGMENT.test(fromColon)) return false;
  return true;
};

// Hoisted regexes — module scope so we don't recompile per process call.
// Hot path: getSusInfo runs once per row, up to 200,000 rows per build.
const _RX_SHELL_PARENTS = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)(\.exe)?$/i;
const _RX_SHELL_CHILDREN = /^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$/i;
const _RX_OFFICE_PARENTS = /^(winword|excel|powerpnt|outlook|onenote|msaccess|mspub)(\.exe)?$/i;
const _RX_MGMT_PARENTS = /^(ccmexec|intunemanagementextension|pdqdeployrunner|salt-minion|chef-client|puppet|taniumclient|kaceagent|automateagent|ninjaoneagent|action1_agent|lansweeper|connectwisecontrol|screenconnect\.clientservice)(\.exe)?$/i;
// Remote-access RMM subset of _RX_MGMT_PARENTS that threat actors routinely abuse for
// hands-on-keyboard access. High-fidelity attack semantics (explicit LSASS dump) under these
// parents must NOT be downgraded the way config-management / patch agents are.
const _RX_RMM_REMOTE_PARENTS = /^(connectwisecontrol|screenconnect\.clientservice|screenconnect\.windowsclient|ninjaoneagent|ninjaonesession|action1_agent|automateagent|atera|ateraagent|syncrosetup|splashtop|sragent|srmanager|anydesk|teamviewer|tvnserver|dwagent|supremo|gotohttp|remotepc|rustdesk)(\.exe)?$/i;

// The management-agent DISCOUNT applies only to unattended configuration and patch
// agents (SCCM, Intune, Puppet, Chef, Salt, Tanium, PDQ...). A remote-ACCESS tool is
// a human at a keyboard, which is precisely the hands-on-keyboard case an intrusion
// looks like — discounting it meant encoded PowerShell launched through a hijacked
// ScreenConnect / ConnectWise / NinjaOne / AnyDesk session was demoted to context,
// and that is the single most common ransomware access pattern in the wild.
const _isMgmtDiscountParent = (pn) => _RX_MGMT_PARENTS.test(pn) && !_RX_RMM_REMOTE_PARENTS.test(pn);
// Unified — see USER_WRITABLE_PATH in detection-rules.js (audit P19).
const _RX_USER_WRITABLE = USER_WRITABLE_PATH;
const _RX_PROG_FILES = /(\\program files\\|\\program files \(x86\)\\)/i;
const _RX_PS_NAME = /^(powershell|pwsh)(\.exe)?$/i;
const _RX_SERVICES_NAME = /^services(\.exe)?$/i;
const _RX_SVCHOST_NAME = /^svchost(\.exe)?$/i;
const _RX_WMIPRVSE_NAME = /^wmiprvse(\.exe)?$/i;
const _RX_SVCHOST_PATH_OK = /\\windows\\(system32|syswow64)\\svchost\.exe$/i;
const _RX_PS_STEALTH = /\s(-w|-windowstyle)\s+hidden\b|\s(-nop|-noprofile)\b|\s(-ep|-executionpolicy)\s+bypass\b/i;
const _RX_PS_CRADLE_BASIC = /\b(iex|invoke-expression|downloadstring|net\.webclient|frombase64string)\b/i;
const _RX_PS_AMSI = /amsiInitFailed|amsiContext|amsiScanBuffer|amsi\.dll.*GetProcAddress|SetProtectionLevel|EtwEventWrite|EtwpEventWriteFull|\[Ref\]\.Assembly/i;
const _RX_PS_DEFENDER_DISABLE = /Set-MpPreference\s+(-Disable|-ExclusionPath|-ExclusionProcess|-ExclusionExtension)/i;
const _RX_PS_DEFENDER_EXCL = /Add-MpPreference\s+-Exclusion/i;
const _RX_PS_IEX = /\b(iex|invoke-expression)\b/i;
const _RX_PS_DOWNLOAD = /(downloadstring|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod)/i;
const _RX_PS_DOWNLOAD_FULL = /\b(downloadstring|downloadfile|net\.webclient|invoke-webrequest|invoke-restmethod|iwr)\b/i;
const _RX_PS_REFLECT = /\[reflection\.assembly\]::load|\[system\.runtime\.interopservices\.marshal\]/i;
const _RX_PS_B64 = /\bfrombase64string\b/i;
const _RX_PS_MEM = /\bnew-object\s+io\.memorystream\b/i;
const _RX_PS_ENCODED_FLAG = /\s(-e|-enc|-encodedcommand|-en|-ec)\b/i;
const _RX_PS_HIDDEN_FLAG = /\s(-w|-windowstyle)\s+hidden\b/i;
const _RX_PS_NOPROFILE_FLAG = /\s(-nop|-noprofile)\b/i;
const _RX_PS_BYPASS_FLAG = /\s(-ep|-executionpolicy)\s+bypass\b/i;
const _RX_PS_CRADLE_SHORT = /\b(iex|invoke-expression|frombase64string)\b/i;
const _RX_MSHTA_NAME = /^mshta(\.exe)?$/i;
const _RX_REGSVR32_NAME = /^regsvr32(\.exe)?$/i;
const _RX_RUNDLL32_NAME = /^rundll32(\.exe)?$/i;
const _RX_DOTNET_LOLBINS = /^(installutil|msbuild|cmstp|regasm|regsvcs)(\.exe)?$/i;
const _RX_FORFILES_NAME = /^forfiles(\.exe)?$/i;
const _RX_PCALUA_NAME = /^pcalua(\.exe)?$/i;
const _RX_ODBCCONF_NAME = /^odbcconf(\.exe)?$/i;
const _RX_CURL_NAME = /^curl(\.exe)?$/i;
const _RX_EXTRAC32_NAME = /^extrac32(\.exe)?$/i;
const _RX_MPCMDRUN_NAME = /^mpcmdrun(\.exe)?$/i;
const _RX_MPCMDRUN_DOWNLOAD = /-DownloadFile\b/i;
const _RX_MPCMDRUN_LOLBIN = /-EncodedCommand\b|\bcom_threats\b/i;
const _RX_DSQUERY_NAME = /^dsquery(\.exe)?$/i;
const _RX_KLIST_NAME = /^klist(\.exe)?$/i;
const _RX_CLOUDFLARED_NAME = /^cloudflared(\.exe)?$/i;
const _RX_PLINK_NAME = /^plink(\.exe)?$/i;
const _RX_SSH_NAME = /^ssh(\.exe)?$/i;
const _RX_PROXY_NAMES = /^(frpc?|chisel|ngrok)(\.exe)?$/i;
const _RX_TUNNEL_RING_FLAGS = /\s(-R|-L|-D)\s/i;
const _RX_TUNNEL_VERBS = /\b(client|server|http|tcp|start|connect|tunnel)\b/i;
const _RX_TUNNEL_FULL_CMD = /\b(cloudflared\s+tunnel|chisel\s+(client|server)|ngrok\s+(http|tcp))\b/i;
const _RX_WSCRIPT_NAME = /^(wscript|cscript)(\.exe)?$/i;
const _RX_USER_PROFILE_PATH = /(\\users\\[^\\]+\\|\\appdata\\)/i;
const _RX_HTTP_URL = /https?:\/\//i;
const _RX_HTML_HANDLERS = /(https?:\/\/|javascript:|vbscript:|about:)/i;
const _RX_REGSVR32_REMOTE = /(\/[sin]\b.*scrobj\.dll|https?:\/\/)/i;
const _RX_JS_HANDLER = /javascript:/i;
const _RX_UNC_PATH = /\\\\[a-z0-9_.-]+\\/i;
const _RX_DOTNET_LOLBIN_ARGS = /(https?:\/\/|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\public\\|\\\\[a-z0-9_.-]+\\|\/u\b|\/i:\S+)/i;
const _RX_FORFILES_C = /\/c\b.*(cmd|powershell|wscript|cscript|mshta|rundll32)/i;
const _RX_PCALUA_A = /-a\b/i;
const _RX_ODBCCONF_AF = /\/(a|f)\b/i;
const _RX_PRIV_GROUPS = /\b(administrators|domain\s*admins|enterprise\s*admins)\b/i;
const _RX_NET_GROUP_PRIV_ADD = /\b(net\s+(localgroup|group)\s+.*(administrators|domain\s*admins).*\/add)/i;
const _RX_DOMAIN_FLAG = /\/domain\b/i;
const _RX_WMI_SUBSCRIPTION = /\b(set-wminstance|__eventfilter|__eventconsumer|commandlineeventconsumer)\b/i;
const _RX_SCHTASKS_REMOTE = /schtasks\b.*\/create\b.*\/s\s+\S/i;
const _RX_SCHTASKS_CREATE = /schtasks\b.*\/create\b/i;
// Strip the invoking executable so a pattern meant for the PAYLOAD cannot match the
// launcher itself. Without this, _RX_PERSIST_HOTPAY (which lists powershell / cmd /
// mshta / rundll32 as hot payloads) matched the word "powershell" in
// `powershell -c Set-Service ...` and promoted every PowerShell-issued service or
// task tweak to high.
const _cmdArgsOnly = (cmd) => {
  const s = String(cmd || "").trimStart();
  if (!s) return "";
  if (s[0] === '"') {
    const end = s.indexOf('"', 1);
    return end < 0 ? "" : s.slice(end + 1);
  }
  const sp = s.search(/\s/);
  return sp < 0 ? "" : s.slice(sp + 1);
};
const _RX_PERSIST_HOTPAY = /(\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\public\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|wscript|cscript|https?:\/\/|\\\\[a-z0-9_.-]+\\)/i;
const _RX_SC_CREATE = /\bsc\s+(create|config)\b/i;
const _RX_REG_AUTORUN = /\breg\b.*\badd\b.*\\(Run|RunOnce|Image\s*File\s*Execution\s*Options|AppInit_DLLs|Winlogon\\(Userinit|Shell))\b/i;
// new-service / register-scheduledtask CREATE something that survives a reboot.
// set-service mostly changes an existing service's start type or description and is
// what every installer, GPO script and admin runbook does — it only matters when it
// repoints the binary or enables something that was disabled.
const _RX_PS_PERSIST = /\b(register-scheduledtask|new-scheduledtask|new-service)\b/i;
const _RX_PS_SET_SERVICE = /\bset-service\b/i;
const _RX_PS_SET_SERVICE_HOT = /-(binarypathname|path)\s+\S+|-startuptype\s+(automatic|boot|system)\b/i;
const _RX_PS_RUN_KEY = /\bset-itemproperty\b.*\\(Run|RunOnce)\b/i;
const _RX_WMIC_PROC_CALL_LOCAL = /\bwmic\b.*\bprocess\s+call\s+create\b/i;
const _RX_WMIC_NODE = /\/node:/i;
const _RX_WMIC_REMOTE_EXEC = /wmic\b.*\/node:\s*\S+.*\bprocess\s+call\s+create\b/i;
const _RX_WMIC_SHADOW_DEL = /wmic\b.*\/node:\s*\S+.*\bshadowcopy\s+delete\b/i;
const _RX_WINRM_LOCAL_CFG = /winrm\s+(quickconfig|get|enumerate|set|identify)\b/i;
const _RX_PS_REMOTING = /\b(invoke-command|enter-pssession|new-pssession)\b/i;
// Invoke-Command is routinely used with -ScriptBlock against the LOCAL machine (it is
// the standard way to run a scriptblock with arguments), and -ComputerName localhost
// is a common build-script idiom. Only an explicit remote target makes it lateral
// movement. Without this gate every packaging and CI script scored critical.
const _RX_PS_REMOTING_TARGET = /-(computername|cn|hostname|vmname|containerid|connectionuri|session)\s+\S+|-computername\s*:?\s*\S+|\b(pssession|cimsession)\s*-computername/i;
const _RX_PS_REMOTING_LOCAL_TARGET = /-(computername|cn)\s+["']?(localhost|127\.0\.0\.1|\.|\$env:computername)["']?(\s|$)/i;
const _RX_WMIC_NODE_ANY = /wmic\b.*\/node:/i;
// Anchor to actual remote-execution verbs / the winrs shell — bare "winrm" as a
// substring (paths, service names, config queries like `winrm get/quickconfig`) is benign.
const _RX_WINRM_GENERIC = /\bwinrm\s+(invoke|i|create|c|delete|d|set|s|enumerate|e)\b|\bwinrs\b/i;
const _RX_CERTUTIL_DECODE = /\bcertutil\b.*(-decode|-decodehex)\b/i;
const _RX_CERTUTIL_URLCACHE = /\bcertutil\b.*-urlcache\b/i;
const _RX_DOWNLOAD_PATHS = /(https?:\/\/|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\public\\|\\\\[a-z0-9_.-]+\\)/i;
const _RX_BITSADMIN_TRANSFER = /\bbitsadmin\b.*\/transfer\b/i;
const _RX_NLTEST_RECON = /\bnltest\b.*\/(dclist|domain_trusts|dsgetdc|dsgetsite|parentdomain|server)/i;
const _RX_SETSPN_RECON = /\bsetspn\b.*-[TQF]\b/i;
const _RX_NET_DOMAIN_QUERY = /\bnet\s+(group|user)\b.*\/domain\b/i;
const _RX_WHOAMI_PRIV = /\bwhoami\b.*\/(groups|priv|all)\b/i;
const _RX_WMIC_LOCAL_RECON = /\bwmic\b.*\b(useraccount|group|ntdomain)\b/i;
const _RX_EXPLORER_SVCHOST = /^(explorer|services|svchost)(\.exe)?$/i;
const _RX_WMI_LATERAL_INDICATORS = /\/node:\s*\S+|invoke-command|enter-pssession|new-pssession|winrm|\\\\[a-z0-9_.-]+\\/i;
// A service-host (pi-2) or interpreter→interpreter (pi-1) chain only earns PRIMARY severity
// when the child command line carries a real attack indicator. Without one, svchost→powershell /
// cmd→powershell are dominated by benign management (SCCM/Intune/GPO/WMI admin), so they are
// recorded as CONTEXT instead. Composed from existing, tested corroborator regexes.
const _chainCorroborated = (cmd) => !!cmd && (
  ENCODED_PS.test(cmd) || _RX_PS_STEALTH.test(cmd) || _RX_PS_CRADLE_BASIC.test(cmd)
  || _RX_DOWNLOAD_PATHS.test(cmd) || _RX_WMI_LATERAL_INDICATORS.test(cmd)
);
// A lone built-in discovery command is everyday helpdesk/login-script activity; it only matters
// CORRELATED (whoami+net+nltest+systeminfo in a window), which the sequence engine handles. As a
// standalone chain it's context, not a primary finding. (net/wmic excluded — they have lateral uses.)
const _RX_DISCOVERY_SINGLETON = /^(whoami|hostname|ipconfig|arp|nslookup|netstat|route|nbtstat|tracert|pathping|tasklist|systeminfo|quser|qwinsta)$/i;

// Service hosts noisy enough that a shell child of theirs is meaningless without a
// corroborating command line. This list used to be the WHOLE pi-2 parent set, which
// also contains wsmprovhost (an inbound WinRM session), dllhost and mmc (DCOM
// lateral movement) and services (a launched service) — the exact remote-execution
// parents an intrusion produces. Those were demoted to context and scored zero.
const _RX_NOISY_SERVICE_PARENTS = /^(svchost|taskeng|taskhostw)(\.exe)?$/i;

// Parents where even a single built-in discovery command matters, because the
// parent itself should never be running one: an IIS worker, a WinRM session host,
// a DCOM surrogate or a database engine executing `whoami` is a web shell or a
// hands-on-keyboard operator, not a login script.
const _RX_HIGH_SIGNAL_PARENTS = /^(w3wp|wsmprovhost|dllhost|mmc|httpd|nginx|tomcat\d*|java|javaw|php-cgi|php|sqlservr|sqlagent|exchange\w*|umworkerprocess|msexchange\w*)(\.exe)?$/i;
const _RX_LSASS_RUNDLL = /rundll32(\.exe)?\s+.*comsvcs\.dll\s*,?\s*minidump.*\blsass\b/i;
const _RX_LSASS_PROCDUMP = /procdump(\.exe)?\s+.*\b(-ma|-mm|-mp)?\b.*\blsass\b/i;
const _RX_OFFICE_STAGED = /(https?:\/\/|javascript:|vbscript:|scrobj\.dll|\/i:http|\bfrombase64string\b|\b(downloadstring|invoke-expression|iex)\b|\s-enc\b)/i;

// --- New technique families (pi-31 through pi-34) ---
// DLL sideload: rundll32/regsvr32 loading a DLL from outside system directories
const _RX_DLL_LOADER_NAME = /^(rundll32|regsvr32)(\.exe)?$/i;
const _RX_SYSTEM_DLL_PATH = /\\windows\\(system32|syswow64|winsxs)\\/i;
const _RX_DLL_EXT = /\.(dll|ocx)\b/i;
// SAM/SECURITY hive copy
const _RX_REG_SAVE_HIVE = /\breg\b.*\bsave\b.*\b(hklm\\sam|hklm\\security|hklm\\system)\b/i;
const _RX_ESENTUTL_COPY = /\besentutl\b.*\/(y|p|r)\b/i;
const _RX_HIVE_TARGETS = /\\(sam|security|system|ntds\.dit)\b/i;
const _RX_NTDSUTIL_SNAPSHOT = /\bntdsutil\b.*\bsnapshot\b/i;
// Token theft / impersonation
const _RX_RUNAS_NETONLY = /\brunas\b.*\/netonly\b/i;
const _RX_MAVINJECT_NAME = /^mavinject(\.exe)?$/i;
const _RX_MAVINJECT_INJECT = /\/injectrunning\b/i;
const _RX_TOKEN_TOOLS = /^(incognito|getsystem|tokenvator|sharpimpersonation|printspoofer|roguepotato|juicypotato|juicypotatong|sweetpotato|godpotato|efspotato)(\.exe)?$/i;
const _RX_PS_TOKEN_MANIP = /\b(invoke-tokenmanipulat\w*|get-system\b|invoke-runascs\b|invoke-tokenimpersonat\w*)\b/i;

// Trust-based detection regexes (pi-34 through pi-38)
// Known LOLBin original filenames — if a binary's OriginalFileName matches one of
// these but the actual processName doesn't, the binary has been renamed (T1036.003).
const _RX_LOLBIN_ORIG_NAMES = /^(cmd|powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|certutil|msbuild|installutil|regasm|regsvcs|cmstp|msiexec|bitsadmin|forfiles|pcalua|odbcconf|svchost|taskhostw|dllhost|mpcmdrun)$/i;
const _RX_SIG_BAD = /^(expired|revoked|invalid|error|broken|unavailable|notsigned)$/i;
// Core OS binaries that are NEVER legitimately signed by a non-Microsoft publisher. Signer
// mismatch (pi-37) only makes sense for these — 3rd-party apps carry their own publisher.
const _RX_PI_CORE_OS = /^(svchost|lsass|services|csrss|smss|winlogon|wininit|spoolsv|lsm|taskhostw|dllhost|conhost)$/i;
// Expected signers for common Windows binaries — lowercase normalized
const _EXPECTED_SIGNERS = new Map([
  ["svchost", "microsoft"], ["cmd", "microsoft"], ["powershell", "microsoft"],
  ["pwsh", "microsoft"], ["rundll32", "microsoft"], ["regsvr32", "microsoft"],
  ["mshta", "microsoft"], ["wscript", "microsoft"], ["cscript", "microsoft"],
  ["certutil", "microsoft"], ["msbuild", "microsoft"], ["taskhostw", "microsoft"],
  ["dllhost", "microsoft"], ["msiexec", "microsoft"], ["schtasks", "microsoft"],
  ["reg", "microsoft"], ["net", "microsoft"], ["netsh", "microsoft"],
  ["wmic", "microsoft"], ["sc", "microsoft"], ["bcdedit", "microsoft"],
  ["chrome", "google"], ["msedge", "microsoft"], ["firefox", "mozilla"],
]);
// Short-lived process safe list — processes that legitimately run for < 2s
const _RX_SHORT_LIVED_SAFE = /^(conhost|consent|werfault|wermgr|splwow64|dllhost|backgroundtaskhost|runtimebroker|searchprotocolhost|searchfilterhost|audiodg|fontdrvhost|ctfmon)$/i;

// --- High-value gap rules (pi-40 through pi-45) ---
// Task/service host launching binary from writable path
const _RX_TASK_SERVICE_PARENTS = /^(taskhostw|taskeng|taskmgr|svchost|services|wmiprvse)(\.exe)?$/i;
// Browser → shell (dedicated, higher confidence than generic chain)
const _RX_BROWSER_PARENTS = /^(chrome|msedge|firefox|iexplore|opera|brave|safari|microsoftedgecp|browser_broker)(\.exe)?$/i;

// --- Adjacent-telemetry (pi-61..pi-64) false-positive control -----------------
// These four rules fire purely on the PRESENCE and volume of Sysmon 3/22/7/11
// events. Volume alone is not evidence: a browser opens hundreds of connections
// and resolves dozens of names, an updater drops PEs into a writable path, and a
// Python venv or Electron app loads unsigned modules from under \Users by design.
// Scoring those as high/critical made every workstation with full Sysmon coverage
// look compromised. The telemetry stays visible; it just needs a reason to score.

// Applications whose normal operation IS network + DNS + file-drop + odd module loads.
const _RX_NETWORK_NATIVE_APPS = /^(chrome|msedge|msedgewebview2|firefox|iexplore|opera|brave|safari|vivaldi|chromium|teams|ms-teams|slack|discord|zoom|outlook|onedrive|onedrivestandaloneupdater|dropbox|googledrivesync|googleupdate|microsoftedgeupdate|updater|squirrel|setup|install|installer|msiexec|tiworker|wuauclt|usoclient|mousocoreworker|spotify|steam|epicgameslauncher|code|devenv|node|python|python3|pythonw|java|javaw|git|git-remote-https|curl|wget|svchost|backgroundtransferhost|smartscreen|mpcmdrun|msmpeng|sensendr|cbcomms|falcon|sentinelagent)(\.exe)?$/i;

// The signature of DLL sideloading is a binary in a TRUSTED location loading an
// unsigned module from a writable one. When the process itself lives in a
// writable directory (venv, Electron app, portable tool), an unsigned neighbour
// module is the norm rather than the exception.
const _RX_TRUSTED_IMAGE_ROOT = /^[a-z]:[\\/](windows|program files|program files \(x86\))[\\/]/i;

// Does anything OTHER than the raw telemetry volume justify scoring this process?
const _pi6xCorroborated = (c) => (
  _chainCorroborated(c.cmd)
  || (SUS_PATHS.test(c.il) && !BENIGN_INSTALL_PATH.test(c.ilc || c.il) && !SAFE_PROCS.test(c.n))
  || _RX_SHELL_CHILDREN.test(c.n)
  || _RX_PS_NAME.test(c.n)
  || _RX_SHELL_CHILDREN.test(c.pn)
  || _RX_PS_NAME.test(c.pn)
  || c.signed === "false"
  || /invalid|expired|revoked|untrusted|error/.test(c.sigStatus || "")
  || !!c.injection
);
// BITS persistence: /SetNotifyCmdLine sets a callback program
const _RX_BITS_PERSIST = /\bbitsadmin\b.*\/setnotifycmdline\b/i;
const _RX_BITS_ADDFILE_SETNOTIFY = /\bbitsadmin\b.*\/(addfile|setnotify|resume|complete)\b/i;
// PowerShell Add-Type / inline C# compilation abuse
const _RX_PS_ADDTYPE = /\bAdd-Type\b.*-TypeDefinition\b/i;
const _RX_PS_ADDTYPE_MEMBER = /\bAdd-Type\b.*-MemberDefinition\b/i;
const _RX_PS_CSHARP_COMPILE = /\b(csc\.exe|vbc\.exe)\b/i;
const _RX_PS_INLINE_INTEROP = /\[DllImport\b|\bMarshal\b.*\bCopy\b|\bVirtualAlloc\b|\bOpenProcess\b|\bWriteProcessMemory\b/i;
// WMI persistence execution hosts
const _RX_MOFCOMP_NAME = /^mofcomp(\.exe)?$/i;
const _RX_SCRCONS_NAME = /^scrcons(\.exe)?$/i;
// PowerShell process injection cmdline patterns (memory manipulation + process targeting)
const _RX_PS_INJECTION = /\b(VirtualAlloc|VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|RtlCreateUserThread)\b/i;

// Canonical image-path anchors for critical Windows system binaries. A binary
// whose processName matches one of these keys but whose full image path does
// NOT match the associated regex is masquerading (T1036.005) — common malware
// trick is to name a payload svchost.exe and drop it into %TEMP%.
// Keys are lowercase, .exe-stripped. Regexes are case-insensitive with \\ anchors.
const _EXPECTED_SYSTEM_PATHS = new Map([
  ["svchost",   /\\(system32|syswow64)\\svchost\.exe$/i],
  ["lsass",     /\\system32\\lsass\.exe$/i],
  ["csrss",     /\\system32\\csrss\.exe$/i],
  ["smss",      /\\system32\\smss\.exe$/i],
  ["winlogon",  /\\system32\\winlogon\.exe$/i],
  ["wininit",   /\\system32\\wininit\.exe$/i],
  ["services",  /\\system32\\services\.exe$/i],
  ["lsm",       /\\system32\\lsm\.exe$/i],
  ["spoolsv",   /\\system32\\spoolsv\.exe$/i],
  ["taskhostw", /\\system32\\taskhostw\.exe$/i],
  ["conhost",   /\\(system32|syswow64)\\conhost\.exe$/i],
  ["rundll32",  /\\(system32|syswow64)\\rundll32\.exe$/i],
  ["regsvr32",  /\\(system32|syswow64)\\regsvr32\.exe$/i],
  ["mshta",     /\\(system32|syswow64)\\mshta\.exe$/i],
  // 32-bit explorer genuinely lives in SysWOW64 on x64 Windows; anchoring on
  // \windows\explorer.exe alone made it a critical masquerade on every host that
  // ever launched a 32-bit shell extension host.
  ["explorer",  /\\windows\\(syswow64\\)?explorer\.exe$/i],
  ["wmiprvse",  /\\(system32|syswow64)\\wbem\\wmiprvse\.exe$/i],
  ["wuauclt",   /\\system32\\wuauclt\.exe$/i],
  ["dllhost",   /\\(system32|syswow64)\\dllhost\.exe$/i],
  ["msiexec",   /\\(system32|syswow64)\\msiexec\.exe$/i],
]);
const _RX_PS_SHELLCODE = /\b(Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-DllInjection|Invoke-ProcessInjection)\b/i;
const _RX_PS_PINVOKE = /\[System\.Runtime\.InteropServices\.Marshal\]::Copy\b|\bGetDelegateForFunctionPointer\b|\b\[IntPtr\].*::Zero\b.*VirtualAlloc/i;

// Context-signal regexes (post-loop section 4)
const _RX_USER_WRITABLE_EXTENDED = USER_WRITABLE_PATH;
const _RX_UNC_PATH_PAREN = /(\\\\[a-z0-9_.-]+\\)/i;
const _RX_NETWORK_URL = /(https?:\/\/|ftp:\/\/)/i;
const _RX_UPDATER_PATTERN = /(\/update|\/install|\/silent|\/passive|trustedinstaller|windows\s*update)/i;

// Rule registry — module scope, built once. Each rule is an object so adding
// fields is safe (the previous sparse-array tuple antipattern would silently
// shift fields if a comma was missed). `test(c)` receives a per-call context
// `c` containing the locals getSusInfo would otherwise close over.
//
// test(c) returns: true | false | { override: N } | { override: N, cat: "context" }
//   - true → use defaultLevel + cat
//   - false → no hit
//   - { override } → replace level
//   - { override, cat } → replace level AND category
// Canonical rule group definitions. Each detection rule in PI_RULES references
// one of these group IDs. The modal imports PI_RULE_GROUPS to render the
// technique-group toggles, so adding a group is a one-file edit here.
export const PI_RULE_GROUPS = [
  { id: "exec", label: "Execution Chains", desc: "Office\u2192Shell, Script Engine, Service-Based, Parent-Child chains" },
  { id: "cred", label: "Credential Access", desc: "Credential dumping, LSASS tools, NTDS extraction, hive copy, token theft" },
  { id: "evasion", label: "Defense Evasion", desc: "Encoded/malicious PowerShell, LOLBin abuse, DLL sideload, download/decode" },
  { id: "persist", label: "Persistence", desc: "Account manipulation, scheduled tasks, services, registry autoruns, WMI subscriptions" },
  { id: "lateral", label: "Lateral Movement", desc: "WMI/WinRM remote commands" },
  { id: "discovery", label: "Discovery", desc: "AD recon tools, network scanners, built-in domain enumeration" },
  { id: "rmm", label: "RMM / C2 / Exfiltration", desc: "Remote admin tools, exfil utilities, tunneling, suspicious archives" },
  { id: "trust", label: "Binary Trust", desc: "Signature anomalies, renamed LOLBins, unsigned in trusted paths" },
  { id: "lifetime", label: "Lifetime Anomalies", desc: "Short-lived processes, missing termination for offensive tools" },
  { id: "misc", label: "Miscellaneous Execution", desc: "Script from user profile, suspicious execution paths" },
];

// Severity label mapping — canonical, used by both the detection engine and the modal.
export const PI_SEV_LABELS = { 3: "critical", 2: "high", 1: "medium", 0: "low" };
export const PI_SEV_COLORS = { critical: "#f85149", high: "#f0883e", medium: "#d29922", low: "#8b949e" };

// Theme-aware variant — preferred in components that have access to `th`.
export const piSevColorsFor = (th) => ({ critical: th.sev.critical, high: th.sev.high, medium: th.sev.med, low: th.sev.low });

// Chain rules (pi-0 through pi-2, pi-18) are classified by _classifyChain, not
// by individual entries in PI_RULES. They still need group + display metadata so
// the modal can render them in technique-group toggles and the config panel.
// `chain: true` marks them as non-test entries (they have no `test` function).
export const PI_CHAIN_RULES = [
  { id: "pi-0", group: "exec", sev: "critical", name: "Office \u2192 Shell (Word/Excel/PPT/Outlook/OneNote/Access/Publisher)", technique: "T1204.002, T1059", count: 28,
    logic: [
      { label: "Type", value: "Parent \u2192 Child chain (28 rules)" },
      { label: "Parents", value: "winword, excel, powerpnt, outlook, onenote, msaccess, mspub" },
      { label: "Children", value: "cmd, powershell, wscript, cscript, msdt, bash, mshta, regsvr32, rundll32, certutil" },
      { label: "Condition", value: "Parent process spawns child process directly" },
      { label: "Example", value: "winword.exe \u2192 powershell.exe = macro execution" },
    ] },
  { id: "pi-1", group: "exec", sev: "high", name: "Script Engine Chains (WScript/CScript/PS/cmd)", technique: "T1059.001, T1059.005", count: 14,
    logic: [
      { label: "Type", value: "Parent \u2192 Child chain (14 rules)" },
      { label: "Chains", value: "wscript\u2192cmd, wscript\u2192powershell, cscript\u2192cmd, ps\u2192ps (double-hop), cmd\u2192ps, ps\u2192wscript, ps\u2192bash" },
      { label: "Condition", value: "Script interpreter spawns another interpreter \u2014 multi-stage execution" },
    ] },
  { id: "pi-2", group: "exec", sev: "high", name: "Service-Based Execution (svchost/WMI/Task Scheduler)", technique: "T1047, T1569.002", count: 18,
    logic: [
      { label: "Type", value: "Parent \u2192 Child chain (18 rules)" },
      { label: "Parents", value: "svchost, wmiprvse, taskeng, taskhostw, wsmprovhost, dllhost, mmc" },
      { label: "Children", value: "cmd, powershell, wscript, cscript, mshta, rundll32, regsvr32" },
      { label: "Condition", value: "Windows service host or WMI provider spawns shell/script" },
    ] },
  { id: "pi-18", group: "exec", sev: "high", name: "Parent-Child Chain Rules (344 rules)", technique: "Multiple", count: 344,
    logic: [
      { label: "Type", value: "344 parent\u2192child process chain rules across 12 ATT&CK tactics" },
      { label: "Tactics", value: "Execution, Defense Evasion, Persistence, Privilege Escalation, Credential Access, Lateral Movement, Discovery, Collection, C2, Exfiltration, Impact, Initial Access" },
      { label: "Parents", value: "Office apps, script engines, service hosts, shells, browsers, system processes, management tools, remote access" },
      { label: "Severity", value: "Level 3 (critical): direct malware indicators. Level 2 (high): likely malicious. Level 1 (medium): suspicious, needs context. Level 0 (low): informational" },
      { label: "Condition", value: "Exact parent\u2192child process name match (case-insensitive, .exe stripped). Highest severity wins if multiple rules match." },
    ] },
  { id: "pi-60", group: "exec", sev: "critical", name: "Grandparent multi-hop chains (Office/script \u2192 shell \u2192 shell)", technique: "T1059, T1204.002", count: 16,
    logic: [
      { label: "Type", value: "Grandparent \u2192 Parent \u2192 Child triple match (16 high-value paths)" },
      { label: "Examples", value: "winword\u2192cmd\u2192powershell, mshta\u2192cmd\u2192powershell, w3wp\u2192powershell\u2192cmd, cmd\u2192ps\u2192certutil" },
      { label: "Condition", value: "Fires on the leaf process when both parent and grandparent names match a known multi-hop attack path (uses consistentParentKey so PID-reuse does not invent chains)" },
    ] },
];

const PI_RULES = [
  { id: "pi-3", group: "evasion", level: 2, reason: "Encoded PowerShell", tid: ["T1059.001"], beh: "script-exec",
    sev: "critical", name: "Encoded PowerShell (-enc / -e flags)", technique: "T1059.001",
    logic: [
      { label: "Process", value: "powershell.exe OR pwsh.exe" },
      { label: "CommandLine", value: "regex: \\s+(-e\\s|-enc\\s|-encodedcommand\\s|-en\\s|-ec\\s)" },
      { label: "Condition", value: "Both process name AND command line must match" },
    ],
    test: (c) => {
      if (!_RX_PS_NAME.test(c.n) || !ENCODED_PS.test(c.cmd)) return false;
      const hasStealth = _RX_PS_STEALTH.test(c.cmd);
      const hasCradle = _RX_PS_CRADLE_BASIC.test(c.cmd);
      if (_isMgmtDiscountParent(c.pn) && !hasStealth && !hasCradle) return { override: 1, cat: "context" };
      if (hasStealth || hasCradle) return { override: 3 };
      return true;
    } },
  { id: "pi-19", group: "evasion", level: 2, reason: "PowerShell malicious semantics", tid: ["T1059.001"], beh: "script-exec",
    sev: "critical", name: "PowerShell Malicious Semantics (IEX/download cradle/AMSI bypass)", technique: "T1059.001",
    logic: [
      { label: "Critical", value: "AMSI bypass (amsiInitFailed, SetProtectionLevel), Defender tamper (Set-MpPreference -Disable, Add-MpPreference -Exclusion), download cradle (IEX + DownloadString), Reflection.Assembly load" },
      { label: "High", value: "IEX/Invoke-Expression, DownloadString/DownloadFile, Net.WebClient, Invoke-WebRequest, Start-BitsTransfer, FromBase64String, IO.MemoryStream" },
      { label: "Condition", value: "Tiered severity: combined download+exec = critical, individual indicators = high" },
    ],
    test: (c) => {
      if (_RX_PS_AMSI.test(c.cmd)) return { override: 3 };
      if (_RX_PS_DEFENDER_DISABLE.test(c.cmd)) return { override: 3 };
      if (_RX_PS_DEFENDER_EXCL.test(c.cmd)) return { override: 3 };
      if (_RX_PS_IEX.test(c.cmd) && _RX_PS_DOWNLOAD.test(c.cmd)) return { override: 3 };
      if (_RX_PS_REFLECT.test(c.cmd)) return { override: 3 };
      if (!_RX_PS_NAME.test(c.n)) return false;
      const hasIex = _RX_PS_IEX.test(c.cmd);
      const hasDownload = _RX_PS_DOWNLOAD_FULL.test(c.cmd);
      const hasB64 = _RX_PS_B64.test(c.cmd);
      const hasMem = _RX_PS_MEM.test(c.cmd);
      const score = (hasIex ? 1 : 0) + (hasDownload ? 1 : 0) + (hasB64 ? 1 : 0) + (hasMem ? 1 : 0);
      // Under management parents (SCCM/GPO/RMM) weak PS semantics are often legitimate, but a
      // genuine cradle under a compromised agent shouldn't vanish — record it as visible context
      // (not a silent drop) so it still correlates and surfaces in hunt views.
      if (_isMgmtDiscountParent(c.pn) && score < 3) return score > 0 ? { override: 1, cat: "context" } : false;
      if (hasIex && (hasDownload || hasB64)) return true;
      if (score >= 3) return true;
      return false;
    } },
  { id: "pi-4", group: "cred", level: 3, reason: "Credential dumping", tid: ["T1003"], beh: "cred",
    sev: "critical", name: "Credential Dumping Commands (comsvcs/sekurlsa/mimikatz)", technique: "T1003",
    logic: [{ label: "CommandLine", value: "regex: comsvcs\\.dll | sekurlsa | lsadump | procdump.*lsass | mimikatz | pypykatz | nanodump" }, { label: "Condition", value: "Any process with matching command line argument" }],
    test: (c) => CRED_DUMP_CMD.test(c.cmd) },
  { id: "pi-5", group: "cred", level: 3, reason: "NTDS extraction", tid: ["T1003.003"], beh: "cred",
    sev: "critical", name: "NTDS Extraction (ntdsutil/secretsdump)", technique: "T1003.003",
    logic: [{ label: "CommandLine", value: "regex: ntdsutil.*ifm | wbadmin.*ntds | secretsdump | ntds\\.dit" }, { label: "Condition", value: "Any process attempting Active Directory database extraction" }],
    test: (c) => NTDS_EXTRACT.test(c.cmd) },
  { id: "pi-7", group: "evasion", level: 2, reason: "Defense evasion", tid: ["T1070"], beh: "evasion",
    sev: "high", name: "Shadow Copy Deletion / Log Clearing / SafeBoot", technique: "T1070",
    logic: [{ label: "CommandLine", value: "regex: vssadmin.*delete | wevtutil\\s+cl | bcdedit.*safeboot | bcdedit.*recoveryenabled" }, { label: "Condition", value: "Any process with anti-forensic or recovery-disabling commands" }],
    test: (c) => DEFENSE_EVASION.test(c.cmd) },
  { id: "pi-21", group: "evasion", level: 2, reason: "LOLBin proxy execution", tid: ["T1218"], beh: "lolbin-exec",
    sev: "critical", name: "LOLBin Proxy Execution (mshta/regsvr32/rundll32/msbuild)", technique: "T1218",
    logic: [
      { label: "Critical", value: "mshta + URL/javascript/vbscript, regsvr32 + scrobj.dll/URL, rundll32 + javascript:" },
      { label: "High", value: "rundll32 + temp/UNC path, installutil, msbuild, cmstp, regasm, regsvcs, forfiles /c, pcalua -a, odbcconf /a" },
      { label: "Condition", value: "Standalone command-line analysis \u2014 detects LOLBin abuse independent of parent process" },
    ],
    test: (c) => {
      if (_RX_MSHTA_NAME.test(c.n) && _RX_HTML_HANDLERS.test(c.cmd)) return { override: 3 };
      if (_RX_REGSVR32_NAME.test(c.n) && _RX_REGSVR32_REMOTE.test(c.cmd)) return { override: 3 };
      if (_RX_RUNDLL32_NAME.test(c.n)) {
        if (_RX_JS_HANDLER.test(c.cmd)) return { override: 3 };
        // rundll32 is how Windows itself invokes control-panel applets, printer UI,
        // shell verbs and per-user installers, and those references live under
        // \AppData\ and \ProgramData\ constantly. Requiring a MODULE argument in a
        // writable path — rather than any writable path anywhere on the line — keeps
        // the sideload case and drops the "rundll32 mentioned AppData" case.
        const _dllArg = (c.cmd.match(/[a-z]:\\[^",]*?\.(dll|ocx|cpl)\b/i) || [])[0] || "";
        if (_dllArg && _RX_USER_WRITABLE.test(_dllArg) && !BENIGN_INSTALL_PATH.test(_dllArg)) return true;
        if (_RX_UNC_PATH.test(c.cmd)) return true;
        if (_RX_USER_WRITABLE.test(c.cmd)) return { override: 1, cat: "context" };
      }
      if (_RX_DOTNET_LOLBINS.test(c.n) && _RX_DOTNET_LOLBIN_ARGS.test(c.cmd)) return true;
      if (_RX_FORFILES_NAME.test(c.n) && _RX_FORFILES_C.test(c.cmd)) return true;
      if (_RX_PCALUA_NAME.test(c.n) && _RX_PCALUA_A.test(c.cmd)) return true;
      if (_RX_ODBCCONF_NAME.test(c.n) && _RX_ODBCCONF_AF.test(c.cmd)) return true;
      return false;
    } },
  { id: "pi-8", group: "persist", level: 2, reason: "Account manipulation", tid: ["T1136"], beh: "persist",
    sev: "high", name: "Account Manipulation (net user/group /add)", technique: "T1136",
    logic: [{ label: "CommandLine", value: "regex: net\\s+(user|group|localgroup)\\s+.*/add" }, { label: "Condition", value: "Account or group creation via net.exe commands" }],
    test: (c) => {
      if (!ACCOUNT_MANIP.test(c.cmd)) return false;
      if (_isMgmtDiscountParent(c.pn) && !_RX_PRIV_GROUPS.test(c.cmd)) return { override: 1, cat: "context" };
      if (_RX_NET_GROUP_PRIV_ADD.test(c.cmd)) return { override: 3 };
      if (_RX_DOMAIN_FLAG.test(c.cmd)) return { override: 2 };
      return true;
    } },
  { id: "pi-20", group: "persist", level: 2, reason: "Persistence installation", tid: ["T1053.005", "T1543.003", "T1547.001"], beh: "persist",
    sev: "critical", name: "Native Persistence Commands (schtasks/sc/reg/WMI)", technique: "T1053.005, T1543.003, T1547.001",
    logic: [
      { label: "Critical", value: "WMI event subscription (__EventFilter/__EventConsumer), remote schtasks /create /s" },
      { label: "High", value: "schtasks /create, sc create/config, reg add Run/RunOnce/IFEO/AppInit_DLLs/Winlogon, Register-ScheduledTask, New-Service, wmic process call create" },
      { label: "Condition", value: "Command-line semantics for persistence installation via native Windows tools and PowerShell cmdlets" },
    ],
    test: (c) => {
      if (_RX_WMI_SUBSCRIPTION.test(c.cmd)) return { override: 3 };
      if (_RX_SCHTASKS_REMOTE.test(c.cmd)) return { override: 3 };
      if (_RX_SCHTASKS_CREATE.test(c.cmd)) {
        if (_RX_PERSIST_HOTPAY.test(_cmdArgsOnly(c.cmd))) return true;
        return { override: 1, cat: "context" };
      }
      if (_RX_SC_CREATE.test(c.cmd)) {
        if (_RX_PERSIST_HOTPAY.test(_cmdArgsOnly(c.cmd))) return true;
        return { override: 1, cat: "context" };
      }
      if (_RX_REG_AUTORUN.test(c.cmd)) return true;
      if (_RX_PS_PERSIST.test(c.cmd)) return true;
      if (_RX_PS_SET_SERVICE.test(c.cmd)) {
        if (_RX_PS_SET_SERVICE_HOT.test(c.cmd) || _RX_PERSIST_HOTPAY.test(_cmdArgsOnly(c.cmd))) return true;
        return { override: 1, cat: "context" };
      }
      if (_RX_PS_RUN_KEY.test(c.cmd)) return true;
      if (_RX_WMIC_PROC_CALL_LOCAL.test(c.cmd) && !_RX_WMIC_NODE.test(c.cmd)) return true;
      return false;
    } },
  { id: "pi-9", group: "lateral", level: 2, reason: "Lateral movement command", tid: ["T1021"], beh: "lateral",
    sev: "high", name: "WMI/WinRM Remote Commands", technique: "T1021",
    logic: [{ label: "CommandLine", value: "regex: wmic.*/node: | winrm" }, { label: "Condition", value: "Remote execution via WMI or WinRM protocols" }],
    test: (c) => {
      if (_RX_WMIC_REMOTE_EXEC.test(c.cmd)) return { override: 3 };
      if (_RX_WMIC_SHADOW_DEL.test(c.cmd)) return { override: 3 };
      if (_RX_WINRM_LOCAL_CFG.test(c.cmd)) return false;
      if (_RX_PS_REMOTING.test(c.cmd)) {
        if (_RX_PS_REMOTING_LOCAL_TARGET.test(c.cmd)) return { override: 0, cat: "context" };
        if (_RX_PS_REMOTING_TARGET.test(c.cmd)) return { override: 3 };
        // Remoting cmdlet with no target named on the command line: the scriptblock
        // form. Keep it visible for correlation, do not score it as lateral movement.
        return { override: 1, cat: "context" };
      }
      if (_RX_WMIC_NODE_ANY.test(c.cmd) || _RX_WINRM_GENERIC.test(c.cmd)) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-22", group: "evasion", level: 2, reason: "Download/decode/stage", tid: ["T1105", "T1140"], beh: "download",
    sev: "critical", name: "Download/Decode/Stage (certutil/bitsadmin/curl/mpcmdrun)", technique: "T1105, T1140",
    logic: [
      { label: "Critical", value: "certutil -decode/-decodehex, mpcmdrun -DownloadFile" },
      { label: "High", value: "certutil -urlcache, bitsadmin /transfer, extrac32, mpcmdrun -EncodedCommand/com_threats" },
      { label: "Medium", value: "curl.exe + URL (common but legitimate)" },
      { label: "Condition", value: "Tiered by confidence \u2014 decode operations more suspicious than downloads" },
    ],
    test: (c) => {
      if (_RX_CERTUTIL_DECODE.test(c.cmd)) return { override: 3 };
      if (_RX_CERTUTIL_URLCACHE.test(c.cmd) && _RX_DOWNLOAD_PATHS.test(c.cmd)) return true;
      if (_RX_BITSADMIN_TRANSFER.test(c.cmd)) {
        if (_RX_DOWNLOAD_PATHS.test(c.cmd)) return true;
        return { override: 1, cat: "context" };
      }
      // curl.exe ships in Windows and is used constantly for benign API/health calls. Only treat
      // it as download/stage when it writes to disk (-o/-O/--output/--remote-name).
      if (_RX_CURL_NAME.test(c.n) && _RX_HTTP_URL.test(c.cmd) && /(?:\s-o\b|\s-O\b|--output\b|--remote-name\b)/i.test(c.cmd)) return { override: 1, cat: "context" };
      if (_RX_EXTRAC32_NAME.test(c.n)) return { override: 1, cat: "context" };
      // mpcmdrun.exe (Defender CLI) is a documented LOLBin: -DownloadFile
      // pulls arbitrary URLs to disk, com_threats can sideload payloads via
      // the threat definition path. The allowlist entry has a matching
      // cmdUntrust so this rule still fires even when the binary lives in
      // its sanctioned install path.
      if (_RX_MPCMDRUN_NAME.test(c.n) && _RX_MPCMDRUN_DOWNLOAD.test(c.cmd)) return { override: 3 };
      if (_RX_MPCMDRUN_NAME.test(c.n) && _RX_MPCMDRUN_LOLBIN.test(c.cmd)) return true;
      return false;
    } },
  { id: "pi-14", group: "rmm", level: 1, reason: "Suspicious archive operation", cat: "context", tid: ["T1560.001"], beh: "exfil",
    sev: "high", name: "Suspicious Archive Operations (7z/rar with password)", technique: "T1560.001",
    logic: [{ label: "CommandLine", value: "regex: \\b(7z|7za|winrar|rar)\\b.*-h?p (password flag)" }, { label: "Condition", value: "Archive tool invoked with a password flag (-p/-hp) \u2014 potential encrypted data staging. Plain archive creation without a password is not flagged (too noisy)." }],
    test: (c) => ARCHIVE_SUSPECT.test(c.cmd) },
  { id: "pi-6", group: "cred", level: 3, reason: "LSASS access tool", tid: ["T1003.001"], beh: "cred",
    sev: "critical", name: "Memory-Dump Tool targeting LSASS", technique: "T1003.001",
    logic: [
      { label: "Process", value: "A known memory-dump utility (procdump, ProcessHacker/SystemInformer, nanodump, createdump, rdrleakdiag, dumpert, sqldumper, avdump, handlekatz, \u2026)" },
      { label: "Critical", value: "The command line names lsass, OR a correlated Sysmon EID 10 shows this process opening a handle to lsass" },
      { label: "Context", value: "Tool present with no lsass target \u2014 procdump on a dev box, ProcessHacker used by support, sqldumper run by SQL Server itself. Recorded, not scored." },
      { label: "Why", value: "The rule used to fire on the NAME alone and go straight to critical, so every workstation with Sysinternals installed produced a credential-theft finding." },
    ],
    test: (c) => {
      if (!LSASS_TOOLS.test(c.n)) return false;
      if (LSASS_TARGET_CMD.test(c.cmd)) return true;
      // Corroboration from telemetry: this process was seen opening lsass.
      if ((c.credAccess?.lsassReadCount || 0) > 0) return true;
      return { override: 0, cat: "context" };
    } },
  { id: "pi-10", group: "discovery", level: 2, reason: "AD recon tool", tid: ["T1087.002"], beh: "recon",
    sev: "high", name: "AD Recon Tools (BloodHound/SharpHound/ADFind/Rubeus)", technique: "T1087.002",
    logic: [{ label: "Process", value: "regex: ^(adfind|sharphound|bloodhound|sharpview|seatbelt|rubeus|certify|certipy)(\\.exe)?$" }, { label: "Condition", value: "Process name matches known Active Directory enumeration tools" }],
    test: (c) => AD_RECON_TOOLS.test(c.n) },
  { id: "pi-23", group: "discovery", level: 2, reason: "Built-in AD recon", tid: ["T1087.002", "T1482"], beh: "recon",
    sev: "high", name: "Built-in AD Recon (nltest/dsquery/setspn/whoami/net)", technique: "T1087.002, T1482",
    logic: [
      { label: "High", value: "nltest /dclist/domain_trusts/dsgetdc, dsquery, setspn -T/-Q/-F" },
      { label: "Medium", value: "net group/user /domain, whoami /groups/priv/all, wmic useraccount/group, klist" },
      { label: "Condition", value: "Native Windows commands commonly used for domain enumeration in early intrusion stages" },
    ],
    test: (c) => {
      if (_RX_NLTEST_RECON.test(c.cmd)) return true;
      if (_RX_DSQUERY_NAME.test(c.n)) return { override: 1, cat: "context" };
      if (_RX_SETSPN_RECON.test(c.cmd)) return true;
      if (_RX_NET_DOMAIN_QUERY.test(c.cmd)) return { override: 1, cat: "context" };
      if (_RX_WHOAMI_PRIV.test(c.cmd)) return { override: 1, cat: "context" };
      if (_RX_KLIST_NAME.test(c.n)) return { override: 0, cat: "context" };
      if (_RX_WMIC_LOCAL_RECON.test(c.cmd) && !_RX_WMIC_NODE.test(c.cmd)) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-11", group: "discovery", level: 2, reason: "Network scanner", tid: ["T1046"], beh: "recon",
    sev: "high", name: "Network Scanners (netscan/masscan/rustscan)", technique: "T1046",
    logic: [{ label: "Process", value: "regex: ^(netscan|netscan64|advanced_ip_scanner|rustscan|masscan|angry_ip_scanner|nbtscan)(\\.exe)?$" }, { label: "Condition", value: "Process name matches known network scanning tools" }],
    test: (c) => NETWORK_SCANNERS.test(c.n) },
  { id: "pi-13", group: "rmm", level: 2, reason: "Exfiltration tool", tid: ["T1567"], beh: "exfil",
    sev: "high", name: "Exfiltration Tools (rclone/WinSCP/MegaSync)", technique: "T1567",
    logic: [{ label: "Process", value: "regex: ^(rclone|filezilla|winscp|megasync|megacmd)(\\.exe)?$" }, { label: "Condition", value: "rclone/megasync are high; FileZilla/WinSCP are dual-use admin clients → context unless run from a writable path or by a shell" }],
    test: (c) => {
      if (!EXFIL_TOOLS.test(c.n)) return false;
      // FileZilla/WinSCP are mainstream SFTP/FTP clients used by admins/devs daily — presence
      // alone is not exfiltration. Demote to context unless launched from a user-writable path
      // or by a shell (the staged-exfil shape). rclone/megasync/megacmd stay high.
      if (/^(filezilla|winscp)(\.exe)?$/i.test(c.n) && !_RX_USER_WRITABLE_EXTENDED.test(c.il) && !_RX_SHELL_PARENTS.test(c.pn)) return { override: 0, cat: "context" };
      return true;
    } },
  { id: "pi-12", group: "rmm", level: 2, reason: "RMM tool \u2014 suspicious context", tid: ["T1219"], beh: "rmm",
    sev: "high", name: "RMM Tools \u2014 Unusual Parent (AnyDesk/TeamViewer/RustDesk)", technique: "T1219",
    logic: [
      { label: "Process", value: "regex: ^(anydesk|splashtop|rustdesk|atera|screenconnect|teamviewer|supremo)(\\.exe)?$" },
      { label: "Parent", value: "NOT explorer.exe (unusual parent = potentially injected or staged)" },
      { label: "Condition", value: "RMM tool launched from non-standard parent process" },
    ],
    test: (c) => {
      if (!RMM_TOOLS.test(c.n)) return false;
      if (_isMgmtDiscountParent(c.pn)) return { override: 1, cat: "context" };
      // Service-installed RMM is the legitimate MSP deployment pattern: the agent runs as a
      // Windows service, so its parent is services.exe/svchost.exe and it often installs to a
      // writable dir (ProgramData/AppData). Threat-actor RMM abuse launches from a shell/
      // explorer or sideloads — not from the service host. Treat service-parented RMM as
      // context so it doesn't flood HIGH findings on every managed endpoint.
      if (/^(services|svchost)(\.exe)?$/i.test(c.pn)) return { override: 1, cat: "context" };
      if (_RX_SHELL_PARENTS.test(c.pn)) return true;
      if (_RX_USER_WRITABLE.test(c.img)) return true;
      if (c.pn && !_RX_PROG_FILES.test(c.img) && !_RX_EXPLORER_SVCHOST.test(c.pn)) return true;
      return false;
    } },
  { id: "pi-24", group: "rmm", level: 2, reason: "Tunnel/proxy/reverse forward", tid: ["T1572", "T1090"], beh: "rmm",
    sev: "high", name: "Tunnel/Proxy/Reverse Forward (cloudflared/plink/ssh/chisel/ngrok)", technique: "T1572, T1090",
    logic: [
      { label: "Process", value: "cloudflared tunnel, plink -R/-L/-D, ssh -R/-L/-D, frp/frpc, chisel, ngrok" },
      { label: "CommandLine", value: "Also detects tunnel commands embedded in other process command lines" },
      { label: "Condition", value: "Port forwarding and tunneling tools commonly used for persistent C2 access" },
    ],
    test: (c) => {
      if (_RX_CLOUDFLARED_NAME.test(c.n) && /\btunnel\b/i.test(c.cmd)) return true;
      if (_RX_PLINK_NAME.test(c.n) && _RX_TUNNEL_RING_FLAGS.test(c.cmd)) return true;
      if (_RX_SSH_NAME.test(c.n) && _RX_TUNNEL_RING_FLAGS.test(c.cmd)) return true;
      if (_RX_PROXY_NAMES.test(c.n) && _RX_TUNNEL_VERBS.test(c.cmd)) return true;
      if (_RX_TUNNEL_FULL_CMD.test(c.cmd)) return true;
      // The canonical catalogue. TUNNEL_TOOLS was derived from tool-aliases.js and
      // exported, but nothing ever imported it — so every tunnel name that was not
      // in the four hardcoded regexes above (ligolo, gost, nps/npc, iox, revsocks,
      // EarthWorm, Stowaway, socat, and every Go release-artifact filename such as
      // frpc_windows_amd64.exe) was invisible.
      if (TUNNEL_TOOLS.test(c.n)) return true;
      // The tunnel may also be established by a native binary: netsh portproxy is
      // the built-in equivalent and needs no dropped tool at all.
      if (/\bnetsh\b[\s\S]*\bportproxy\b[\s\S]*\b(add|set)\b/i.test(c.cmd)) return true;
      return false;
    } },
  { id: "pi-25", group: "evasion", level: 2, reason: "PowerShell stealth flag combo", tid: ["T1059.001", "T1027"], beh: "script-exec",
    sev: "critical", name: "PowerShell Stealth Flag Combo", technique: "T1059.001, T1027",
    logic: [
      { label: "Process", value: "powershell.exe OR pwsh.exe" },
      { label: "Critical", value: "Encoded command + any stealth/cradle indicator (-w hidden, -nop, -ep bypass, IEX/Base64)" },
      { label: "High", value: "No encoded command: requires cradle + 2 stealth flags + shell/script parent" },
      { label: "Condition", value: "Tuned to avoid alerting on single admin-style PowerShell flags" },
    ],
    test: (c) => {
      if (!_RX_PS_NAME.test(c.n)) return false;
      const hasEncoded = _RX_PS_ENCODED_FLAG.test(c.cmd);
      const hasHidden = _RX_PS_HIDDEN_FLAG.test(c.cmd);
      const hasNoProfile = _RX_PS_NOPROFILE_FLAG.test(c.cmd);
      const hasBypass = _RX_PS_BYPASS_FLAG.test(c.cmd);
      const hasCradle = _RX_PS_CRADLE_SHORT.test(c.cmd);
      if (hasEncoded && (hasHidden || hasNoProfile || hasBypass || hasCradle)) return { override: 3 };
      const stealthCount = (hasHidden ? 1 : 0) + (hasNoProfile ? 1 : 0) + (hasBypass ? 1 : 0);
      // Parent gate: shell/script parents, services.exe (planted persistence), and
      // management parents are all valid origins for stealth+cradle combos.
      if (!hasEncoded && hasCradle && stealthCount >= 2 &&
        (_RX_SHELL_PARENTS.test(c.pn) || _RX_SERVICES_NAME.test(c.pn) || _RX_MGMT_PARENTS.test(c.pn))) return true;
      return false;
    } },
  { id: "pi-26", group: "persist", level: 2, reason: "Service-launched binary from writable path", tid: ["T1543.003"], beh: "service-exec",
    sev: "critical", name: "Service Child from Writable Path", technique: "T1543.003",
    logic: [
      { label: "Parent", value: "services.exe" },
      { label: "Critical", value: "Shell/LOLBin child (cmd/powershell/mshta/rundll32/regsvr32/wscript/cscript) in Temp/Tmp/AppData/Downloads/Public" },
      { label: "Context", value: "Non-shell binaries in writable path are treated as low-confidence context only" },
    ],
    test: (c) => {
      if (!_RX_SERVICES_NAME.test(c.pn)) return false;
      // \ProgramData\ is writable by BUILTIN\Users on a default install and is the
      // classic drop location for a planted service binary; the old path set left it
      // out entirely, so services.exe -> C:\ProgramData\<random>\svc.exe scored zero.
      // Vendor subdirectories under ProgramData are excluded (agents legitimately
      // run their service binaries from there).
      const writable = _RX_USER_WRITABLE.test(c.il) && !BENIGN_INSTALL_PATH.test(c.ilc || c.il);
      if (!writable) return false;
      if (_RX_SHELL_CHILDREN.test(c.n)) return { override: 3 };
      return { override: 1, cat: "context" };
    } },
  { id: "pi-27", group: "evasion", level: 3, reason: "svchost path anomaly", tid: ["T1036"], beh: "service-exec",
    sev: "critical", name: "svchost Path Anomaly", technique: "T1036",
    logic: [
      { label: "Process", value: "svchost.exe" },
      { label: "Image Path", value: "NOT \\Windows\\System32\\svchost.exe or \\Windows\\SysWOW64\\svchost.exe" },
      { label: "Condition", value: "Masqueraded svchost binary path" },
    ],
    test: (c) => {
      if (!_RX_SVCHOST_NAME.test(c.n)) return false;
      if (!c.ilc || !c.ilc.includes("\\")) return false;
      // The SAME anchor pi-46 uses. These two rules previously carried different
      // regexes — pi-27 additionally required a literal "\windows\" segment — so a
      // \SystemRoot\System32\svchost.exe fired one and not the other.
      const expected = _EXPECTED_SYSTEM_PATHS.get("svchost");
      if (expected.test(c.ilc)) return false;
      return { override: 3 };
    } },
  { id: "pi-28", group: "lateral", level: 2, reason: "WMI provider spawning shell/proxy", tid: ["T1047", "T1021"], beh: "lateral",
    sev: "high", name: "WMI Provider Spawning Shell/Proxy", technique: "T1047, T1021",
    logic: [
      { label: "Parent", value: "wmiprvse.exe" },
      { label: "Children", value: "cmd/powershell/wscript/cscript/mshta/rundll32/regsvr32" },
      { label: "Critical", value: "Command line includes /node, WinRM, Invoke-Command, PSSession, or UNC remote path" },
      { label: "Context", value: "Without remote indicators, treated as low-confidence context only" },
    ],
    test: (c) => {
      if (!_RX_WMIPRVSE_NAME.test(c.pn)) return false;
      if (!_RX_SHELL_CHILDREN.test(c.n)) return false;
      if (_RX_WMI_LATERAL_INDICATORS.test(c.cmd)) return { override: 3 };
      return { override: 1, cat: "context" };
    } },
  { id: "pi-29", group: "cred", level: 3, reason: "LSASS dump commandline pattern", tid: ["T1003.001"], beh: "cred",
    sev: "critical", name: "Explicit LSASS Dump Commandline", technique: "T1003.001",
    logic: [{ label: "Patterns", value: "rundll32 ... comsvcs.dll,MiniDump ... lsass OR procdump ... lsass" }, { label: "Condition", value: "Direct command-line dump semantics, low ambiguity" }],
    test: (c) => {
      if (_RX_LSASS_RUNDLL.test(c.cmd)) return { override: 3 };
      if (_RX_LSASS_PROCDUMP.test(c.cmd)) {
        // procdump is a legit Sysinternals tool patch/config agents deploy for crash diagnostics,
        // so downgrade under config-management parents — but NOT under remote-access RMM, where
        // procdump against lsass is hands-on-keyboard credential theft.
        if (_isMgmtDiscountParent(c.pn)) return { override: 1, cat: "context" };
        return { override: 3 };
      }
      return false;
    } },
  { id: "pi-30", group: "exec", level: 2, reason: "Office child with staged payload indicators", tid: ["T1204.002", "T1218"], beh: "shell-exec",
    sev: "critical", name: "Office Child + Staged Payload Indicators", technique: "T1204.002, T1218",
    logic: [
      { label: "Parent", value: "Office app (Word/Excel/PPT/Outlook/OneNote/Access/Publisher)" },
      { label: "Child", value: "Shell/LOLBin child (cmd/powershell/mshta/rundll32/regsvr32/wscript/cscript)" },
      { label: "Condition", value: "Only fires when cmdline has URL/scriptlet/base64/download cradle indicators" },
    ],
    test: (c) => {
      if (!_RX_OFFICE_PARENTS.test(c.pn) || !_RX_SHELL_CHILDREN.test(c.n)) return false;
      if (_RX_OFFICE_STAGED.test(c.cmd)) return { override: 3 };
      return false;
    } },
  // --- New technique families ---
  { id: "pi-31", group: "evasion", level: 2, reason: "DLL sideload from non-system path", tid: ["T1574.002"], beh: "lolbin-exec",
    sev: "high", name: "DLL Sideload (rundll32/regsvr32 outside System32)", technique: "T1574.002",
    logic: [
      { label: "Process", value: "rundll32.exe OR regsvr32.exe" },
      { label: "Condition", value: "Command line references a .dll/.ocx NOT under \\Windows\\System32, SysWOW64, or WinSxS" },
      { label: "High", value: "DLL in user-writable or UNC path" },
      { label: "Context", value: "DLL under \\Program Files treated as low-confidence context" },
    ],
    test: (c) => {
      if (!_RX_DLL_LOADER_NAME.test(c.n)) return false;
      if (!_RX_DLL_EXT.test(c.cmd)) return false;
      if (_RX_SYSTEM_DLL_PATH.test(c.cmd)) return false; // legit system DLL
      // Sideloading needs a MODULE PATH. A bare module name — `rundll32
      // shell32.dll,Control_RunDLL desk.cpl`, `regsvr32 /s scrobj.dll` — resolves
      // through the normal search order out of System32, but matched "any other
      // non-system path" below and scored high on some of the most common command
      // lines on Windows. Require an actual directory reference before judging it.
      const _dllRef = (c.cmd.match(/(?:[a-z]:[\\/]|\\\\|%\w+%[\\/]|\.[\\/])[^",;]*?\.(dll|ocx)\b/i) || [])[0] || "";
      if (!_dllRef) return false;
      if (_RX_SYSTEM_DLL_PATH.test(_dllRef)) return false;
      // DLL in user-writable or UNC path = high confidence
      if ((_RX_USER_WRITABLE.test(_dllRef) && !BENIGN_INSTALL_PATH.test(_dllRef)) || _RX_UNC_PATH.test(_dllRef)) return true;
      // DLL somewhere else (e.g. Program Files) = context only
      if (_RX_PROG_FILES.test(_dllRef) || BENIGN_INSTALL_PATH.test(_dllRef)) return { override: 1, cat: "context" };
      // Any other non-system path
      return true;
    } },
  { id: "pi-32", group: "cred", level: 3, reason: "SAM/SECURITY hive copy", tid: ["T1003.002"], beh: "cred",
    sev: "critical", name: "SAM/SECURITY Hive Copy (reg save / esentutl)", technique: "T1003.002",
    logic: [
      { label: "Critical", value: "reg save HKLM\\SAM, reg save HKLM\\SECURITY, reg save HKLM\\SYSTEM" },
      { label: "High", value: "esentutl /y targeting SAM, SECURITY, SYSTEM, or ntds.dit" },
      { label: "High", value: "ntdsutil snapshot (shadow copy for offline extraction)" },
      { label: "Condition", value: "Direct registry hive extraction for offline cracking" },
    ],
    test: (c) => {
      if (_RX_REG_SAVE_HIVE.test(c.cmd)) return { override: 3 };
      if (_RX_ESENTUTL_COPY.test(c.cmd) && _RX_HIVE_TARGETS.test(c.cmd)) return true;
      if (_RX_NTDSUTIL_SNAPSHOT.test(c.cmd)) return true;
      return false;
    } },
  { id: "pi-33", group: "cred", level: 2, reason: "Token theft / impersonation", tid: ["T1134.001", "T1134.003"], beh: "cred",
    sev: "high", name: "Token Theft / Impersonation (runas /netonly, mavinject)", technique: "T1134.001, T1134.003",
    logic: [
      { label: "Critical", value: "mavinject /INJECTRUNNING (signed MS binary used for DLL injection into running process)" },
      { label: "High", value: "runas /netonly (creates process with stolen network credentials)" },
      { label: "High", value: "Known token manipulation tools: incognito, getsystem, tokenvator, SharpImpersonation" },
      { label: "High", value: "PowerShell token cmdlets: Invoke-TokenManipulation, Get-System, Invoke-RunasCs" },
    ],
    test: (c) => {
      // mavinject.exe /INJECTRUNNING — signed MS binary, always suspicious
      if (_RX_MAVINJECT_NAME.test(c.n) && _RX_MAVINJECT_INJECT.test(c.cmd)) return { override: 3 };
      // runas /netonly — creates process with stolen network credentials
      if (_RX_RUNAS_NETONLY.test(c.cmd)) return true;
      // Dedicated token theft tools
      if (_RX_TOKEN_TOOLS.test(c.n)) return true;
      // PowerShell token manipulation cmdlets
      if (_RX_PS_TOKEN_MANIP.test(c.cmd)) return true;
      return false;
    } },
  // --- Binary trust rules ---
  { id: "pi-34", group: "trust", level: 2, reason: "Renamed LOLBin (OriginalFileName mismatch)", tid: ["T1036.003"], beh: "evasion",
    sev: "critical", name: "Renamed LOLBin (OriginalFileName \u2260 ProcessName)", technique: "T1036.003",
    logic: [
      { label: "Condition", value: "PE OriginalFileName is a known LOLBin but the actual process name differs" },
      { label: "Critical", value: "OriginalFileName is powershell/cmd and current name doesn\u2019t match" },
      { label: "High", value: "Any other LOLBin rename" },
    ],
    test: (c) => {
      if (!c.origFn) return false;
      if (c.origFn === c.n.replace(/\.exe$/i, "")) return false; // names match — no rename
      if (!_RX_LOLBIN_ORIG_NAMES.test(c.origFn)) return false;
      // Critical: renamed powershell or cmd
      if (/^(cmd|powershell|pwsh)$/.test(c.origFn)) return { override: 3 };
      return true;
    } },
  { id: "pi-35", group: "trust", level: 1, reason: "Unsigned binary in trusted path", cat: "context", tid: ["T1036.005"], beh: "evasion",
    sev: "medium", name: "Unsigned Binary in Trusted Path", technique: "T1036.005",
    logic: [
      { label: "Condition", value: "Binary is explicitly unsigned (Signed=false) but lives under Program Files or Windows directory" },
      { label: "Why It Matters", value: "Corroborating context only — many legitimate third-party apps and drivers ship unsigned helpers under Program Files, so this elevates a node only alongside a primary finding (never fires on missing/unknown signature metadata)" },
    ],
    test: (c) => {
      if (c.signed !== "false") return false; // explicit false only — missing metadata never fires
      if (!_isUnderTrustedRoot(c.ilc)) return false;
      return true;
    } },
  { id: "pi-36", group: "trust", level: 2, reason: "Expired/revoked/invalid signature", tid: ["T1553.002"], beh: "evasion",
    sev: "high", name: "Expired/Revoked/Invalid Signature", technique: "T1553.002",
    logic: [
      { label: "Condition", value: "SignatureStatus is expired, revoked, invalid, or error" },
    ],
    test: (c) => {
      if (!c.sigStatus) return false;
      // Genuine tamper indicators stay HIGH.
      if (/^(revoked|invalid)$/i.test(c.sigStatus)) return true;
      // Expired/error/broken/unavailable are overwhelmingly benign legacy/3rd-party software —
      // record as context so they corroborate but don't dominate triage. 'notsigned' is owned by pi-35.
      if (/^(expired|error|broken|unavailable)$/i.test(c.sigStatus)) return { override: 0, cat: "context" };
      return false;
    } },
  { id: "pi-37", group: "trust", level: 2, reason: "Signer mismatch for known binary", tid: ["T1553.002"], beh: "evasion",
    sev: "high", name: "Signer Mismatch for Known Binary", technique: "T1553.002",
    logic: [
      { label: "Condition", value: "Signer field is non-empty but doesn\u2019t match the expected publisher for the binary name" },
      { label: "Map", value: "svchost/cmd/powershell/rundll32 \u2192 Microsoft, chrome \u2192 Google, firefox \u2192 Mozilla, etc." },
    ],
    test: (c) => {
      // Need a real signer string (4688/EvtxECmd often truncate or omit it → length guard).
      if (!c.signer || c.signer.length <= 3) return false;
      const baseName = c.origFn || c.n.replace(/\.exe$/i, "");
      // Only core OS binaries — a 3rd-party app legitimately carries its own publisher.
      if (!_RX_PI_CORE_OS.test(baseName)) return false;
      // A bad/expired/unavailable signature is pi-36's job; pi-37 is specifically a VALID
      // signature whose publisher is wrong (the masquerade signal).
      if (c.sigStatus && _RX_SIG_BAD.test(c.sigStatus)) return false;
      const expected = _EXPECTED_SIGNERS.get(baseName);
      if (!expected) return false;
      if (c.signer.includes(expected)) return false; // signer contains expected publisher
      return true;
    } },
  { id: "pi-56", group: "trust", level: 2, reason: "Cross-host hash mismatch for same image path", tid: ["T1036.005", "T1553.002"], beh: "binary-trust",
    sev: "high", name: "Same Image Path, Different Hashes Across Hosts", technique: "T1036.005, T1553.002",
    logic: [
      { label: "Condition", value: "The same normalized image path appears on multiple hosts with more than one executable hash" },
      { label: "Why It Matters", value: "Useful for spotting binary substitution, compromised update paths, or version drift that needs analyst review" },
      { label: "Critical", value: "Raised when the mismatch occurs under Windows or Program Files paths where hash divergence is more sensitive" },
    ],
    test: () => false },
  { id: "pi-57", group: "trust", level: 2, reason: "Same process name from unusual path", tid: ["T1036.005"], beh: "binary-trust",
    sev: "high", name: "Same Process Name from Rare or Writable Path", technique: "T1036.005",
    logic: [
      { label: "Condition", value: "A process name appears repeatedly in the dataset, but one instance executes from a rare path, especially user-writable locations" },
      { label: "Why It Matters", value: "Helps find renamed droppers or lookalike tools that blend in by borrowing a common process name" },
    ],
    test: () => false },
  // --- Lifetime anomaly rules ---
  { id: "pi-38", group: "lifetime", level: 1, reason: "Extremely short-lived process", tid: ["T1059"], beh: "lifetime-short", cat: "context",
    sev: "low", name: "Extremely Short-Lived Process (<2s)", technique: "T1059",
    logic: [
      { label: "Condition", value: "Process duration < 2 seconds AND not a known short-lived system / installer process" },
      { label: "Note", value: "Corroborating context only — a brief lifetime alone (one-shot commands, installers) is not suspicious; it elevates a node only alongside a primary finding" },
    ],
    test: (c) => {
      if (!Number.isFinite(c.dur) || c.dur >= 2000) return false;
      const base = c.n.replace(/\.exe$/i, "");
      // Known transient system hosts, plus installers/updaters/housekeeping (SAFE_PROCS) that
      // legitimately spin up and exit in well under 2s.
      if (_RX_SHORT_LIVED_SAFE.test(base) || SAFE_PROCS.test(c.n)) return false;
      // Short lifetime is weak on its own. Surface it as context (visible, correlates via the
      // sequence/cluster engine) instead of an auto-HIGH that floods on every quick command.
      return { override: 0, cat: "context" };
    } },
  { id: "pi-39", group: "lifetime", level: 1, reason: "No termination for offensive tool", tid: ["T1059"], beh: "lifetime-missing", cat: "context",
    sev: "medium", name: "No Termination Observed for Offensive Tool", technique: "T1059",
    logic: [
      { label: "Condition", value: "Known offensive tool has no matching terminate event \u2014 possible crash, kill, or log gap" },
      { label: "Tools", value: "AD recon, network scanners, LSASS tools, exfil tools, credential dump commands" },
    ],
    test: (c) => {
      // Only meaningful when the dataset actually records terminations somewhere — otherwise
      // every process has NaN duration and this would fire on every offensive tool by default.
      if (!c.datasetHasTermination) return false;
      if (Number.isFinite(c.dur)) return false; // has termination — not applicable
      // Only flag known offensive tools
      if (AD_RECON_TOOLS.test(c.n) || NETWORK_SCANNERS.test(c.n) || LSASS_TOOLS.test(c.n) || EXFIL_TOOLS.test(c.n)) return true;
      return false;
    } },
  { id: "pi-53", group: "lifetime", level: 2, reason: "Repeated short-lived process respawns", tid: ["T1059"], beh: "lifetime-respawn",
    sev: "high", name: "Repeated Short-Lived Respawns", technique: "T1059",
    logic: [
      { label: "Condition", value: "Same process name on the same host starts 4+ times inside a 10-minute window and each instance exits within 5 seconds" },
      { label: "Why It Matters", value: "Short respawn bursts can indicate failed payload execution, watchdog behavior, script loops, or crash/retry activity worth triage" },
    ],
    test: () => false },
  // --- High-value gap rules ---
  { id: "pi-40", group: "persist", level: 2, reason: "Task/service host launched payload from writable path", tid: ["T1053.005", "T1543.003"], beh: "service-exec",
    sev: "high", name: "Task/Service Host Payload from Writable Path", technique: "T1053.005, T1543.003",
    logic: [
      { label: "Parent", value: "taskhostw, taskeng, svchost, services, wmiprvse" },
      { label: "Condition", value: "Child binary image lives in a user-writable path (\u2014 not a known shell/LOLBin, which pi-26 covers)" },
      { label: "High", value: "Non-shell binary executed from Temp/AppData/Downloads/Public by task or service host" },
      { label: "Rationale", value: "Catches the actual malware payload running via scheduled task or service, not just the creation command" },
    ],
    test: (c) => {
      if (!_RX_TASK_SERVICE_PARENTS.test(c.pn)) return false;
      if (!_RX_USER_WRITABLE.test(c.il)) return false;
      // pi-26 already covers services.exe → shell children from writable path.
      // This rule catches non-shell binaries from task/service hosts.
      if (_RX_SHELL_CHILDREN.test(c.n)) return false;
      return true;
    } },
  { id: "pi-41", group: "exec", level: 2, reason: "Browser spawned shell or script engine", tid: ["T1189", "T1059"], beh: "shell-exec",
    sev: "critical", name: "Browser \u2192 Shell/Script (drive-by / exploit indicator)", technique: "T1189, T1059",
    logic: [
      { label: "Parent", value: "chrome, msedge, firefox, iexplore, opera, brave, safari" },
      { label: "Children", value: "cmd, powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32" },
      { label: "Critical", value: "If child command line contains download cradle, encoded command, or network URL" },
      { label: "High", value: "Any shell/script child from browser without staged payload indicators" },
    ],
    test: (c) => {
      if (!_RX_BROWSER_PARENTS.test(c.pn)) return false;
      if (!_RX_SHELL_CHILDREN.test(c.n)) return false;
      // Upgrade to critical if command line has staged payload indicators
      if (_RX_OFFICE_STAGED.test(c.cmd) || ENCODED_PS.test(c.cmd) || _RX_HTTP_URL.test(c.cmd)) return { override: 3 };
      return true;
    } },
  { id: "pi-42", group: "persist", level: 3, reason: "BITS job persistence via SetNotifyCmdLine", tid: ["T1197"], beh: "persist",
    sev: "critical", name: "BITS Persistence (SetNotifyCmdLine callback)", technique: "T1197",
    logic: [
      { label: "Critical", value: "bitsadmin /SetNotifyCmdLine — registers a program to execute when a BITS job completes" },
      { label: "Condition", value: "This is a persistence vector, not a download: the callback survives reboots" },
      { label: "Context", value: "bitsadmin /addfile + /resume without SetNotifyCmdLine is covered by pi-22 as download" },
    ],
    test: (c) => {
      if (_RX_BITS_PERSIST.test(c.cmd)) return { override: 3 };
      return false;
    } },
  { id: "pi-43", group: "evasion", level: 2, reason: "PowerShell inline C# compilation / Add-Type abuse", tid: ["T1059.001", "T1027.004"], beh: "script-exec",
    sev: "critical", name: "PowerShell Add-Type / Inline C# Compilation", technique: "T1059.001, T1027.004",
    logic: [
      { label: "Critical", value: "Add-Type -TypeDefinition with DllImport, Marshal, VirtualAlloc, OpenProcess, or WriteProcessMemory" },
      { label: "High", value: "Add-Type -TypeDefinition or -MemberDefinition without obvious interop (may be benign tooling)" },
      { label: "Condition", value: "Detects runtime C# compilation used for AMSI bypass, process injection setup, and P/Invoke abuse" },
    ],
    test: (c) => {
      if (!_RX_PS_NAME.test(c.n)) return false;
      const hasAddType = _RX_PS_ADDTYPE.test(c.cmd) || _RX_PS_ADDTYPE_MEMBER.test(c.cmd);
      if (!hasAddType) return false;
      // Critical: Add-Type with interop signatures (injection/P-Invoke setup)
      if (_RX_PS_INLINE_INTEROP.test(c.cmd)) return { override: 3 };
      return true;
    } },
  { id: "pi-44", group: "persist", level: 2, reason: "WMI persistence execution host", tid: ["T1546.003"], beh: "persist",
    sev: "high", name: "WMI Persistence Execution (mofcomp / scrcons)", technique: "T1546.003",
    logic: [
      { label: "Process", value: "mofcomp.exe — MOF compiler, used to install WMI event subscriptions" },
      { label: "Process", value: "scrcons.exe — WMI script consumer host, executes scripts registered via WMI subscriptions" },
      { label: "High", value: "mofcomp loading a .mof file (installing a WMI subscription)" },
      { label: "Context", value: "scrcons.exe executing — fires when any WMI event consumer runs, including legitimate monitoring/management subscriptions, so on its own it is corroborating context" },
    ],
    test: (c) => {
      if (_RX_MOFCOMP_NAME.test(c.n) && /\.mof\b/i.test(c.cmd)) return true;
      // scrcons hosts WMI script consumers; legitimate management agents use these too, so a bare
      // scrcons launch is context (it correlates with a malicious consumer payload elsewhere).
      if (_RX_SCRCONS_NAME.test(c.n)) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-45", group: "evasion", level: 3, reason: "PowerShell process injection pattern", tid: ["T1055.001", "T1055.003", "T1055.004"], beh: "evasion",
    sev: "critical", name: "PowerShell Process Injection (VirtualAlloc / CreateRemoteThread / shellcode)", technique: "T1055.001, T1055.003",
    logic: [
      { label: "Critical", value: "Win32 API calls: VirtualAlloc(Ex), WriteProcessMemory, CreateRemoteThread, NtCreateThreadEx, QueueUserAPC" },
      { label: "Critical", value: "Known injection frameworks: Invoke-Shellcode, Invoke-ReflectivePEInjection, Invoke-DllInjection" },
      { label: "Critical", value: "P/Invoke delegation: Marshal::Copy + GetDelegateForFunctionPointer + VirtualAlloc" },
      { label: "Condition", value: "Any of these in a PowerShell command line is near-certain injection activity" },
    ],
    test: (c) => {
      if (!_RX_PS_NAME.test(c.n)) return false;
      if (_RX_PS_INJECTION.test(c.cmd)) return { override: 3 };
      if (_RX_PS_SHELLCODE.test(c.cmd)) return { override: 3 };
      if (_RX_PS_PINVOKE.test(c.cmd)) return { override: 3 };
      return false;
    } },
  { id: "pi-46", group: "trust", level: 3, reason: "System binary in unexpected path", tid: ["T1036.005"], beh: "evasion",
    sev: "critical", name: "System Binary Masquerading (Image Path Anomaly)", technique: "T1036.005",
    logic: [
      { label: "Condition", value: "Process name matches a critical Windows binary (svchost/lsass/explorer/rundll32/etc.) but the image path does not match the expected System32/SysWOW64/Windows location" },
      { label: "Critical", value: "Near-certain masquerading \u2014 legitimate system binaries never run from user-writable locations" },
      { label: "Caveat", value: "Skipped when image path is missing (dataset lacks full path) to avoid noise on Security 4688 without ParentImage" },
    ],
    test: (c) => {
      const baseName = c.n.replace(/\.exe$/i, "");
      // svchost is also covered by the dedicated pi-27. Both are kept (they carry
      // different behaviours and technique tags) but they now share ONE anchor, so
      // they can no longer return different verdicts for the same path.
      const expected = _EXPECTED_SYSTEM_PATHS.get(baseName);
      if (!expected) return false;
      if (!c.ilc) return false;
      // Compared against the canonicalised path (see _canonImagePath), so NT,
      // device, \SystemRoot and forward-slash renderings are not read as anomalies.
      return !expected.test(c.ilc);
    } },
  { id: "pi-47", group: "evasion", level: 3, reason: "Process access with injection-like rights", tid: ["T1055"], beh: "evasion",
    sev: "critical", name: "Target of ProcessAccess with VM_WRITE / Full Access (EID 10)", technique: "T1055",
    logic: [
      { label: "Condition", value: "Backend matched Sysmon EID 10 events targeting this process with GrantedAccess granting memory write (0x20), VM_OPERATION+VM_WRITE (0x28), or full access (0x1F0FFF)" },
      { label: "Critical", value: "Two or more suspicious access events \u2014 sustained injection attempts" },
      { label: "High", value: "One suspicious access event \u2014 possible reconnaissance or single-shot injection" },
    ],
    test: (c) => {
      if (!c.injection) return false;
      if (!c.injection.suspiciousAccessCount) return false;
      if (c.injection.suspiciousAccessCount >= 2) return { override: 3 };
      return { override: 2 };
    } },
  { id: "pi-48", group: "evasion", level: 3, reason: "Possible process hollowing (early-lifetime injection-like access)", tid: ["T1055.012"], beh: "evasion",
    sev: "critical", name: "Process Hollowing Indicator (EID 10 within 500ms of creation)", technique: "T1055.012",
    logic: [
      { label: "Condition", value: "Target received an EID 10 ProcessAccess event with injection-like GrantedAccess within 500ms of its own creation timestamp" },
      { label: "Critical", value: "Pattern consistent with CreateProcess(SUSPENDED) \u2192 VM_WRITE \u2192 SetThreadContext \u2192 ResumeThread hollowing chain" },
      { label: "Caveat", value: "Requires Sysmon EID 1 + EID 10 in the dataset. Absent when only Security 4688 is available" },
    ],
    test: (c) => {
      if (!c.injection) return false;
      if (!c.injection.hollowingLikely) return false;
      return { override: 3 };
    } },
  { id: "pi-50", group: "cred", level: 2, reason: "SeDebugPrivilege invoked (injection primitive)", tid: ["T1134.001"], beh: "cred",
    sev: "high", name: "SeDebugPrivilege Invoked (EID 4673 / 4674)", technique: "T1134.001",
    logic: [
      { label: "Condition", value: "Backend matched a Security 4673/4674 event on this process whose PrivilegeList includes SeDebugPrivilege" },
      { label: "Context", value: "SeDebug lets a process open any other process for memory read/write \u2014 the prerequisite for cross-process injection and credential dumping from lsass" },
      { label: "Critical", value: "Upgrade when the same process also has EID 10 injection indicators OR a PowerShell injection cmdline pattern \u2014 priv use + injection capability = confirmed" },
      { label: "Caveat", value: "Sysmon / legitimate services (lsass, ServiceControlManager) naturally use SeDebug \u2014 default level 2 keeps this evidence visible without dominating" },
    ],
    test: (c) => {
      if (!c.privilege) return false;
      const count = c.privilege.privileges?.sedebugprivilege || 0;
      if (count === 0) return false;
      if ((c.injection?.suspiciousAccessCount || 0) >= 1) return { override: 3 };
      if (_RX_PS_INJECTION.test(c.cmd) || _RX_PS_SHELLCODE.test(c.cmd) || _RX_PS_PINVOKE.test(c.cmd)) return { override: 3 };
      return true;
    } },
  { id: "pi-51", group: "evasion", level: 3, reason: "SeLoadDriverPrivilege invoked (driver sideload)", tid: ["T1068", "T1543.003"], beh: "evasion",
    sev: "critical", name: "SeLoadDriverPrivilege Invoked (EID 4673 / 4674)", technique: "T1068",
    logic: [
      { label: "Condition", value: "Security 4673/4674 event shows this process invoking SeLoadDriverPrivilege \u2014 the OS prerequisite for loading a kernel driver" },
      { label: "Critical", value: "Primary indicator of Bring-Your-Own-Vulnerable-Driver (BYOVD) attacks \u2014 a non-system process using this privilege is highly suspicious" },
      { label: "Context", value: "Legitimate use is rare and confined to specific service contexts (Plug and Play, kernel debuggers). Any invocation deserves triage" },
    ],
    test: (c) => {
      if (!c.privilege) return false;
      const count = c.privilege.privileges?.seloaddriverprivilege || 0;
      return count > 0 ? { override: 3 } : false;
    } },
  { id: "pi-52", group: "cred", level: 3, reason: "Multiple high-risk privileges concentrated in one process", tid: ["T1134"], beh: "cred",
    sev: "critical", name: "Privilege Concentration (3+ high-risk privileges invoked)", technique: "T1134",
    logic: [
      { label: "Condition", value: "Single process invoked 3+ DISTINCT high-risk privileges across its 4673/4674 events (SeDebug, SeTcb, SeImpersonate, SeAssignPrimaryToken, SeLoadDriver, SeCreateToken, SeTakeOwnership, SeBackup, SeRestore)" },
      { label: "Critical", value: "Concentrated privilege use is a strong post-exploitation signal \u2014 legitimate services use 1\u20132 privileges; attacker tooling (elevators, token stealers, rootkit loaders) often touches many" },
    ],
    test: (c) => {
      if (!c.privilege) return false;
      if ((c.privilege.uniqueHighRisk || 0) >= 3) return { override: 3 };
      return false;
    } },
  { id: "pi-49", group: "trust", level: 0, cat: "context", reason: "Parent link disagreement (reported vs. linked parent)", tid: [], beh: "evasion",
    sev: "info", name: "Parent Link Disagreement (reported ParentImage \u2260 linked parent)", technique: "",
    logic: [
      { label: "Condition", value: "The child\u2019s ParentImage field names a different binary than the process this tree linked it to" },
      { label: "What it means", value: "Almost always a LINK-QUALITY problem: the parent PID was recycled and the relink attached to a later process with the same PID. Read it as \u2018do not trust this branch of the tree\u2019, not as an attack." },
      { label: "Why not T1134.004", value: "Real parent-PID spoofing sets PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, so the OS records the SPOOFED parent in both the event and the actual parent field \u2014 the two AGREE. A disagreement is evidence of the opposite: a reconstruction error. Spoofing is caught by the parent/child plausibility rules instead." },
      { label: "Level", value: "Low when the link was a 1:1 GUID join (a genuine field disagreement); context otherwise" },
      { label: "Caveat", value: "Requires both fields populated \u2014 skipped when ParentImage is missing or was backfilled from the linked parent (basenames match by construction)" },
    ],
    test: (c) => {
      if (!c.parentImageReported || !c.pil) return false;
      const rep = c.parentImageReported.split(/[\\/]/).pop().replace(/\.exe$/i, "").trim();
      const lnk = c.pil.split(/[\\/]/).pop().replace(/\.exe$/i, "").trim();
      if (!rep || !lnk) return false;
      if (rep === lnk) return false;
      // A GUID link is an identity join, so the two fields genuinely disagree —
      // worth a low finding. A PID-based relink disagreeing is the expected
      // symptom of PID reuse and stays context.
      if (c.linkSource === "guid") return { override: 1, cat: "context" };
      return { override: 0, cat: "context" };
    } },
  { id: "pi-15", group: "misc", level: 2, reason: "Script engine running a script from a user profile path", tid: ["T1059.005"], beh: "script-exec",
    sev: "high", name: "Script from User Profile Path", technique: "T1059.005",
    logic: [
      { label: "Process", value: "wscript.exe OR cscript.exe" },
      { label: "Condition", value: "The SCRIPT named on the command line lives under \\Users\\<name>\\ or \\AppData\\" },
      { label: "Why", value: "The rule used to test the IMAGE path, but wscript.exe and cscript.exe always live in System32 \u2014 so it could never fire. The interesting path is the script's, which is an argument." },
      { label: "Fallback", value: "A script engine genuinely running from outside System32 is itself an anomaly and still fires" },
    ],
    test: (c) => {
      if (!_RX_WSCRIPT_NAME.test(c.n)) return false;
      // The interpreter is in System32 by definition; the script is the argument.
      const _scriptArg = (c.cmd.match(/[^\s"']*\.(vbs|vbe|js|jse|wsf|wsh|hta|ps1|bat|cmd)\b/i) || [])[0] || "";
      if (_scriptArg && _RX_USER_PROFILE_PATH.test(_scriptArg) && !BENIGN_INSTALL_PATH.test(_scriptArg)) return true;
      // No script path on the line (or an unqualified name) — fall back to the old
      // test, which still catches a relocated interpreter.
      if (_RX_USER_PROFILE_PATH.test(c.img)) return true;
      return false;
    } },
  { id: "pi-16", group: "misc", level: 1, reason: "Suspicious path", cat: "context", tid: ["T1204"], beh: "path",
    sev: "medium", name: "Suspicious Execution Path (temp/appdata/downloads)", technique: "T1204",
    logic: [{ label: "Image Path", value: "regex: \\\\temp\\\\ | \\\\tmp\\\\ | \\\\appdata\\\\ | \\\\downloads\\\\ | \\\\public\\\\ | \\\\recycle | \\\\perflogs\\\\" }, { label: "Exclusions", value: "Safe processes: mpcmdrun, msmpeng, tiworker, trustedinstaller, msiexec, etc." }, { label: "Condition", value: "Non-whitelisted process executing from user-writable or staging directory" }],
    test: (c) => {
      // A validly-signed binary executing from Temp/AppData is overwhelmingly a legitimate
      // updater/installer stub (Chrome/Teams/Slack/Zoom/Squirrel/MSI) — the single highest-volume
      // path FP. Skip those; keep the genuine "unsigned/untrusted EXE from a staging dir" case.
      if (c.signed === "true" && (!c.sigStatus || !_RX_SIG_BAD.test(c.sigStatus))) return false;
      // USER_WRITABLE_PATH now also covers \Users\ and \ProgramData\ (audit P19),
      // which is where per-user and per-vendor installs legitimately live — exclude
      // those so closing the coverage gap does not open a false-positive one.
      if (BENIGN_INSTALL_PATH.test(c.ilc || c.il)) return false;
      return SUS_PATHS.test(c.img) && !SAFE_PROCS.test(c.n);
    } },
  // pi-17 (RMM Tools \u2014 Normal Parent) removed: it fired on every endpoint that merely HAS
  // an RMM tool installed (a level-0 inventory note), which is pure noise. Genuinely
  // suspicious RMM usage is covered by pi-12 (unusual parent) and pi-24 (tunnels).

  // --- Adjacent telemetry (EID 3 / 22 / 7 / 11) — requires tree-builder enrichment ---
  { id: "pi-61", group: "lateral", level: 2, reason: "Outbound network from suspicious process", tid: ["T1071"], beh: "network",
    sev: "high", name: "Network Connect after suspicious process (Sysmon EID 3)", technique: "T1071",
    logic: [
      { label: "Condition", value: "Process has correlated Sysmon EID 3 NetworkConnect events AND is already flagged primary OR has 3+ distinct destinations" },
      { label: "High", value: "Rare external destinations or high connection volume from shell/script/LOLBin parents" },
    ],
    test: (c) => {
      if (!c.network || !(c.network.eventCount > 0)) return false;
      const dests = c.network.destCount || 0;
      const rare = c.network.rareDestCount || 0;
      // Talking to the internet is what a browser, updater or sync client is FOR.
      if (_RX_NETWORK_NATIVE_APPS.test(c.n)) return { override: 0, cat: "context" };
      const corroborated = _pi6xCorroborated(c);
      if (!corroborated) {
        // Volume alone: record it, do not score it.
        return { override: 0, cat: "context" };
      }
      if (rare >= 1 || dests >= 5) return { override: dests >= 10 || rare >= 3 ? 3 : 2 };
      if (_RX_SHELL_CHILDREN.test(c.n) || _RX_PS_NAME.test(c.n)) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-62", group: "discovery", level: 1, reason: "DNS queries from process", tid: ["T1071.004"], beh: "dns",
    sev: "medium", name: "DNS Query activity (Sysmon EID 22)", technique: "T1071.004",
    logic: [
      { label: "Condition", value: "Process has correlated Sysmon EID 22 DNS queries" },
      { label: "High", value: "Many distinct query names (beacon / staging) or queries alongside other primary detections" },
    ],
    test: (c) => {
      if (!c.dns || !(c.dns.eventCount > 0)) return false;
      const names = c.dns.queryCount || 0;
      // Name resolution volume is not a detection on its own — every browser tab
      // and every telemetry agent produces more of it than any implant.
      if (_RX_NETWORK_NATIVE_APPS.test(c.n) || !_pi6xCorroborated(c)) return { override: 0, cat: "context" };
      if (names >= 8) return { override: 2 };
      if (names >= 2) return { override: 1 };
      return { override: 0, cat: "context" };
    } },
  { id: "pi-63", group: "evasion", level: 2, reason: "Unsigned / rare image load", tid: ["T1574.002"], beh: "image-load",
    sev: "high", name: "Suspicious Image Load (Sysmon EID 7)", technique: "T1574.002",
    logic: [
      { label: "Condition", value: "Process loaded modules correlated via EID 7 with unsigned or non-Microsoft signed samples" },
      { label: "Critical", value: "Unsigned DLL from user-writable path loaded into a trusted process" },
    ],
    test: (c) => {
      if (!c.imageLoads || !(c.imageLoads.eventCount > 0)) return false;
      const unsigned = c.imageLoads.unsignedCount || 0;
      const writable = c.imageLoads.writablePathCount || 0;
      // Sideloading means a binary in a TRUSTED location pulling in an unsigned
      // module from a writable one. A process that itself lives under \Users
      // (venv, Electron app, portable tool) loading unsigned neighbours is normal.
      const hostTrusted = _RX_TRUSTED_IMAGE_ROOT.test(c.il || "");
      // Deliberately NOT _pi6xCorroborated: that helper treats "the process lives in
      // a writable path" as corroboration, which is exactly the condition that makes
      // an unsigned module load UNREMARKABLE here (a venv, an Electron app or a
      // portable tool loading its own bundled modules). Only signals independent of
      // the host's location count.
      const _sideloadCorroborated = _chainCorroborated(c.cmd)
        || c.signed === "false"
        || /invalid|expired|revoked|untrusted|error/.test(c.sigStatus || "")
        || !!c.injection
        || _RX_SHELL_CHILDREN.test(c.n)
        || _RX_PS_NAME.test(c.n);
      if (!hostTrusted && !_sideloadCorroborated) return { override: 0, cat: "context" };
      if (unsigned >= 1 && writable >= 1) return { override: hostTrusted ? 3 : 2 };
      if (unsigned >= 2 || writable >= 1) return { override: hostTrusted ? 2 : 1 };
      if (unsigned >= 1) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-64", group: "evasion", level: 2, reason: "File create then execute staging", tid: ["T1105"], beh: "file-drop",
    sev: "high", name: "File Create activity (Sysmon EID 11)", technique: "T1105",
    logic: [
      { label: "Condition", value: "Process created files (EID 11) especially PE/script extensions in user-writable paths" },
      { label: "High", value: "Dropped .exe/.dll/.ps1/.hta/.js under Temp/AppData/Downloads" },
    ],
    test: (c) => {
      if (!c.fileCreates || !(c.fileCreates.eventCount > 0)) return false;
      const pe = c.fileCreates.peCount || 0;
      const script = c.fileCreates.scriptCount || 0;
      const writable = c.fileCreates.writablePathCount || 0;
      // Writing executables into a writable directory is precisely what an
      // installer, an updater and a package manager do.
      if (_RX_NETWORK_NATIVE_APPS.test(c.n) || SAFE_PROCS.test(c.n)) return { override: 0, cat: "context" };
      const corroborated = _pi6xCorroborated(c);
      if ((pe >= 1 || script >= 1) && writable >= 1) return { override: corroborated ? (pe >= 1 ? 3 : 2) : 1 };
      if (pe >= 1 || script >= 2) return { override: corroborated ? 2 : 1 };
      if (c.fileCreates.eventCount >= 5) return { override: 1, cat: "context" };
      return false;
    } },
  { id: "pi-65", group: "cred", level: 3, reason: "Opened LSASS with memory-read access", tid: ["T1003.001"], beh: "cred",
    sev: "critical", name: "LSASS Memory Read (Sysmon EID 10, source side)", technique: "T1003.001",
    logic: [
      { label: "Condition", value: "A correlated Sysmon EID 10 shows THIS process opening a handle to lsass.exe that includes PROCESS_VM_READ (or full access)" },
      { label: "Why it matters", value: "0x1010 / 0x1410 / 0x1438 on lsass is the mimikatz, procdump, nanodump and comsvcs.dll MiniDump signature. It needs no VM_WRITE, so the injection rules never saw it." },
      { label: "Context", value: "Query-only handles (0x400 / 0x1000) are what Task Manager, EDR agents and every process enumerator take \u2014 recorded, not scored" },
      { label: "Coverage", value: "Requires Sysmon EID 10 with lsass in scope. The event is attributed to the ACCESSING process; previously all EID 10 indicators landed on the target, so the tool itself carried no finding." },
    ],
    test: (c) => {
      if (!c.credAccess || !(c.credAccess.lsassAccessCount > 0)) return false;
      if ((c.credAccess.lsassReadCount || 0) > 0) return { override: 3 };
      return { override: 0, cat: "context" };
    } },
];

// Rules whose default category is "context" — pre-computed so the hot loop
// doesn't re-check the field every iteration.
const _PI_CONTEXT_RULE_IDS = new Set(PI_RULES.filter((r) => r.cat === "context").map((r) => r.id));

// --- Derived canonical exports for the modal ---
// All display metadata lives on PI_RULES/PI_CHAIN_RULES above. The modal
// imports these derived structures instead of maintaining parallel arrays.

// Combined rule list: chain rules + standalone rules, ordered by ID for stable
// indexing. The modal uses this for the config-panel rule cards.
export const PI_ALL_RULES = [...PI_CHAIN_RULES, ...PI_RULES];

// Technique groups with rule IDs (replaces the old numeric-index groups in the
// modal). Each group.ruleIds is a list of pi-N strings that belong to it.
export const PI_TECHNIQUE_GROUPS = PI_RULE_GROUPS.map((g) => ({
  ...g,
  ruleIds: PI_ALL_RULES.filter((r) => r.group === g.id).map((r) => r.id),
}));

// Grandparent multi-hop chains — exact basename triples (no .exe).
// Fires as pi-60 so intermediate hop demotion does not hide the full path.
const _GP_CHAIN_RULES = [
  { g: "winword", p: "cmd", c: "powershell", level: 3, reason: "Word \u2192 cmd \u2192 PowerShell \u2014 multi-hop macro execution [T1059.001]", tid: ["T1059.001", "T1204.002"], beh: "script-exec" },
  { g: "winword", p: "cmd", c: "pwsh", level: 3, reason: "Word \u2192 cmd \u2192 pwsh \u2014 multi-hop macro execution [T1059.001]", tid: ["T1059.001", "T1204.002"], beh: "script-exec" },
  { g: "excel", p: "cmd", c: "powershell", level: 3, reason: "Excel \u2192 cmd \u2192 PowerShell \u2014 multi-hop macro execution [T1059.001]", tid: ["T1059.001", "T1204.002"], beh: "script-exec" },
  { g: "excel", p: "cmd", c: "pwsh", level: 3, reason: "Excel \u2192 cmd \u2192 pwsh \u2014 multi-hop macro execution [T1059.001]", tid: ["T1059.001", "T1204.002"], beh: "script-exec" },
  { g: "winword", p: "powershell", c: "cmd", level: 3, reason: "Word \u2192 PS \u2192 cmd \u2014 multi-hop macro execution [T1059.003]", tid: ["T1059.003", "T1204.002"], beh: "shell-exec" },
  { g: "excel", p: "powershell", c: "cmd", level: 3, reason: "Excel \u2192 PS \u2192 cmd \u2014 multi-hop macro execution [T1059.003]", tid: ["T1059.003", "T1204.002"], beh: "shell-exec" },
  { g: "outlook", p: "cmd", c: "powershell", level: 3, reason: "Outlook \u2192 cmd \u2192 PowerShell \u2014 phishing multi-hop [T1566.001]", tid: ["T1566.001", "T1059.001"], beh: "script-exec" },
  { g: "wscript", p: "cmd", c: "powershell", level: 2, reason: "WScript \u2192 cmd \u2192 PowerShell \u2014 script multi-hop [T1059.005]", tid: ["T1059.005", "T1059.001"], beh: "script-exec" },
  { g: "cscript", p: "cmd", c: "powershell", level: 2, reason: "CScript \u2192 cmd \u2192 PowerShell \u2014 script multi-hop [T1059.005]", tid: ["T1059.005", "T1059.001"], beh: "script-exec" },
  { g: "mshta", p: "cmd", c: "powershell", level: 3, reason: "mshta \u2192 cmd \u2192 PowerShell \u2014 HTA multi-hop [T1218.005]", tid: ["T1218.005", "T1059.001"], beh: "script-exec" },
  { g: "mshta", p: "powershell", c: "cmd", level: 3, reason: "mshta \u2192 PS \u2192 cmd \u2014 HTA multi-hop [T1218.005]", tid: ["T1218.005", "T1059.003"], beh: "shell-exec" },
  { g: "powershell", p: "cmd", c: "bitsadmin", level: 2, reason: "PS \u2192 cmd \u2192 bitsadmin \u2014 multi-hop download stage [T1105]", tid: ["T1105", "T1059"], beh: "download" },
  { g: "cmd", p: "powershell", c: "bitsadmin", level: 2, reason: "cmd \u2192 PS \u2192 bitsadmin \u2014 multi-hop download stage [T1105]", tid: ["T1105", "T1059"], beh: "download" },
  { g: "cmd", p: "powershell", c: "certutil", level: 2, reason: "cmd \u2192 PS \u2192 certutil \u2014 multi-hop decode/download [T1140]", tid: ["T1140", "T1105"], beh: "download" },
  { g: "w3wp", p: "cmd", c: "powershell", level: 3, reason: "IIS \u2192 cmd \u2192 PowerShell \u2014 webshell multi-hop [T1505.003]", tid: ["T1505.003", "T1059.001"], beh: "script-exec" },
  { g: "w3wp", p: "powershell", c: "cmd", level: 3, reason: "IIS \u2192 PS \u2192 cmd \u2014 webshell multi-hop [T1505.003]", tid: ["T1505.003", "T1059.003"], beh: "shell-exec" },
];
const _GP_CHAIN_MAP = new Map(_GP_CHAIN_RULES.map((r) => [`${r.g}:${r.p}:${r.c}`, r]));
const _matchGrandparentChain = (g, p, c) => _GP_CHAIN_MAP.get(`${g}:${p}:${c}`) || null;

export const getSusInfo = (node, parentNode, opts) => {
  const n = (node.processName || "").toLowerCase();
  const pn = (parentNode?.processName || "").toLowerCase();
  const cmd = node.cmdLine || "";
  const img = node.image || "";
  const nBase = n.replace(/\.exe$/, "");
  const pnBase = pn.replace(/\.exe$/, "");
  const disabled = opts?.disabledRules;
  const il = img.toLowerCase();
  const pil = (parentNode?.image || "").toLowerCase();
  const ilc = _canonImagePath(img);
  const pilc = _canonImagePath(parentNode?.image);
  // Allowlist check — name must match, then: vendor path OR command-line test.
  // Path matches now require the image to live under a trusted system root with
  // no user-writable segment (see _isUnderTrustedRoot). An entry can also opt
  // out of allowlisting via `cmdUntrust`: if that pattern matches the cmdline,
  // the entry is treated as if it weren't allowlisted at all. mpcmdrun uses
  // this to keep its `-DownloadFile` LOLBin behavior visible.
  const _alEntries = PI_ALLOWLIST.get(nBase);
  let _alEntry = null;
  let _allowlisted = false;
  if (_alEntries) {
    for (const ae of _alEntries) {
      if (ae.cmdUntrust && ae.cmdUntrust.test(cmd)) continue;
      if (ae.paths && _isUnderTrustedRoot(ilc) && ae.paths.some(p => ilc.includes(p))) {
        _alEntry = ae; _allowlisted = true; break;
      }
      if (ae.cmdTest && ae.cmdTest.test(cmd)) { _alEntry = ae; _allowlisted = true; break; }
    }
  }
  const evidence = [];
  // 1. Chain evidence (no early return — collect alongside standalone)
  // Skipped when the caller tells us the parent edge is a PID-reuse mislink: a
  // parent->child RULE is only meaningful if the edge is real. Standalone callers
  // (tests, the row-detail panel) pass no flag and are unaffected.
  const _edgeTrusted = opts?.parentEdgeConsistent !== false;
  if (pnBase && !_edgeTrusted) {
    evidence.push({
      cat: "context", level: 0, ruleId: "pi-49",
      reason: "Parent chain rules skipped — the reported parent does not match the linked parent",
      tid: [], beh: "evasion",
    });
  }
  if (pnBase && _edgeTrusted) {
    // resolveChainRule (not a bare map lookup): pairs whose severity depends on the
    // arguments — vssadmin/wmic/bcdedit/wevtutil/wbadmin/reg/sc/netsh/psexec — are
    // capped at low until the command line proves the destructive variant.
    const chainHit = resolveChainRule(pnBase + ":" + nBase, cmd);
    if (chainHit) {
      const ruleId = _classifyChain(pnBase, nBase);
      if (!disabled?.has(ruleId)) {
        const _chainBeh = ruleId === "pi-0" ? "shell-exec" : ruleId === "pi-1" ? "script-exec" : ruleId === "pi-2" ? "service-exec" : "shell-exec";
        // FP gate (largest false-positive class): service-host (pi-2) and generic
        // interpreter→interpreter (pi-1) chains flood triage with benign management
        // activity (SCCM/Intune/GPO/WMI admin: svchost→powershell, cmd↔powershell). Without a
        // corroborating command-line indicator they carry no real signal, so demote to CONTEXT
        // (level 0) — still feeds the allowlist/suppression + sequence/cluster engine, but no
        // longer scores as a standalone primary finding. Office (pi-0) and the specific pi-18
        // chains (LSASS, accessibility, browser-exploit, etc.) keep full severity.
        // Narrowed gate (audit P6). pi-2 is only demoted for the genuinely noisy
        // service hosts, and no chain under a high-signal parent is demoted at all.
        const _noisyChain = ruleId === "pi-1"
          || (ruleId === "pi-2" && _RX_NOISY_SERVICE_PARENTS.test(pn))
          || _RX_DISCOVERY_SINGLETON.test(nBase);
        if (_noisyChain && !_RX_HIGH_SIGNAL_PARENTS.test(pn) && !_chainCorroborated(cmd)) {
          evidence.push({ cat: "context", level: 0, reason: chainHit.reason + " — no corroborating command-line indicator", ruleId, tid: chainHit.techniques, beh: _chainBeh });
        } else {
          evidence.push({ cat: "chain", level: chainHit.level, reason: chainHit.reason, ruleId, tid: chainHit.techniques, beh: _chainBeh });
        }
      }
    }
  }
  // 1b. Grandparent multi-hop chains (e.g. winword → cmd → powershell). These fire even when
  // intermediate hops are demoted by the chain gate, because the full path is the signal.
  const gpNode = opts?.grandparentNode || null;
  const gpBase = (gpNode?.processName || "").toLowerCase().replace(/\.exe$/, "");
  if (gpBase && pnBase && nBase && !disabled?.has("pi-60")) {
    const gpHit = _matchGrandparentChain(gpBase, pnBase, nBase);
    if (gpHit) {
      evidence.push({
        cat: "chain",
        level: gpHit.level,
        reason: gpHit.reason,
        ruleId: "pi-60",
        tid: gpHit.tid,
        beh: gpHit.beh || "shell-exec",
      });
    }
  }
  // 2. Standalone + context checks. Rules live in module-scope PI_RULES so the
  // array (and its 80+ regexes) is built once at load, not per process row.
  // Each rule.test(ctx) takes the per-call context object below.
  const ctx = {
    n, pn, cmd, img, il, pil, ilc, pilc,
    // Trust metadata (may be empty depending on dataset — Sysmon only)
    origFn: (node.originalFileName || "").toLowerCase().replace(/\.exe$/i, ""),
    signed: (node.signed || "").toLowerCase(),
    sigStatus: (node.signatureStatus || "").toLowerCase(),
    signer: (node.signer || "").toLowerCase(),
    company: (node.company || "").toLowerCase(),
    hashes: node.hashes || "",
    // Lifetime metadata (populated by backend terminate-event matching)
    dur: node.durationMs,
    exitCode: node.exitCode || "",
    // Injection metadata (populated by backend EID 10 ProcessAccess matching)
    injection: node.injectionIndicators || null,
    // Credential access — this process opened a handle to lsass (EID 10, source side).
    credAccess: node.credentialAccess || null,
    // Privilege-use metadata (populated by backend EID 4673 / 4674 matching).
    // Shape: { eventCount, privileges: { <lowername>: count }, highRiskCount,
    // uniqueHighRisk, services: [...] }. Null means no privilege audit events
    // were correlated to this process.
    privilege: node.privilegeUse || null,
    // Adjacent Sysmon telemetry (EID 3/22/7/11) — counts/samples from tree builder.
    network: node.networkActivity || null,
    dns: node.dnsActivity || null,
    imageLoads: node.imageLoads || null,
    fileCreates: node.fileCreates || null,
    // Parent-image the child ROW reported, before any backfill. When the linked
    // parent (parentNode.image → c.pil) differs, the child is claiming a parent
    // that wasn't actually running at that PID — the classic parent PID spoof
    // signature. Backfilled rows have node.parentImage === parentNode.image by
    // construction, so the pi-49 rule below compares basenames and stays silent
    // on backfilled data.
    parentImageReported: (node.parentImage || "").toLowerCase(),
    parentSigner: (parentNode?.signer || "").toLowerCase(),
    // How the parent link was established. "guid" is a 1:1 identity join; anything
    // else is a PID-based relink that can attach to a recycled PID. pi-49 needs this
    // to tell a genuine field disagreement from a mislink.
    linkSource: node.linkSource || "",
    linkConfidence: node.linkConfidence || "",
    // Dataset-level flag (set by the pipeline): does ANY process in this dataset carry a
    // matched terminate event? When false the source simply lacks 4689/Sysmon-5 records, so a
    // missing termination is a logging gap — not a signal. Defaults true for standalone calls.
    datasetHasTermination: opts?.datasetHasTermination !== false,
  };
  for (let i = 0; i < PI_RULES.length; i++) {
    const rule = PI_RULES[i];
    if (disabled?.has(rule.id)) continue;
    const isContextRule = _PI_CONTEXT_RULE_IDS.has(rule.id);
    // Sanctioned processes: suppress context-category rules entirely.
    // pi-16/pi-17 are explicitly listed for clarity even though they're now
    // covered by _PI_CONTEXT_RULE_IDS — preserves the original semantics.
    if (_allowlisted && (isContextRule || rule.id === "pi-16" || rule.id === "pi-17")) continue;
    const result = rule.test(ctx);
    if (result === false) continue;
    const level = result === true ? rule.level : (result.override ?? rule.level);
    const cat = (result !== true && result.cat) || rule.cat || "standalone";
    // Sanctioned + context result from a primary rule: suppress
    if (_allowlisted && cat === "context") continue;
    evidence.push({ cat, level, reason: rule.reason, ruleId: rule.id, tid: rule.tid, beh: rule.beh });
  }
  // 3. Custom rules — multi-field (parent/process/path/cmd) + optional regex.
  // Cmdline length capped as a ReDoS backstop even when the nested-quantifier
  // guard in compileCustomRules is bypassed.
  if (opts?.customRules) {
    const _capCmd = cmd.length > 8192 ? cmd.slice(0, 8192) : cmd;
    const _capCmdLower = _capCmd.toLowerCase();
    const sevMap = { critical: 3, high: 2, medium: 1, med: 1, low: 0 };
    for (let ci = 0; ci < opts.customRules.length; ci++) {
      const cr = opts.customRules[ci];
      if (cr.parentProcess && cr.parentProcess !== pnBase) continue;
      if (cr.processName && cr.processName !== nBase) continue;
      if (cr.imageContains && !il.includes(cr.imageContains)) continue;
      if (cr.cmdContains && !_capCmdLower.includes(cr.cmdContains)) continue;
      if (cr._rx && !(cr._rx.test(_capCmd) || cr._rx.test(n) || cr._rx.test(img))) continue;
      // If only optional fields were empty and no regex, skip empty-match
      if (!cr.parentProcess && !cr.processName && !cr.imageContains && !cr.cmdContains && !cr._rx) continue;
      const cTid = cr.technique ? [cr.technique] : [];
      const cBeh = cr.behavior || null;
      evidence.push({
        cat: "standalone",
        level: sevMap[cr.severity] ?? 1,
        reason: `${cr.category || "Custom"} \u2014 ${cr.name}`,
        ruleId: `custom-${ci}`,
        tid: cTid,
        beh: cBeh,
      });
    }
  }
  // 4. Context signals — path/arg analysis. Only stack onto a node that already has a PRIMARY
  // (non-context) finding; otherwise a lone context/demoted-chain hit accretes up to five generic
  // "lives in AppData / has a URL" pills AND its triageScore inflates purely from evidence count.
  const _hasPrimary = evidence.some((e) => e.cat !== "context");
  if (_hasPrimary && !_allowlisted) {
    if (_RX_USER_WRITABLE_EXTENDED.test(il))
      evidence.push({ cat: "context", level: 0, reason: "User-writable path" });
    if (_RX_UNC_PATH_PAREN.test(il))
      evidence.push({ cat: "context", level: 0, reason: "UNC path execution" });
    if (_RX_NETWORK_URL.test(cmd))
      evidence.push({ cat: "context", level: 0, reason: "Network reference in args" });
    if (_RX_PROG_FILES.test(il) && _RX_PROG_FILES.test(pil))
      evidence.push({ cat: "context", level: 0, reason: "Both in Program Files", dampen: true });
    if ((pnBase === "services" && nBase === "svchost") || (pnBase === "svchost" && nBase === "wmiprvse"))
      evidence.push({ cat: "context", level: 0, reason: "Expected service chain", dampen: true });
    if (_RX_UPDATER_PATTERN.test(cmd))
      evidence.push({ cat: "context", level: 0, reason: "Updater/installer pattern", dampen: true });
  }
  // 4b. Sanctioned tooling state — explicit state for known DFIR/EDR/AV/RMM/update agents
  const sanctioned = _allowlisted ? { cat: _alEntry.cat, match: _alEntry.cmdTest ? "cmdline" : "path" } : null;
  if (sanctioned && evidence.length > 0) {
    evidence.push({ cat: "context", level: 0, reason: `Sanctioned ${_alEntry.cat.toUpperCase()} tool`, dampen: true });
  }
  // 5. Score from accumulated evidence — single-pass aggregation.
  // Old code did: filter().filter().map().reduce() + spread() + flatMap() ≈ 6 passes
  // and an array allocation per process. At 200k rows that's ~1.2M throwaway arrays.
  // Keep the sanctioned state even when there is no finding. Dataset-level
  // passes (for example same-name path rarity) need it to avoid reintroducing
  // an alert that the exact-name/vendor-path baseline already resolved.
  if (!evidence.length) return { level: 0, reason: null, sanctioned };
  let primaryCount = 0;
  let hiCount = 0;
  let maxLevel = -Infinity;
  let best = null;
  let bestIsPrimary = false;
  const behSet = new Set();
  const tidSet = new Set();
  for (let i = 0; i < evidence.length; i++) {
    const e = evidence[i];
    const isPrimary = e.cat !== "context";
    if (isPrimary) {
      primaryCount++;
      if (e.level >= 2) hiCount++;
    }
    if (!e.dampen && e.level > maxLevel) maxLevel = e.level;
    // Best entry: prefer any primary; among primaries pick highest level.
    // If no primary exists yet, fall back to highest non-dampen entry.
    if (isPrimary) {
      if (!bestIsPrimary || e.level > best.level) { best = e; bestIsPrimary = true; }
    } else if (!bestIsPrimary && !e.dampen) {
      if (!best || e.level > best.level) best = e;
    }
    if (e.beh) behSet.add(e.beh);
    if (e.tid) for (let t = 0; t < e.tid.length; t++) tidSet.add(e.tid[t]);
  }
  // Sanctioned + no primary evidence = fully suppressed (level 0)
  if (sanctioned && primaryCount === 0) return { level: 0, reason: null, sanctioned };
  // Confidence depends ONLY on primary evidence (chain + standalone), never context
  const confidence = hiCount >= 2 ? "confirmed"
    : hiCount === 1 && primaryCount >= 2 ? "confirmed"
    : primaryCount > 0 ? "likely"
    : "context";
  if (maxLevel === -Infinity) maxLevel = 0;
  const baseResult = {
    level: maxLevel < 0 ? 0 : maxLevel > 3 ? 3 : maxLevel,
    confidence,
    reason: best.reason,
    primaryRuleId: best.ruleId,
    evidence,
    techniques: [...tidSet],
    behaviors: [...behSet],
    sanctioned,
  };
  const analystProfile = opts?.analystProfile || PI_ANALYST_PROFILE_DEFAULT;
  const suppressionHit = (analystProfile.suppressions || []).find((entry) => _piAnalystEntryMatches(entry, node, parentNode, best.reason));
  if (suppressionHit) {
    return { ...baseResult, level: 0, reason: null, confidence: "suppressed", suppressed: suppressionHit };
  }
  const baselineHit = (analystProfile.baselines || []).find((entry) => _piAnalystEntryMatches(entry, node, parentNode, best.reason));
  if (baselineHit) {
    const loweredLevel = baseResult.level <= 1 ? 0 : baseResult.level - 1;
    return {
      ...baseResult,
      level: loweredLevel,
      confidence: loweredLevel >= 2 ? baseResult.confidence : "context",
      baselined: baselineHit,
    };
  }
  return baseResult;
};

// Classify chain hit into PI_RULES group for disabled-rule filtering
export const _classifyChain = (() => {
  const OFFICE = new Set(["winword","excel","powerpnt","outlook","onenote","msaccess","mspub"]);
  const SCRIPT_P = new Set(["wscript","cscript","powershell","pwsh","cmd","mshta"]);
  const SCRIPT_C = new Set(["cmd","powershell","pwsh","wscript","cscript","bash","mshta"]);
  const SERVICE = new Set(["svchost","wmiprvse","taskeng","taskhostw","wsmprovhost","dllhost","mmc","services"]);
  return (pnBase, nBase) => {
    if (OFFICE.has(pnBase)) return "pi-0";
    if (SCRIPT_P.has(pnBase) && SCRIPT_C.has(nBase)) return "pi-1";
    if (SERVICE.has(pnBase)) return "pi-2";
    return "pi-18";
  };
})();


export const _integrityShort = (raw) => {
  if (!raw) return "";
  if (/16384|System/i.test(raw)) return "System";
  if (/12288|High/i.test(raw)) return "High";
  if (/8192|Medium/i.test(raw)) return "Medium";
  if (/4096|Low/i.test(raw)) return "Low";
  if (/\b0\b|Untrusted/i.test(raw)) return "Untrusted";
  return raw.replace(/^S-1-16-\d+\s*/i, "").replace(/^.*\\/, "") || raw;
};

export const _providerShort = (p) => {
  if (!p) return "";
  if (p.includes("Sysmon")) return "Sysmon";
  if (p.includes("Security-Auditing")) return "Security";
  return p.replace(/^Microsoft-Windows-/i, "");
};


export const _piProcBase = (value) => String(value || "").trim().toLowerCase().replace(/^.*[/\\]/, "").replace(/\.exe$/i, "");
export const _piTextNorm = (value) => String(value || "").trim().toLowerCase();
export const _piFieldMatch = (expected, actual) => !expected || _piTextNorm(expected) === _piTextNorm(actual);
export const _piProcMatch = (expected, actual) => !expected || _piProcBase(expected) === _piProcBase(actual);
export const _piCmdMatch = (expected, actual) => !expected || _piTextNorm(actual).includes(_piTextNorm(expected));
export const _ptFormatDuration = (ms) => {
  if (!ms || !Number.isFinite(ms) || ms <= 0) return "";
  const mins = Math.max(1, Math.round(ms / 60000));
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  const rem = mins % 60;
  if (hrs < 24) return rem ? `${hrs}h ${rem}m` : `${hrs}h`;
  const days = Math.floor(hrs / 24);
  const remHrs = hrs % 24;
  return remHrs ? `${days}d ${remHrs}h` : `${days}d`;
};
export const _piAnalystEntryMatches = (entry, node, parentNode, reason) => {
  if (!entry) return false;
  if (!_piFieldMatch(entry.reason, reason)) return false;
  if (!_piProcMatch(entry.processName, node?.processName || node?.image)) return false;
  if (!_piProcMatch(entry.parentProcessName, parentNode?.processName || parentNode?.image)) return false;
  if (!_piFieldMatch(entry.hostname, node?.hostname)) return false;
  if (!_piFieldMatch(entry.user, node?.user)) return false;
  if (!_piFieldMatch(entry.image, node?.image)) return false;
  if (!_piCmdMatch(entry.cmdContains, node?.cmdLine)) return false;
  return true;
};
