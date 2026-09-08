/**
 * lateral-movement/utils.js — Shared constants, patterns, and helpers
 *
 * All constants and utility functions used across lateral movement sub-modules.
 */

// IPs excluded from source resolution
const EXCLUDED_IPS = new Set(["-", "::1", "127.0.0.1", "0.0.0.0", ""]);

// Service/machine account filter
const SERVICE_RE = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$/i;

// Session-only events: don't create graph edges, only used for RDP session correlation
const SESSION_ONLY_EVENTS = new Set(["20","23","24","32","33","34","35","39","40","4634","4647","4672","4769","4776","4779"]);

// RDP event descriptions for session timeline
const RDP_EVENT_DESC = {
  "1149": "RDP connection established (auth not proven)", "4624": "Logon succeeded", "4625": "Logon failed",
  "21": "Session logon succeeded", "22": "Shell start notification", "23": "Session logoff",
  "24": "Session disconnected", "25": "Session reconnected", "39": "Disconnected by another session",
  "40": "Session disconnect (reason code)", "4634": "Account logged off", "4647": "User-initiated logoff",
  "4648": "Explicit credentials used", "4672": "Admin privileges assigned",
  "4776": "NTLM authentication", "4778": "Session reconnected (window station)", "4779": "Session disconnected (window station)",
};

// DC pattern: matches common naming conventions including prefixed/suffixed variants
const DC_PAT = /(?:^|[\-_])(DC|PDC|BDC|ADDS|ADCS|ADFS)\d{0,3}(?:$|[\-_])|^AD\d{0,3}$/i;
const SRV_PAT = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)(?=[_\-\d]|$)/i;

// Outlier hostname detection patterns — always flagged regardless of frequency
const OUTLIER_PATS_ALWAYS = [
  [/^KALI$/i, "Kali Linux default"],
  [/^PARROT$/i, "Parrot OS default"],
  [/^(USER-?PC|YOURNAME|ADMIN|TEST|PC|WIN10|WIN11|OWNER-?PC|USER|WINDOWS|LOCALHOST|HACKER|ATTACKER|ROOT)$/i, "Generic hostname"],
  [/[^\x00-\x7F]/, "Non-ASCII hostname"],
];

// Default Windows hostname pattern (frequency-dependent outlier)
const DEFAULT_WIN_PAT = /^(DESKTOP-[A-Z0-9]{5,}|WIN-[A-Z0-9]{5,})$/;

// Management source pattern (dampener)
const MGMT_SRC_PAT = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;

// Service account pattern (dampener)
const SVC_ACCT_PAT = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;

// Severity ordering for sort
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// Technique priority for edge inference
const TECH_PRIORITY = { "Admin Share": 7, "Service Exec": 6, "Cleartext": 5, "RDP": 4, "Interactive": 3, "Network Logon": 2, "Cached": 1, "Reconnect": 0 };

// SubStatus reason mapping for 4625 failure context
const SUBSTATUS_REASONS = {
  "0XC000006A": "bad password", "0XC0000064": "unknown user", "0XC000006D": "bad credentials",
  "0XC0000234": "account locked", "0XC0000072": "account disabled", "0XC000006E": "account restriction",
  "0XC000006F": "outside hours", "0XC0000070": "workstation restriction", "0XC0000071": "password expired",
  "0XC0000193": "account expired", "0XC0000133": "clock skew", "0XC0000224": "must change password",
  "0XC0000413": "auth firewall", "0XC000015B": "logon type denied",
};

// Common service/vendor names (for random-name detection FP control)
const COMMON_SVC = new Set([
  "system","service","server","client","agent","local","admin","power","event","setup","shell","start","print","audit","group","share","trust","alert","cache","debug","error","index","input","media","model","panel","patch","proxy","query","queue","route","scene","scope","stack","stage","state","store","style","super","table","theme","timer","token","trace","track","train","trend","union","unity","usage","valid","watch",
  "qemu","virtio","spice","vbox","vmware","hyper","xen",
  "cortex","traps","cyverak","cyvrfsfd","cyvrmtgn","cyeason","cylance","carbon","sentinel","crowdstrike","falcon","defend","defender","mdatp","sense","epdr","eset","sophos","hmpalert","savservice","sophossps","mbam","npcap","winpcap","usbpcap",
  "tedrdrv","tdevflt","trellix","mfemms","mfefire","mfehidk","mfeavfk","mfevtp","enterceptagent",
  "kaspersky","klif","klifks","klflt","klhk","ksld","kneps",
  "avast","avgnt","bdagent","bitdefender","clamav","comodo",
  "ccmsetup","ccmexec","sccm","intune","landesk","altiris","bigfix","tanium","puppet","chef","ansible","salt",
  "google","mozilla","firefox","chrome","adobe","java","oracle","dell","lenovo","vmtools","splunk","elastic","wazuh",
  "printer","spooler","wuauserv","bits","themes","dnscache","dhcp","winrm","winmgmt","msiserver","office","onedrive","teams",
]);

/**
 * Detect outlier hostname (always-flagged patterns only).
 * Returns the reason string or null.
 */
function detectOutlier(hostname) {
  for (const [pat, reason] of OUTLIER_PATS_ALWAYS) {
    if (pat.test(hostname)) return reason;
  }
  return null;
}

/**
 * Build the full outlier host set, including frequency-dependent DESKTOP-* and WIN-* detection.
 */
function buildOutlierSet(hostSet) {
  const outlierHosts = new Set();
  const totalHosts = hostSet.size;
  let defaultWinCount = 0;
  for (const [id] of hostSet) {
    if (DEFAULT_WIN_PAT.test(id)) defaultWinCount++;
  }
  const defaultWinIsMinority = totalHosts > 0 && (defaultWinCount / totalHosts) < 0.2;
  for (const [id] of hostSet) {
    const alwaysOutlier = detectOutlier(id);
    if (alwaysOutlier) {
      outlierHosts.add(id);
    } else if (defaultWinIsMinority && DEFAULT_WIN_PAT.test(id)) {
      outlierHosts.add(id);
    }
  }
  return outlierHosts;
}

// Finding-based technique map for chain/edge enrichment
const FINDING_TECH_MAP = {
  "PsExec Native": "PsExec", "Impacket Execution": "Impacket", "Impacket Summary": "Impacket",
  "Remote Service Execution": "Remote Service",
  "WMI Remote Execution": "WMI", "WMI Remote Activity": "WMI",
  "WinRM Remote Execution": "WinRM", "WinRM Remote Activity": "WinRM",
  "Scheduled Task Remote Execution": "Scheduled Task",
  "Admin Share Access": "Admin Share",
};

module.exports = {
  EXCLUDED_IPS, SERVICE_RE, SESSION_ONLY_EVENTS, RDP_EVENT_DESC,
  DC_PAT, SRV_PAT, OUTLIER_PATS_ALWAYS, DEFAULT_WIN_PAT,
  MGMT_SRC_PAT, SVC_ACCT_PAT, SEV_ORDER, TECH_PRIORITY,
  SUBSTATUS_REASONS, COMMON_SVC,
  detectOutlier, buildOutlierSet,
  FINDING_TECH_MAP,
};
