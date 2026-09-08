/**
 * constants.js — module-scope constants for the lateral-movement analyzer.
 *
 * These were previously declared inline (and lazily) inside the
 * getLateralMovement() closure. They are pure, frozen data / regex literals
 * with no captured state, so hoisting them to module scope is behavior-neutral
 * and removes ~15 inline declarations from the orchestrator. Mirrors the
 * pure-constant pattern already used by the sibling network/ analyzer.
 *
 * Consumers import these and alias them back to their original in-function
 * names (e.g. `DC_PAT: _DC_PAT`) so existing usage sites stay unchanged.
 */

// IPs that are never a meaningful lateral-movement source/target.
const EXCLUDED_IPS = new Set(["-", "::1", "127.0.0.1", "0.0.0.0", ""]);

// Built-in/service principals that are not interactive user accounts.
//
// Extended beyond the five built-ins because real estates are dominated by
// auto-generated service identities that authenticate constantly and produced the
// bulk of the "lateral movement" volume: Exchange health-probe mailboxes
// (HealthMailbox<hex>, and the SM_<hex> system mailboxes), IIS application-pool
// identities, and the Entra/AAD Connect sync accounts (MSOL_<hex>, AAD_<hex>,
// Sync_<host>_<hex>). Each shape is anchored and includes its generated hex/GUID
// suffix, so an attacker cannot hide behind a plain account merely named
// "healthmailbox" or "msol".
const SERVICE_RE = /^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON|IUSR|IWAM_[A-Z0-9-]+|HEALTHMAILBOX[0-9A-F]{8,}|SM_[0-9A-F]{8,}|MSOL_[0-9A-F]{8,}|AAD_[0-9A-F]{8,}|SYNC_[A-Z0-9-]+_[0-9A-F]{8,}|DEFAULTAPPPOOL|\.NET\s*V\d[\d.]*(\s*CLASSIC)?\s*APPPOOL)$/i;

// Account DOMAINS that only ever hold machine/service principals. The username on
// its own cannot identify an IIS application pool ("DefaultAppPool", "MyApp") —
// the domain is what makes it unambiguous, so it is tested separately wherever the
// domain column is available.
const SERVICE_DOMAIN_RE = /^(NT AUTHORITY|NT SERVICE|IIS APPPOOL|WINDOW MANAGER|FONT DRIVER HOST|NT VIRTUAL MACHINE|DWM|UMFD)$/i;

// Events used for RDP session correlation but which do NOT create graph edges.
const SESSION_ONLY_EVENTS = new Set(["20", "23", "24", "32", "33", "34", "35", "39", "40", "4634", "4647", "4672", "4769", "4776", "4779"]);

// Events that can participate in an RDP authentication/session reconstruction.
// General authentication events remain in the main logon graph, but only this
// subset is copied into the RDP state machine.
const RDP_CONTEXT_EVENT_IDS = new Set([
  "20", "21", "22", "23", "24", "25", "32", "33", "34", "35", "39", "40",
  "1149", "4624", "4625", "4634", "4647", "4648", "4672", "4776", "4778", "4779",
]);

// TerminalServices session event IDs that collide with other providers. Sysmon
// uses 1-29 for entirely different records (22 = DNS query, 23 = file delete,
// 24 = clipboard change, 25 = process tampering), so on a consolidated export —
// an EvtxECmd CSV or a Hayabusa run covering every channel — these IDs are
// ambiguous and MUST be qualified by channel before they are read as RDP.
const TERMSVC_AMBIGUOUS_EIDS = new Set(["20", "21", "22", "23", "24", "25", "32", "33", "34", "35", "39", "40", "131", "140"]);

// Channel substrings (lowercased) that legitimately emit the IDs above. Covers
// the full Windows channel names and Hayabusa's RDS-LSM / RDS-RCM short codes.
const TERMSVC_CHANNEL_HINTS = [
  "localsessionmanager", "remoteconnectionmanager", "terminalservices", "rds-lsm", "rds-rcm",
  // RdpCoreTS carries the NLA-era connection and authentication-failure events
  // (131 accepted, 140 bad username/password) and lives under a different product
  // name, so the TerminalServices hints above do not cover it.
  "rdpcorets", "rdp-corets", "remotedesktopservices",
];

// RDP session shadowing. The analyzer keyed this on LocalSessionManager 20/32-35,
// which are not shadow events at all; the real ones are RemoteConnectionManager
// /Admin 20503 (shadow session started) and 20504 (shadow session stopped).
const RDP_SHADOW_EIDS = new Set(["20503", "20504"]);

// RdpCoreTS: 131 = TCP connection accepted from a client, 140 = the connection
// failed because the username or password was wrong. 140 is the ONLY event that
// identifies an RDP authentication failure once NLA is enabled, because NLA makes
// Windows log the failure as a Security 4625 with LogonType 3 (network) rather
// than 10 — which is why RDP brute force was being reported as network brute force.
const RDP_CORETS_EIDS = new Set(["131", "140"]);

// Human-readable descriptions for RDP/logon event IDs.
const RDP_EVENT_DESC = {
  "1149": "RDP connection established (auth not proven)", "4624": "Logon succeeded", "4625": "Logon failed",
  "21": "Session logon succeeded", "22": "Shell start notification", "23": "Session logoff",
  "24": "Session disconnected", "25": "Session reconnected", "39": "Disconnected by another session",
  "40": "Session disconnect (reason code)", "4634": "Account logged off", "4647": "User-initiated logoff",
  "4648": "Explicit credentials used", "4672": "Admin privileges assigned",
  "4776": "NTLM authentication", "4778": "Session reconnected (window station)", "4779": "Session disconnected (window station)",
};

// Hostname pattern → likely Domain Controller.
const DC_PAT = /(?:^|[\-_])(DC|PDC|BDC|ADDS|ADCS|ADFS)\d{0,3}(?:$|[\-_])|^AD\d{0,3}$/i;

// Hostname pattern → likely server role.
const SRV_PAT = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)(?=[_\-\d]|$)/i;

// Hostname pattern → privileged-access / management workstation (jump/bastion/PAM/orchestration).
const MGMT_SRC_PAT = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|MONITOR|NAGIOS|ZABBIX|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;

// Severity ordering for sorting findings (lower = more severe).
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

// Telemetry coverage categories — which event IDs constitute each detection capability.
const TELEMETRY_CATEGORIES = [
  { id: "auth",     label: "Auth (Logon)",      eids: ["4624", "4625"], critical: true },
  { id: "explicit", label: "Explicit Creds",    eids: ["4648"],         critical: false },
  { id: "process",  label: "Process Creation",  eids: ["4688", "1"],    critical: true },
  { id: "service",  label: "Service Install",   eids: ["7045", "4697"], critical: false },
  { id: "task",     label: "Scheduled Task",    eids: ["4698"],         critical: false },
  { id: "rdp",      label: "RDP Session",       eids: ["1149", "21", "22", "25"], critical: false },
  { id: "share",    label: "Share Access",      eids: ["5140", "5145"], critical: false },
  { id: "kerberos", label: "Kerberos",          eids: ["4769", "4768", "4771"], critical: false },
  { id: "ntlm",     label: "NTLM",              eids: ["4776"],         critical: false },
  { id: "dsaccess", label: "DS Access",         eids: ["4662"],         critical: false },
  { id: "sysmon10", label: "Process Access",    eids: ["10"],           critical: false },
];

// Account-name pattern → privileged identity (administrator/root/domain-admin/etc.).
const PRIVILEGED_NAME_RE = /^(ADMINISTRATOR|ADMIN|ROOT|DA[_-]|DOMAIN ADMIN|ENTERPRISE ADMIN|SCHEMA ADMIN|BACKUP)/i;

module.exports = {
  EXCLUDED_IPS,
  SERVICE_RE,
  SERVICE_DOMAIN_RE,
  SESSION_ONLY_EVENTS,
  RDP_CONTEXT_EVENT_IDS,
  TERMSVC_AMBIGUOUS_EIDS,
  TERMSVC_CHANNEL_HINTS,
  RDP_SHADOW_EIDS,
  RDP_CORETS_EIDS,
  RDP_EVENT_DESC,
  DC_PAT,
  SRV_PAT,
  MGMT_SRC_PAT,
  SEV_ORDER,
  TELEMETRY_CATEGORIES,
  PRIVILEGED_NAME_RE,
};
