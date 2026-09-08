/**
 * analyzers/evtx-utils.js — Shared EVTX field parsing utilities
 *
 * Extracted from TimelineDB class methods. Used by all analyzers
 * (lateral-movement, persistence, process-tree) for dataset detection,
 * compact key-value parsing, channel normalization, and field cleanup.
 */

const { getCompactAliasDefinitions } = require("../utils/dfir-event-fields");

function _isHayabusaDataset(metaOrHeaders) {
  const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
  if (!Array.isArray(headers) || headers.length === 0) return false;
  const has = (re) => headers.some((h) => re.test(h));
  return has(/^RuleTitle$/i) && has(/^Details$/i) && has(/^EventID$/i) && has(/^Channel$/i);
}

function _isChainsawDataset(metaOrHeaders) {
  const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
  if (!Array.isArray(headers) || headers.length === 0) return false;
  const has = (re) => headers.some((h) => re.test(h));
  return has(/^system_time$/i) && has(/^id$/i)
    && (has(/^detection_rules$/i) || has(/^computer_name$/i) || has(/^workstation_name$/i));
}

function _isChainsawProcessDataset(metaOrHeaders) {
  const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
  if (!_isChainsawDataset(headers)) return false;
  const has = (re) => headers.some((h) => re.test(h));
  return has(/^process_name$/i)
    || has(/^Event\.EventData\.Image$/i)
    || has(/^command_line$/i)
    || has(/^Event\.EventData\.CommandLine$/i);
}

function _isChainsawLogonDataset(metaOrHeaders) {
  const headers = Array.isArray(metaOrHeaders) ? metaOrHeaders : metaOrHeaders?.headers;
  if (!_isChainsawDataset(headers)) return false;
  const has = (re) => headers.some((h) => re.test(h));
  return has(/^target_username$/i)
    && has(/^logon_type$/i)
    && (has(/^source_ip$/i) || has(/^workstation_name$/i));
}

function _cleanWrappedField(value, options = {}) {
  const { lineJoiner = "" } = options;
  if (value == null) return "";
  let s = String(value).replace(/\u0000/g, "");
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  s = s.replace(/\n+/g, lineJoiner);
  s = s.trim();
  while (s.length >= 2 && (
    (s.startsWith('"') && s.endsWith('"'))
    || (s.startsWith("'") && s.endsWith("'"))
  )) {
    s = s.slice(1, -1).trim();
  }
  return s;
}

function _normalizeCompactKey(key) {
  return String(key || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function _parseCompactKeyValues(...texts) {
  const map = new Map();
  for (const text of texts) {
    if (!text) continue;
    const parts = String(text).split(/\s*[¦\r\n]+\s*/);
    for (const rawPart of parts) {
      const part = rawPart.trim();
      if (!part) continue;
      const idx = part.indexOf(":");
      if (idx <= 0) continue;
      const key = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      if (!key || !value) continue;
      const norm = _normalizeCompactKey(key);
      if (!norm || map.has(norm)) continue;
      map.set(norm, value);
    }
  }
  return map;
}

function _compactGet(map, ...aliases) {
  if (!(map instanceof Map) || map.size === 0) return "";
  for (const alias of aliases) {
    const norm = _normalizeCompactKey(alias);
    if (!norm) continue;
    const value = map.get(norm);
    if (value != null) {
      const trimmed = String(value).trim();
      if (trimmed !== "" && trimmed !== "-") return trimmed;
    }
  }
  return "";
}

function _extractFirstInteger(value) {
  if (value == null) return "";
  const s = String(value).trim();
  if (!s) return "";
  if (/^0x[0-9a-f]+$/i.test(s)) return String(parseInt(s, 16));
  const m = s.match(/0x[0-9a-f]+|\d+/i);
  if (!m) return "";
  if (/^0x/i.test(m[0])) return String(parseInt(m[0], 16));
  return m[0];
}

function _compactGetInt(map, ...aliases) {
  for (const alias of aliases) {
    const value = _compactGet(map, alias);
    const parsed = _extractFirstInteger(value);
    if (parsed) return parsed;
  }
  return "";
}

function _normalizeEvtxChannel(channel) {
  const raw = String(channel || "").trim().toLowerCase();
  if (!raw) return "";
  if (raw === "sec" || raw.includes("security")) return "security";
  if (raw === "sys" || raw.includes("system")) return "system";
  if (raw.includes("sysmon")) return "sysmon";
  if (raw === "tasksch" || raw.includes("taskscheduler") || raw.includes("task scheduler")) return "taskscheduler";
  if (raw === "pwsh" || raw.includes("powershell")) return "powershell";
  if (raw === "wmi" || raw.includes("wmi-activity")) return "wmi-activity";
  if (raw === "winrm" || raw.includes("winrm")) return "winrm";
  // Hayabusa rewrites the channel to a short code from
  // rules/config/channel_abbreviations.txt, so the full-name checks below never
  // match its output. Without these two the TerminalServices channel of a
  // Hayabusa CSV is unrecognisable, and any channel gate keyed on it silently
  // drops every RDP session row.
  if (raw === "rds-lsm" || raw === "rdslsm") return "localsessionmanager";
  if (raw === "rds-rcm" || raw === "rdsrcm") return "remoteconnectionmanager";
  if (raw.includes("localsessionmanager")) return "localsessionmanager";
  if (raw.includes("remoteconnectionmanager")) return "remoteconnectionmanager";
  return raw;
}

function _resolveEventChannel(row) {
  const explicit = row?.channel || row?.provider || row?._channel;
  const normalized = _normalizeEvtxChannel(explicit);
  if (normalized) return normalized;

  const eventId = _extractFirstInteger(row?.eventId || row?.id);
  if (!eventId) return "";

  const hasLmShape = !!(row?.source || row?.workstation || row?.user || row?.logonType);
  if (eventId === "1149") return "remoteconnectionmanager";
  if (hasLmShape && ["21", "22", "23", "24", "25", "39", "40"].includes(eventId)) return "localsessionmanager";
  if (["1", "6", "7", "11", "12", "13", "14", "19", "20", "21", "25"].includes(eventId)) return "sysmon";
  if (["7040", "7045", "7035", "7036"].includes(eventId)) return "system";
  if (["106", "118", "119", "129", "140", "141", "200"].includes(eventId)) return "taskscheduler";
  if (eventId === "4104") return "powershell";
  if (["4624", "4625", "4634", "4647", "4648", "4657", "4672", "4688", "4689", "4697", "4698", "4699", "4702", "4720", "4724", "4728", "4732", "4738", "4756", "4769", "4778", "4779", "5136", "5137", "5140", "5141", "5145"].includes(eventId)) return "security";
  // Defender (Microsoft-Windows-Windows Defender/Operational) and WMI-Activity. Without these,
  // a Chainsaw / raw-EVTX export with a blank <Channel> resolves to "" and the persistence
  // analyzer's channel gate silently DROPS the entire Defender-tamper + critical WMI-subscription
  // rules. These EIDs are unambiguous, so map them by event id when the channel is missing.
  if (["5001", "5007", "5010", "5012", "5101"].includes(eventId)) return "defender";
  // WMI-Activity and WinRM Operational. Same reasoning as Defender above: a raw-EVTX or
  // Chainsaw export with a blank <Channel> would otherwise resolve to "" and the
  // channel gate would drop the remote-execution rules entirely. Only consulted when the
  // channel is genuinely absent, so a differently-provided 145/169 is unaffected.
  if (["5857", "5858", "5860", "5861"].includes(eventId)) return "wmi-activity";
  if (["142", "145", "161", "169"].includes(eventId)) return "winrm";
  return "";
}

function _evtxChannelMatches(channel, wantedChannels = []) {
  if (!wantedChannels || wantedChannels.length === 0) return true;
  const raw = String(channel || "").toLowerCase();
  const norm = _normalizeEvtxChannel(channel);
  return wantedChannels.some((wanted) => {
    const needle = String(wanted || "").trim().toLowerCase();
    if (!needle) return false;
    if (raw.includes(needle) || norm.includes(needle)) return true;
    if (needle === "security" && norm === "security") return true;
    if (needle === "system" && norm === "system") return true;
    if (needle === "sysmon" && norm === "sysmon") return true;
    if (needle === "taskscheduler" && norm === "taskscheduler") return true;
    if (needle === "powershell" && norm === "powershell") return true;
    if (needle === "wmi-activity" && norm === "wmi-activity") return true;
    if (needle === "winrm" && norm === "winrm") return true;
    return false;
  });
}

function _buildCompactAliasBlob(map) {
  if (!(map instanceof Map) || map.size === 0) return "";
  const parts = [];
  const add = (label, ...aliases) => {
    const value = _compactGet(map, ...aliases);
    if (value) parts.push(`${label}: ${value}`);
  };

  for (const { label, aliases } of getCompactAliasDefinitions()) {
    add(label, ...aliases);
  }

  return parts.join(" | ");
}

function _buildChainsawAliasBlob(row) {
  const parts = [];
  const add = (label, value, options = {}) => {
    const cleaned = _cleanWrappedField(value, options);
    if (cleaned) parts.push(`${label}: ${cleaned}`);
  };

  add("RuleTitle", row.ruleTitle || row.detectionRule, { lineJoiner: " | " });
  add("Computer", row.computer || row.hostname);
  add("Image", row.image);
  add("CommandLine", row.cmdLine);
  add("TargetFilename", row.targetFilename);
  add("TargetObject", row.targetObject);
  add("Details", row.details);
  add("IpAddress", row.source);
  add("WorkstationName", row.workstation);
  add("TargetUserName", row.user);
  add("LogonType", row.logonType);

  return parts.join(" | ");
}

// Raw .evtx EventData fields that detection rules (esp. persistence) match on. For
// EvtxECmd/Hayabusa these live inside payload/details and are already in the haystack;
// for the app's own raw-EVTX parser each is a SEPARATE column. Analyzers detect these
// columns (via the `aliases`) into row[key], and we serialize them here under the
// canonical `label` so rule extractors `P("Field")` and payloadFilters still match.
// Without this, payloadFilter-gated raw-EVTX rules (e.g. Sysmon EID 6/7 driver/DLL
// signature checks, AD 5136/5137/5141, Security 4657) silently never fire.
const RAW_EVTX_HAYSTACK_FIELDS = [
  { key: "evSigned", label: "Signed", aliases: [/^Signed$/i] },
  { key: "evSignatureStatus", label: "SignatureStatus", aliases: [/^SignatureStatus$/i] },
  { key: "evSigner", label: "Signer", aliases: [/^Signer$/i] },
  { key: "evImageLoaded", label: "ImageLoaded", aliases: [/^ImageLoaded$/i] },
  { key: "evNewName", label: "NewName", aliases: [/^NewName$/i] },
  { key: "evEventType", label: "EventType", aliases: [/^EventType$/i] },
  { key: "evTargetUserName", label: "TargetUserName", aliases: [/^TargetUserName$/i] },
  { key: "evSubjectUserName", label: "SubjectUserName", aliases: [/^SubjectUserName$/i] },
  { key: "evMemberName", label: "MemberName", aliases: [/^MemberName$/i] },
  { key: "evSamAccountName", label: "SamAccountName", aliases: [/^SamAccountName$/i, /^SAMAccountName$/i] },
  { key: "evObjectName", label: "ObjectName", aliases: [/^ObjectName$/i] },
  { key: "evObjectValueName", label: "ObjectValueName", aliases: [/^ObjectValueName$/i] },
  { key: "evNewValue", label: "NewValue", aliases: [/^NewValue$/i] },
  { key: "evOldValue", label: "OldValue", aliases: [/^OldValue$/i] },
  { key: "evObjectDN", label: "ObjectDN", aliases: [/^ObjectDN$/i] },
  { key: "evObjectClass", label: "ObjectClass", aliases: [/^ObjectClass$/i] },
  { key: "evAttributeLDAPDisplayName", label: "AttributeLDAPDisplayName", aliases: [/^AttributeLDAPDisplayName$/i] },
  { key: "evAttributeValue", label: "AttributeValue", aliases: [/^AttributeValue$/i] },
  { key: "evOperationType", label: "OperationType", aliases: [/^OperationType$/i] },
  { key: "evServiceName", label: "ServiceName", aliases: [/^ServiceName$/i] },
  { key: "evImagePath", label: "ImagePath", aliases: [/^ImagePath$/i] },
  { key: "evServiceFileName", label: "ServiceFileName", aliases: [/^ServiceFileName$/i] },
  { key: "evServiceType", label: "ServiceType", aliases: [/^ServiceType$/i] },
  { key: "evStartType", label: "StartType", aliases: [/^StartType$/i] },
  { key: "evServiceStartType", label: "ServiceStartType", aliases: [/^ServiceStartType$/i] },
  { key: "evAccountName", label: "AccountName", aliases: [/^AccountName$/i] },
  { key: "evServiceAccount", label: "ServiceAccount", aliases: [/^ServiceAccount$/i] },
  { key: "evProcessName", label: "ProcessName", aliases: [/^ProcessName$/i] },
  { key: "evScriptPath", label: "ScriptPath", aliases: [/^ScriptPath$/i] },
  { key: "evNewUacValue", label: "NewUacValue", aliases: [/^NewUacValue$/i] },
  { key: "evUserAccountControl", label: "UserAccountControl", aliases: [/^UserAccountControl$/i] },
  // --- Task Scheduler (Microsoft-Windows-TaskScheduler/Operational) ---
  // Raw .evtx puts the task identity in TaskName (106/140/141/129/200/118/119) and the
  // action in Path (129) / ActionName (200). Without these the persistence rules'
  // P("Task")/P("TaskName")/P("Name") extractors match nothing and EVERY scheduled-task
  // finding comes back with an empty artifact — which also defeats the
  // LEGIT_TASK_PREFIXES suppression (an empty artifact can never match ^\Microsoft\),
  // so thousands of benign taskhostw runs surface at high severity.
  { key: "evTaskName", label: "TaskName", aliases: [/^TaskName$/i] },
  { key: "evTaskPath", label: "Path", aliases: [/^Path$/i] },
  { key: "evActionName", label: "ActionName", aliases: [/^ActionName$/i] },
  { key: "evTaskInstanceId", label: "TaskInstanceId", aliases: [/^TaskInstanceId$/i, /^InstanceId$/i] },
  { key: "evTaskProcessId", label: "ProcessID", aliases: [/^ProcessID$/i] },
  { key: "evUserContext", label: "UserContext", aliases: [/^UserContext$/i] },
  { key: "evTaskContent", label: "TaskContent", aliases: [/^TaskContent$/i] },
  { key: "evTaskContentNew", label: "TaskContentNew", aliases: [/^TaskContentNew$/i] },
  // --- Service Control Manager (System log, EID 7040/7036/7035/7000) ---
  // 7040 carries the display name in param1, the old/new start type in param2/param3 and
  // the SERVICE name in param4; 7036/7035 carry the display name in param1. These are the
  // only fields those events have, so without them a raw-EVTX 7040 produces an anonymous
  // high-severity item and the 7036 service-start correlation never matches.
  { key: "evParam1", label: "param1", aliases: [/^param1$/i] },
  { key: "evParam2", label: "param2", aliases: [/^param2$/i] },
  { key: "evParam3", label: "param3", aliases: [/^param3$/i] },
  { key: "evParam4", label: "param4", aliases: [/^param4$/i] },
  // --- Process creation (Security 4688, Sysmon 1) ---
  // These are correlation-only events: the persistence analyzer never reports them, it uses
  // them to promote a service install from "present" to "confirmed". Without the image and
  // parent in the haystack that promotion can never happen on raw .evtx, no matter how many
  // files are merged — the correlation regexes have nothing to match.
  { key: "evNewProcessName", label: "NewProcessName", aliases: [/^NewProcessName$/i] },
  { key: "evParentProcessName", label: "ParentProcessName", aliases: [/^ParentProcessName$/i] },
  { key: "evParentImage", label: "ParentImage", aliases: [/^ParentImage$/i] },
  { key: "evParentCommandLine", label: "ParentCommandLine", aliases: [/^ParentCommandLine$/i] },
  // --- PowerShell script block logging (4104) ---
  // Reassembly keys on ScriptBlockId + MessageNumber/MessageTotal; the text is the evidence.
  { key: "evScriptBlockText", label: "ScriptBlockText", aliases: [/^ScriptBlockText$/i] },
  { key: "evScriptBlockId", label: "ScriptBlockId", aliases: [/^ScriptBlockId$/i] },
  { key: "evMessageNumber", label: "MessageNumber", aliases: [/^MessageNumber$/i] },
  { key: "evMessageTotal", label: "MessageTotal", aliases: [/^MessageTotal$/i] },
  { key: "evHostApplication", label: "HostApplication", aliases: [/^HostApplication$/i] },
  // --- Remote execution context (WinRM Operational, WMI-Activity, Security logons) ---
  // These name the machine on the OTHER end of a remote operation. They are what turns
  // "a service was installed here" into "a service was installed here BY that host", which
  // is the join key between a persistence artifact and a lateral-movement edge.
  { key: "evClientMachine", label: "ClientMachine", aliases: [/^ClientMachine$/i] },
  { key: "evClientMachineFqdn", label: "ClientMachineFQDN", aliases: [/^ClientMachineFQDN$/i] },
  { key: "evClientProcessId", label: "ClientProcessId", aliases: [/^ClientProcessId$/i] },
  { key: "evProviderName", label: "ProviderName", aliases: [/^ProviderName$/i] },
  { key: "evPossibleCause", label: "PossibleCause", aliases: [/^PossibleCause$/i] },
  { key: "evAuthMechanism", label: "AuthenticationMechanism", aliases: [/^AuthenticationMechanism$/i] },
  { key: "evTargetLogonId", label: "TargetLogonId", aliases: [/^TargetLogonId$/i] },
  { key: "evSubjectLogonId", label: "SubjectLogonId", aliases: [/^SubjectLogonId$/i] },
  { key: "evLogonProcessName", label: "LogonProcessName", aliases: [/^LogonProcessName$/i] },
  { key: "evOperationName", label: "operationName", aliases: [/^operationName$/i] },
  // --- WMI (Sysmon 19/20/21, WMI-Activity 5861) ---
  { key: "evWmiName", label: "Name", aliases: [/^Name$/i] },
  { key: "evWmiQuery", label: "Query", aliases: [/^Query$/i] },
  { key: "evWmiConsumer", label: "Consumer", aliases: [/^Consumer$/i] },
  { key: "evWmiFilter", label: "Filter", aliases: [/^Filter$/i] },
  { key: "evWmiDestination", label: "Destination", aliases: [/^Destination$/i] },
  { key: "evWmiNamespace", label: "EventNamespace", aliases: [/^EventNamespace$/i] },
  { key: "evWmiOperation", label: "Operation", aliases: [/^Operation$/i] },
  { key: "evWmiType", label: "Type", aliases: [/^Type$/i] },
];

function _buildRawEvtxFieldBlob(row) {
  if (!row) return "";
  const parts = [];
  for (const { key, label } of RAW_EVTX_HAYSTACK_FIELDS) {
    const v = _cleanWrappedField(row[key]);
    if (v) parts.push(`${label}: ${v}`);
  }
  return parts.join(" | ");
}

function _buildEvtxHaystack(row) {
  const baseParts = [
    row.payload, row.payload2, row.payload3, row.payload4, row.payload5, row.payload6,
    row.mapDesc, row.execInfo, row.details, row.extra, row.ruleTitle, row.detectionRule,
  ].filter(Boolean);
  const compactMap = _parseCompactKeyValues(row.details, row.extra);
  const aliasBlob = _buildCompactAliasBlob(compactMap);
  if (aliasBlob) baseParts.push(aliasBlob);
  const chainsawAliasBlob = _buildChainsawAliasBlob(row);
  if (chainsawAliasBlob) baseParts.push(chainsawAliasBlob);
  const rawEvtxBlob = _buildRawEvtxFieldBlob(row);
  if (rawEvtxBlob) baseParts.push(rawEvtxBlob);
  return baseParts.join(" | ");
}

// Export with both underscore names (internal) and clean names (for ctx objects)
module.exports = {
  _isHayabusaDataset, isHayabusaDataset: _isHayabusaDataset,
  _isChainsawDataset, isChainsawDataset: _isChainsawDataset,
  _isChainsawProcessDataset, isChainsawProcessDataset: _isChainsawProcessDataset,
  _isChainsawLogonDataset, isChainsawLogonDataset: _isChainsawLogonDataset,
  _cleanWrappedField, cleanWrappedField: _cleanWrappedField,
  _normalizeCompactKey, normalizeCompactKey: _normalizeCompactKey,
  _parseCompactKeyValues, parseCompactKeyValues: _parseCompactKeyValues,
  _compactGet, compactGet: _compactGet,
  _extractFirstInteger, extractFirstInteger: _extractFirstInteger,
  _compactGetInt, compactGetInt: _compactGetInt,
  _normalizeEvtxChannel, normalizeEvtxChannel: _normalizeEvtxChannel,
  _resolveEventChannel, resolveEventChannel: _resolveEventChannel,
  _evtxChannelMatches, evtxChannelMatches: _evtxChannelMatches,
  _buildCompactAliasBlob, buildCompactAliasBlob: _buildCompactAliasBlob,
  _buildChainsawAliasBlob, buildChainsawAliasBlob: _buildChainsawAliasBlob,
  _buildRawEvtxFieldBlob, buildRawEvtxFieldBlob: _buildRawEvtxFieldBlob,
  _buildEvtxHaystack, buildEvtxHaystack: _buildEvtxHaystack,
  RAW_EVTX_HAYSTACK_FIELDS,
};
