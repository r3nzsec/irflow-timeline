/**
 * detector-registry.js — the single source of truth for which events each
 * lateral-movement detector needs.
 *
 * Why this exists: the event-id list used to be written out by hand in four places that
 * drifted apart — the analyzer default (index.js), the multi-source default
 * (multi-source.js), the pre-flight preview (db.js) and the renderer's rule table
 * (LateralMovementModal.jsx). The renderer's copy was the narrowest, and because it
 * always passed `eventIds` explicitly it won. The result was that Admin Share Access
 * (5140/5145), Remote Execution Sequence (which needs a share step), Kerberos brute
 * force (4771), RDP shadow/session-takeover (20/32-35) and the NTLM correlation signal
 * (4776) could never fire in production — while the pre-flight panel cheerfully
 * reported how many of those events the dataset contained.
 *
 * Detectors now declare what they consume and every consumer derives from that.
 *
 * Acquisition modes (a detector uses exactly one):
 *   spineEids     — served by the single main query, parsed into timeOrdered/the graph
 *   scanFamilies  — served by the stratified process/service scan (see
 *                   detectors/process-service-scan.js, which owns the family -> eid table)
 *   ownQueryEids  — the detector issues its own scoped query
 *
 * `id` doubles as the value callers put in `options.disabledDetectors`. Ids that already
 * shipped as disable keys (rmm, schtask, kerberoast, asreproast, dcsync, cobaltstrike,
 * lsass, regsave, portproxy, wmisub) MUST keep their spelling — they are a public option.
 */

const DETECTORS = [
  // ── Spine: authentication graph ───────────────────────────────────────────────
  {
    id: "logon-graph",
    label: "Logon Graph",
    findingCategories: [],
    mitre: [],
    spineEids: ["4624", "4634", "4647"],
    uiGroup: "Auth",
    // Not toggleable: without successful logons there is no graph, no accounts and
    // nothing for any other detector to correlate against.
    toggleable: false,
    core: true,
  },
  {
    id: "bruteforce",
    label: "Brute Force",
    findingCategories: ["Brute Force"],
    mitre: ["T1110.001"],
    spineEids: ["4625", "4771"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "password-spray",
    label: "Password Spray",
    findingCategories: ["Password Spray"],
    mitre: ["T1110.003"],
    spineEids: ["4625", "4624"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "cred-compromise",
    label: "Credential Compromise",
    findingCategories: ["Credential Compromise"],
    mitre: ["T1078"],
    spineEids: ["4625", "4624", "4648"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "alternate-creds",
    label: "Alternate Credentials / Overpass-the-Hash",
    findingCategories: ["Alternate Credentials"],
    mitre: ["T1550.002", "T1078"],
    // Type 9 (NewCredentials) logons. These are always logged with workstation ==
    // computer, so they were being removed by the local-logon filter before any
    // detector saw them.
    spineEids: ["4624", "4648"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "explicit-creds",
    label: "Explicit Credentials (RunAs)",
    findingCategories: [],
    mitre: ["T1078"],
    spineEids: ["4648"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "admin-priv",
    label: "Admin Privileges Assigned",
    findingCategories: [],
    mitre: [],
    spineEids: ["4672"],
    uiGroup: "Auth",
    toggleable: true,
  },
  {
    id: "ntlm",
    label: "NTLM Authentication",
    findingCategories: ["Operator Host"],
    mitre: ["T1078"],
    // Feeds RDP pre-auth correlation and the Operator Host signal.
    spineEids: ["4776"],
    uiGroup: "Auth",
    toggleable: true,
  },

  // ── Spine: RDP ────────────────────────────────────────────────────────────────
  {
    id: "rdp-sessions",
    label: "RDP Sessions",
    findingCategories: ["Concurrent RDP Sessions", "Tunnelled RDP"],
    mitre: ["T1021.001"],
    // The session state machine needs the whole lifecycle. Dropping individual ids
    // here does not reduce findings, it silently breaks session reconstruction.
    spineEids: ["1149", "21", "22", "23", "24", "25", "39", "40", "4778", "4779"],
    uiGroup: "RDP",
    toggleable: true,
  },
  {
    id: "rdp-shadow",
    label: "RDP Shadow / Session Takeover",
    findingCategories: ["RDP Session Shadowing"],
    mitre: ["T1021.001"],
    // 20503/20504 are the actual shadow events (RemoteConnectionManager/Admin).
    // 20/32-35 were the original list and are kept only because a handful of
    // exports label session-takeover rows that way; they are channel-gated, so
    // they can no longer pull in unrelated providers' small event ids.
    spineEids: ["20503", "20504", "20", "32", "33", "34", "35"],
    uiGroup: "RDP",
    toggleable: true,
  },
  {
    id: "rdp-nla-failures",
    label: "RDP Auth Failures (NLA)",
    findingCategories: ["RDP Brute Force"],
    mitre: ["T1110.001", "T1021.001"],
    // With NLA on — the default since Windows 8 / Server 2012 — a failed RDP logon
    // is written as a Security 4625 with LogonType 3, indistinguishable from an SMB
    // or LDAP failure. RdpCoreTS 140 is the event that names it as RDP.
    spineEids: ["131", "140"],
    uiGroup: "RDP",
    toggleable: true,
  },

  // ── Spine: SMB ────────────────────────────────────────────────────────────────
  {
    id: "adminshare",
    label: "Admin Share Access",
    findingCategories: ["Admin Share Access", "Remote Execution Sequence"],
    mitre: ["T1021.002", "T1569.002"],
    spineEids: ["5140", "5145"],
    uiGroup: "Share Access",
    toggleable: true,
  },

  // ── Spine: Kerberos service tickets (telemetry + session correlation) ─────────
  {
    id: "kerberos-tickets",
    label: "Kerberos Service Tickets",
    findingCategories: [],
    mitre: [],
    spineEids: ["4769"],
    uiGroup: "Kerberos",
    toggleable: true,
  },

  // ── Stratified scan families ─────────────────────────────────────────────────
  {
    id: "remote-exec",
    label: "Remote Execution (PsExec / Impacket / WMI / WinRM / DCOM / SSH)",
    findingCategories: [
      "PsExec Execution", "Impacket Execution", "Impacket Credential Access",
      "Remote Service Execution", "DCOM Remote Execution", "WMI Remote Execution",
      "WinRM Remote Execution", "SSH Remote Access", "SSH Tunneling",
    ],
    mitre: ["T1569.002", "T1047", "T1021.006", "T1021.003", "T1021.004", "T1572"],
    scanFamilies: ["process", "service"],
    uiGroup: "Execution",
    // Individually un-toggleable today: these all share the process/service families.
    toggleable: false,
  },
  {
    id: "rmm",
    label: "RMM / Remote Access Tools",
    findingCategories: ["RMM Tool"],
    mitre: ["T1219"],
    scanFamilies: ["process", "service"],
    uiGroup: "Execution",
    toggleable: true,
  },
  {
    id: "schtask",
    label: "Scheduled Task Remote Execution",
    findingCategories: ["Scheduled Task Execution"],
    mitre: ["T1053.005"],
    scanFamilies: ["task", "process"],
    uiGroup: "Execution",
    toggleable: true,
  },
  {
    id: "cobaltstrike",
    label: "Cobalt Strike Indicators",
    findingCategories: ["Cobalt Strike"],
    mitre: ["T1055"],
    scanFamilies: ["process", "namedpipe", "createthread", "service"],
    uiGroup: "Execution",
    toggleable: true,
  },
  {
    id: "wmisub",
    label: "WMI Event Subscription",
    findingCategories: ["WMI Event Subscription"],
    mitre: ["T1546.003"],
    scanFamilies: ["wmisub"],
    uiGroup: "Execution",
    toggleable: true,
  },
  {
    id: "lsass",
    label: "LSASS Direct Access",
    findingCategories: ["LSASS Access"],
    mitre: ["T1003.001"],
    scanFamilies: ["openprocess"],
    uiGroup: "Credential Access",
    toggleable: true,
  },
  {
    id: "regsave",
    label: "SAM / LSA Registry Dump",
    findingCategories: ["Credential Theft"],
    mitre: ["T1003.002"],
    scanFamilies: ["process"],
    uiGroup: "Credential Access",
    toggleable: true,
  },
  {
    id: "portproxy",
    label: "Port Forwarding",
    findingCategories: ["Port Forwarding"],
    mitre: ["T1090.001"],
    scanFamilies: ["process"],
    uiGroup: "Execution",
    toggleable: true,
  },

  // ── Own-query credential attacks ─────────────────────────────────────────────
  {
    id: "kerberoast",
    label: "Kerberoasting",
    findingCategories: ["Kerberoasting"],
    mitre: ["T1558.003"],
    ownQueryEids: ["4769"],
    uiGroup: "Kerberos",
    toggleable: true,
  },
  {
    id: "asreproast",
    label: "AS-REP Roasting",
    findingCategories: ["AS-REP Roasting"],
    mitre: ["T1558.004"],
    ownQueryEids: ["4768"],
    uiGroup: "Kerberos",
    toggleable: true,
  },
  {
    id: "dcsync",
    label: "DCSync",
    findingCategories: ["DCSync"],
    mitre: ["T1003.006"],
    ownQueryEids: ["4662"],
    uiGroup: "Credential Access",
    toggleable: true,
  },
];

const _uniq = (values) => [...new Set(values)];

/** Every event id the main spine query must fetch when all detectors are enabled. */
const SPINE_EVENT_IDS = _uniq(DETECTORS.flatMap((d) => d.spineEids || []));

/** Scan-family labels in use, for cross-checking against process-service-scan.js. */
const SCAN_FAMILY_IDS = _uniq(DETECTORS.flatMap((d) => d.scanFamilies || []));

/** Event ids fetched by detectors that run their own queries. */
const OWN_QUERY_EVENT_IDS = _uniq(DETECTORS.flatMap((d) => d.ownQueryEids || []));

/**
 * Event ids the pre-flight preview counts. This is deliberately broader than the spine:
 * the analyst should see process/service/task volume too, since those drive the scan
 * families. It must be a superset of SPINE_EVENT_IDS or the preview would under-report
 * events the analysis is about to use — the exact mismatch this module exists to prevent.
 */
const PREVIEW_EVENT_IDS = _uniq([
  ...SPINE_EVENT_IDS,
  ...OWN_QUERY_EVENT_IDS,
  "4688", "1",       // process creation
  "7045", "4697",    // service install
  "4698",            // scheduled task
]);

/**
 * Resolve the spine event ids for a run.
 *
 * An event id survives if at least one ENABLED detector needs it, so disabling a
 * detector only drops ids nothing else claims (4625 stays for Password Spray even
 * with Brute Force off). Core detectors are never dropped.
 *
 * @param {Iterable<string>} disabledDetectors ids from options.disabledDetectors
 * @param {Iterable<string>} [extraEventIds]   caller-supplied additions (custom rules)
 * @returns {string[]}
 */
function resolveSpineEventIds(disabledDetectors = [], extraEventIds = []) {
  const disabled = new Set([...disabledDetectors].map(String));
  const out = new Set();
  for (const d of DETECTORS) {
    if (!d.spineEids) continue;
    if (d.toggleable && !d.core && disabled.has(d.id)) continue;
    for (const eid of d.spineEids) out.add(eid);
  }
  for (const eid of extraEventIds) {
    const v = String(eid).trim();
    if (v) out.add(v);
  }
  return [...out];
}

/** Detectors grouped for display, so the UI can render availability without its own table. */
function buildDetectorCatalog() {
  return DETECTORS.map((d) => ({
    id: d.id,
    label: d.label,
    uiGroup: d.uiGroup,
    toggleable: !!d.toggleable,
    core: !!d.core,
    mitre: d.mitre || [],
    findingCategories: d.findingCategories || [],
    eventIds: _uniq([...(d.spineEids || []), ...(d.ownQueryEids || [])]),
    scanFamilies: d.scanFamilies || [],
  }));
}

module.exports = {
  DETECTORS,
  SPINE_EVENT_IDS,
  SCAN_FAMILY_IDS,
  OWN_QUERY_EVENT_IDS,
  PREVIEW_EVENT_IDS,
  resolveSpineEventIds,
  buildDetectorCatalog,
};
