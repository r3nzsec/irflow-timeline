// Process Inspector pipeline — pure functions extracted from ProcessTreeModal.jsx.
//
// The modal originally inlined five computation passes as in-render IIFEs that
// mutated a `ptCacheRef.current` object. That worked but:
//   • the JSX file owned detection/sequence/cluster/story logic that has
//     nothing to do with rendering,
//   • the passes could not be unit-tested in isolation,
//   • mutating refs during render is a footgun for concurrent React,
//   • adding a sequence definition required editing a 3,000-line JSX file.
//
// Each function here is a pure transformation: same inputs → same output.
// The modal still wraps these in its existing cache-by-input-identity layer
// so we don't change memoization semantics.

import { getSusInfo } from "./process-inspector.js";
import { SAFE_PROCS, USER_WRITABLE_PATH, BENIGN_INSTALL_PATH } from "../detection-rules.js";
import { normalizeTimestamp, normalizeHost } from "./forensic-normalize.js";
import { _ptFormatDuration } from "./process-inspector.js";

// ---------- byKey / childMap ----------

export const buildByKeyMap = (data) => {
  if (!data?.processes?.length) return new Map();
  return new Map(data.processes.map((p) => [p.key, p]));
};

export const buildChildMap = (data) => {
  const m = new Map();
  if (!data?.processes?.length) return m;
  for (const p of data.processes) {
    if (!m.has(p.parentKey)) m.set(p.parentKey, []);
    m.get(p.parentKey).push(p.key);
  }
  return m;
};

// ---------- Detection map (per-process getSusInfo) ----------

// Catastrophic-backtracking guard for analyst-supplied regexes.
// Rejects nested quantifiers like (a+)+, (a*)+, ([abc]+)*, etc. — the classic
// ReDoS shape where one quantifier wraps a group that itself contains a
// quantifier. Not a complete safety net (a determined user can still write
// pathological lookbehinds), but it catches the canonical foot-guns and lets
// the rest of the codebase trust that custom_rule.test(cmd) terminates.
const _RX_NESTED_QUANT = /\([^)]*[+*?][^)]*\)\s*[+*?]/;

// Per-rule compile-error sink. The modal can read this to surface bad rules
// to the analyst-profile UI instead of silently dropping them. Keyed by
// pattern source so re-compilation across renders doesn't lose the message.
export const customRuleErrors = new Map();

export const validateCustomRulePattern = (pattern, { optional = false } = {}) => {
  const source = String(pattern || "").trim();
  if (!source) return optional ? "" : "Regex pattern is required.";
  if (_RX_NESTED_QUANT.test(source)) return "rejected: nested quantifier (potential ReDoS)";
  try {
    new RegExp(source, "i");
  } catch (e) {
    return `compile error: ${e.message}`;
  }
  return "";
};

/** Multi-field custom rule: at least one match criterion required (pattern or field). */
export const validateCustomRule = (cr = {}) => {
  const name = String(cr.name || "").trim();
  if (!name) return "Rule name is required.";
  const pattern = String(cr.pattern || "").trim();
  const parentProcess = String(cr.parentProcess || "").trim();
  const processName = String(cr.processName || "").trim();
  const imageContains = String(cr.imageContains || "").trim();
  const cmdContains = String(cr.cmdContains || "").trim();
  const hasField = !!(parentProcess || processName || imageContains || cmdContains || pattern);
  if (!hasField) return "Add a process/parent/path/cmdline field or a regex pattern.";
  const patternError = validateCustomRulePattern(pattern, { optional: true });
  if (patternError) return patternError;
  return "";
};

// Compile a custom-rule list once. Errors are recorded in customRuleErrors
// so the modal can surface them; bad rules are dropped from the working set.
// Supports multi-field rules: optional regex + parent/process/path/cmd substrings.
export const compileCustomRules = (customRules) => {
  if (!customRules?.length) return null;
  const out = [];
  for (const cr of customRules) {
    const pattern = String(cr.pattern || "").trim();
    const key = pattern || cr.name || "custom";
    const error = validateCustomRule(cr);
    if (error) {
      customRuleErrors.set(key, error);
      continue;
    }
    try {
      const compiled = {
        ...cr,
        pattern,
        parentProcess: String(cr.parentProcess || "").trim().toLowerCase().replace(/\.exe$/i, ""),
        processName: String(cr.processName || "").trim().toLowerCase().replace(/\.exe$/i, ""),
        imageContains: String(cr.imageContains || "").trim().toLowerCase(),
        cmdContains: String(cr.cmdContains || "").trim().toLowerCase(),
        _rx: pattern ? new RegExp(pattern, "i") : null,
      };
      out.push(compiled);
      customRuleErrors.delete(key);
    } catch (e) {
      customRuleErrors.set(key, `compile error: ${e.message}`);
    }
  }
  return out.length ? out : null;
};

// Build a stable string key for memoization. The modal uses this to avoid
// recomputing the detection map across renders that didn't touch the rules.
export const makeDetMapRuleKey = (disabledRules, customRules, piAnalystProfile) => {
  const disKey = disabledRules?.size ? [...disabledRules].sort().join(",") : "";
  const custKey = customRules?.length
    ? customRules.map((r) =>
      [r.pattern, r.parentProcess, r.processName, r.imageContains, r.cmdContains, r.severity, r.behavior || "", r.technique || ""].join("|")
    ).join(";;")
    : "";
  const profileKey = JSON.stringify({
    suppressions: (piAnalystProfile?.suppressions || []).map((r) =>
      [r.reason, r.processName, r.parentProcessName, r.hostname, r.user, r.image, r.cmdContains]),
    baselines: (piAnalystProfile?.baselines || []).map((r) =>
      [r.reason, r.processName, r.parentProcessName, r.hostname, r.user, r.image, r.cmdContains]),
  });
  return `${disKey}||${custKey}||${profileKey}`;
};

const _ptLower = (value) => String(value || "").trim().toLowerCase();
const _ptInc = (map, key) => {
  if (!key) return;
  map.set(key, (map.get(key) || 0) + 1);
};
const _ptSetAdd = (map, key, value) => {
  if (!key || !value) return;
  let set = map.get(key);
  if (!set) { set = new Set(); map.set(key, set); }
  set.add(value);
};

export const buildPrevalenceModel = (data) => {
  const processes = data?.processes || [];
  const total = processes.length;
  const processCounts = new Map();
  const imageCounts = new Map();
  const commandCounts = new Map();
  const parentChildCounts = new Map();
  const processHosts = new Map();
  const processUsers = new Map();
  const commandHosts = new Map();
  const imageHosts = new Map();
  for (const p of processes) {
    const host = normalizeHost(p.hostname);
    const user = _ptLower(p.user);
    const proc = _ptProcBase(p.processName || p.image);
    const img = _ptLower(p.image);
    const cmd = _ptNormCmd(p.cmdLine);
    const parent = _ptProcBase(p.parentProcessName || "");
    const pair = parent && proc ? `${parent}->${proc}` : "";
    _ptInc(processCounts, proc);
    _ptInc(imageCounts, img);
    _ptInc(commandCounts, cmd);
    _ptInc(parentChildCounts, pair);
    _ptSetAdd(processHosts, proc, host);
    _ptSetAdd(processUsers, proc, user);
    _ptSetAdd(commandHosts, cmd, host);
    _ptSetAdd(imageHosts, img, host);
  }
  const rareCount = total >= 100 ? Math.max(2, Math.ceil(total * 0.005)) : 1;
  const uncommonCount = total >= 100 ? Math.max(5, Math.ceil(total * 0.02)) : 2;
  const scoreNode = (p) => {
    const host = normalizeHost(p.hostname);
    const proc = _ptProcBase(p.processName || p.image);
    const img = _ptLower(p.image);
    const cmd = _ptNormCmd(p.cmdLine);
    const parent = _ptProcBase(p.parentProcessName || "");
    const pair = parent && proc ? `${parent}->${proc}` : "";
    const processCount = processCounts.get(proc) || 0;
    const imageCount = imageCounts.get(img) || 0;
    const commandCount = commandCounts.get(cmd) || 0;
    const parentChildCount = parentChildCounts.get(pair) || 0;
    const hostCount = processHosts.get(proc)?.size || 0;
    const commandHostCount = commandHosts.get(cmd)?.size || 0;
    const imageHostCount = imageHosts.get(img)?.size || 0;
    const userCount = processUsers.get(proc)?.size || 0;
    const signals = [];
    let scoreBoost = 0;
    if (proc && processCount > 0 && processCount <= rareCount) {
      signals.push(`rare process name (${processCount}/${total})`);
      scoreBoost += 15;
    } else if (proc && processCount > 0 && processCount <= uncommonCount) {
      signals.push(`uncommon process name (${processCount}/${total})`);
      scoreBoost += 7;
    }
    if (cmd && commandCount > 0 && commandCount <= rareCount) {
      signals.push("rare command template");
      scoreBoost += 15;
    } else if (cmd && commandCount > 0 && commandCount <= uncommonCount) {
      signals.push("uncommon command template");
      scoreBoost += 6;
    }
    if (pair && parentChildCount > 0 && parentChildCount <= rareCount) {
      signals.push("rare parent-child pair");
      scoreBoost += 10;
    }
    if (img && imageCount > 0 && imageCount <= rareCount) {
      signals.push("rare image path");
      scoreBoost += 8;
    }
    if (host && hostCount === 1 && processCount > 1) {
      signals.push("process seen on one host");
      scoreBoost += 4;
    }
    const rarity = signals.some((s) => s.startsWith("rare ")) ? "rare"
      : signals.some((s) => s.startsWith("uncommon ")) ? "uncommon"
      : "common";
    return {
      total,
      rarity,
      scoreBoost,
      signals,
      processCount,
      imageCount,
      commandCount,
      parentChildCount,
      hostCount,
      commandHostCount,
      imageHostCount,
      userCount,
    };
  };
  return { total, rareCount, uncommonCount, scoreNode };
};

export const buildPrevalenceSummary = (data, detMap, limit = 12) => {
  const processes = data?.processes || [];
  const model = buildPrevalenceModel(data);
  const grouped = new Map();
  const stats = {
    totalProcesses: processes.length,
    rare: 0,
    uncommon: 0,
    common: 0,
    rareDetected: 0,
    uncommonDetected: 0,
    oneHost: 0,
  };
  const _rank = (rarity) => rarity === "rare" ? 2 : rarity === "uncommon" ? 1 : 0;
  const _timeMs = (p) => Number.isFinite(p?.tsMs) ? p.tsMs : normalizeTimestamp(p?.ts);

  for (const p of processes) {
    const prevalence = model.scoreNode(p);
    const det = detMap?.get?.(p.key) || null;
    // Clean sanctioned EDR agents are expected to be uncommon in many exports.
    // Do not promote them into the analyst-facing rare-process strip solely
    // because the collection contains few agent events.
    if (det?.sanctioned?.cat === "edr" && (det.level || 0) <= 0) {
      stats.common++;
      continue;
    }
    if (prevalence.rarity === "rare") stats.rare++;
    else if (prevalence.rarity === "uncommon") stats.uncommon++;
    else stats.common++;
    if (prevalence.hostCount === 1 && prevalence.processCount > 1) stats.oneHost++;
    if (det?.level > 0 && prevalence.rarity === "rare") stats.rareDetected++;
    if (det?.level > 0 && prevalence.rarity === "uncommon") stats.uncommonDetected++;

    if (prevalence.rarity === "common" && !(det?.level > 0 && prevalence.scoreBoost > 0)) continue;

    const processName = p.processName || (p.image || "").replace(/^.*[/\\]/, "") || "(unknown)";
    const groupKey = [
      _ptProcBase(processName),
      _ptLower(p.image),
      _ptNormCmd(p.cmdLine),
    ].join("||");
    let item = grouped.get(groupKey);
    if (!item) {
      item = {
        key: p.key,
        keys: [],
        processName,
        image: p.image || "",
        commandTemplate: _ptNormCmd(p.cmdLine),
        sampleCommandLine: p.cmdLine || "",
        firstSeen: p.ts || "",
        lastSeen: p.ts || "",
        firstSeenMs: Number.POSITIVE_INFINITY,
        lastSeenMs: Number.NEGATIVE_INFINITY,
        count: 0,
        hosts: new Set(),
        users: new Set(),
        signals: new Set(),
        rarity: prevalence.rarity,
        scoreBoost: 0,
        maxTriageScore: 0,
        maxDetectionLevel: 0,
        detectionReasons: new Map(),
        prevalence,
      };
      grouped.set(groupKey, item);
    }
    item.keys.push(p.key);
    item.count++;
    if (p.hostname) item.hosts.add(normalizeHost(p.hostname));
    if (p.user) item.users.add(String(p.user));
    for (const sig of prevalence.signals || []) item.signals.add(sig);
    if (_rank(prevalence.rarity) > _rank(item.rarity)) item.rarity = prevalence.rarity;
    if ((prevalence.scoreBoost || 0) > item.scoreBoost) item.scoreBoost = prevalence.scoreBoost || 0;
    if ((det?.triageScore || 0) > item.maxTriageScore) item.maxTriageScore = det.triageScore || 0;
    if ((det?.level || 0) > item.maxDetectionLevel) item.maxDetectionLevel = det.level || 0;
    if (det?.reason) item.detectionReasons.set(det.reason, (item.detectionReasons.get(det.reason) || 0) + 1);
    const tsMs = _timeMs(p);
    if (Number.isFinite(tsMs)) {
      if (tsMs < item.firstSeenMs) { item.firstSeenMs = tsMs; item.firstSeen = p.ts || item.firstSeen; item.key = p.key; }
      if (tsMs > item.lastSeenMs) { item.lastSeenMs = tsMs; item.lastSeen = p.ts || item.lastSeen; }
    }
  }

  const items = [...grouped.values()].map((item) => ({
    ...item,
    hosts: [...item.hosts].filter(Boolean).sort(),
    users: [...item.users].filter(Boolean).sort(),
    signals: [...item.signals].slice(0, 8),
    detectionReasons: [...item.detectionReasons.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([reason]) => reason),
    firstSeenMs: Number.isFinite(item.firstSeenMs) ? item.firstSeenMs : 0,
    lastSeenMs: Number.isFinite(item.lastSeenMs) ? item.lastSeenMs : 0,
  })).sort((a, b) =>
    (b.maxTriageScore || 0) - (a.maxTriageScore || 0) ||
    (b.maxDetectionLevel || 0) - (a.maxDetectionLevel || 0) ||
    _rank(b.rarity) - _rank(a.rarity) ||
    (b.scoreBoost || 0) - (a.scoreBoost || 0) ||
    (b.count || 0) - (a.count || 0)
  );

  return {
    stats,
    totalCandidates: items.length,
    items: items.slice(0, limit),
  };
};

const _confidenceScore = (confidence) => ({
  confirmed: 30,
  likely: 15,
  context: 3,
  suppressed: -50,
}[confidence] || 0);

// Unified — see USER_WRITABLE_PATH in detection-rules.js (audit P19).
const _RX_PT_USER_WRITABLE_PATH = USER_WRITABLE_PATH;
// Legitimate per-user install / auto-update locations. These ARE user-writable but are
// overwhelmingly benign — Squirrel/Electron updaters (\AppData\Local\<Vendor>\app-<ver>),
// per-user app installs (\AppData\Local\Programs\), and Microsoft per-user apps (Teams,
// OneDrive). pi-57 ("same name from unusual path") skips them to avoid flooding FPs on
// normal endpoints. NOTE: \AppData\Local\Temp is intentionally NOT here — staging dirs stay flagged.
// Kept alongside the shared BENIGN_INSTALL_PATH because it also matches the
// Squirrel/Electron "app-<version>" layout, which is version-numbered rather than
// vendor-named.
const _RX_PT_BENIGN_PERUSER_PATH = /\\appdata\\local\\(programs\\|microsoft\\(teams|onedrive|edgeupdate)\\|[^\\]+\\app-\d)/i;
const _isBenignInstallPath = (img) => _RX_PT_BENIGN_PERUSER_PATH.test(img) || BENIGN_INSTALL_PATH.test(img);
const _RX_PT_TRUST_SENSITIVE_PATH = /^[a-z]:[\\/](windows|program files|program files \(x86\))[\\/]/i;

const _strongHash = (value) => {
  const text = String(value || "").trim();
  if (!text) return "";
  const pairs = [...text.matchAll(/\b(md5|sha1|sha256|imphash)\s*[:=]\s*([a-f0-9]{32,128})\b/ig)];
  const byName = new Map(pairs.map((m) => [m[1].toLowerCase(), m[2].toLowerCase()]));
  return byName.get("sha256") || byName.get("sha1") || byName.get("md5") || byName.get("imphash")
    || (text.match(/\b[a-f0-9]{64}\b/i)?.[0] || text.match(/\b[a-f0-9]{40}\b/i)?.[0] || text.match(/\b[a-f0-9]{32}\b/i)?.[0] || "").toLowerCase();
};

// Processes whose whole job is to start, do one thing and exit. On any host with
// 4689 / Sysmon-5 enabled these churn constantly — a console window per command,
// a crash reporter per fault, a broker per activation — so "4+ short-lived
// instances in 10 minutes" is their NORMAL state, not a finding. Without this,
// pi-53 fired on essentially every workstation in a dataset. Deliberately narrow:
// only names that cannot carry an attacker's payload by themselves.
const _RX_RESPAWN_BENIGN = /^(conhost|cmd|consent|dllhost|wermgr|werfault|werfaultsecure|taskhostw|backgroundtaskhost|runtimebroker|gpupdate|gpresult|ngen|ngentask|mscorsvw|sppsvc|sppextcomobj|cleanmgr|tiworker|wuauclt|usoclient|mousocoreworker|searchprotocolhost|searchfilterhost|searchindexer|compattelrunner|dismhost|drvinst|msiexec|omadmclient|deviceenroller|ipconfig|net1|whoami|hostname|chcp|where|find|findstr|timeout|ping|reg|sc|tasklist|systeminfo)$/i;

const _lifetimeEvidenceFor = (info, node, disabledRules) => {
  if (!info) return null;
  const img = String(node?.image || "");
  // An Electron/Teams-style per-user install directory is user-writable by
  // construction; treating it as "suspicious path" made every updater helper a
  // level-2 respawn finding.
  const benignPerUser = _isBenignInstallPath(img);
  const isWritable = _RX_PT_USER_WRITABLE_PATH.test(img) && !benignPerUser;
  const nameBase = String(node?.processName || "").toLowerCase().replace(/\.exe$/i, "");
  if (info.type === "short-respawn") {
    if (disabledRules?.has("pi-53")) return null;
    // A known-churning name running from a normal location is expected behaviour.
    // Keep it visible as context (it still feeds sequence/cluster correlation) but
    // stop it scoring. A same-named binary from a writable path is NOT excluded —
    // that is the masquerade case and keeps full severity below.
    if (!isWritable && (_RX_RESPAWN_BENIGN.test(nameBase) || SAFE_PROCS.test(nameBase))) {
      return {
        cat: "context",
        level: 0,
        reason: `Repeated short-lived respawns (expected for ${nameBase || "this process"})`,
        ruleId: "pi-53",
        tid: [],
        beh: "lifetime-respawn",
        confidence: "context",
      };
    }
    return {
      cat: "lifetime",
      level: isWritable ? 2 : 1,
      reason: "Repeated short-lived process respawns",
      ruleId: "pi-53",
      tid: ["T1059"],
      beh: "lifetime-respawn",
      confidence: isWritable ? "likely" : "context",
    };
  }
  return null;
};

const _applyLifetime = (det, node, lifetimeInfo, disabledRules) => {
  const evidence = _lifetimeEvidenceFor(lifetimeInfo, node, disabledRules);
  if (!evidence) return det;

  const existingEvidence = det?.evidence || [];
  const nextEvidence = [
    ...existingEvidence,
    evidence,
    { cat: "context", level: 0, reason: lifetimeInfo.label, dampen: false },
  ];
  const priorLevel = det?.level || 0;
  const nextLevel = Math.max(priorLevel, evidence.level || 0);
  const techniques = new Set(det?.techniques || []);
  for (const tid of evidence.tid || []) techniques.add(tid);
  const behaviors = new Set(det?.behaviors || []);
  if (evidence.beh) behaviors.add(evidence.beh);
  const nextConfidence = evidence.confidence === "likely" && _confidenceScore(evidence.confidence) > _confidenceScore(det?.confidence)
    ? "likely"
    : (det?.confidence || evidence.confidence || "context");
  const preferLifetimeReason = evidence.cat === "lifetime" && evidence.level >= priorLevel;

  return {
    ...(det || {}),
    level: nextLevel,
    confidence: nextConfidence,
    reason: !preferLifetimeReason && priorLevel >= evidence.level && det?.reason ? det.reason : evidence.reason,
    primaryRuleId: !preferLifetimeReason && priorLevel >= evidence.level && det?.primaryRuleId ? det.primaryRuleId : evidence.ruleId,
    evidence: nextEvidence,
    techniques: [...techniques],
    behaviors: [...behaviors],
    lifetime: lifetimeInfo,
  };
};

const _trustEvidenceFor = (info, disabledRules) => {
  if (!info) return null;
  if (info.type === "cross-host-hash-mismatch") {
    if (disabledRules?.has("pi-56")) return null;
    return {
      cat: "trust",
      level: info.sensitivePath ? 3 : 2,
      reason: "Cross-host hash mismatch for same image path",
      ruleId: "pi-56",
      tid: ["T1036.005", "T1553.002"],
      beh: "binary-trust",
      confidence: "likely",
    };
  }
  if (info.type === "same-name-unusual-path") {
    if (disabledRules?.has("pi-57")) return null;
    return {
      cat: "trust",
      level: info.userWritable ? 2 : 1,
      reason: "Same process name from unusual path",
      ruleId: "pi-57",
      tid: ["T1036.005"],
      beh: "binary-trust",
      confidence: info.userWritable ? "likely" : "context",
    };
  }
  return null;
};

const _applyTrust = (det, trustInfo, disabledRules) => {
  // An allowlisted vendor binary can legitimately execute from more than one
  // protected install/staging path. Preserve the cross-host hash-mismatch
  // signal (possible tampering/version drift), but do not turn path rarity
  // alone into pi-57 for an exact-name, trusted-root sanctioned match.
  if (det?.sanctioned && trustInfo?.type === "same-name-unusual-path") {
    return {
      ...det,
      trust: {
        ...trustInfo,
        suppressed: true,
        suppressionReason: "sanctioned vendor path",
      },
    };
  }
  const evidence = _trustEvidenceFor(trustInfo, disabledRules);
  if (!evidence) return det;

  const existingEvidence = det?.evidence || [];
  const nextEvidence = [
    ...existingEvidence,
    evidence,
    { cat: "context", level: 0, reason: trustInfo.label, dampen: false },
  ];
  const priorLevel = det?.level || 0;
  const nextLevel = Math.max(priorLevel, evidence.level || 0);
  const techniques = new Set(det?.techniques || []);
  for (const tid of evidence.tid || []) techniques.add(tid);
  const behaviors = new Set(det?.behaviors || []);
  if (evidence.beh) behaviors.add(evidence.beh);
  const nextConfidence = evidence.confidence === "likely" && _confidenceScore(evidence.confidence) > _confidenceScore(det?.confidence)
    ? "likely"
    : (det?.confidence || evidence.confidence || "context");
  const preferTrustReason = evidence.cat === "trust" && evidence.level >= priorLevel;

  return {
    ...(det || {}),
    level: nextLevel,
    confidence: nextConfidence,
    reason: !preferTrustReason && priorLevel >= evidence.level && det?.reason ? det.reason : evidence.reason,
    primaryRuleId: !preferTrustReason && priorLevel >= evidence.level && det?.primaryRuleId ? det.primaryRuleId : evidence.ruleId,
    evidence: nextEvidence,
    techniques: [...techniques],
    behaviors: [...behaviors],
    trust: trustInfo,
  };
};

const _applyPrevalence = (det, node, model) => {
  if (!det) return det;
  const prevalence = model?.scoreNode ? model.scoreNode(node) : null;
  if (det.sanctioned?.cat === "edr" && (det.level || 0) <= 0) {
    return {
      ...det,
      prevalence: prevalence ? {
        ...prevalence,
        rawRarity: prevalence.rarity,
        rarity: "baseline",
        scoreBoost: 0,
        signals: [],
        suppressed: true,
      } : null,
    };
  }
  if ((det.level || 0) <= 0) return { ...det, prevalence };
  const boost = prevalence?.scoreBoost || 0;
  // Only boost when the respawn actually scored — a benign conhost churn is
  // demoted to context above and must not carry a prevalence bonus with it.
  const _respawnScored = (det.evidence || []).some((e) => e.ruleId === "pi-53" && (e.level || 0) > 0);
  const lifetimeBoost = det.lifetime?.type === "short-respawn" && _respawnScored ? 15 : 0;
  const trustBoost = det.trust?.suppressed ? 0
    : det.trust?.type === "cross-host-hash-mismatch" ? 25
    : det.trust?.type === "same-name-unusual-path" ? 15
    : 0;
  const triageScore = (det.level * 100) + _confidenceScore(det.confidence) + boost + lifetimeBoost + trustBoost + Math.min(12, (det.evidence?.length || 0) * 2);
  const evidence = boost > 0
    ? [...(det.evidence || []), { cat: "context", level: 0, reason: `Prevalence: ${prevalence.rarity}`, dampen: false }]
    : det.evidence;
  return {
    ...det,
    evidence,
    prevalence,
    triageScore,
  };
};

const _scoreOneProcess = (p, byK, susOpts, lifetimeMap, trustMap, prevalenceModel, disabledRules) => {
  const parent = byK.get(p.parentKey) || null;
  // Is the IMMEDIATE edge trustworthy? consistentParentKey returns null when the
  // row's own ParentProcessName disagrees with the process we linked it to — the
  // signature of a PID-reuse mislink. The grandparent already went through this
  // check, but the parent did not, so a mislinked edge could still manufacture a
  // parent->child chain finding (a spurious "office -> shell") out of two
  // unrelated processes that happened to share a PID.
  const parentEdgeConsistent = parent ? !!consistentParentKey(p, byK) : true;
  // Grandparent for multi-hop chain rules (winword→cmd→powershell). Use
  // consistentParentKey so PID-reuse edges don't invent a false office→shell path.
  let grandparent = null;
  if (parent && parentEdgeConsistent) {
    const gpk = consistentParentKey(parent, byK);
    if (gpk) grandparent = byK.get(gpk) || null;
  }
  const det = getSusInfo(p, parent, { ...susOpts, grandparentNode: grandparent, parentEdgeConsistent });
  const withLifetime = _applyLifetime(det, p, lifetimeMap.get(p.key), disabledRules);
  const withTrust = _applyTrust(withLifetime, trustMap.get(p.key), disabledRules);
  return _applyPrevalence(withTrust, p, prevalenceModel);
};

export const buildDetectionMap = (data, opts) => {
  const m = new Map();
  if (!data?.processes?.length) return m;
  const byK = buildByKeyMap(data);
  const compiled = compileCustomRules(opts?.customRules);
  const prevalenceModel = opts?.prevalenceModel || buildPrevalenceModel(data);
  const lifetimeMap = opts?.lifetimeMap || buildLifetimeAnalysis(data);
  const trustMap = opts?.trustMap || buildTrustAnalysis(data);
  // pi-39 (no-termination) is only a signal when the dataset records terminations at all;
  // if no process has a matched terminate event, missing durations are a logging gap.
  const datasetHasTermination = data.processes.some((p) => Number.isFinite(p.durationMs));
  const susOpts = {
    disabledRules: opts?.disabledRules || null,
    customRules: compiled,
    analystProfile: opts?.analystProfile,
    datasetHasTermination,
  };
  const disabledRules = opts?.disabledRules || null;
  for (const p of data.processes) {
    m.set(p.key, _scoreOneProcess(p, byK, susOpts, lifetimeMap, trustMap, prevalenceModel, disabledRules));
  }
  return m;
};

/**
 * Chunked async detection scoring for large process trees.
 * Yields to the event loop between batches so the UI can paint progress.
 *
 * @param {object} data
 * @param {object} opts - same as buildDetectionMap
 * @param {{ batchSize?: number, onProgress?: Function, shouldCancel?: () => boolean }} chunkOpts
 * @returns {Promise<Map>}
 */
export const buildDetectionMapChunked = async (data, opts = {}, chunkOpts = {}) => {
  const processes = data?.processes || [];
  const total = processes.length;
  const batchSize = Math.max(200, Number(chunkOpts.batchSize) || 2500);
  const onProgress = typeof chunkOpts.onProgress === "function" ? chunkOpts.onProgress : null;
  const shouldCancel = typeof chunkOpts.shouldCancel === "function" ? chunkOpts.shouldCancel : () => false;

  if (total === 0) {
    onProgress?.({ done: 0, total: 0, percent: 100 });
    return new Map();
  }
  if (total <= batchSize) {
    const m = buildDetectionMap(data, opts);
    onProgress?.({ done: total, total, percent: 100 });
    return m;
  }

  const byK = buildByKeyMap(data);
  const compiled = compileCustomRules(opts?.customRules);
  const prevalenceModel = opts?.prevalenceModel || buildPrevalenceModel(data);
  const lifetimeMap = opts?.lifetimeMap || buildLifetimeAnalysis(data);
  const trustMap = opts?.trustMap || buildTrustAnalysis(data);
  const datasetHasTermination = processes.some((p) => Number.isFinite(p.durationMs));
  const susOpts = {
    disabledRules: opts?.disabledRules || null,
    customRules: compiled,
    analystProfile: opts?.analystProfile,
    datasetHasTermination,
  };
  const disabledRules = opts?.disabledRules || null;
  const m = new Map();

  for (let i = 0; i < total; i += batchSize) {
    if (shouldCancel()) {
      const err = new Error("Scoring cancelled");
      err.cancelled = true;
      throw err;
    }
    const end = Math.min(total, i + batchSize);
    for (let j = i; j < end; j++) {
      const p = processes[j];
      m.set(p.key, _scoreOneProcess(p, byK, susOpts, lifetimeMap, trustMap, prevalenceModel, disabledRules));
    }
    const percent = Math.min(100, Math.round((end / total) * 100));
    onProgress?.({ done: end, total, percent });
    // Yield so React can paint and the main thread stays responsive.
    await new Promise((r) => setTimeout(r, 0));
  }
  return m;
};

// ---------- Sequence detection (multi-stage attack windows) ----------

const SEQ_WINDOW_MS = 10 * 60 * 1000; // 10-minute correlation window

const _hasBeh = (det, beh, minLevel) => {
  if (!det.behaviors?.includes(beh)) return false;
  const ml = minLevel ?? 1;
  // Analyst-baselined or sanctioned tools require stronger evidence for sequence promotion.
  const threshold = det.sanctioned || det.baselined ? Math.max(ml, 2) : ml;
  return det.evidence?.some((e) => e.beh === beh && e.cat !== "context" && !e.dampen && e.level >= threshold);
};

const _hasBehAny = (det, behs, minLevel) => behs.some((b) => _hasBeh(det, b, minLevel));

// Office/script-origin: shell-exec only from Office chain (pi-0), or any script-exec
const _isOfficeOrScriptOrigin = (det) => {
  const ml = det.sanctioned || det.baselined ? 2 : 1;
  return det.evidence?.some((e) => !e.dampen && e.cat !== "context" && e.level >= ml &&
    ((e.beh === "script-exec") || (e.beh === "shell-exec" && e.ruleId === "pi-0")));
};

// Sequence catalog — moved out of the JSX file. Adding a sequence is now a
// one-file edit, and stages are matched on normalized behavior tags so the
// definitions don't depend on rule-ID taxonomy.
export const SEQ_DEFS = [
  { id: "seq-dl-exec", name: "Download \u2192 Execute", tid: ["T1105"],
    stages: [
      (det) => _hasBeh(det, "download", 2),
      (det) => _hasBehAny(det, ["script-exec", "shell-exec", "lolbin-exec", "evasion"], 2),
    ], minStages: 2 },
  { id: "seq-office-lolbin", name: "Office/Script \u2192 LOLBin", tid: ["T1204.002"],
    stages: [
      (det) => _isOfficeOrScriptOrigin(det),
      (det) => _hasBeh(det, "lolbin-exec", 2),
      (det) => _hasBehAny(det, ["rmm", "exfil"], 1),
    ], minStages: 2 },
  { id: "seq-recon-lateral", name: "Recon \u2192 Lateral Movement", tid: ["T1087.002", "T1021"],
    stages: [
      (det) => _hasBeh(det, "recon", 2),
      (det) => _hasBeh(det, "lateral", 2),
    ], minStages: 2 },
  { id: "seq-script-persist", name: "Script \u2192 Persistence", tid: ["T1059.001", "T1053.005"],
    stages: [
      (det) => _hasBeh(det, "script-exec", 1),
      (det) => _hasBeh(det, "persist", 2),
    ], minStages: 2 },
  { id: "seq-cred-lateral", name: "Credential Access \u2192 Lateral", tid: ["T1003", "T1021"],
    stages: [
      (det) => _hasBeh(det, "cred", 2),
      (det) => _hasBeh(det, "lateral", 2),
    ], minStages: 2 },
  { id: "seq-persist-exec", name: "Persistence \u2192 Execution", tid: ["T1053.005", "T1569.002"],
    stages: [
      (det) => _hasBeh(det, "persist", 2),
      (det) => _hasBehAny(det, ["service-exec", "shell-exec", "lolbin-exec"], 2),
    ], minStages: 2 },
  // Multi-hop LOLBIN chain — catches staged payload chains where a driver
  // (script or shell) invokes a LOLBIN that itself spawns another LOLBIN or
  // downloads/evades. Common shape: cmd/powershell \u2192 certutil \u2192 bitsadmin,
  // or mshta \u2192 rundll32 \u2192 regsvr32. Three distinct stages in the
  // 10-minute window \u2014 each stage must fire on a different process to count.
  { id: "seq-multihop-lolbin", name: "Multi-Hop LOLBIN Chain", tid: ["T1218", "T1105"],
    stages: [
      (det) => _hasBehAny(det, ["script-exec", "shell-exec"], 1),
      (det) => _hasBeh(det, "lolbin-exec", 1),
      (det) => _hasBehAny(det, ["lolbin-exec", "download", "evasion", "exfil"], 1),
    ], minStages: 3 },
  // Cred dump \u2192 lateral is the classic post-compromise pivot.
  { id: "seq-dump-lateral", name: "LSASS/Cred Dump \u2192 Lateral", tid: ["T1003", "T1021"],
    stages: [
      (det) => _hasBeh(det, "cred", 2),
      (det) => _hasBehAny(det, ["lateral", "rmm"], 1),
    ], minStages: 2 },
  // Office macro / script drops a payload then installs RMM hands-on-keyboard access.
  { id: "seq-office-download-rmm", name: "Office/Script \u2192 Download \u2192 RMM", tid: ["T1204.002", "T1105", "T1219"],
    stages: [
      (det) => _isOfficeOrScriptOrigin(det),
      (det) => _hasBeh(det, "download", 1),
      (det) => _hasBeh(det, "rmm", 1),
    ], minStages: 2 },
  // AMSI/ETW tamper followed by injection or reflective load is high-confidence.
  { id: "seq-amsi-inject", name: "AMSI/ETW Patch \u2192 Inject", tid: ["T1562.001", "T1055"],
    stages: [
      (det) => _hasBeh(det, "evasion", 2),
      (det) => _hasBehAny(det, ["inject", "script-exec"], 2),
    ], minStages: 2 },
  // Defender disable / exclusion then payload execution.
  { id: "seq-defender-payload", name: "Disable Defender \u2192 Payload", tid: ["T1562.001", "T1059"],
    stages: [
      (det) => _hasBeh(det, "evasion", 2),
      (det) => _hasBehAny(det, ["download", "lolbin-exec", "shell-exec", "script-exec"], 2),
    ], minStages: 2 },
  // certutil/bitsadmin stage then scheduled-task / service persistence.
  { id: "seq-stage-persist", name: "Download/Stage \u2192 Persistence", tid: ["T1105", "T1053.005"],
    stages: [
      (det) => _hasBehAny(det, ["download", "lolbin-exec"], 1),
      (det) => _hasBeh(det, "persist", 2),
    ], minStages: 2 },
  // Network/DNS beacon after suspicious execution (needs EID 3/22 enrichment rules).
  { id: "seq-exec-network", name: "Suspicious Exec \u2192 Network/DNS", tid: ["T1071", "T1059"],
    stages: [
      (det) => _hasBehAny(det, ["shell-exec", "script-exec", "lolbin-exec", "download"], 1),
      (det) => _hasBehAny(det, ["network", "dns"], 1),
    ], minStages: 2 },
  // Dropper: file create / image load then execute.
  { id: "seq-drop-exec", name: "Drop File/Module \u2192 Execute", tid: ["T1105", "T1204"],
    stages: [
      (det) => _hasBehAny(det, ["file-drop", "image-load"], 1),
      (det) => _hasBehAny(det, ["shell-exec", "script-exec", "lolbin-exec"], 1),
    ], minStages: 2 },
];

// Single source of truth for "is this parent edge trustworthy?". Returns node.parentKey
// ONLY when the link is name-consistent — i.e. the node's DECLARED parentProcessName
// matches the ACTUAL parent node's processName (basenames, .exe-stripped). A positive
// mismatch (a PID-reuse mislinked edge) returns null so ancestry walks STOP instead of
// climbing into an unrelated subtree. No parentKey → null; a missing parentProcessName or
// an unresolved parent node → the raw parentKey (we can't judge consistency without both
// names, so let the caller's own byKey.has() guard handle termination). Used by _rootKeyOf
// AND every renderer ancestry walk (ProcessTreeModal) so the whole UI agrees on where a
// chain ends — this is what stops the cortex-xdr-payload → skype.exe misattribution
// recurring in any walk (story root, chain highlight, detail chain, expand-to-ancestor).
export const consistentParentKey = (node, byKey) => {
  const pk = node?.parentKey;
  if (!pk) return null;
  const parent = byKey.get(pk);
  if (!parent) return pk;
  const declared = (node.parentProcessName || "").toLowerCase().replace(/\.exe$/, "");
  const actual = (parent.processName || "").toLowerCase().replace(/\.exe$/, "");
  if (declared && actual && declared !== actual) return null;
  return pk;
};

// Walk parentKey chain to top of tree (cycle-safe, capped at 200 hops). Stops at the
// first PID-reuse mislinked edge (see consistentParentKey). Memoizes via the cache.
const _rootKeyOf = (key, byKey, rootCache) => {
  if (rootCache.has(key)) return rootCache.get(key);
  let cur = key;
  let hops = 0;
  while (hops++ < 200) {
    const node = byKey.get(cur);
    if (!node) break;
    const pk = consistentParentKey(node, byKey);
    if (!pk || !byKey.has(pk)) break;
    cur = pk;
  }
  rootCache.set(key, cur);
  return cur;
};

export const buildSequenceMap = (data, detMap) => {
  const seqMap = new Map();
  if (!data?.processes?.length || !detMap?.size) return seqMap;
  const byK = buildByKeyMap(data);
  const rootCache = new Map();
  // Collect detected processes with enriched metadata
  const detected = [];
  for (const p of data.processes) {
    const det = detMap.get(p.key);
    if (!det || det.level === 0 || !det.evidence) continue;
    // Host scope: only use a real hostname. Empty hostnames stay empty so they
    // only group within themselves (Finding #4 — never collapse to user-domain).
    const host = normalizeHost(p.hostname);
    const user = (p.user || "").toLowerCase();
    const root = _rootKeyOf(p.key, byK, rootCache);
    const tsMs = normalizeTimestamp(p.ts);
    detected.push({ key: p.key, det, host, user, root, ts: Number.isFinite(tsMs) ? tsMs : 0 });
  }
  // Group by (host, user, rootKey) for tree-level correlation
  // Also build fallback host+user groups for cross-tree sequences (lower confidence)
  const treeGroups = new Map();
  const huGroups = new Map();
  for (const d of detected) {
    const tk = `${d.host}||${d.user}||${d.root}`;
    let tg = treeGroups.get(tk);
    if (!tg) { tg = []; treeGroups.set(tk, tg); }
    tg.push(d);
    const hk = `${d.host}||${d.user}`;
    let hg = huGroups.get(hk);
    if (!hg) { hg = []; huGroups.set(hk, hg); }
    hg.push(d);
  }
  for (const g of treeGroups.values()) g.sort((a, b) => a.ts - b.ts);
  for (const g of huGroups.values()) g.sort((a, b) => a.ts - b.ts);
  // Sliding-window sequence checker
  const _checkGroup = (g, confidence) => {
    if (g.length < 2) return;
    for (let i = 0; i < g.length; i++) {
      const windowEnd = g[i].ts + SEQ_WINDOW_MS;
      let j = i + 1;
      while (j < g.length && g[j].ts <= windowEnd) j++;
      if (j - i < 2) continue;
      const win = g.slice(i, j);
      for (const seq of SEQ_DEFS) {
        const stageHits = seq.stages.map(() => []);
        for (const proc of win) {
          for (let s = 0; s < seq.stages.length; s++) {
            if (seq.stages[s](proc.det)) stageHits[s].push(proc.key);
          }
        }
        const satisfied = stageHits.filter((h) => h.length > 0).length;
        if (satisfied < seq.minStages) continue;
        // Chronological order check — use a loop, not Math.min(...arr), to
        // avoid call-stack issues on very large windows.
        const stageFirstTs = stageHits.map((hits) => {
          if (hits.length === 0) return Infinity;
          let mn = Infinity;
          for (const k of hits) {
            const proc = win.find((p) => p.key === k);
            if (proc && proc.ts < mn) mn = proc.ts;
          }
          return mn;
        });
        let ordered = true;
        let prevTs = -Infinity;
        for (const t of stageFirstTs) {
          if (t === Infinity) continue;
          if (t < prevTs) { ordered = false; break; }
          prevTs = t;
        }
        if (!ordered) continue;
        const allKeys = new Set();
        for (const hits of stageHits) for (const k of hits) allKeys.add(k);
        const keysArr = [...allKeys];
        for (let s = 0; s < stageHits.length; s++) {
          for (const k of stageHits[s]) {
            let existing = seqMap.get(k);
            if (!existing) { existing = []; seqMap.set(k, existing); }
            // Only upgrade confidence, never downgrade; deduplicate by seqId
            const prev = existing.find((e) => e.seqId === seq.id);
            if (prev) {
              if (confidence === "high" && prev.confidence !== "high") prev.confidence = "high";
            } else {
              existing.push({ seqId: seq.id, seqName: seq.name, stageIdx: s,
                stageName: `Stage ${s + 1}/${seq.stages.length}`,
                level: seq.level ?? 3, confidence, peers: keysArr, tid: seq.tid });
            }
          }
        }
      }
    }
  };
  // Pass 1: tree-level groups → high confidence
  for (const g of treeGroups.values()) _checkGroup(g, "high");
  // Pass 2: host+user groups → medium confidence (only adds new sequences not already found)
  for (const g of huGroups.values()) _checkGroup(g, "medium");
  return seqMap;
};

// ---------- Cluster computation ----------

// Parse executable from command line, handling quoted paths and Windows conventions
export const _ptParseExe = (cmd) => {
  if (!cmd) return { bin: "", rest: "" };
  const s = cmd.trimStart();
  let exe, rest;
  if (s[0] === '"') {
    const close = s.indexOf('"', 1);
    if (close > 0) { exe = s.slice(1, close); rest = s.slice(close + 1).trimStart(); }
    else { exe = s.slice(1); rest = ""; }
  } else if (s[0] === "'") {
    const close = s.indexOf("'", 1);
    if (close > 0) { exe = s.slice(1, close); rest = s.slice(close + 1).trimStart(); }
    else { exe = s.slice(1); rest = ""; }
  } else {
    // Unquoted: scan for .exe/.com/.bat/.cmd/.ps1/.vbs/.js boundary then take the next space
    const exeMatch = s.match(/^(\S*?\.\w{2,4})(\s|$)/i);
    if (exeMatch) { exe = exeMatch[1]; rest = s.slice(exeMatch[0].length).trimStart(); }
    else { const sp = s.indexOf(" "); exe = sp > 0 ? s.slice(0, sp) : s; rest = sp > 0 ? s.slice(sp + 1).trimStart() : ""; }
  }
  const bin = exe.replace(/^.*[/\\]/, "").toLowerCase();
  return { bin, rest };
};

// Normalize command line to a template: extract binary, collapse volatile args
export const _ptNormCmd = (cmd) => {
  if (!cmd) return "";
  const { bin, rest } = _ptParseExe(cmd);
  if (!rest) return bin;
  // Tokenize remaining args respecting quotes
  const args = [];
  let i = 0;
  while (i < rest.length) {
    if (rest[i] === '"' || rest[i] === "'") {
      const q = rest[i]; const end = rest.indexOf(q, i + 1);
      const tok = end > i ? rest.slice(i + 1, end) : rest.slice(i + 1);
      args.push(tok); i = end > i ? end + 1 : rest.length;
    } else if (/\s/.test(rest[i])) { i++; }
    else { const end = rest.indexOf(" ", i); const tok = end > i ? rest.slice(i, end) : rest.slice(i); args.push(tok); i = end > i ? end + 1 : rest.length; }
  }
  const norm = args.map((a) =>
    /^[a-f0-9]{32,}$/i.test(a) ? "<hash>" :
    /^[A-Z]:[/\\]|^\/|^\\\\/.test(a) ? "<path>" :
    /^https?:\/\//i.test(a) ? "<url>" :
    /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(a) ? "<guid>" : a
  ).join(" ");
  return `${bin} ${norm}`.trim();
};

const _ptProcBase = (name) => (name || "").toLowerCase().replace(/^.*[/\\]/, "").replace(/\.exe$/i, "");

const _ptParseChainReason = (reason) => {
  const txt = String(reason || "").trim();
  if (!txt.includes("\u2192")) return null;
  const mitreLess = txt.replace(/\s+\[(T\d{4}(?:\.\d{3})?)\]\s*$/i, "").trim();
  const parts = mitreLess.split("\u2014");
  const chainPart = parts[0]?.trim() || "";
  const detail = parts.slice(1).join("\u2014").trim() || txt;
  const pair = chainPart.split("\u2192").map((s) => s.trim()).filter(Boolean);
  if (pair.length < 2) return null;
  return { parent: pair[0], child: pair[1], detail };
};

export const buildChainClusters = (data, detMap, seqMap) => {
  const allClusters = [];
  if (!data?.processes?.length || !detMap?.size) return allClusters;
  const CLUSTER_WINDOW_MS = 15 * 60 * 1000; // 15-minute gap splits clusters into separate windows
  const windowMap = new Map();
  const _mkCluster = (ck, det, p, hostname, cmdTpl, win) => {
    const mitre = (det.reason || "").match(/\[(T\d{4}(?:\.\d{3})?)\]/);
    const primaryEvidence = (det.evidence || []).find((e) => e.reason === det.reason) || null;
    const chainReason = primaryEvidence?.cat === "chain" ? _ptParseChainReason(det.reason) : null;
    const seedMs = normalizeTimestamp(p.ts);
	    const cl = { id: `${ck}||w${win}`, reason: det.reason, level: det.level, hostname,
	      users: [], firstSeen: p.ts || "", lastSeen: p.ts || "",
	      firstSeenMs: Number.isFinite(seedMs) ? seedMs : Number.POSITIVE_INFINITY,
	      lastSeenMs: Number.isFinite(seedMs) ? seedMs : Number.NEGATIVE_INFINITY,
	      count: 0, members: [], allKeys: [], cmdVariants: [], parentNames: [], childNames: [],
	      parentFreq: new Map(), childFreq: new Map(),
	      cmdTemplate: cmdTpl, mitreId: mitre ? mitre[1] : null,
	      isChainDetection: !!chainReason,
	      chainParent: chainReason?.parent || "",
	      chainChild: chainReason?.child || "",
	      displayReason: chainReason?.detail || det.reason,
	      maxTriageScore: det.triageScore || (det.level * 100),
	      rareCount: 0,
	      uncommonCount: 0,
	      prevalenceSignals: det.prevalence?.signals?.length ? [...det.prevalence.signals] : [] };
    allClusters.push(cl);
    return cl;
  };
  for (const p of data.processes) {
    const det = detMap.get(p.key);
    if (!det || det.level === 0) continue;
    // Cluster key uses normalized hostname only — never the user's domain (Finding #4).
    const hostname = normalizeHost(p.hostname);
    const parent = (p.parentProcessName || "").toLowerCase();
    const child = (p.processName || "").toLowerCase();
    const cmdTpl = _ptNormCmd(p.cmdLine);
    const ck = `${det.reason}||${hostname}||${parent}||${child}||${cmdTpl}`;
    let windows = windowMap.get(ck);
    if (!windows) { windows = []; windowMap.set(ck, windows); }
    let cl = windows.length > 0 ? windows[windows.length - 1] : null;
    // Split into new window if gap exceeds threshold. Compare via canonical
    // epoch ms (lastSeenMs) so non-ISO formats gap-split correctly.
    const pTsMs = normalizeTimestamp(p.ts);
    if (cl && Number.isFinite(pTsMs) && Number.isFinite(cl.lastSeenMs)) {
      if (pTsMs - cl.lastSeenMs > CLUSTER_WINDOW_MS) cl = null;
    }
	    if (!cl) { cl = _mkCluster(ck, det, p, hostname, cmdTpl, windows.length); windows.push(cl); }
	    cl.count++;
	    cl.allKeys.push(p.key);
	    if (det.level > cl.level) cl.level = det.level;
	    if ((det.triageScore || 0) > (cl.maxTriageScore || 0)) cl.maxTriageScore = det.triageScore || 0;
	    if (det.prevalence?.rarity === "rare") cl.rareCount++;
	    else if (det.prevalence?.rarity === "uncommon") cl.uncommonCount++;
	    for (const sig of (det.prevalence?.signals || [])) {
	      if (cl.prevalenceSignals.length >= 8) break;
	      if (!cl.prevalenceSignals.includes(sig)) cl.prevalenceSignals.push(sig);
	    }
    if (Number.isFinite(pTsMs)) {
      if (pTsMs < cl.firstSeenMs) { cl.firstSeenMs = pTsMs; cl.firstSeen = p.ts; }
      if (pTsMs > cl.lastSeenMs)  { cl.lastSeenMs  = pTsMs; cl.lastSeen  = p.ts; }
    } else if (!cl.firstSeen && p.ts) {
      cl.firstSeen = p.ts;
      cl.lastSeen = p.ts;
    }
    if (cl.members.length < 200)
      cl.members.push({ key: p.key, processName: p.processName, parentProcessName: p.parentProcessName,
        pid: p.pid, ppid: p.ppid, user: p.user, ts: p.ts, cmdLine: p.cmdLine, image: p.image });
    if (p.user && !cl.users.includes(p.user)) cl.users.push(p.user);
    if (p.cmdLine && cl.cmdVariants.length < 10 && !cl.cmdVariants.includes(p.cmdLine)) cl.cmdVariants.push(p.cmdLine);
    if (p.parentProcessName && !cl.parentNames.includes(p.parentProcessName)) cl.parentNames.push(p.parentProcessName);
    if (p.processName && !cl.childNames.includes(p.processName)) cl.childNames.push(p.processName);
    cl.parentFreq.set(p.parentProcessName || "", (cl.parentFreq.get(p.parentProcessName || "") || 0) + 1);
    cl.childFreq.set(p.processName || "", (cl.childFreq.get(p.processName || "") || 0) + 1);
  }
  // Compute dominant parent/child names and best sequence confidence per cluster
  for (const cl of allClusters) {
    let topP = "", topPc = 0; for (const [n, c] of cl.parentFreq) if (c > topPc) { topP = n; topPc = c; }
    let topC = "", topCc = 0; for (const [n, c] of cl.childFreq) if (c > topCc) { topC = n; topCc = c; }
    cl.dominantParent = topP; cl.dominantChild = topC;
    const actualParent = cl.dominantParent || cl.parentNames[0] || "";
    const actualChild = cl.dominantChild || cl.childNames[0] || "";
    const parentMatchesChain = actualParent && cl.chainParent && _ptProcBase(actualParent) === _ptProcBase(cl.chainParent);
    const childMatchesChain = actualChild && cl.chainChild && _ptProcBase(actualChild) === _ptProcBase(cl.chainChild);
    cl.displayParent = parentMatchesChain ? actualParent : (actualParent || cl.chainParent || "Unknown parent");
    cl.displayChild = childMatchesChain ? actualChild : (actualChild || cl.chainChild || "Unknown child");
    delete cl.parentFreq; delete cl.childFreq;
    // Annotate cluster with best sequence confidence from member processes
    // seqRank: 2 = high (same-tree), 1 = medium (host+user), 0 = no sequence
    let bestSeqRank = 0;
    for (const k of cl.allKeys) {
      const seqs = seqMap?.get(k);
      if (seqs) for (const s of seqs) {
        const r = s.confidence === "high" ? 2 : 1;
        if (r > bestSeqRank) bestSeqRank = r;
      }
      if (bestSeqRank === 2) break;
    }
    cl.seqRank = bestSeqRank;
  }
	  // Sort by triage score first so rare high-signal process activity does not
	  // get buried below repetitive commodity hits with the same severity.
	  allClusters.sort((a, b) => (b.maxTriageScore || 0) - (a.maxTriageScore || 0) || b.level - a.level || b.seqRank - a.seqRank || b.count - a.count);
  return allClusters;
};

export const buildNodeClusterMap = (clusters) => {
  const m = new Map();
  if (!clusters?.length) return m;
  for (const cl of clusters) for (const k of cl.allKeys) m.set(k, cl);
  return m;
};

// ---------- Incident stories ----------

export const buildIncidentStories = (data, byKeyMap, childMap, detMap, seqMap, nodeClusterMap) => {
  if (!data?.processes?.length) return [];
  const GAP_MS = 20 * 60 * 1000;
  const hostOf = (p) => normalizeHost(p.hostname);
  const rootCache = new Map();
  const rootKeyOf = (key) => _rootKeyOf(key, byKeyMap, rootCache);
  const grouped = new Map();
  for (const p of (data.processes || [])) {
    const det = detMap.get(p.key);
    if (!det || det.level === 0 || !det.reason) continue;
    const host = hostOf(p);
    const user = String(p.user || "").trim();
    const groupKey = `${host}||${user.toLowerCase() || "(unknown)"}`;
    const _tsRaw = normalizeTimestamp(p.ts);
    const ts = Number.isFinite(_tsRaw) ? _tsRaw : 0;
    const seqs = seqMap.get(p.key) || [];
    const cluster = nodeClusterMap.get(p.key) || null;
    const ev = { key: p.key, node: p, det, seqs, cluster, host, user, rootKey: rootKeyOf(p.key), ts };
    if (!grouped.has(groupKey)) grouped.set(groupKey, []);
    grouped.get(groupKey).push(ev);
  }
  const stories = [];
  const mkStory = (ev) => ({
    host: ev.host,
    firstSeen: ev.node.ts || "",
    lastSeen: ev.node.ts || "",
    firstTs: ev.ts || 0,
    lastTs: ev.ts || 0,
    eventMap: new Map(),
    users: new Set(),
    rootKeys: new Set(),
    clusterIds: new Set(),
    reasons: new Map(),
    techniques: new Set(),
    sequenceMap: new Map(),
	    commands: [],
	    processLabels: new Map(),
	    maxLevel: 0,
	    maxScore: 0,
	    prevalenceSignals: new Set(),
	    bestSeqRank: 0,
	    anchor: null,
	  });
  const eventRank = (ev) => {
    let seqRank = 0;
    for (const s of ev.seqs || []) seqRank = Math.max(seqRank, s.confidence === "high" ? 2 : 1);
    const clusterCount = ev.cluster?.count || 0;
	    return [ev.det.triageScore || ((ev.det.level || 0) * 100), ev.det.level || 0, seqRank, clusterCount];
	  };
  const isBetterAnchor = (next, cur) => {
    if (!cur) return true;
    const a = eventRank(next);
    const b = eventRank(cur);
	    if (a[0] !== b[0]) return a[0] > b[0];
	    if (a[1] !== b[1]) return a[1] > b[1];
	    if (a[2] !== b[2]) return a[2] > b[2];
	    if (a[3] !== b[3]) return a[3] > b[3];
    if (next.ts && cur.ts) return next.ts < cur.ts;
    return false;
  };
  const addStoryEvent = (story, ev) => {
    if (story.eventMap.has(ev.key)) return;
    story.eventMap.set(ev.key, ev);
    if (ev.user) story.users.add(ev.user);
    if (ev.rootKey) story.rootKeys.add(ev.rootKey);
    if (ev.cluster?.id) story.clusterIds.add(ev.cluster.id);
    if (ev.ts && (!story.firstTs || ev.ts < story.firstTs)) {
      story.firstTs = ev.ts;
      if (ev.node.ts) story.firstSeen = ev.node.ts;
    }
    if (ev.ts && ev.ts > story.lastTs) {
      story.lastTs = ev.ts;
      if (ev.node.ts) story.lastSeen = ev.node.ts;
    }
    if (!story.firstSeen && ev.node.ts) story.firstSeen = ev.node.ts;
    if (!story.lastSeen && ev.node.ts) story.lastSeen = ev.node.ts;
	    if ((ev.det.level || 0) > story.maxLevel) story.maxLevel = ev.det.level || 0;
	    if ((ev.det.triageScore || 0) > story.maxScore) story.maxScore = ev.det.triageScore || 0;
	    for (const sig of (ev.det.prevalence?.signals || [])) story.prevalenceSignals.add(sig);
    const reason = ev.det.reason || "Suspicious process activity";
    story.reasons.set(reason, (story.reasons.get(reason) || 0) + 1);
    const procLabel = `${ev.node.parentProcessName || "Unknown parent"} \u2192 ${ev.node.processName || "Unknown process"}`;
    story.processLabels.set(procLabel, (story.processLabels.get(procLabel) || 0) + 1);
    for (const tid of (ev.det.techniques || [])) story.techniques.add(tid);
    for (const seq of (ev.seqs || [])) {
      const prev = story.sequenceMap.get(seq.seqId);
      const seqRank = seq.confidence === "high" ? 2 : 1;
      if (seqRank > story.bestSeqRank) story.bestSeqRank = seqRank;
      if (!prev) {
        story.sequenceMap.set(seq.seqId, { seqId: seq.seqId, name: seq.seqName, confidence: seq.confidence, count: 1, tid: [...(seq.tid || [])] });
      } else {
        prev.count += 1;
        if (seq.confidence === "high") prev.confidence = "high";
        for (const tid of (seq.tid || [])) if (!prev.tid.includes(tid)) prev.tid.push(tid);
      }
    }
    if (ev.node.cmdLine && !story.commands.includes(ev.node.cmdLine) && story.commands.length < 6) story.commands.push(ev.node.cmdLine);
    if (isBetterAnchor(ev, story.anchor)) story.anchor = ev;
  };
  const finalizeStory = (story, storyIdx) => {
    const events = [...story.eventMap.values()].sort((a, b) => {
      const at = a.ts || Number.MAX_SAFE_INTEGER;
      const bt = b.ts || Number.MAX_SAFE_INTEGER;
      return at - bt || b.det.level - a.det.level;
    });
    if (events.length === 0) return null;
    const anchor = story.anchor || events[0];
    const primaryCluster = anchor.cluster || null;
    const reasonList = [...story.reasons.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const processList = [...story.processLabels.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const sequences = [...story.sequenceMap.values()].sort((a, b) =>
      (b.confidence === "high") - (a.confidence === "high") || b.count - a.count || a.name.localeCompare(b.name)
    );
    const rootNames = [...story.rootKeys].map((k) => byKeyMap.get(k)?.processName).filter(Boolean);
    const durationMs = story.firstTs && story.lastTs && story.lastTs >= story.firstTs ? (story.lastTs - story.firstTs) : 0;
    const durationLabel = _ptFormatDuration(durationMs);
    const contextEventMap = new Map(events.map((ev) => [ev.key, { ...ev, isContext: false, contextRole: "" }]));
    const CONTEXT_NODE_LIMIT = 24;
    const addContextNode = (node, role, originEv) => {
      if (!node || contextEventMap.has(node.key) || contextEventMap.size >= CONTEXT_NODE_LIMIT) return;
      contextEventMap.set(node.key, {
        key: node.key,
        node,
        det: detMap.get(node.key) || { level: 0, reason: null },
        seqs: seqMap.get(node.key) || [],
        cluster: nodeClusterMap.get(node.key) || null,
        host: hostOf(node),
        user: String(node.user || "").trim(),
        rootKey: rootKeyOf(node.key),
        ts: (() => { const _t = normalizeTimestamp(node.ts); return Number.isFinite(_t) ? _t : 0; })(),
        isContext: true,
        contextRole: role,
        originKey: originEv?.key || "",
      });
    };
    for (const seed of events) {
      let curNode = byKeyMap.get(seed.key);
      let hops = 0;
      while (curNode?.parentKey && byKeyMap.has(curNode.parentKey) && hops++ < 6 && contextEventMap.size < CONTEXT_NODE_LIMIT) {
        const parentNode = byKeyMap.get(curNode.parentKey);
        addContextNode(parentNode, "ancestor", seed);
        curNode = parentNode;
      }
      const queue = [{ key: seed.key, depth: 0 }];
      while (queue.length > 0 && contextEventMap.size < CONTEXT_NODE_LIMIT) {
        const { key, depth } = queue.shift();
        if (depth >= 2) continue;
        for (const childKey of (childMap.get(key) || [])) {
          const childNode = byKeyMap.get(childKey);
          if (!childNode) continue;
          const _ct = normalizeTimestamp(childNode.ts);
          const childTs = Number.isFinite(_ct) ? _ct : 0;
          if (seed.ts && childTs && Math.abs(childTs - seed.ts) > GAP_MS) continue;
          addContextNode(childNode, "descendant", seed);
          queue.push({ key: childKey, depth: depth + 1 });
          if (contextEventMap.size >= CONTEXT_NODE_LIMIT) break;
        }
      }
    }
    const contextEvents = [...contextEventMap.values()].sort((a, b) => {
      const at = a.ts || Number.MAX_SAFE_INTEGER;
      const bt = b.ts || Number.MAX_SAFE_INTEGER;
      return at - bt || (b.det.level || 0) - (a.det.level || 0);
    });
    const contextOnlyCount = contextEvents.filter((ev) => ev.isContext).length;
    const title = primaryCluster
      ? `${primaryCluster.displayParent} \u2192 ${primaryCluster.displayChild}`
      : (processList[0]?.[0] || `${anchor.node.processName || "Process"} suspicious activity`);
    const leadReason = primaryCluster?.displayReason || reasonList[0]?.[0] || anchor.det.reason || "Suspicious process activity";
    const users = [...story.users].filter(Boolean);
    const headlineHost = story.host || "Current host";
    const storyline = [];
    const seenSteps = new Set();
    for (const ev of contextEvents) {
      const stepReason = ev.isContext
        ? ev.contextRole === "ancestor"
          ? "Process ancestry"
          : ev.contextRole === "descendant"
            ? "Child process context"
            : "Process context"
        : ev.det.reason;
      const stepSig = `${ev.isContext ? ev.contextRole : ev.det.reason}||${ev.node.parentProcessName || ""}||${ev.node.processName || ""}`;
      if (seenSteps.has(stepSig) && storyline.length >= 4) continue;
      seenSteps.add(stepSig);
      storyline.push({
        key: ev.key,
        ts: ev.node.ts || "",
        level: ev.det.level || 0,
        reason: stepReason,
        parent: ev.node.parentProcessName || "Unknown parent",
        child: ev.node.processName || "Unknown process",
        cmdLine: ev.node.cmdLine || "",
        sequences: ev.isContext ? [] : (ev.seqs || []).map((s) => s.seqName),
        isContext: !!ev.isContext,
        contextRole: ev.contextRole || "",
      });
      if (storyline.length >= 8) break;
    }
    const narrativeBits = [
      `On ${headlineHost}${users.length ? ` as ${users.slice(0, 2).join(", ")}` : ""}, activity started with ${title}.`,
      `${leadReason}${durationLabel ? ` over ${durationLabel}` : ""}.`,
      `${story.clusterIds.size || 1} detection chain${(story.clusterIds.size || 1) !== 1 ? "s" : ""}, ${events.length} suspicious event${events.length !== 1 ? "s" : ""}${sequences.length ? `, ${sequences.length} behavioral sequence${sequences.length !== 1 ? "s" : ""}` : ""}.`,
      contextOnlyCount > 0 ? `${contextOnlyCount} related process context event${contextOnlyCount !== 1 ? "s" : ""} included for ancestry and child activity.` : null,
    ];
    const searchBlob = [
      headlineHost, ...users, title, leadReason, ...reasonList.map(([r]) => r), ...rootNames,
      ...story.commands, ...sequences.map((s) => s.name), ...storyline.map((s) => `${s.parent} ${s.child} ${s.reason}`),
    ].join("\n").toLowerCase();
	    const prevalenceSignals = [...story.prevalenceSignals].slice(0, 8);
	    // Severity is a BAND, not a term. The old form added cluster count and raw
	    // event count to a level*100 base, so a noisy high-severity story (many
	    // clusters, ~100 events) outscored a single critical finding and took the
	    // hero banner — the banner said "critical" while headlining the wrong
	    // incident. Volume now only orders stories WITHIN a severity band.
	    const _severityBand = (story.maxLevel || 0) * 1000;
	    const _withinBand = Math.min(
	      999,
	      Math.max(0, (story.maxScore || 0) - ((story.maxLevel || 0) * 100))
	      + (story.bestSeqRank * 20) + ((story.clusterIds.size || 0) * 6) + events.length,
	    );
	    const triageScore = _severityBand + _withinBand;
    return {
      id: `story-${headlineHost || "host"}-${users[0] || "user"}-${story.firstTs || storyIdx}-${storyIdx}`,
      hostname: headlineHost,
      users,
      firstSeen: story.firstSeen,
      lastSeen: story.lastSeen,
      firstTs: story.firstTs,
      lastTs: story.lastTs,
      durationMs,
      durationLabel,
      level: story.maxLevel,
      seqRank: story.bestSeqRank,
      chainCount: Math.max(1, story.clusterIds.size),
      eventCount: events.length,
      sequenceCount: sequences.length,
      techniques: [...story.techniques].sort(),
      sequences,
      rootNames,
      title,
      leadReason,
      narrative: narrativeBits.join(" "),
      steps: storyline,
      commands: story.commands,
	      reasonList,
	      prevalenceSignals,
	      anchorKey: anchor.key,
      allKeys: events.map((ev) => ev.key),
      contextKeys: contextEvents.map((ev) => ev.key),
      contextEventCount: contextEvents.length,
      contextOnlyCount,
      triageScore,
      searchBlob,
    };
  };
	  for (const events of grouped.values()) {
	    events.sort((a, b) => {
	      const at = a.ts || Number.MAX_SAFE_INTEGER;
	      const bt = b.ts || Number.MAX_SAFE_INTEGER;
	      return at - bt || (b.det.triageScore || 0) - (a.det.triageScore || 0) || b.det.level - a.det.level;
	    });
    let cur = null;
    for (const ev of events) {
      const sameRoot = !!(cur && cur.rootKeys.has(ev.rootKey));
      const closeInTime = !!(cur && ev.ts && cur.lastTs && (ev.ts - cur.lastTs) <= GAP_MS);
      // An incident is a process SUBTREE, not "everything on this host/user in a 20-min
      // window." Merge into the current story only when the event shares its execution
      // root (sameRoot) AND is temporally close. Time-proximity ALONE must not merge two
      // unrelated roots — that previously let an unrelated process that merely happened
      // near in time absorb a detection and capture the story headline + chain/event
      // counts (the cortex-xdr-payload.exe → skype.exe misattribution). Same-root but
      // far-apart re-execution also starts a fresh story so durations stay meaningful.
      if (!cur || !(sameRoot && closeInTime)) {
        const finalized = cur ? finalizeStory(cur, stories.length) : null;
        if (finalized) stories.push(finalized);
        cur = mkStory(ev);
      }
      addStoryEvent(cur, ev);
    }
    const finalized = cur ? finalizeStory(cur, stories.length) : null;
    if (finalized) stories.push(finalized);
  }
  stories.sort((a, b) => b.triageScore - a.triageScore || b.lastTs - a.lastTs || b.eventCount - a.eventCount);
  return stories;
};

export const buildNodeStoryMap = (stories) => {
  const m = new Map();
  if (!stories?.length) return m;
  for (const story of stories) {
    for (const key of story.allKeys) m.set(key, story);
    for (const key of (story.contextKeys || [])) if (!m.has(key)) m.set(key, story);
  }
  return m;
};

// ---------- Lifetime analysis (cross-node) ----------

// Detects respawn patterns: short-lived respawns and service/task-driven
// re-execution. Returns a Map<processKey, lifetimeInfo>.
export const buildLifetimeAnalysis = (data) => {
  const result = new Map();
  if (!data?.processes?.length) return result;

  // Group processes by (processName, normHost) — use the actual processName
  // plus normalized hostname so PID-reuse-on-different-hosts doesn't collide.
  const groups = new Map();
  for (const p of data.processes) {
    const pn = (p.processName || "").toLowerCase();
    if (!pn) continue;
    const host = (p.normHost || p.hostname || "").toLowerCase();
    const gk = `${pn}||${host}`;
    if (!groups.has(gk)) groups.set(gk, []);
    groups.get(gk).push(p);
  }

  const SHORT_THRESHOLD_MS = 5000; // 5 seconds
  const RESPAWN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
  const MIN_RESPAWN_COUNT = 4;

  for (const [, procs] of groups) {
    if (procs.length < MIN_RESPAWN_COUNT) continue;
    // Sort by creation time
    const sorted = procs.filter((p) => Number.isFinite(p.tsMs)).sort((a, b) => a.tsMs - b.tsMs);
    if (sorted.length < MIN_RESPAWN_COUNT) continue;

    // Sliding window: find clusters of short-lived respawns
    for (let i = 0; i < sorted.length; i++) {
      const windowEnd = sorted[i].tsMs + RESPAWN_WINDOW_MS;
      const window = [];
      for (let j = i; j < sorted.length && sorted[j].tsMs <= windowEnd; j++) window.push(sorted[j]);
      if (window.length < MIN_RESPAWN_COUNT) continue;

      // Count short-lived instances in this window
      const shortLived = window.filter((p) => Number.isFinite(p.durationMs) && p.durationMs < SHORT_THRESHOLD_MS);

      if (shortLived.length >= MIN_RESPAWN_COUNT) {
        for (const p of shortLived) {
          if (!result.has(p.key)) {
            result.set(p.key, {
              type: "short-respawn",
              count: shortLived.length,
              windowMs: RESPAWN_WINDOW_MS,
              label: `${shortLived.length}x short-lived respawns in ${Math.round(RESPAWN_WINDOW_MS / 60000)}min`,
            });
          }
        }
      }

      // Per-element scan (i++ each step). The result Map is keyed by p.key, so overlapping
      // windows can't create duplicate entries. Window-building is bounded by the 10-minute
      // time window, so this stays cheap and is computed once (memoized by callers).
    }
  }
  return result;
};

// ---------- Trust analysis (cross-host hash anomaly) ----------

// Detects cross-row binary trust anomalies: same image path with different
// hashes across hosts, and same process name appearing from a rare or
// user-writable path. These are cross-dataset signals, so they live outside the
// single-node rule catalog and are injected into buildDetectionMap.
export const buildTrustAnalysis = (data) => {
  const result = new Map();
  const processes = data?.processes || [];
  if (!processes.length) return result;

  // Group by normalized image path — collect unique host/hash pairs.
  const imageGroups = new Map();
  const nameGroups = new Map();
  for (const p of processes) {
    const img = _ptLower(p.image);
    const name = _ptLower(p.processName || "").replace(/\.exe$/i, "");
    const hash = _strongHash(p.hashes);
    const host = (p.normHost || p.hostname || "").toLowerCase();
    if (img && hash && host) {
      if (!imageGroups.has(img)) imageGroups.set(img, new Map());
      const hashMap = imageGroups.get(img);
      if (!hashMap.has(hash)) hashMap.set(hash, { hosts: new Set(), keys: [] });
      hashMap.get(hash).hosts.add(host);
      hashMap.get(hash).keys.push(p.key);
    }
    if (name && img) {
      if (!nameGroups.has(name)) nameGroups.set(name, new Map());
      const pathMap = nameGroups.get(name);
      if (!pathMap.has(img)) pathMap.set(img, { keys: [], hosts: new Set(), userWritable: _RX_PT_USER_WRITABLE_PATH.test(img) });
      pathMap.get(img).keys.push(p.key);
      if (host) pathMap.get(img).hosts.add(host);
    }
  }

  for (const [img, hashMap] of imageGroups) {
    if (hashMap.size < 2) continue;
    const allHosts = new Set();
    for (const info of hashMap.values()) for (const host of info.hosts) allHosts.add(host);
    if (allHosts.size < 2) continue;
    for (const [, info] of hashMap) {
      for (const key of info.keys) {
        result.set(key, {
          type: "cross-host-hash-mismatch",
          imagePath: img,
          hostCount: allHosts.size,
          hashCount: hashMap.size,
          sensitivePath: _RX_PT_TRUST_SENSITIVE_PATH.test(img),
          label: `Same path on ${allHosts.size} hosts with ${hashMap.size} different hashes`,
        });
      }
    }
  }

  for (const [name, pathMap] of nameGroups) {
    const total = [...pathMap.values()].reduce((sum, info) => sum + info.keys.length, 0);
    if (total < 3 || pathMap.size < 2) continue;
    for (const [img, info] of pathMap) {
      const count = info.keys.length;
      const userWritable = info.userWritable || _RX_PT_USER_WRITABLE_PATH.test(img);
      // Skip legit per-user install/update dirs — a same-named binary appearing from a
      // Squirrel/Electron app dir or \AppData\Local\Programs is normal, not a dropper.
      if (userWritable && _RX_PT_BENIGN_PERUSER_PATH.test(img)) continue;
      if (count > 1 && !userWritable) continue;
      if (!userWritable && total < 10) continue;
      const existingScore = userWritable ? 2 : 1;
      for (const key of info.keys) {
        const existing = result.get(key);
        if (existing?.type === "cross-host-hash-mismatch") continue;
        if (existing && existingScore <= 1) continue;
        result.set(key, {
          type: "same-name-unusual-path",
          processName: name.endsWith(".exe") ? name : `${name}.exe`,
          imagePath: img,
          pathCount: pathMap.size,
          instanceCount: count,
          totalCount: total,
          userWritable,
          label: `${name}.exe appears from rare path ${img}`,
        });
      }
    }
  }
  return result;
};
