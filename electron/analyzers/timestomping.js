const { dbg } = require("../logger");
const { classifyPath, isServicingChurn } = require("../utils/path-class");

/**
 * Timestomping Detector (MITRE T1070.006) — finds MFT files whose
 * $STANDARD_INFORMATION (0x10 / $SI, attacker-forgeable) timestamps disagree with
 * $FILE_NAME (0x30 / $FN, OS-maintained) timestamps, scores them, and surfaces the
 * suspicious population with confidence/severity.
 *
 * Signals (Tier 0/1/2):
 *   - backdating: $SI earlier than $FN at FULL 100ns precision (the classic tell);
 *   - sub-second-only backdating + zeroed $SI sub-seconds (the strongest modern tell);
 *   - forward-dating: $SI LATER than $FN, and future-dated $SI;
 *   - modified-before-created anomaly;
 *   - mass / identical-$SI clustering (bulk-timestomp tool signature).
 * False-positive floor: shared path classifier (servicing/cache churn down-weighted,
 * but System32 / Temp / staging NOT — those are adversary drop sites), Mark-of-the-Web
 * (downloaded) dampening, and per-field (not blanket) sub-second-zero weighting.
 */

// ── Module constants (lifted to module scope for inspectability/testing) ──────
const EXEC_EXTS = new Set([".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta", ".scr", ".pif", ".msi", ".com", ".sys", ".drv", ".jar", ".lnk"]);
const ARCHIVE_EXTS = new Set([".zip", ".rar", ".7z", ".iso", ".img", ".cab"]);
// The forward/future-dating fetch (Tier 3 / C1) is no longer EXEC-only: web-shells, Office macros,
// scripts, and staging/dropper containers are equally high-value timestomp targets. Extension-less
// payloads are picked up by a separate clause. Kept to a high-value SET (not all files) so the
// column-vs-column / vs-now comparison stays bounded on a 30-50GB volume.
const SUSPICIOUS_EXTS = new Set([
  ...EXEC_EXTS, ...ARCHIVE_EXTS,
  ".aspx", ".asp", ".php", ".jsp", ".jspx", ".cfm", ".ashx", ".asmx",       // web shells
  ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xll", ".one",               // Office macros / add-ins
  ".py", ".rb", ".pl", ".sh", ".psm1", ".psd1",                              // scripts
  ".dat", ".bin", ".tmp", ".db", ".log", ".chk",                             // staging / dropper containers
]);
// High-frequency container/cache extensions whose $SI commonly LEADS $FN benignly ($FN-update lag,
// clock adjustments on logs/temp/caches/SQLite DBs). They are fetched (for the future-dated / multi-
// signal / corroborated cases) but a BARE forward-only hit on one is suppressed (review FP fix).
const CHURNY_CONTAINER_EXTS = new Set([".dat", ".bin", ".tmp", ".db", ".log", ".chk"]);

// The four comparable $SI/$FN timestamp pairs. Order = severity weight order.
const FIELD_DEFS = [
  ["Created", "siCreated", "fnCreated"],
  ["Modified", "siModified", "fnModified"],
  ["RecordChange", "siRecordChange", "fnRecordChange"],
  ["Accessed", "siAccess", "fnAccess"],
];

const CLUSTER_MIN = 5;        // ≥N candidates sharing one exact $SI Created = mass-timestomp signature
const MAX_FETCH = 50000;      // cap candidate rows scored in one pass (note truncation beyond this)
// A $SI stamp must lead "now" by more than this to count as future-dated (A3): RTC drift, cloned/
// misconfigured VMs, backups from a future-clocked host, and import/DST skew routinely push a naive-UTC
// stamp a little past the wall clock. A 30-second-future stamp is skew; a 2099 stamp is a stomp.
const FUTURE_SKEW_MS = 24 * 3600 * 1000; // 1 day

// ── Timestamp parsing (FULL 100ns precision — the canonical MFT form is
//    "YYYY-MM-DD HH:MM:SS.fffffff"; MFTECmd CSVs carry the same sub-second field) ──
//
// Returns { ms, frac } where frac is the sub-second component in 100ns ticks (0..9999999),
// or null when unparseable. Returns an OBJECT for the Unix epoch (ms===0) so callers can
// guard on `!== null` instead of truthiness (a 1970-01-01 00:00:00 stamp is a real instant).
function parseTsParts(s) {
  if (s == null) return null;
  const m = String(s).match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?/);
  if (!m) return null;
  const ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  if (Number.isNaN(ms)) return null;
  const frac = m[7] ? Number((m[7] + "0000000").slice(0, 7)) : 0;
  return { ms, frac };
}

// Full-precision comparison of two parsed parts: -1 (a<b), 0 (equal), 1 (a>b).
function cmpParts(a, b) {
  if (!a || !b) return null;
  if (a.ms !== b.ms) return a.ms < b.ms ? -1 : 1;
  if (a.frac !== b.frac) return a.frac < b.frac ? -1 : 1;
  return 0;
}

/**
 * Analyze one fetched candidate row: classify per-field SI/FN relationships at full
 * precision, derive signals, and compute a base score (cluster boost applied later).
 * Pure (besides reading the row); returns the enriched row with computed fields.
 */
function analyzeFile(f, nowMs) {
  const stompedFields = [];     // SI < FN  (backdating)
  const forwardFields = [];     // SI > FN  (forward/post-dating)
  const deltas = [];
  const mismatchMap = {};
  let subSecondOnly = false;    // backdated by a sub-second margin only (second-equal, frac-earlier)
  let zeroedStompedField = false; // a STOMPED field whose $SI sub-second is zeroed (aligned signal)
  let futureDated = false;
  const siParts = {};

  for (const [field, siKey, fnKey] of FIELD_DEFS) {
    const sp = parseTsParts(f[siKey]);
    const fp = parseTsParts(f[fnKey]);
    siParts[field] = sp;
    if (sp && sp.ms > nowMs + FUTURE_SKEW_MS) futureDated = true;
    if (sp === null || fp === null) continue;
    const cmp = cmpParts(sp, fp);
    if (cmp < 0) {
      stompedFields.push(field);
      const deltaHours = Math.abs(fp.ms - sp.ms) / 3600000;
      deltas.push(deltaHours);
      mismatchMap[field] = deltaHours;
      if (sp.ms === fp.ms) subSecondOnly = true; // equal to the second, earlier sub-second
      if (sp.frac === 0) zeroedStompedField = true;
    } else if (cmp > 0) {
      forwardFields.push(field);
    }
  }

  // $SI all-four-equal at full precision (bulk-timestomp hallmark)
  const siVals = FIELD_DEFS.map(([fld]) => siParts[fld]).filter(Boolean);
  const allFourSiEqual = siVals.length === 4 && siVals.every((p) => cmpParts(p, siVals[0]) === 0);
  const anySiZeroed = siVals.some((p) => p.frac === 0);

  // modified-before-created anomaly ($SI Modified earlier than $SI Created)
  const siC = siParts.Created, siM = siParts.Modified;
  const modifiedBeforeCreated = siC && siM && cmpParts(siM, siC) < 0;

  f.stompedFields = stompedFields;
  f.forwardFields = forwardFields;
  f.maxDeltaHours = deltas.length > 0 ? Math.max(...deltas) : 0;

  const extension = (f.extension || "").toLowerCase();
  const parentPath = f.parentPath || "";
  const pathClass = classifyPath(parentPath);
  const isChurn = isServicingChurn(parentPath);
  const isExec = EXEC_EXTS.has(extension);
  const isArchive = ARCHIVE_EXTS.has(extension);
  const hasMotw = String(f.zoneId || "").trim() !== ""; // Mark-of-the-Web → downloaded
  const createdMismatch = mismatchMap.Created != null;
  const hasFnCreated = parseTsParts(f.fnCreated) !== null;
  const onlyAccessMismatch = stompedFields.length === 1 && stompedFields[0] === "Accessed";
  const hasForward = forwardFields.length > 0;

  let score = 0;
  const indicators = [];
  // ── Positive signals ──
  if (createdMismatch && hasFnCreated) { score += 3; indicators.push("SI created precedes FN created"); }
  if (mismatchMap.Modified != null) { score += 2; indicators.push("SI modified precedes FN modified"); }
  if (mismatchMap.RecordChange != null) { score += 1; indicators.push("SI record change precedes FN record change"); }
  if (subSecondOnly && createdMismatch) indicators.push("sub-second SI<FN backdating");
  if (hasForward) { score += 2; indicators.push(`FN precedes SI (forward-dated: ${forwardFields.join(", ")})`); }
  if (futureDated) { score += 2; indicators.push("SI timestamp is in the future"); }
  if (stompedFields.length >= 2) { score += 1; indicators.push("multiple SI/FN mismatches"); }
  if (zeroedStompedField) { score += 2; indicators.push("zeroed SI sub-seconds on a stomped field"); }
  if (allFourSiEqual && anySiZeroed && (createdMismatch || hasForward)) { score += 1; indicators.push("all four SI timestamps identical + zeroed (bulk hallmark)"); }
  if (modifiedBeforeCreated) indicators.push("SI modified precedes SI created (copy or stomp)");
  if (f.maxDeltaHours >= 24 * 30) score += 1;
  if (f.maxDeltaHours >= 24 * 365) score += 1;
  if (isExec) { score += 2; indicators.push("executable/script extension"); }
  else if (isArchive) { score += 1; indicators.push("container/archive extension"); }
  // Path boost is GATED behind an independent malice signal (Tier 1): a stomped/zeroed file in
  // System32 (attacker drop site) is notable; user-writable membership alone is NOT.
  if (isExec || zeroedStompedField) {
    if (pathClass === "system" && !isChurn) { score += 2; indicators.push("stomped binary in a system path"); }
    else if (pathClass !== "servicing-churn" && pathClass !== "program-files") { score += 1; }
  }
  // ── Dampeners ──
  if (isChurn) { score -= 4; indicators.push("OS servicing/cache churn path (dampened)"); }
  if (hasMotw) { score -= 2; indicators.push("has Mark-of-the-Web (downloaded)"); }
  // Copy-provenance dampener (Copied = $SI created > modified, set identically by the app parser
  // and MFTECmd). Gated so it can never bury an ALIGNED stomp signal (zeroed / forward / future), but
  // NOT gated off for executables (A5): copying/restoring a benign tool legitimately backdates an exe's
  // $SI, and the bare exec extension is not itself malice — only the aligned lanes escalate execs.
  const looksCopied = String(f.copied || "").toLowerCase() === "true";
  if (looksCopied && !zeroedStompedField && !hasForward && !futureDated) { score -= 2; indicators.push("copy-like timestamp pattern (dampened)"); }
  // Program-Files install/extraction backdating (A1): an installer writing a binary whose $SI Created
  // (and often Modified) = the vendor build time, earlier than $FN = landing time — the single most
  // common benign SI<FN population. With NO aligned signal (zeroed sub-seconds / forward / future) and
  // only Created/Modified backdating, this is install-backdating, not a stomp. A long delta here is the
  // install SIGNATURE, not evidence. Flagged (not scored) so a cluster member can veto it downstream.
  const onlyCreatedModified = stompedFields.length > 0 && stompedFields.every((x) => x === "Created" || x === "Modified");
  f.benignBackdateCandidate = pathClass === "program-files" && !zeroedStompedField && !hasForward && !futureDated && onlyCreatedModified;

  f.score = score;
  f.indicators = indicators;
  f.pathClass = pathClass;
  f.isChurn = isChurn;
  f.hasMotw = hasMotw;
  f.noisyContext = isChurn;
  f.isExec = isExec;
  f.zeroedStompedField = zeroedStompedField;
  f.createdMismatch = createdMismatch;
  f.onlyAccessMismatch = onlyAccessMismatch;
  f.hasForward = hasForward;
  f.futureDated = futureDated;
  return f;
}

/** Finalize confidence/severity from the (post-cluster, post-corroboration) score + signals. */
function finalizeSeverity(f) {
  // Cross-artifact CONFIRMATION (Tier 2) overrides the $SI-vs-$FN inference: Sysmon EID 2 (FileCreateTime)
  // IS the literal timestomp event — a match is a confirmed stomp (critical) regardless of path/MotW.
  if (f.eid2Corroborated) { f.confidence = "high"; f.severity = "critical"; return f; }
  // A USN FileCreate that postdates the (backdated) $SI Created is a forgery-resistant contradiction.
  const usnStrong = !!f.usnContradicted;
  // Install/copy backdating under Program Files with no aligned malice signal — the dominant benign
  // SI<FN population — is capped at low so it can never flood high/critical (A1). A clustered or
  // USN-contradicted file is NOT treated as benign here.
  if (f.benignBackdateCandidate && !f.clusterMember && !usnStrong) { f.confidence = "low"; f.severity = "low"; return f; }

  // A lone future-dated $SI (beyond the skew tolerance) is suspicious but ambiguous (clock/skew/clone);
  // it counts as a STRONG signal only when it co-occurs with an actual SI/FN mismatch or zeroing (A3).
  const futureStrong = f.futureDated && (f.stompedFields.length >= 1 || f.zeroedStompedField || f.hasForward);
  const strong = (f.createdMismatch && f.zeroedStompedField) || f.clusterMember || futureStrong || usnStrong;
  // Mark-of-the-Web explains PLAIN backdating (vendor build < download time), so it dampens the gates —
  // but it does NOT explain a forgery-resistant aligned signal (zeroed sub-seconds, forward/future-dating,
  // bulk-cluster membership, or a USN contradiction). A downloaded-then-timestomped payload must not be
  // buried by its download provenance (review fix).
  const aligned = f.zeroedStompedField || f.hasForward || futureStrong || f.clusterMember || usnStrong;
  const motwOk = !f.hasMotw || aligned;
  // A USN create-time contradiction is forgery-resistant and BEATS the servicing-churn path floor (B2).
  const churnOk = !f.isChurn || usnStrong;
  let confidence = "low";
  if (strong && churnOk && motwOk && (f.isExec || f.stompedFields.length >= 2 || f.clusterMember || usnStrong)) confidence = "high";
  // Medium requires an ALIGNED signal (zeroed sub-seconds, multi-field, forward, future-strong, or USN
  // contradiction) — NOT a long delta alone (A1) and NOT a Mark-of-the-Web download lacking one (A4).
  else if ((f.createdMismatch || f.hasForward || usnStrong) && churnOk && motwOk && (f.zeroedStompedField || f.stompedFields.length >= 2 || f.hasForward || futureStrong || usnStrong)) confidence = "medium";
  f.confidence = confidence;

  // EID 2 (handled above) is critical; a USN-only contradiction is forgery-resistant but leaf-name-matched
  // (some same-name FP risk), so it caps at HIGH unless the file is also an exec/cluster member.
  if (confidence === "high" && (f.isExec || f.clusterMember)) f.severity = "critical";
  else if (confidence === "high" || (confidence === "medium" && f.isExec)) f.severity = "high";
  else if (confidence === "medium" || f.score >= 3) f.severity = "medium";
  else f.severity = "low";
  return f;
}

/** Suppression predicate (extracted + loosened — Tier 1). Returns a reason string or null. */
function suppressReason(f) {
  // Cross-artifact confirmed/contradicted findings (Tier 2) are NEVER suppressed — the forgery-resistant
  // witness overrides path-class / score / access-only / install-backdate floors.
  if (f.eid2Corroborated || f.usnContradicted) return null;
  if (f.score <= 0) return "score<=0";
  // Program-Files install/extraction backdating with no aligned signal (A1) — the dominant benign
  // SI<FN population — is dropped (still counted in suppressedCount). A cluster member is never benign.
  if (f.benignBackdateCandidate && !f.clusterMember) return "program-files-backdate";
  // Access-only evidence with no other signal is noise.
  if (f.onlyAccessMismatch && !f.isExec && !f.zeroedStompedField && !f.clusterMember && !f.hasForward) return "access-only";
  // Bare forward-dating on a high-frequency container/cache extension (.log/.tmp/.dat/.db/.bin/.chk) is
  // routine ($FN-update lag / clock adjustment), not a stomp — drop it unless paired with a real signal
  // (zeroed / cluster / future / >=2 stomped fields; corroboration is exempted at the top of this fn).
  if (CHURNY_CONTAINER_EXTS.has((f.extension || "").toLowerCase()) && f.hasForward && !f.isExec &&
      !f.zeroedStompedField && !f.clusterMember && !f.futureDated && f.stompedFields.length < 2) return "forward-only-container";
  // Churn paths are dropped only when there is no real corroborating signal.
  if (f.isChurn && !f.isExec && !f.zeroedStompedField && !f.clusterMember && f.confidence !== "high") return "servicing-churn";
  return null;
}

/**
 * Synthesize a timestomping incident verdict (Tier 4). PURE (no DB/clock) so it is unit-testable.
 * Keeps IMPACT (severity) and EVIDENTIARY STRENGTH (confidence) separate: confidence is 'corroborated'
 * only when a forgery-resistant witness (Sysmon EID 2 / USN FileCreate) backs the $SI/$FN inference;
 * 'weak' when companions are loaded but corroborate nothing; 'observed' for single-source $MFT.
 * The coverage block states what is and isn't visible (a full-copy $SI==$FN stomp leaves no $MFT mismatch).
 */
function _buildTimestompVerdict(o) {
  const total = o.totalTimestomped || 0;
  const crit = o.criticalCount || 0, high = o.highCount || 0, med = o.mediumCount || 0;
  const clusters = o.clusterCount || 0, fwd = o.forwardCount || 0, fut = o.futureCount || 0;
  const corr = o.correlation || {};
  const noMatch = (o.confirmedStompsNoMftMatch || []).length;
  const eid2 = corr.candidatesEid2Corroborated || 0, usn = corr.candidatesUsnContradicted || 0;
  const corroborated = eid2 > 0 || usn > 0 || noMatch > 0;
  const companionLoaded = !!(corr.evtxAvailable || corr.usnAvailable);

  const coverage = [];
  coverage.push({ label: "$SI vs $FN ($MFT)", detail: "$STANDARD_INFORMATION ($SI) is attacker-forgeable; $FILE_NAME ($FN) is OS-maintained. SI<FN, forward/future-dating and zeroed sub-seconds are indicators, not proof.", status: "partial" });
  coverage.push(corr.evtxAvailable
    ? { label: "Sysmon EID 2 (FileCreateTime)", detail: `${(corr.evtxFileCreateTimeTotal || 0).toLocaleString()} event(s); ${eid2} candidate(s) confirmed, ${noMatch} stomp(s) with no $MFT mismatch.`, status: (eid2 || noMatch) ? "ok" : "partial" }
    : { label: "Sysmon EID 2 (FileCreateTime)", detail: "No Sysmon EVTX companion — the literal timestomp event (pre-stomp time + tool), and full-copy / $FN-rewriting stomps, are not visible.", status: "gap" });
  coverage.push(corr.usnAvailable
    ? { label: "USN ($J) FileCreate", detail: `${(corr.usnFileCreateTotal || 0).toLocaleString()} FileCreate(s); ${usn} create-time contradiction(s).`, status: usn ? "ok" : "partial" }
    : { label: "USN ($J) FileCreate", detail: "No USN companion — the forgery-resistant create-time contradiction check did not run.", status: "gap" });
  if (o.truncated) coverage.push({ label: "Scan cap", detail: `Candidate scan capped at ${MAX_FETCH.toLocaleString()}; lower-signal records beyond the cap were not scored.`, status: "partial" });
  if (corr.evtxCapped || corr.usnCapped) coverage.push({ label: "Companion cap", detail: "A companion scan hit its row cap — corroboration counts are a floor.", status: "partial" });

  if (total === 0 && noMatch === 0) {
    return {
      severity: "info", severityScore: 0, confidence: companionLoaded ? "observed" : "none",
      headline: "No timestomp indicators detected.",
      narrative: `No $SI/$FN inconsistency, forward/future-dating, or bulk-$SI cluster was found in the analyzed $MFT${companionLoaded ? ", and no Sysmon EID 2 / USN contradiction was present in the loaded companion(s)." : "."} $SI is attacker-forgeable and a full-copy $SI==$FN zeroed stomp leaves NO $MFT mismatch${companionLoaded ? "" : " — load a Sysmon EVTX (EID 2) / USN companion to corroborate"}.`,
      factors: [], mitre: [], coverage,
    };
  }

  let score = Math.min(40, crit * 12 + high * 6 + med * 2);
  if (clusters > 0) score += Math.min(20, 8 + clusters * 4);
  if (noMatch > 0) score += Math.min(25, 10 + noMatch * 3);
  if (fut > 0) score += 5;
  score = Math.min(100, Math.round(score));

  let severity;
  if (crit > 0 || noMatch > 0 || (clusters > 0 && corroborated)) severity = "critical";
  else if (high > 0 || clusters > 0) severity = "high";
  else if (med > 0) severity = "medium";
  else if (total > 0) severity = "low";
  else severity = "info";

  let confidence, confNote;
  if (corroborated) { confidence = "corroborated"; confNote = "backed by forgery-resistant Sysmon EID 2 / USN evidence"; }
  else if (companionLoaded) { confidence = "weak"; confNote = "companion EVTX/USN tabs are loaded but do not corroborate the $SI/$FN findings"; }
  else { confidence = "observed"; confNote = "single-source $MFT ($SI vs $FN) — load a Sysmon EVTX (EID 2) / USN companion to corroborate"; }

  const factors = [];
  if (crit > 0) factors.push({ label: `${crit} critical`, detail: "confirmed or strong-signal timestomp(s)", severity: "high" });
  if (clusters > 0) factors.push({ label: `${clusters} bulk-stomp cluster${clusters === 1 ? "" : "s"}`, detail: "files sharing one $SI Created with an aligned signal — a mass-timestomp tool signature", severity: "high" });
  if (noMatch > 0) factors.push({ label: `${noMatch} EID-2 confirmed, no $MFT mismatch`, detail: "full-copy / double-stomp the $MFT alone can't see", severity: "high" });
  if (eid2 > 0) factors.push({ label: `${eid2} Sysmon-confirmed`, detail: "matched a FileCreateTime event; pre-stomp time + tool recovered", severity: "info" });
  if (usn > 0) factors.push({ label: `${usn} USN-contradicted`, detail: "real create time postdates the backdated $SI", severity: "info" });
  if (fwd > 0) factors.push({ label: `${fwd} forward-dated`, detail: "$SI later than $FN", severity: "medium" });
  if (fut > 0) factors.push({ label: `${fut} future-dated`, detail: "$SI beyond the present (skew-tolerant)", severity: "medium" });

  const mitre = [{ technique: "T1070.006", name: "Indicator Removal: Timestomp", confidence: corroborated ? "corroborated" : "observed", evidence: corroborated ? (eid2 ? "Sysmon EID 2 FileCreateTime events on flagged files" : usn ? "USN FileCreate contradictions" : "Sysmon EID 2 stomps with no $MFT mismatch") : "$SI/$FN inconsistency + forward/future-dating ($MFT)" }];

  const cap = severity.toUpperCase();
  const lead = (total === 0 && noMatch > 0)
    ? `${noMatch} Sysmon-confirmed timestomp(s) with no $MFT mismatch`
    : `${total.toLocaleString()} timestomp indicator(s)${crit > 0 ? `, ${crit} critical` : ""}${(eid2 + noMatch) > 0 ? `, ${eid2 + noMatch} Sysmon-confirmed` : ""}`;
  const headline = `${cap} (${confidence}): ${lead}.`;

  const bits = [];
  bits.push(`${total.toLocaleString()} file(s) flagged from ${(o.rawSiFnCount || 0).toLocaleString()} candidate(s) (${(o.suppressedCount || 0).toLocaleString()} suppressed as install / servicing-churn / MotW).`);
  if (clusters > 0) bits.push(`${clusters} bulk-$SI cluster(s) indicate a mass-timestomp tool.`);
  if (noMatch > 0) bits.push(`${noMatch} Sysmon EID 2 stomp(s) had NO $MFT mismatch — full-copy / $FN-rewriting stomps the $MFT alone cannot reveal.`);
  if (eid2 > 0 || usn > 0) bits.push(`Forgery-resistant corroboration: ${eid2} Sysmon-confirmed, ${usn} USN-contradicted.`);
  bits.push(`Confidence is ${confidence} — ${confNote}. $SI is user-settable; corroborate flagged files with Sysmon EID 2 (the literal timestomp event) and the USN journal before relying on them.`);

  return { severity, severityScore: score, confidence, headline, narrative: bits.join(" "), factors, mitre, coverage };
}

function detectTimestomping(meta, opts = {}) {
  const empty = {
    totalTimestomped: 0, rawSiFnCount: 0, suppressedCount: 0, totalFiles: 0, percentTimestomped: 0,
    files: [], clusters: [], topDirectories: [], extensionBreakdown: [],
    criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0,
    highConfidenceCount: 0, likelyCount: 0, contextCount: 0,
    forwardCount: 0, futureCount: 0, clusterCount: 0, truncated: false, notes: [],
    correlation: { evtxAvailable: false, usnAvailable: false, evtxFileCreateTimeTotal: 0, usnFileCreateTotal: 0, candidatesEid2Corroborated: 0, candidatesUsnContradicted: 0, evtxScanned: 0, evtxCapped: false, usnScanned: 0, usnCapped: false },
    confirmedStompsNoMftMatch: [], verdict: null,
  };
  if (!meta) return empty;

  const db = meta.db;
  const col = (name) => meta.colMap[name];
  const siFN = col("SI<FN"), fn = col("FileName"), ext = col("Extension"), pp = col("ParentPath");
  const entry = col("EntryNumber"), inUse = col("InUse"), isDir = col("IsDirectory");
  const uSecZeros = col("uSecZeros"), zoneId = col("ZoneIdContents"), copied = col("Copied");
  const siCreated = col("Created0x10"), fnCreated = col("Created0x30");
  const siModified = col("LastModified0x10"), fnModified = col("LastModified0x30");
  const siRecordChange = col("LastRecordChange0x10"), fnRecordChange = col("LastRecordChange0x30");
  const siAccess = col("LastAccess0x10"), fnAccess = col("LastAccess0x30");
  if (!siFN || !fn || !entry) return { ...empty, error: "Required MFT columns not found (SI<FN, FileName, EntryNumber)." };

  const notDir = isDir ? `AND (${isDir} IS NULL OR ${isDir} = '' OR ${isDir} = 'False')` : "";

  // ── Candidate predicate (Tier 2: broaden beyond backdating) ──
  // Primary: backdating (SI<FN='True', computed at 100ns by the parser/MFTECmd) — the fast,
  // precomputed boolean. PLUS forward-dating ($SI LATER than $FN on ANY field) and future-dated $SI
  // on ANY field (C5). Tier 3 (C1): the forward/future lane is NO LONGER exec-only — web-shells,
  // Office macros, scripts, staging containers (SUSPICIOUS_EXTS) and extension-less payloads are
  // equally high-value timestomp targets; kept to that high-value set so the column-vs-column /
  // vs-now comparison stays bounded. Comparisons use sort_datetime() (a per-tab UDF) so they are
  // robust to MFTECmd locale formats. (Full-copy SI==FN zeroed stomps are still NOT fetched here —
  // indistinguishable from a benign zeroed install without a forgery-resistant witness; the Tier-2
  // Sysmon EID 2 / USN passes surface the corroborated ones.)
  const orParts = [`${siFN} = 'True'`];
  if (ext) {
    const suspList = [...SUSPICIOUS_EXTS].map((e) => `'${e.replace(/'/g, "''")}'`).join(",");
    // high-value extension set OR extension-less (droppers frequently drop name-only payloads)
    const suspGate = `(LOWER(${ext}) IN (${suspList}) OR ${ext} IS NULL OR ${ext} = '')`;
    // Compare the RAW columns, NOT sort_datetime(): the canonical $SI/$FN form is the lexically-sortable
    // "YYYY-MM-DD HH:MM:SS.fffffff", so a string compare is already chronological — wrapping every cell in
    // the UDF would force hundreds of millions of per-row JS/C++ crossings across the candidate scan (the
    // File Activity sibling avoids it for the same reason). This SQL is only a coarse FETCH filter;
    // analyzeFile() does the precise 100ns comparison, so a rare locale-format mis-sort here is corrected.
    const fwd = [];
    for (const [si, fn2] of [[siCreated, fnCreated], [siModified, fnModified], [siRecordChange, fnRecordChange], [siAccess, fnAccess]]) {
      if (si && fn2) fwd.push(`${si} > ${fn2}`);
    }
    // future-dated $SI on ANY of the four fields (C5) — beyond a 1-day skew, vs scan-time now.
    const nowPlusSkew = new Date(Date.now() + FUTURE_SKEW_MS).toISOString().slice(0, 19).replace("T", " ");
    for (const si of [siCreated, siModified, siRecordChange, siAccess]) {
      if (si) fwd.push(`${si} > '${nowPlusSkew}'`);
    }
    if (fwd.length) orParts.push(`(${suspGate} AND (${fwd.join(" OR ")}))`);
  }
  const candWhere = `(${orParts.join(" OR ")})`;

  try {
    const rawSiFnCount = db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${candWhere} ${notDir}`).get()?.cnt || 0;
    // Short-circuit ONLY when there is no companion: with a Sysmon EVTX / USN tab loaded we must still
    // run the cross-artifact pass below, which surfaces full-copy / $FN-rewriting stomps that leave NO
    // $MFT mismatch (rawSiFnCount===0) — the headline Tier-2 capability would otherwise be dead code.
    if (rawSiFnCount === 0 && !opts.usnMeta && !opts.evtxMeta) return { ...empty, rawSiFnCount: 0 };

    // T5 (F3): use the cached row count for the percentage denominator instead of a second full COUNT(*)
    // scan; fall back to the COUNT only when the meta doesn't carry a row count. (A percentage doesn't
    // need directory-exact precision.)
    const totalFiles = meta.rowCount || db.prepare(`SELECT COUNT(*) as cnt FROM data ${notDir ? "WHERE " + notDir.slice(4) : ""}`).get()?.cnt || 0;

    const sel = (c, alias) => (c ? `${c} as ${alias}` : `'' as ${alias}`);
    const files = db.prepare(
      // rowid is the physical row identity — tag/select by it (NOT the non-unique EntryNumber, which
      // NTFS reuses and which MFTECmd emits once per ADS stream) so tagging matches exactly what was scored (E1).
      `SELECT rowid as rowId, ${entry} as entryNumber, ${fn} as fileName, ${sel(ext, "extension")}, ${sel(pp, "parentPath")}, ` +
      `${sel(uSecZeros, "uSecZeros")}, ${sel(zoneId, "zoneId")}, ${sel(copied, "copied")}, ` +
      `${sel(siCreated, "siCreated")}, ${sel(fnCreated, "fnCreated")}, ${sel(siModified, "siModified")}, ${sel(fnModified, "fnModified")}, ` +
      `${sel(siRecordChange, "siRecordChange")}, ${sel(fnRecordChange, "fnRecordChange")}, ${sel(siAccess, "siAccess")}, ${sel(fnAccess, "fnAccess")}, ` +
      // C4: when the candidate set exceeds MAX_FETCH, keep the HIGHEST-SIGNAL rows, not the oldest. A
      // flat `ORDER BY siCreated ASC` dropped the most-recent + all forward/future-dated candidates
      // (which sort to the end) — the very signals we most want. Prioritize zeroed $SI sub-seconds (the
      // strongest aligned tell), then most-recent $SI Created (the incident window).
      `${sel(inUse, "inUse")} FROM data WHERE ${candWhere} ${notDir} ` +
      // raw canonical-ISO compare (chronological without the per-row sort_datetime UDF — see the gate above)
      `ORDER BY ${uSecZeros ? `(CASE WHEN ${uSecZeros} = 'True' THEN 0 ELSE 1 END), ` : ""}${siCreated || fn} DESC, rowid DESC LIMIT ${MAX_FETCH}`
    ).all();
    const truncated = rawSiFnCount > files.length;

    const nowMs = Date.now();
    for (const f of files) analyzeFile(f, nowMs);

    // ── Tier 2: identical-$SI clustering (mass-timestomp tool signature) ──
    // Group candidates by their exact $SI Created string; clusters of ≥CLUSTER_MIN files
    // sharing one value are a bulk-stomp hallmark — boost members and surface the cluster.
    const byCreated = new Map();
    for (const f of files) {
      const k = (f.siCreated || "").trim();
      if (!k) continue;
      if (!byCreated.has(k)) byCreated.set(k, []);
      byCreated.get(k).push(f);
    }
    const clusters = [];
    for (const [siValue, members] of byCreated) {
      // A timestomp cluster needs an ALIGNED signal per member (zeroed sub-seconds, forward-dating, or
      // future-dating beyond skew) — NOT mere backdating (A2). A batch of benign files merely SHARING a
      // backdated $SI (installer/extraction stamping one vendor build time) is not evidence of stomping,
      // and must not self-escalate its members to critical.
      const real = members.filter((f) => f.zeroedStompedField || f.hasForward || f.futureDated);
      if (real.length < CLUSTER_MIN) continue;
      for (const f of real) { f.clusterMember = true; f.score += 2; f.indicators.push(`part of identical-$SI cluster (${real.length} files)`); }
      const exts = {};
      for (const f of real) { const e = (f.extension || "").toLowerCase() || "(none)"; exts[e] = (exts[e] || 0) + 1; }
      const dominantExt = Object.entries(exts).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
      clusters.push({
        siCreated: siValue, count: real.length, dominantExt,
        zeroedSubseconds: real.some((f) => f.zeroedStompedField),
        directories: [...new Set(real.map((f) => f.parentPath || ""))].slice(0, 10),
        anyExec: real.some((f) => f.isExec),
      });
    }
    clusters.sort((a, b) => b.count - a.count);

    // ── Tier 2: cross-artifact corroboration (forgery-resistant witnesses) ───────────────────────
    // (a) Sysmon EID 2 (FileCreateTime) is the LITERAL timestomp event: match a candidate's filename to
    //     CONFIRM the stomp, recover PreviousCreationUtcTime (the pre-stomp $SI), and name the Image
    //     (the tool). EID-2 events with NO MFT candidate are confirmed stomps the $MFT alone can't see
    //     (double-stomp / full-copy classes). (b) USN ($J) FileCreate whose timestamp postdates the
    //     backdated $SI Created is a forgery-resistant contradiction that beats the path-class floor.
    //     Companion rows are materialized ONCE into in-memory maps (no per-candidate scan); every access
    //     is wrapped in try/catch so a companion failure never breaks the MFT result.
    const correlation = { evtxAvailable: false, usnAvailable: false, evtxFileCreateTimeTotal: 0, usnFileCreateTotal: 0, candidatesEid2Corroborated: 0, candidatesUsnContradicted: 0, evtxScanned: 0, evtxCapped: false, usnScanned: 0, usnCapped: false };
    const confirmedStompsNoMftMatch = [];
    const usnMeta = opts.usnMeta || null, evtxMeta = opts.evtxMeta || null;
    const leafOf = (p) => { const s = String(p == null ? "" : p).trim(); return (s.split(/[\\/]/).pop() || s).toLowerCase(); };
    const normPath = (p) => String(p == null ? "" : p).toLowerCase().replace(/\//g, "\\").replace(/^[.\\]+/, "");
    const candidatesByLeaf = new Map();
    for (const f of files) { const k = leafOf(f.fileName); if (!k) continue; if (!candidatesByLeaf.has(k)) candidatesByLeaf.set(k, []); candidatesByLeaf.get(k).push(f); }

    if (evtxMeta && evtxMeta.db) {
      try {
        const { _rwResolveEvtxCols } = require("./ransomware");
        const c = _rwResolveEvtxCols(evtxMeta);
        const headers = evtxMeta.headers || [];
        const hcol = (re) => { const h = headers.find((x) => re.test(x)); return h && evtxMeta.colMap ? evtxMeta.colMap[h] : null; };
        const tfCol = hcol(/^target_?filename$/i);
        const prevCol = hcol(/^previous_?creation_?utc_?time$/i) || hcol(/^prevcreationtime$/i);
        const creatCol = hcol(/^creation_?utc_?time$/i); // anchored — must NOT match PreviousCreationUtcTime
        const imgCol = (c && c.proc && c.proc.image) || hcol(/^image$/i);
        if (c && c.eid) {
          correlation.evtxAvailable = true;
          const chan = c.channel ? ` AND LOWER(${c.channel}) LIKE '%sysmon%'` : "";
          try { correlation.evtxFileCreateTimeTotal = evtxMeta.db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE CAST(${c.eid} AS TEXT) = '2'${chan}`).get()?.cnt || 0; } catch { correlation.evtxFileCreateTimeTotal = 0; }
          if (correlation.evtxFileCreateTimeTotal > 0) {
            const blobCols = [];
            if (tfCol) blobCols.push(tfCol);
            if (prevCol) blobCols.push(prevCol);
            if (c.textCols && c.textCols.length) blobCols.push(...c.textCols);
            const blobExpr = blobCols.length ? blobCols.map((x) => `COALESCE(${x},'')`).join("||' '||") : "''";
            let rows = [];
            try {
              rows = evtxMeta.db.prepare(
                `SELECT ${tfCol || "''"} as tf, ${prevCol || "''"} as prev, ${creatCol || "''"} as creat, ${imgCol || "''"} as img, ${c.ts || "''"} as ts, (${blobExpr}) as blob FROM data WHERE CAST(${c.eid} AS TEXT) = '2'${chan} LIMIT 200000`
              ).all();
            } catch { rows = []; }
            correlation.evtxScanned = rows.length;
            correlation.evtxCapped = correlation.evtxFileCreateTimeTotal > rows.length;
            // Pull a "Key: value" / "Key=value" field from a payload blob (EvtxECmd PayloadData / Hayabusa
            // Details — space/label-separated, often no commas) when a dedicated column isn't present. The
            // value ends at the next "FieldName:" label (or ¦|, / newline / EOL); a left word-boundary stops
            // 'CreationUtcTime' from matching inside 'PreviousCreationUtcTime'.
            const grab = (b, key) => { const m = String(b || "").match(new RegExp("(?:^|[^A-Za-z])" + key + "['\"]?\\s*[:=]\\s*['\"]?(.+?)(?:\\s*[¦|,]|\\n|$|(?=\\s+[A-Za-z][A-Za-z0-9_]+\\s*[:=]))")); return m ? m[1].trim() : ""; };
            // Same-named files in different directories must not cross-confirm: when both the EID-2
            // TargetFilename and the candidate carry a directory, require a full-path tail match.
            const pathMatches = (target, f) => {
              const t = normPath(target);
              if (!t.includes("\\") || !f.parentPath) return true; // drive-relative / no candidate path → leaf-only
              const candFull = normPath(f.parentPath).replace(/\\+$/, "") + "\\" + leafOf(f.fileName);
              return t === candFull || t.endsWith("\\" + candFull) || candFull.endsWith("\\" + t) || candFull === t;
            };
            for (const r of rows) {
              const target = (r.tf && String(r.tf).trim()) || grab(r.blob, "TargetFilename");
              const leaf = leafOf(target);
              if (!leaf) continue;
              const prevTime = (r.prev && String(r.prev).trim()) || grab(r.blob, "PreviousCreationUtcTime");
              const image = (r.img && String(r.img).trim()) || grab(r.blob, "Image");
              const newCreated = (r.creat && String(r.creat).trim()) || grab(r.blob, "CreationUtcTime");
              const cands = (candidatesByLeaf.get(leaf) || []).filter((f) => pathMatches(target, f));
              if (cands.length) {
                for (const f of cands) {
                  if (f.eid2Corroborated) continue;
                  f.preStompCreated = prevTime || null; f.stompTool = image || null; f.stompTime = (r.ts && String(r.ts).trim()) || null;
                  // A SetFileTime by an installer/extractor on a Program-Files install-backdate is consistent
                  // with a benign install — record the EID 2 presence but do NOT auto-confirm to critical (FP guard).
                  if (f.benignBackdateCandidate) { f.indicators.push(`Sysmon EID 2 (FileCreateTime) present${image ? " via " + image : ""} — consistent with install, not auto-confirmed`); continue; }
                  f.eid2Corroborated = true;
                  f.indicators.push(`CONFIRMED by Sysmon EID 2 (FileCreateTime)${image ? " via " + image : ""}${prevTime ? "; pre-stomp created " + prevTime : ""}`);
                  correlation.candidatesEid2Corroborated++;
                }
              } else if (confirmedStompsNoMftMatch.length < 200) {
                // EID 2 with no $MFT candidate is a confirmed stomp only when the event itself shows a
                // BACKDATE (new creation earlier than the previous) — skip benign forward/touch changes.
                const pp = parseTsParts(prevTime), np = parseTsParts(newCreated);
                if (pp && np && cmpParts(np, pp) < 0) {
                  confirmedStompsNoMftMatch.push({ targetFilename: target, preStompCreated: prevTime || null, newCreated: newCreated || null, image: image || null, ts: (r.ts && String(r.ts).trim()) || null });
                }
              }
            }
          }
        }
      } catch { /* ransomware helper unavailable or EVTX unreadable — skip */ }
    }

    if (usnMeta && usnMeta.db && usnMeta.colMap) {
      try {
        const uName = usnMeta.colMap["Name"], uTs = usnMeta.colMap["UpdateTimestamp"], uReasons = usnMeta.colMap["UpdateReasons"], uEntry = usnMeta.colMap["EntryNumber"];
        if (uName && uTs && uReasons) {
          correlation.usnAvailable = true;
          try { correlation.usnFileCreateTotal = usnMeta.db.prepare(`SELECT COUNT(*) as cnt FROM data WHERE ${uReasons} LIKE '%FileCreate%'`).get()?.cnt || 0; } catch { correlation.usnFileCreateTotal = 0; }
          // Require EntryNumber to disambiguate same-named files across directories AND entry-number reuse
          // (key on entry+leaf). A leaf-only match is too FP-prone (it resurrects benign churn copies), so
          // skip the contradiction check entirely when EntryNumber is unavailable.
          if (correlation.usnFileCreateTotal > 0 && uEntry) {
            // Per-file EARLIEST FileCreate via SQL GROUP BY MIN (bounded by distinct files, not events —
            // avoids materializing a multi-million-row $J; the canonical USN timestamp is ISO so MIN is chronological).
            let urows = [];
            try { urows = usnMeta.db.prepare(`SELECT ${uName} as n, ${uEntry} as e, MIN(${uTs}) as mint FROM data WHERE ${uReasons} LIKE '%FileCreate%' GROUP BY ${uEntry}, ${uName} LIMIT 500000`).all(); } catch { urows = []; }
            correlation.usnScanned = urows.length;
            correlation.usnCapped = urows.length >= 500000;
            const earliestCreate = new Map(); // `${entry}|${leaf}` → earliest FileCreate ms
            for (const r of urows) {
              const leaf = leafOf(r.n); if (!leaf) continue;
              const p = parseTsParts(r.mint); if (!p) continue;
              earliestCreate.set(`${r.e == null ? "" : r.e}|${leaf}`, p.ms);
            }
            for (const f of files) {
              if (f.eid2Corroborated || !f.createdMismatch) continue; // EID 2 already confirms; contradiction is about a backdated Created
              const usnMs = earliestCreate.get(`${f.entryNumber == null ? "" : f.entryNumber}|${leafOf(f.fileName)}`);
              const sip = parseTsParts(f.siCreated);
              if (usnMs != null && sip && usnMs > sip.ms + 60 * 1000) { // USN create postdates $SI Created by > 1 min
                f.usnContradicted = true;
                f.usnCreateTime = new Date(usnMs).toISOString().slice(0, 19).replace("T", " ");
                f.indicators.push(`USN FileCreate (${f.usnCreateTime}) postdates the backdated $SI Created — forgery-resistant contradiction`);
                correlation.candidatesUsnContradicted++;
              }
            }
          }
        }
      } catch { /* USN unreadable — skip */ }
    }

    // ── Finalize + suppress ──
    let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
    let highConfidenceCount = 0, likelyCount = 0, contextCount = 0;
    let suppressedCount = 0, forwardCount = 0, futureCount = 0;
    const kept = [];
    for (const f of files) {
      finalizeSeverity(f);
      const reason = suppressReason(f);
      if (reason) { suppressedCount++; continue; }
      if (f.confidence === "high") highConfidenceCount++;
      else if (f.confidence === "medium") likelyCount++;
      else contextCount++;
      if (f.severity === "critical") criticalCount++;
      else if (f.severity === "high") highCount++;
      else if (f.severity === "medium") mediumCount++;
      else lowCount++;
      if (f.hasForward) forwardCount++;
      if (f.futureDated) futureCount++;
      kept.push(f);
    }

    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    kept.sort((a, b) => (sevOrder[a.severity] - sevOrder[b.severity]) || ((b.score || 0) - (a.score || 0)) || (b.maxDeltaHours - a.maxDeltaHours));

    const totalTimestomped = kept.length;
    const tallyBy = (keyFn) => {
      const m = new Map();
      for (const f of kept) { const k = keyFn(f); if (k == null) continue; m.set(k, (m.get(k) || 0) + 1); }
      return [...m.entries()].map(([k, count]) => count && k != null ? { _k: k, count } : null).filter(Boolean).sort((a, b) => b.count - a.count).slice(0, 20);
    };
    const topDirectories = tallyBy((f) => f.parentPath || "").map((x) => ({ path: x._k, count: x.count }));
    const extensionBreakdown = tallyBy((f) => f.extension || "").map((x) => ({ extension: x._k, count: x.count }));

    const result = {
      totalTimestomped, rawSiFnCount, suppressedCount, totalFiles,
      percentTimestomped: totalFiles > 0 ? (totalTimestomped / totalFiles * 100) : 0,
      files: kept, clusters,
      topDirectories, extensionBreakdown,
      criticalCount, highCount, mediumCount, lowCount,
      highConfidenceCount, likelyCount, contextCount,
      forwardCount, futureCount, clusterCount: clusters.length, truncated,
      correlation, confirmedStompsNoMftMatch,
      notes: [
        "$SI is attacker-forgeable; $FN is OS-maintained. SI<FN, forward-dating, and zeroed sub-seconds are indicators, not proof.",
        "OS servicing/cache churn paths, Program Files install-backdating, and Mark-of-the-Web (downloaded) files are dampened/suppressed.",
        "Identical-$SI clusters indicate bulk timestomping by a tool.",
        correlation.evtxAvailable
          ? `Sysmon EID 2 (FileCreateTime) corroboration ACTIVE: ${correlation.candidatesEid2Corroborated} candidate(s) confirmed; ${confirmedStompsNoMftMatch.length} EID-2 stomp(s) had no $MFT mismatch (full-copy / double-stomp the $MFT alone can't see).`
          : "Single-source $MFT: a full-copy $SI==$FN zeroed stomp, or one that also rewrites $FN, is NOT detectable here — load a Sysmon EVTX companion (EID 2) to corroborate.",
        correlation.usnAvailable
          ? `USN ($J) FileCreate contradiction ACTIVE: ${correlation.candidatesUsnContradicted} file(s) have a real create time that postdates their backdated $SI.`
          : "No USN ($J) companion loaded — the forgery-resistant create-time contradiction check did not run.",
        (correlation.evtxCapped || correlation.usnCapped) ? "Companion scan hit its row cap — cross-artifact corroboration covers a subset; the confirmed/contradicted counts are a floor." : null,
        meta.indexesReady === false ? "Column indexes are still building — this scan ran without them and may be slow; re-run after indexing completes for best performance." : null,
        !copied ? "Copy-provenance (Copied column) unavailable on this tab — copied files may over-score." : null,
        truncated ? `Showing the first ${files.length} of ${rawSiFnCount} candidate records (scan capped); the newest/forward-dated may be omitted.` : null,
      ].filter(Boolean),
    };
    result.verdict = _buildTimestompVerdict(result);
    return result;
  } catch (err) {
    dbg("TIMESTOMP", "detectTimestomping failed", { error: err.message });
    return { ...empty, error: err.message };
  }
}

module.exports = { detectTimestomping, parseTsParts, cmpParts, analyzeFile, finalizeSeverity, suppressReason, _buildTimestompVerdict };
