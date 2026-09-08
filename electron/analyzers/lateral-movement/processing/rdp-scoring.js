/**
 * processing/rdp-scoring.js — RDP-focused scoring for the lateral-movement analyzer.
 *
 * Episode clustering per edge, RDP session suspicion scoring, and concurrent-RDP
 * session detection. Extracted verbatim from getLateralMovement(). Attaches
 * episodes to edges, scores rdpSessions in place (suspicionScore/flags/findingIds/
 * isConcurrent/_concurrentTargets), pushes concurrent-RDP findings (advancing fid),
 * and re-sorts findings by severity.
 *
 * @param {object} state - { timeOrdered, edgeMap, rdpSessions, _findingPairs,
 *                           _outlierHosts, findings, fid }
 * @returns {{fid: number}}
 */
const { DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT, MGMT_SRC_PAT: _MGMT_SRC_PAT, SEV_ORDER: sevOrder } = require("../constants");
const { buildFindingPairs } = require("./triage-and-clustering");
const { normalizeTimestamp } = require("../../../utils/forensic-normalize");

function scoreRdpSessions(state) {
  const { timeOrdered, edgeMap, rdpSessions, _outlierHosts, findings, options } = state;
  // Off-hours is a LOCAL-time question about the organisation being investigated, but
  // the timestamps are UTC. A fixed UTC window means an Asian or Australian estate has
  // its entire working day scored as off-hours (09:00 in UTC+8 is 01:00 UTC), while a
  // US estate has its evenings scored as normal. `orgTimezoneOffsetMinutes` shifts the
  // window to the estate's local time; 0 (UTC) keeps the previous behaviour, so nothing
  // changes for anyone who does not set it.
  const _orgOffsetMin = (() => {
    const raw = options?.orgTimezoneOffsetMinutes;
    const n = Number(raw);
    if (!Number.isFinite(n)) return 0;
    return Math.max(-840, Math.min(840, Math.round(n)));
  })();
  const _orgLabel = _orgOffsetMin === 0
    ? "UTC"
    : `UTC${_orgOffsetMin > 0 ? "+" : "-"}${String(Math.floor(Math.abs(_orgOffsetMin) / 60)).padStart(2, "0")}:${String(Math.abs(_orgOffsetMin) % 60).padStart(2, "0")}`;
  // Business hours, expressed in the organisation's local time.
  const _bizStartHour = Number.isFinite(Number(options?.orgBusinessStartHour)) ? Math.max(0, Math.min(23, Math.round(Number(options.orgBusinessStartHour)))) : 6;
  const _bizEndHour = Number.isFinite(Number(options?.orgBusinessEndHour)) ? Math.max(1, Math.min(24, Math.round(Number(options.orgBusinessEndHour)))) : 22;
  // This stage now runs BEFORE triage scoring (so the Concurrent RDP findings it emits
  // get a triageScore like everything else), which means the caller no longer has a
  // pair index to hand over. Build one from the findings that exist at this point.
  // The final index is rebuilt by correlateTriageAndCluster over the complete array.
  const _findingPairs = state._findingPairs || buildFindingPairs(findings);
  const _findingById = new Map(findings.map((finding) => [finding.id, finding]));
  let fid = state.fid;

      // === Episode Clustering per Edge ===
      // Split by user + phase (failed/success/reconnect) + technique family + 30-min gap
      const _evtsByEdge = new Map();
      for (const evt of timeOrdered) {
        const ek = `${evt.source}->${evt.target}`;
        if (!_evtsByEdge.has(ek)) _evtsByEdge.set(ek, []);
        _evtsByEdge.get(ek).push(evt);
      }
      const _FAIL_EIDS = new Set(["4625", "4771"]);
      const _RECON_EIDS = new Set(["25", "4778", "39", "40"]);
      const _RDP_LTS = new Set(["10", "12"]);
      const _epPhase = (evt) => {
        if (_FAIL_EIDS.has(evt.eventId)) return "failed";
        if (_RECON_EIDS.has(evt.eventId) || evt.logonType === "7") return "reconnect";
        return "success";
      };
      const _epTechFamily = (evt) => {
        if (_RDP_LTS.has(evt.logonType) || ["1149", "21", "22", "24", "25"].includes(evt.eventId)) return "RDP";
        if (evt.logonType === "3" && ["7045", "4697"].includes(evt.eventId)) return "ServiceExec";
        if ((evt.eventId === "5140" || evt.eventId === "5145") && evt.shareName) {
          const sn = (evt.shareName || "").replace(/^\\\\\*\\/, "").toUpperCase();
          if (/^(ADMIN\$|C\$|[A-Z]\$|IPC\$)$/.test(sn)) return "AdminShare";
        }
        if (evt.logonType === "3") return "Network";
        if (evt.logonType === "8") return "Cleartext";
        if (evt.logonType === "2") return "Interactive";
        return "Other";
      };
      const EPISODE_GAP_MS = 1800000; // 30 min
      for (const [ek, evts] of _evtsByEdge) {
        evts.sort((a, b) => {
          const at = normalizeTimestamp(a.ts);
          const bt = normalizeTimestamp(b.ts);
          return Number.isFinite(at) && Number.isFinite(bt)
            ? at - bt
            : String(a.ts || "").localeCompare(String(b.ts || ""));
        });
        const episodes = [];
        let cur = null;
        for (const evt of evts) {
          const uk = (evt.user || "(unknown)").toUpperCase();
          const phase = _epPhase(evt);
          const techFam = _epTechFamily(evt);
          if (cur && cur._uk === uk && cur._phase === phase && cur._techFam === techFam) {
            const gap = normalizeTimestamp(evt.ts) - normalizeTimestamp(cur.lastTs);
            if (Number.isFinite(gap) && gap >= 0 && gap <= EPISODE_GAP_MS) {
              cur.count++;
              cur.lastTs = evt.ts;
              cur.eids.add(evt.eventId);
              if (evt.logonType) cur.lts.add(evt.logonType);
              continue;
            }
          }
          cur = { _uk: uk, _phase: phase, _techFam: techFam, user: evt.user || "(unknown)", phase, techFamily: techFam, count: 1, firstTs: evt.ts, lastTs: evt.ts, eids: new Set([evt.eventId]), lts: new Set(evt.logonType ? [evt.logonType] : []) };
          episodes.push(cur);
        }
        const edge = edgeMap.get(ek);
        if (edge) {
          edge.episodes = episodes.map(ep => ({ user: ep.user, phase: ep.phase, techFamily: ep.techFamily, count: ep.count, firstTs: ep.firstTs, lastTs: ep.lastTs, eventIds: [...ep.eids], logonTypes: [...ep.lts] }));
        }
      }
      for (const edge of edgeMap.values()) { if (!edge.episodes) edge.episodes = []; }

      // === RDP Session Suspicion Scoring ===
      const _pairFirst = new Map();
      const _pairCount = new Map();
      for (const s of rdpSessions) {
        const pk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}|${(s.user || "").toUpperCase()}`;
        const ex = _pairFirst.get(pk);
        if (!ex || (s.startTime && s.startTime < ex)) _pairFirst.set(pk, s.startTime);
        _pairCount.set(pk, (_pairCount.get(pk) || 0) + 1);
      }
      for (const s of rdpSessions) {
        let score = 0;
        const flags = [];
        // Source is outlier
        if (s.source && _outlierHosts.has(s.source.toUpperCase())) { score += 20; flags.push("Source is outlier"); }
        // Target is DC or server
        if (s.target && _DC_PAT.test(s.target)) { score += 15; flags.push("Target is DC"); }
        else if (s.target && _SRV_PAT.test(s.target)) { score += 8; flags.push("Target is server"); }
        // Admin privileges
        if (s.hasAdmin) { score += 15; flags.push("Admin privileges (4672)"); }
        // Failures
        if (s.hasFailed && (s.attemptCount || 1) > 1) { score += 10; flags.push(`${s.attemptCount} failed attempts`); }
        else if (s.hasFailed) { score += 5; flags.push("Failed auth"); }
        // Explicit creds (more weight if temporally correlated via pre-auth)
        if (s.preAuthEvents?.some(e => e.eventId === "4648")) { score += 12; flags.push("Explicit creds (4648, pre-auth correlated)"); }
        else if (s.events.some(e => e.eventId === "4648")) { score += 10; flags.push("Explicit creds (4648)"); }
        // NTLM pre-auth (indicates NTLM instead of Kerberos — downgrade or legacy)
        if (s.preAuthEvents?.some(e => e.eventId === "4776")) { score += 5; flags.push("NTLM auth (4776, pre-auth correlated)"); }
        // Session replaced by another connection (EID 40 reason 5 — potential session hijacking)
        if (s.replacedByAnotherSession) { score += 15; flags.push("Session replaced by another connection"); }
        // Disconnect reason enrichment
        if (s.disconnectReason && s.disconnectReasonCode !== "1" && s.disconnectReasonCode !== "11") {
          // Non-user-initiated disconnects are more interesting
          if (s.disconnectReasonCode === "2") { score += 5; flags.push("Admin-forced disconnect"); }
        }
        // Off-hours scoring: RDP sessions starting outside business hours are more suspicious.
        // Evaluated in UTC. `new Date(naive).getHours()` read BOTH the parse and the hour in
        // the analyst's local zone, so the same evidence scored differently depending on where
        // it was opened — an analyst in UTC+8 shifted every off-hours/weekend verdict by 8h.
        // normalizeTimestamp treats a zone-less timestamp as UTC, matching the app convention.
        if (s.startTime) {
          const ms = normalizeTimestamp(s.startTime);
          if (Number.isFinite(ms)) {
            // Shift into organisation-local time, then read the wall clock with the
            // UTC getters (the shift is already applied to the value).
            const d = new Date(ms + (_orgOffsetMin * 60000));
            const hour = d.getUTCHours();
            const dow = d.getUTCDay(); // 0=Sun, 6=Sat
            const isWeekend = dow === 0 || dow === 6;
            const isOffHours = hour < _bizStartHour || hour >= _bizEndHour;
            const dayName = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"][dow];
            if (isWeekend && isOffHours) { score += 15; flags.push(`Weekend off-hours (${dayName} ${hour}:00 ${_orgLabel})`); }
            else if (isWeekend) { score += 8; flags.push(`Weekend (${dayName} ${_orgLabel})`); }
            else if (isOffHours) { score += 10; flags.push(`Off-hours (${hour}:00 ${_orgLabel})`); }
          }
        }
        // Missing telemetry and low reconstruction confidence are evidence-quality
        // caveats, not malicious behavior. They must never increase suspicion.
        if (s.missingExpected && s.missingExpected.length > 0) flags.push(`Telemetry gap: missing ${s.missingExpected.join(", ")}`);
        if (s.confidence === "low") flags.push("Low reconstruction confidence");
        if (s.evidenceLevel === "correlated") flags.push("RDP classification is correlated, not direct");
        // First-seen pair
        const _pk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}|${(s.user || "").toUpperCase()}`;
        if (_pairFirst.get(_pk) === s.startTime) {
          const pairCount = _pairCount.get(_pk) || 0;
          if (pairCount === 1) { score += 8; flags.push("First-seen pair"); }
        }
        // Finding overlap — pair identity alone is not enough. A finding from a
        // different day on the same hosts must not inflate this session.
        const _fk = `${(s.source || "").toUpperCase()}->${(s.target || "").toUpperCase()}`;
        const sessionStart = normalizeTimestamp(s.startTime);
        const sessionEnd = normalizeTimestamp(s.endTime || s.effectiveEnd || s.startTime);
        const CORRELATION_PAD_MS = 10 * 60000;
        const matchedFids = (_findingPairs.get(_fk) || []).filter((findingId) => {
          const finding = _findingById.get(findingId);
          if (!finding) return false;
          const findingStart = normalizeTimestamp(finding.timeRange?.from);
          const findingEnd = normalizeTimestamp(finding.timeRange?.to || finding.timeRange?.from);
          // If either side genuinely lacks time, retain the pair correlation but
          // describe it as pair-level in the UI. Normal findings carry timeRange.
          if (!Number.isFinite(sessionStart) || !Number.isFinite(findingStart)) return true;
          const se = Number.isFinite(sessionEnd) ? sessionEnd : sessionStart;
          const fe = Number.isFinite(findingEnd) ? findingEnd : findingStart;
          return findingStart <= se + CORRELATION_PAD_MS && fe >= sessionStart - CORRELATION_PAD_MS;
        });
        if (matchedFids.length > 0) {
          score += 12;
          const fCats = [...new Set(matchedFids.map(fid => _findingById.get(fid)?.category).filter(Boolean))];
          flags.push(...fCats.map(c => `Finding: ${c}`));
        }
        // RDP session shadowing (EIDs 32/33) — an attacker or admin viewing the session
        if (s.isShadowed) { score += 15; flags.push("Session shadowed (EID 32)"); }
        // Upgrade technique if suspicious enough
        if (score >= 25 && s.technique === "RDP") s.technique = "Suspicious RDP";
        s.suspicionScore = score;
        s.flags = flags;
        s.findingIds = matchedFids;
      }

      // === Concurrent RDP Session Detection (T1021.001) ===
      // Detect same user with overlapping RDP sessions on different targets
      {
        // Step 1: Collect eligible sessions (exclude failed, exclude incomplete junk)
        const _concSessions = [];
        for (const s of rdpSessions) {
          if (s.status === "failed" || s.status === "incomplete" || s.status === "connecting") continue;
          if (!s.user || !s.target || !s.startTime) continue;
          // Normalize end time: use endTime, else last event ts, else cap at start + 30min
          const startMs = normalizeTimestamp(s.startTime);
          if (!Number.isFinite(startMs)) continue;
          let effectiveEnd = s.endTime;
          let endMs = normalizeTimestamp(effectiveEnd);
          if (!Number.isFinite(endMs) || endMs <= startMs) {
            const lastEvtTs = s.events.length > 0 ? s.events[s.events.length - 1]?.ts : null;
            const lastEvtMs = normalizeTimestamp(lastEvtTs);
            if (Number.isFinite(lastEvtMs) && lastEvtMs > startMs) {
              effectiveEnd = lastEvtTs;
              endMs = lastEvtMs;
            } else {
              // Cap open-ended sessions at start + 30 min to avoid over-firing
              endMs = startMs + 1800000;
              effectiveEnd = new Date(endMs).toISOString();
            }
          }
          _concSessions.push({
            id: s.id, user: (s.user || "").toUpperCase(), target: (s.target || "").toUpperCase(),
            source: (s.source || "").toUpperCase(), start: s.startTime, end: effectiveEnd,
            startMs, endMs,
            confidence: s.confidence || "low", hasAdmin: !!s.hasAdmin,
            suspicionScore: s.suspicionScore || 0, technique: s.technique || "RDP",
            _session: s,
          });
        }
        // Step 2: Group by normalized user
        const _byUser = new Map();
        for (const cs of _concSessions) {
          if (!_byUser.has(cs.user)) _byUser.set(cs.user, []);
          _byUser.get(cs.user).push(cs);
        }
        // Step 3: For each user, find overlapping sessions on different targets
        const MIN_OVERLAP_MS = 60000; // 1 min minimum to avoid timestamp noise
        const _concGroups = []; // {user, sessions[], targets[], sources[], overlapStart, overlapEnd}
        for (const [user, sessions] of _byUser) {
          if (sessions.length < 2) continue;
          // Sort by start time
          sessions.sort((a, b) => a.startMs - b.startMs);
          // Find distinct-target overlaps via sweep
          // For each session, check forward for overlapping sessions on different targets
          const used = new Set(); // session ids already clustered
          for (let i = 0; i < sessions.length; i++) {
            if (used.has(sessions[i].id)) continue;
            const cluster = [sessions[i]];
            const clusterTargets = new Set([sessions[i].target]);
            // Track the intersection window — all members must be active during this range
            let intStart = sessions[i].start; // max(starts)
            let intEnd = sessions[i].end;     // min(ends)
            let intStartMs = sessions[i].startMs;
            let intEndMs = sessions[i].endMs;
            for (let j = i + 1; j < sessions.length; j++) {
              if (used.has(sessions[j].id)) continue;
              // Candidate intersection with existing cluster window
              const useCandidateStart = sessions[j].startMs > intStartMs;
              const useCandidateEnd = sessions[j].endMs < intEndMs;
              const newIntStart = useCandidateStart ? sessions[j].start : intStart;
              const newIntEnd = useCandidateEnd ? sessions[j].end : intEnd;
              const newIntStartMs = Math.max(sessions[j].startMs, intStartMs);
              const newIntEndMs = Math.min(sessions[j].endMs, intEndMs);
              const overlapMs = newIntEndMs - newIntStartMs;
              if (!Number.isFinite(overlapMs) || overlapMs < MIN_OVERLAP_MS) continue;
              // Require different target to establish concurrency, or extend existing multi-target cluster
              if (clusterTargets.has(sessions[j].target) && clusterTargets.size < 2) continue;
              cluster.push(sessions[j]);
              clusterTargets.add(sessions[j].target);
              intStart = newIntStart;
              intEnd = newIntEnd;
              intStartMs = newIntStartMs;
              intEndMs = newIntEndMs;
            }
            // Only emit if we have 2+ different targets
            if (clusterTargets.size < 2) continue;
            // Mark used
            for (const cs of cluster) used.add(cs.id);
            _concGroups.push({
              user,
              sessions: cluster,
              targets: [...clusterTargets],
              sources: [...new Set(cluster.map(c => c.source).filter(Boolean))],
              overlapStart: intStart,
              overlapEnd: intEnd,
              overlapMs: intEndMs - intStartMs,
            });
          }
        }
        // Step 4: Emit findings with severity tiers + FP controls
        // Dampener patterns
        const _concSvcPat = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
        for (const grp of _concGroups) {
          const { user, sessions: cSessions, targets, sources, overlapStart, overlapEnd } = grp;
          const highConfCount = cSessions.filter(c => c.confidence === "high" || c.confidence === "medium").length;
          const adminTargets = targets.filter(t => _DC_PAT.test(t) || _SRV_PAT.test(t));
          const hasAdminPriv = cSessions.some(c => c.hasAdmin);
          const allHosts = [...new Set([...targets, ...sources])];
          const sessionIds = cSessions.map(c => c.id);
          // FP dampeners (applied as severity reduction, not exclusion)
          let isSvcAccount = _concSvcPat.test(user);
          let isMgmtSource = sources.length > 0 && sources.every(s => _MGMT_SRC_PAT.test(s));
          // Source diversity is what makes concurrency suspicious. One admin sitting
          // at ONE jump host with three RDP windows open is a normal working day; the
          // same account driving sessions from several different machines at once is
          // credential sharing or a stolen credential in use. Severity used to be
          // decided by target count alone, so every multi-window admin was critical.
          const distinctSources = sources.length;
          const singleSource = distinctSources <= 1;
          // Severity tiers
          let severity;
          if (targets.length >= 3 || (adminTargets.length > 0 && hasAdminPriv)) {
            severity = "critical";
          } else if (highConfCount >= 2) {
            severity = "high";
          } else {
            severity = "medium";
          }
          // One source (or none recorded) — cap at high; the concurrency is explained
          // by a single operator at a single console.
          if (singleSource && severity === "critical") severity = "high";
          // Multiple distinct sources for the same account at the same instant is the
          // real signal and lifts the floor.
          if (distinctSources >= 2 && severity === "medium") severity = "high";
          // Dampeners: reduce severity, never exclude
          if (isSvcAccount) {
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          if (isMgmtSource) {
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          // Check for very short overlap — further dampening
          const overlapMs = grp.overlapMs;
          if (Number.isFinite(overlapMs) && overlapMs < 120000) { // < 2 min
            if (severity === "critical") severity = "high";
            else if (severity === "high") severity = "medium";
          }
          const targetLabel = targets.slice(0, 4).join(", ") + (targets.length > 4 ? ` +${targets.length - 4}` : "");
          const srcLabel = sources.length > 0 ? ` from ${sources.slice(0, 2).join(", ")}${sources.length > 2 ? ` +${sources.length - 2}` : ""}` : "";
          const adminLabel = adminTargets.length > 0 ? ` (includes ${adminTargets.slice(0, 2).join(", ")})` : "";
          const overlapLabel = overlapStart && overlapEnd ? ` Overlap: ${overlapStart.slice(0, 19)} \u2013 ${overlapEnd.slice(0, 19)}.` : "";
          const _rdpPills = [{ text: `${targets.length} concurrent targets`, type: "context" }];
          if (distinctSources >= 2) _rdpPills.push({ text: `${distinctSources} distinct sources`, type: "correlation" });
          else if (singleSource) _rdpPills.push({ text: "single source host", type: "context" });
          if (targets.some(t => _DC_PAT.test(t))) _rdpPills.push({ text: "DC target", type: "target" });
          else if (targets.some(t => _SRV_PAT.test(t))) _rdpPills.push({ text: "server target", type: "target" });
          if (hasAdminPriv) _rdpPills.push({ text: "admin privileges", type: "credential" });
          findings.push({
            id: fid++, severity, category: "Concurrent RDP Sessions", mitre: "T1021.001",
            title: `Concurrent RDP: ${user} on ${targets.length} targets (${targetLabel})`,
            description: `${user} has ${cSessions.length} overlapping RDP sessions on ${targets.length} targets${srcLabel}${adminLabel}.${overlapLabel} ${highConfCount}/${cSessions.length} sessions are medium/high confidence.${hasAdminPriv ? " Admin privileges detected." : ""}`,
            source: sources.join(", "), target: targets.join(", "),
            filterHosts: allHosts,
            timeRange: { from: overlapStart || "", to: overlapEnd || "" },
            eventCount: cSessions.reduce((s, c) => s + (c._session.events?.length || 0), 0),
            filterEids: ["4624", "1149", "21", "22"],
            _concurrentSessionIds: sessionIds,
            evidencePills: _rdpPills,
            users: [user.toUpperCase()],
          });
          // Flag the sessions themselves
          for (const cs of cSessions) {
            cs._session.isConcurrent = true;
            cs._session._concurrentTargets = targets.filter(t => t !== cs.target);
          }
        }
      }


  return { fid };
}

module.exports = { scoreRdpSessions };
