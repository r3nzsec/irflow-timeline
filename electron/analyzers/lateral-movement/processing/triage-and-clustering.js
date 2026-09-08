/**
 * processing/triage-and-clustering.js — post-detection correlation, triage scoring,
 * and execution-session / incident clustering for the lateral-movement analyzer.
 *
 * Extracted verbatim from getLateralMovement(). Consumes the finished findings +
 * chains, mutates each finding in place (relatedFindingIds + triageScore, then
 * sorts findings by triage score), and returns the cross-stage structures the
 * later scoring/assembly stages consume.
 *
 * @param {object} state - { findings, chains, timeOrdered, _outlierHosts,
 *                           _dedupeEvidenceRefs, _rowidsFromRefs }
 * @returns {{_findingPairs: Map, _chainEdges: Set, executionSessions: Array, incidents: Array}}
 */
const { DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT, SEV_ORDER: sevOrder } = require("../constants");
const { tsMs, cmpTs } = require("../time");

/**
 * Index findings by "SOURCE->TARGET". A pure projection of the findings array, so any
 * stage can rebuild it for the findings that exist at its point in the pipeline —
 * stages that emit findings now run before triage and still need this index.
 */
function buildFindingPairs(findings) {
  const pairs = new Map();
  for (const f of findings || []) {
    if (!f.source) continue;
    const targets = (f.target || "").split(", ").filter(Boolean);
    for (const t of targets) {
      const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
      if (!pairs.has(pk)) pairs.set(pk, []);
      pairs.get(pk).push(f.id);
    }
  }
  return pairs;
}

/** Set of "A->B" hops present in any chain. Pure projection of `chains`. */
function buildChainEdges(chains) {
  const edges = new Set();
  for (const chain of chains || []) {
    for (let ci = 0; ci < chain.path.length - 1; ci++) edges.add(`${chain.path[ci]}->${chain.path[ci + 1]}`);
  }
  return edges;
}

function correlateTriageAndCluster(state) {
  const { findings, chains, timeOrdered, _outlierHosts, _dedupeEvidenceRefs, _rowidsFromRefs } = state;

      // === _findingPairs: index findings by source->target pair ===
      const _findingPairs = buildFindingPairs(findings);

      // === Related findings: other findings on same source->target pair ===
      for (const f of findings) {
        const related = new Set();
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        for (const t of fTargets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          for (const pid of (_findingPairs.get(pk) || [])) { if (pid !== f.id) related.add(pid); }
        }
        f.relatedFindingIds = [...related];
      }

      // === Chain edges set (for triage scoring + edge scoring) ===
      const _chainEdges = buildChainEdges(chains);

      // === Triage priority score ===
      const _sevBase = { critical: 40, high: 25, medium: 12, low: 3 };
      const _dsEnd = timeOrdered.length > 0 ? tsMs(timeOrdered[timeOrdered.length - 1].ts) : null;
      for (const f of findings) {
        let ts = _sevBase[f.severity] || 0;
        // DC / server target bonus
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        if (fTargets.some(t => _DC_PAT.test(t))) ts += 15;
        else if (fTargets.some(t => _SRV_PAT.test(t))) ts += 10;
        // Tool overlap on same pair
        if (f.relatedFindingIds.length > 0) ts += 10;
        // Concurrent RDP on same pair
        if (f.category === "Concurrent RDP Sessions") ts += 8;
        // Chain membership
        if (f.source && fTargets.some(t => _chainEdges.has(`${f.source}->${t}`))) ts += 5;
        // Outlier source
        if (f.source && _outlierHosts.has(f.source)) ts += 5;
        // Recency: last event within 1 hour of dataset end
        if (_dsEnd && f.timeRange && f.timeRange.to) {
          const fEnd = tsMs(f.timeRange.to);
          if (fEnd != null && (_dsEnd - fEnd) <= 3600000) ts += 5;
        }
        // Multiple hosts involved
        if (fTargets.length > 1 || ((f.source || "").split(", ").filter(Boolean).length > 1)) ts += 3;
        f.triageScore = ts;
      }

      // Sort by triage score descending, severity as tiebreaker
      // sevOrder → ./constants (SEV_ORDER)
      findings.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));

      // === Execution Sessions ===
      // Clusters execution-tool findings into operator-readable sessions:
      //   (technique-family, source→target pair, user, time-window)
      // This mirrors the RDP Sessions tab but for WMI, WinRM, PsExec, Impacket,
      // remote-service, RMM, scheduled-task, and admin-share findings.
      // Sessions are built from findings (not raw hits) so they inherit severity,
      // pills, triage scores, and user attribution for free.
      const executionSessions = [];
      {
        // Which finding categories are "execution" (non-RDP, non-contextual)?
        const _execCategories = new Set([
          "PsExec Native", "Impacket Execution", "Impacket Credential Access",
          "Remote Service Execution", "WMI Remote Execution", "WMI Remote Activity",
          "WinRM Remote Execution", "WinRM Remote Activity",
          "Scheduled Task Remote Execution", "Admin Share Access",
          "RMM Tool", "RMM Suspicious Execution", "RMM Executed", "RMM Installed",
          "Remote Access Tunnel", "Cobalt Strike",
        ]);
        // Map categories to short technique labels for the UI
        const _techLabel = (cat) => {
          if (cat.startsWith("PsExec")) return "PsExec";
          if (cat.startsWith("Impacket Credential")) return "Impacket Cred";
          if (cat.startsWith("Impacket")) return "Impacket";
          if (cat.startsWith("Remote Service")) return "Svc Exec";
          if (cat.startsWith("WMI")) return "WMI";
          if (cat.startsWith("WinRM")) return "WinRM";
          if (cat.startsWith("Scheduled Task")) return "Sched Task";
          if (cat.startsWith("Admin Share")) return "Admin Share";
          if (cat.startsWith("Cobalt Strike")) return "Cobalt Strike";
          if (cat.includes("RMM") || cat.includes("Remote Access")) return "RMM";
          return cat;
        };
        // Status heuristic: execution > activity > observed
        const _statusFromCat = (cat) => {
          if (/Execution|Credential|Executed|PsExec|Cobalt Strike|Sched.*Task|Remote Access/i.test(cat)) return "executed";
          if (/Activity|Installed/i.test(cat)) return "observed";
          return "executed";
        };

        // Filter to execution findings, normalize per-target (split multi-target)
        const _execFindings = [];
        for (const f of findings) {
          if (!_execCategories.has(f.category)) continue;
          const targets = (f.target || "").split(", ").filter(Boolean);
          const sources = (f.source || "").split(", ").filter(Boolean);
          const src = sources[0] || "";
          if (targets.length === 0) {
            // No target — still sessionize with empty target
            _execFindings.push({ ...f, _src: src, _tgt: "", _tech: _techLabel(f.category) });
          } else {
            for (const t of targets) {
              _execFindings.push({ ...f, _src: src, _tgt: t, _tech: _techLabel(f.category) });
            }
          }
        }

        // Group by (technique-label, source→target, user-set-key)
        // User set is sorted + joined so findings with the same operator cluster together
        const _sessKey = (ef) => {
          const userKey = (ef.users || []).slice().sort().join("+") || "(unknown)";
          return `${ef._tech}\0${ef._src}\0${ef._tgt}\0${userKey}`;
        };
        const _sessGroups = new Map();
        for (const ef of _execFindings) {
          const k = _sessKey(ef);
          if (!_sessGroups.has(k)) _sessGroups.set(k, []);
          _sessGroups.get(k).push(ef);
        }

        // Within each group, sort by time and split into sessions at >10 min gap
        let _esId = 0;
        // Parsed as UTC, not host-local — see time.js. The old form dropped the zone
        // and let the analyst's timezone decide where a session boundary fell.
        const _parseTime = (s) => tsMs(s) ?? 0;
        for (const [, group] of _sessGroups) {
          group.sort((a, b) => cmpTs(a.timeRange?.from, b.timeRange?.from));
          const clusters = [];
          let cur = [group[0]];
          for (let i = 1; i < group.length; i++) {
            const prevEnd = _parseTime(cur[cur.length - 1].timeRange?.to);
            const nextStart = _parseTime(group[i].timeRange?.from);
            if (prevEnd && nextStart && nextStart - prevEnd > 600000) {
              clusters.push(cur);
              cur = [];
            }
            cur.push(group[i]);
          }
          if (cur.length > 0) clusters.push(cur);

          for (const cl of clusters) {
            const allTs = cl.flatMap(f => [f.timeRange?.from, f.timeRange?.to]).filter(Boolean).sort(cmpTs);
            const worstSev = cl.reduce((b, f) => (sevOrder[f.severity] ?? 4) < (sevOrder[b] ?? 4) ? f.severity : b, "low");
            const maxTriage = Math.max(...cl.map(f => f.triageScore || 0));
            const totalEvents = cl.reduce((s, f) => s + (f.eventCount || 0), 0);
            const allUsers = [...new Set(cl.flatMap(f => f.users || []))];
            const allPills = [];
            const _pillSeen = new Set();
            for (const f of cl) for (const p of (f.evidencePills || [])) { if (!_pillSeen.has(p.text)) { _pillSeen.add(p.text); allPills.push(p); } }
            const allFilterEids = [...new Set(cl.flatMap(f => f.filterEids || []))];
            const allFilterHosts = [...new Set(cl.flatMap(f => f.filterHosts || []))];
            const allEvidenceRefs = _dedupeEvidenceRefs(cl.flatMap(f => f.evidenceRefs || []));
            const categories = [...new Set(cl.map(f => f.category))];
            const _uniqueText = (values) => [...new Set(values.map(v => String(v || "").trim()).filter(Boolean))];
            const serviceNames = _uniqueText(cl.flatMap(f => f.serviceNames || []));
            const imagePaths = _uniqueText(cl.flatMap(f => f.imagePaths || []));
            const commandLines = _uniqueText(cl.flatMap(f => f.commandLines || []));
            const eventActors = _uniqueText(cl.flatMap(f => f.eventActors || []));
            const serviceAccounts = _uniqueText(cl.flatMap(f => f.serviceAccounts || []));
            const executors = _uniqueText(cl.flatMap(f => f.executors || []));
            const executionDetails = [];
            const _detailSeen = new Set();
            for (const detail of cl.flatMap(f => f.executionDetails || [])) {
              const key = [
                detail?.eventId, detail?.timestamp, detail?.target, detail?.serviceName,
                detail?.imagePath, detail?.commandLine, detail?.rowId,
              ].join("\0");
              if (_detailSeen.has(key)) continue;
              _detailSeen.add(key);
              executionDetails.push(detail);
            }
            const bestStatus = cl.some(f => _statusFromCat(f.category) === "executed") ? "executed"
              : cl.some(f => _statusFromCat(f.category) === "observed") ? "observed" : "executed";
            const src = cl[0]._src;
            const tgt = cl[0]._tgt;
            const tech = cl[0]._tech;

            executionSessions.push({
              id: _esId++,
              technique: tech,
              categories,
              source: src,
              target: tgt,
              users: allUsers,
              startTime: allTs[0] || "",
              endTime: allTs[allTs.length - 1] || "",
              eventCount: totalEvents,
              findingCount: cl.length,
              findingIds: cl.map(f => f.id),
              status: bestStatus,
              severity: worstSev,
              triageScore: maxTriage,
              evidencePills: allPills,
              filterEids: allFilterEids,
              filterHosts: allFilterHosts,
              evidenceRefs: allEvidenceRefs,
              serviceNames,
              imagePaths,
              commandLines,
              eventActors,
              serviceAccounts,
              executors,
              executionDetails,
              itemRowids: _rowidsFromRefs(allEvidenceRefs),
            });
          }
        }
        // Sort by triage score desc, then severity
        executionSessions.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));
      }

      // === Incident Clustering ===
      // Group pair-specific findings by normalized SOURCE->TARGET pair, merge within 30-min gaps, 2+ = incident.
      // Multi-target findings (comma-separated targets) are source-centric — they only join a pair's
      // incident when corroborated by a pair-specific finding already in that bucket.
      const _incByPair = new Map();
      const _multiTargetFindings = []; // deferred — join only if corroborated
      for (const f of findings) {
        if (!f.source) continue;
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        if (fTargets.length <= 1) {
          // Single-target finding: direct pair assignment
          const pk = `${(f.source || "").toUpperCase()}->${(fTargets[0] || "").toUpperCase()}`;
          if (!_incByPair.has(pk)) _incByPair.set(pk, []);
          _incByPair.get(pk).push(f);
        } else {
          _multiTargetFindings.push(f);
        }
      }
      // Multi-target findings: only join a pair bucket if that bucket already has a pair-specific finding
      for (const f of _multiTargetFindings) {
        const fTargets = (f.target || "").split(", ").filter(Boolean);
        for (const t of fTargets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          if (_incByPair.has(pk) && _incByPair.get(pk).length > 0) {
            _incByPair.get(pk).push(f);
          }
        }
      }
      const incidents = [];
      let _incId = 0;
      const _incUsedFids = new Set(); // prevent same finding appearing in multiple incidents
      for (const [pk, pFindings] of _incByPair) {
        if (pFindings.length < 2) continue;
        // Sort by timeRange.from
        pFindings.sort((a, b) => cmpTs(a.timeRange?.from, b.timeRange?.from));
        // Merge within 30-min gaps
        const clusters = [];
        let cur = [pFindings[0]];
        for (let i = 1; i < pFindings.length; i++) {
          const prevEnd = tsMs(cur[cur.length - 1].timeRange?.to);
          const nextStart = tsMs(pFindings[i].timeRange?.from);
          if (prevEnd != null && nextStart != null && (nextStart - prevEnd) <= 1800000) {
            cur.push(pFindings[i]);
          } else {
            clusters.push(cur);
            cur = [pFindings[i]];
          }
        }
        clusters.push(cur);
        for (const cl of clusters) {
          if (cl.length < 2) continue;
          // Deduplicate: skip multi-target findings already claimed by a higher-scoring incident
          const dedupedCl = cl.filter(f => !_incUsedFids.has(f.id));
          if (dedupedCl.length < 2) continue;
          const [src, tgt] = pk.split("->");
          const memberIds = [...new Set(dedupedCl.map(f => f.id))];
          for (const mid of memberIds) _incUsedFids.add(mid);
          const allCategories = [...new Set(dedupedCl.map(f => f.category))];
          const allUsers = [...new Set(dedupedCl.flatMap(f => f.users || []))];
          const allTechniques = [...new Set(dedupedCl.map(f => f.mitre))];
          const allEvidenceRefs = _dedupeEvidenceRefs(dedupedCl.flatMap(f => f.evidenceRefs || []));
          const incSeverity = dedupedCl.reduce((best, f) => (sevOrder[f.severity] ?? 4) < (sevOrder[best] ?? 4) ? f.severity : best, "low");
          const incTriageScore = Math.max(...dedupedCl.map(f => f.triageScore || 0)) + 5;
          const allTs = dedupedCl.flatMap(f => [f.timeRange?.from, f.timeRange?.to]).filter(Boolean).sort(cmpTs);
          const totalEvents = dedupedCl.reduce((s, f) => s + (f.eventCount || 0), 0);
          // Auto-generate narrative
          const chain = allCategories.join(" \u2192 ");
          let narrative = `${allCategories.length} related detections on ${src} \u2192 ${tgt}`;
          if (allUsers.length > 0) narrative += ` involving ${allUsers.slice(0, 3).join(", ")}`;
          narrative += `: ${chain}.`;
          if (allCategories.includes("Credential Compromise") && allCategories.some(c => c.includes("PsExec") || c.includes("Impacket") || c.includes("Admin Share"))) {
            narrative += " Credential compromise followed by execution tools — likely active intrusion.";
          }
          incidents.push({
            id: _incId++, severity: incSeverity, triageScore: incTriageScore,
            category: chain, findings: memberIds,
            source: src, target: tgt,
            users: allUsers, techniques: allTechniques,
            timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
            eventCount: totalEvents, narrative,
            evidenceRefs: allEvidenceRefs,
            itemRowids: _rowidsFromRefs(allEvidenceRefs),
          });
        }
      }
      incidents.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));


  return { _findingPairs, _chainEdges, executionSessions, incidents };
}

module.exports = { correlateTriageAndCluster, buildFindingPairs, buildChainEdges };
