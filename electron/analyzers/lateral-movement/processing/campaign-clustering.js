/**
 * processing/campaign-clustering.js — campaign/storyline clustering plus edge-risk
 * scoring, chain-hop technique enrichment + confidence scoring, lateral-pivot,
 * operator-host detection, and anomalous-hostname findings.
 *
 * Extracted verbatim from getLateralMovement(). Mutates findings/chains/edgeMap in
 * place, pushes new findings (advancing the fid counter), and returns the campaigns
 * array consumed by the final result assembly.
 *
 * @param {object} state - { incidents, findings, chains, edgeMap, timeOrdered, hostSet,
 *   _chainEdges, _findingPairs, _outlierHosts, _conventionOutliers, _computerHosts,
 *   detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs, fid }
 * @returns {{campaigns: Array, fid: number}}
 */
const { DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT, MGMT_SRC_PAT: _MGMT_SRC_PAT, SEV_ORDER: sevOrder } = require("../constants");
const { generateConventionFindings } = require("../convention-detector");
const { tsMs, cmpTs, gapMs } = require("../time");

/**
 * Roll pair-based incidents up into multi-hop storylines.
 *
 * Split out of clusterCampaignsAndEnrich because it is the only half that depends on
 * `incidents` — and therefore the only half that must run AFTER triage. The enrichment
 * and finding-emitting half now runs before triage so its findings get scored.
 *
 * @param {object} state - { incidents, findings, _rowidsFromRefs }
 * @returns {{campaigns: Array}}
 */
function clusterCampaigns(state) {
  const { incidents, findings, _dedupeEvidenceRefs, _rowidsFromRefs } = state;
  const campaigns = _buildCampaigns({ incidents, findings, _dedupeEvidenceRefs, _rowidsFromRefs });
  return { campaigns };
}

/**
 * Edge-risk scoring, chain-hop technique enrichment + confidence scoring, and the
 * Lateral Pivot / Operator Host / Anomalous Hostname emitters. None of this needs
 * `incidents`, so it runs before triage scoring.
 *
 * @returns {{fid: number}}
 */
function enrichEdgesAndChains(state) {
  const {
    findings, chains, edgeMap, timeOrdered, hostSet,
    _chainEdges, _findingPairs, _outlierHosts, _conventionOutliers, _computerHosts,
    detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs,
  } = state;
  let fid = state.fid;
  return _enrichAndEmit({
    findings, chains, edgeMap, timeOrdered, hostSet,
    _chainEdges, _findingPairs, _outlierHosts, _conventionOutliers, _computerHosts,
    detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs, fid,
  });
}

/** Backwards-compatible wrapper: enrich + emit, then cluster campaigns, in one call. */
function clusterCampaignsAndEnrich(state) {
  const { campaigns } = clusterCampaigns(state);
  const { fid } = enrichEdgesAndChains(state);
  return { campaigns, fid };
}

function _buildCampaigns(state) {
  const {
    incidents, findings,
    _dedupeEvidenceRefs, _rowidsFromRefs,
  } = state;

      // === Campaign / Storyline Clustering ===
      // Rolls up pair-based incidents into multi-hop storylines so analysts can see
      // operator A moving from Host1→Host2→Host3 as a single campaign rather than
      // two separate pair-incidents.
      //
      // Strategy: build an undirected graph over incidents where two incidents are
      // connected if they share a host (one's target is the other's source or target),
      // a user, OR overlap within a time window. Then run connected-components.
      // Each component with 2+ incidents becomes a campaign.
      const campaigns = [];
      if (incidents.length >= 2) {
        // Build adjacency list
        const _incAdj = new Map(); // incId -> Set<incId>
        const _addEdge = (a, b) => {
          if (!_incAdj.has(a)) _incAdj.set(a, new Set());
          if (!_incAdj.has(b)) _incAdj.set(b, new Set());
          _incAdj.get(a).add(b);
          _incAdj.get(b).add(a);
        };
        // Was `new Date(s.replace("T"," ").replace("Z",""))`, which strips the zone and
        // then parses HOST-LOCAL — so every campaign proximity window moved with the
        // analyst's timezone and broke across their DST change. tsMs treats a zone-less
        // timestamp as UTC, the app-wide convention.
        const _parseIso = (s) => tsMs(s) ?? 0;

        for (let i = 0; i < incidents.length; i++) {
          const a = incidents[i];
          const aHosts = new Set([a.source, a.target].filter(Boolean).map(h => h.toUpperCase()));
          const aUsers = new Set((a.users || []).map(u => u.toUpperCase()));
          const aFrom = _parseIso(a.timeRange?.from);
          const aTo = _parseIso(a.timeRange?.to) || aFrom;

          for (let j = i + 1; j < incidents.length; j++) {
            const b = incidents[j];
            // Host overlap: A's target is B's source or target (hop continuity)
            const bSrc = (b.source || "").toUpperCase();
            const bTgt = (b.target || "").toUpperCase();
            const hostOverlap = (bSrc && aHosts.has(bSrc)) || (bTgt && aHosts.has(bTgt));

            // User overlap
            const bUsers = new Set((b.users || []).map(u => u.toUpperCase()));
            let userOverlap = false;
            for (const u of aUsers) { if (bUsers.has(u)) { userOverlap = true; break; } }

            // Time proximity: overlapping or within 2 hours of each other
            const bFrom = _parseIso(b.timeRange?.from);
            const bTo = _parseIso(b.timeRange?.to) || bFrom;
            const timeProximate = aFrom && bFrom && !(aTo + 7200000 < bFrom || bTo + 7200000 < aFrom);

            // Connect if: (host overlap + time proximity) OR (user overlap + time proximity)
            if (timeProximate && (hostOverlap || userOverlap)) {
              _addEdge(a.id, b.id);
            }
          }
        }

        // Connected components via BFS
        const _visited = new Set();
        let _campId = 0;
        for (const inc of incidents) {
          if (_visited.has(inc.id)) continue;
          const queue = [inc.id];
          const component = [];
          _visited.add(inc.id);
          while (queue.length > 0) {
            const cur = queue.shift();
            component.push(cur);
            const neighbors = _incAdj.get(cur);
            if (neighbors) {
              for (const n of neighbors) {
                if (!_visited.has(n)) {
                  _visited.add(n);
                  queue.push(n);
                }
              }
            }
          }
          if (component.length < 2) continue;

          // Build campaign from component
          const memberIncs = component.map(id => incidents.find(inc => inc.id === id)).filter(Boolean);
          const allHosts = [...new Set(memberIncs.flatMap(inc => [inc.source, inc.target].filter(Boolean)))];
          const allUsers = [...new Set(memberIncs.flatMap(inc => inc.users || []))];
          const allTechs = [...new Set(memberIncs.flatMap(inc => inc.techniques || []))];
          const allTs = memberIncs.flatMap(inc => [inc.timeRange?.from, inc.timeRange?.to]).filter(Boolean).sort(cmpTs);
          const worstSev = memberIncs.reduce((b, inc) => (sevOrder[inc.severity] ?? 4) < (sevOrder[b] ?? 4) ? inc.severity : b, "low");
          const maxTriage = Math.max(...memberIncs.map(inc => inc.triageScore || 0)) + 10;
          const totalEvents = memberIncs.reduce((s, inc) => s + (inc.eventCount || 0), 0);
          const allFindingIds = [...new Set(memberIncs.flatMap(inc => inc.findings || []))];
          const allEvidenceRefs = _dedupeEvidenceRefs(memberIncs.flatMap(inc => inc.evidenceRefs || []));

          // Build movement path: extract unique source→target pairs ordered by time
          const hopPairs = memberIncs
            .sort((a, b) => cmpTs(a.timeRange?.from, b.timeRange?.from))
            .map(inc => `${inc.source} \u2192 ${inc.target}`)
            .filter((v, i, arr) => arr.indexOf(v) === i);

          // Narrative
          let narrative = `Campaign across ${allHosts.length} hosts: ${hopPairs.join(", ")}`;
          if (allUsers.length > 0) narrative += `. Operators: ${allUsers.slice(0, 5).join(", ")}${allUsers.length > 5 ? ` +${allUsers.length - 5}` : ""}`;
          narrative += `. ${memberIncs.length} related incidents spanning ${allFindingIds.length} findings.`;

          campaigns.push({
            id: _campId++,
            severity: worstSev,
            triageScore: maxTriage,
            hosts: allHosts,
            users: allUsers,
            techniques: allTechs,
            incidentIds: component,
            incidentCount: component.length,
            findingIds: allFindingIds,
            findingCount: allFindingIds.length,
            eventCount: totalEvents,
            timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
            hopPairs,
            narrative,
            evidenceRefs: allEvidenceRefs,
            itemRowids: _rowidsFromRefs(allEvidenceRefs),
          });
        }
        campaigns.sort((a, b) => (b.triageScore - a.triageScore) || ((sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4)));
      }

  return campaigns;
}

function _enrichAndEmit(state) {
  const {
    findings, chains, edgeMap, timeOrdered, hostSet,
    _chainEdges, _findingPairs, _outlierHosts, _conventionOutliers, _computerHosts,
    detectOutlier, _dedupeEvidenceRefs, _rowidsFromRefs,
  } = state;
  let fid = state.fid;

      // === Edge Risk Scoring ===
      // Dampener patterns: known management/jump hosts, service accounts, high-frequency routine edges
      // _MGMT_SRC_PAT → ./constants (MGMT_SRC_PAT)
      const _SVC_ACCT_PAT = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP|TASK[_\-]|SCH[_\-]|SA[_\-])/i;
      // Compute edge frequency percentile for recurring-edge dampener
      const _edgeCounts = [...edgeMap.values()].map(e => e.count).sort((a, b) => a - b);
      const _p90Count = _edgeCounts.length > 0 ? _edgeCounts[Math.floor(_edgeCounts.length * 0.9)] : Infinity;

      for (const edge of edgeMap.values()) {
        let score = 0;
        const eFlags = [];
        const ek = `${edge.source}->${edge.target}`;
        // Positive signals
        if (edge.source && detectOutlier(edge.source)) { score += 20; eFlags.push("Outlier source"); }
        if (edge.target && _DC_PAT.test(edge.target)) { score += 15; eFlags.push("Target is DC"); }
        else if (edge.target && _SRV_PAT.test(edge.target)) { score += 8; eFlags.push("Target is server"); }
        if (edge.logonTypes.has("8")) { score += 15; eFlags.push("Cleartext auth (Type 8)"); }
        if (edge.hasFailures) { score += 8; eFlags.push("Failed logons"); }
        if (edge.users.size > 1) { score += 5; eFlags.push(`${edge.users.size} users`); }
        if (edge.isFirstSeen) { score += 8; eFlags.push("First-seen pair"); }
        if (_chainEdges.has(ek)) { score += 10; eFlags.push("In lateral chain"); }
        const _efk = `${(edge.source || "").toUpperCase()}->${(edge.target || "").toUpperCase()}`;
        const eFids = _findingPairs.get(_efk) || [];
        if (eFids.length > 0) {
          score += 12;
          const eCats = [...new Set(eFids.map(fid => findings.find(f => f.id === fid)?.category).filter(Boolean))];
          eFlags.push(...eCats.map(c => `Finding: ${c}`));
        }
        if (edge._adminShareCount > 0) { score += 12; eFlags.push(`Admin share access (${edge._adminShareCount}x)`); }
        if (edge.sourceLabel === "unresolved") { score += 3; eFlags.push("Unresolved source"); }
        // Dampeners — reduce score for known benign patterns
        if (edge.source && _MGMT_SRC_PAT.test(edge.source)) { score = Math.max(0, score - 15); eFlags.push("Mgmt source (dampened)"); }
        const userArr = [...edge.users];
        const allSvcAccts = userArr.length > 0 && userArr.every(u => _SVC_ACCT_PAT.test(u));
        if (allSvcAccts) { score = Math.max(0, score - 10); eFlags.push("Service accounts (dampened)"); }
        if (edge.count >= _p90Count && _p90Count > 10 && !_chainEdges.has(ek)) { score = Math.max(0, score - 8); eFlags.push("Recurring edge (dampened)"); }
        edge.riskScore = score;
        edge.flags = eFlags;
        edge.findingIds = eFids;
      }

      // === Chain Hop Technique Enrichment + Confidence Scoring ===
      // Build findings-based technique map: "SOURCE->TARGET" => best technique label
      const _FINDING_TECH_MAP = {
        "PsExec Native": "PsExec", "Impacket Execution": "Impacket", "Impacket Summary": "Impacket",
        "Remote Service Execution": "Remote Service",
        "WMI Remote Execution": "WMI", "WMI Remote Activity": "WMI",
        "WinRM Remote Execution": "WinRM", "WinRM Remote Activity": "WinRM",
        "Scheduled Task Remote Execution": "Scheduled Task",
        "Admin Share Access": "Admin Share",
      };
      const _findingTechByPair = new Map(); // "SRC->TGT" => technique label
      for (const f of findings) {
        const techLabel = _FINDING_TECH_MAP[f.category];
        if (!techLabel) continue;
        if (!f.source) continue;
        const targets = (f.target || "").split(", ").filter(Boolean);
        for (const t of targets) {
          const pk = `${(f.source || "").toUpperCase()}->${t.toUpperCase()}`;
          // Keep highest-specificity technique (first match wins — PsExec/Impacket over generic)
          if (!_findingTechByPair.has(pk)) _findingTechByPair.set(pk, techLabel);
        }
      }
      // Enrich edge technique from findings when edge is "Network Logon" or "Unknown"
      for (const edge of edgeMap.values()) {
        if (edge.technique !== "Network Logon" && edge.technique !== "Unknown") continue;
        const ek = `${(edge.source || "").toUpperCase()}->${(edge.target || "").toUpperCase()}`;
        const ft = _findingTechByPair.get(ek);
        if (ft) {
          if (edge.technique !== "Unknown") edge.otherTechniques = [edge.technique, ...(edge.otherTechniques || [])];
          edge.technique = ft;
        }
      }

      // Enrich "Network Logon" hops from findings or edge technique
      for (const chain of chains) {
        for (const hop of chain._rawHops) {
          if (hop.technique !== "Network Logon") continue;
          const pk = `${hop.source.toUpperCase()}->${hop.target.toUpperCase()}`;
          // Priority 1: findings-based technique (PsExec, Impacket, WMI, Remote Service)
          const findingTech = _findingTechByPair.get(pk);
          if (findingTech) { hop.technique = findingTech; continue; }
          // Priority 2: edge primary technique if more specific
          const edge = edgeMap.get(`${hop.source}->${hop.target}`);
          if (edge && edge.technique && edge.technique !== "Unknown" && edge.technique !== "Network Logon") {
            hop.technique = edge.technique;
          }
        }
        // Rebuild techniques list and hopDetails after enrichment
        chain.techniques = [...new Set(chain._rawHops.map(h => h.technique).filter(Boolean))];
        chain.hopDetails = chain._rawHops.map(h => ({
          source: h.source, target: h.target, user: h.user, ts: h.ts,
          technique: h.technique, eventId: h.eventId, logonType: h.logonType,
          evidenceRefs: _dedupeEvidenceRefs(h.evidenceRefs || []),
        }));
      }

      for (const chain of chains) {
        const ch = chain._rawHops;
        let conf = 0;
        const confFlags = [];
        // Same user across all hops (+20)
        if (chain.users.length === 1 && chain.users[0] !== "(unknown)") { conf += 20; confFlags.push("Same user throughout"); }
        // Technique-backed hops (+5 each, max 20)
        const backedHops = ch.filter(h => h.technique && h.technique !== "Network Logon").length;
        if (backedHops > 0) { const boost = Math.min(20, backedHops * 5); conf += boost; confFlags.push(`${backedHops} technique-backed hop${backedHops > 1 ? "s" : ""}`); }
        // DC/server target on final hop (+10/+5)
        const finalTarget = ch[ch.length - 1].target;
        if (_DC_PAT.test(finalTarget)) { conf += 10; confFlags.push("Terminal target is DC"); }
        else if (_SRV_PAT.test(finalTarget)) { conf += 5; confFlags.push("Terminal target is server"); }
        // First-seen pair on any hop (+5)
        if (ch.some(h => { const e = edgeMap.get(`${h.source}->${h.target}`); return e && e.isFirstSeen; })) { conf += 5; confFlags.push("First-seen pair in chain"); }
        // Finding overlap (+10)
        const chainFindingIds = [];
        for (const h of ch) {
          const fk = `${h.source.toUpperCase()}->${h.target.toUpperCase()}`;
          const mf = _findingPairs.get(fk) || [];
          if (mf.length > 0) chainFindingIds.push(...mf);
        }
        if (chainFindingIds.length > 0) { conf += 10; confFlags.push("Finding overlap"); }
        // 3+ hops (+5)
        if (chain.hops >= 3) { conf += 5; confFlags.push(`${chain.hops} hops`); }
        // Penalties
        if (chain.users.length > 1) { conf = Math.max(0, conf - 5); confFlags.push("Mixed users (penalty)"); }
        if (chain.techniques.length === 1 && chain.techniques[0] === "Network Logon") { conf = Math.max(0, conf - 5); confFlags.push("Only generic logon (penalty)"); }
        let wideGaps = 0;
        for (let i = 1; i < ch.length; i++) {
          const gap = gapMs(ch[i - 1].ts, ch[i].ts);
          if (gap != null && gap > 1800000) wideGaps++;
        }
        if (wideGaps > 0) { conf = Math.max(0, conf - wideGaps * 3); confFlags.push(`${wideGaps} wide gap${wideGaps > 1 ? "s" : ""} (penalty)`); }
        chain.confidence = conf >= 30 ? "high" : conf >= 15 ? "medium" : "low";
        chain.confidenceScore = conf;
        chain.confidenceFlags = confFlags;
        chain.findingIds = [...new Set(chainFindingIds)];
        delete chain._rawHops; // clean up internal field
      }
      chains.sort((a, b) => b.confidenceScore - a.confidenceScore || b.hops - a.hops);

      // === Lateral Pivot (T1021): middle hosts in chains ===
      // Severity derived from the best supporting chain's confidence
      const pivotHosts = new Map(); // host -> best chain
      for (const chain of chains) {
        for (let i = 1; i < chain.path.length - 1; i++) {
          const host = chain.path[i];
          const existing = pivotHosts.get(host);
          if (!existing || (chain.confidenceScore || 0) > (existing.confidenceScore || 0)) {
            pivotHosts.set(host, { chain, hopIdx: i });
          }
        }
      }
      for (const [host, { chain, hopIdx }] of pivotHosts) {
        const conf = chain.confidence || "low";
        const severity = conf === "high" ? "high" : conf === "medium" ? "medium" : "low";
        const pills = [{ text: `${chain.hops}-hop chain`, type: "correlation" }, { text: `pivot: ${host}`, type: "target" }];
        if (conf !== "high") pills.push({ text: `${conf} confidence`, type: "context" });
        const _pivotUsers = (chain.users || []).filter(u => u && u !== "(unknown)" && !String(u).endsWith("$"));
        findings.push({ id: fid++, severity, category: "Lateral Pivot", mitre: "T1021", title: `Pivot host: ${host}`, description: `Used as pivot in ${chain.hops}-hop chain: ${chain.path.join(" \u2192 ")} (${conf} confidence, score ${chain.confidenceScore || 0})`, source: chain.path[hopIdx - 1], target: chain.path[hopIdx + 1], timeRange: { from: chain.timestamps[hopIdx] || "", to: chain.timestamps[hopIdx + 1] || "" }, eventCount: chain.hops, evidencePills: pills, users: _pivotUsers });
      }

      // === Operator Host Detection ===
      // Cross-correlates source hostnames across event types (4624 WorkstationName, 4776
      // SourceWorkstation, 4778/4779 ClientName) to identify the machine that appears
      // repeatedly as the remote origin.  A host seen across 2+ distinct field types
      // (workstation + clientName, or workstation + ip resolved from different EIDs) with
      // high target fan-out is flagged as the likely operator-controlled machine.
      {
        // Group events by source host, tracking which event categories contributed
        const _opHostMap = new Map(); // host -> { eventTypes: Set<eid>, fieldTypes: Set, targets: Set, users: Set, count, firstSeen, lastSeen }
        const _OP_RELEVANT_EIDS = new Set(["4624", "4625", "4648", "4776", "4778", "4779", "5140", "5145"]);
        for (const evt of timeOrdered) {
          if (!evt.source || !_OP_RELEVANT_EIDS.has(evt.eventId)) continue;
          if (!_opHostMap.has(evt.source)) {
            _opHostMap.set(evt.source, { eventTypes: new Set(), fieldTypes: new Set(), targets: new Set(), users: new Set(), count: 0, firstSeen: evt.ts, lastSeen: evt.ts });
          }
          const entry = _opHostMap.get(evt.source);
          entry.eventTypes.add(evt.eventId);
          if (evt.sourceFieldType) entry.fieldTypes.add(evt.sourceFieldType);
          if (evt.target) entry.targets.add(evt.target);
          if (evt.user) entry.users.add(evt.user);
          entry.count++;
          if (evt.ts && evt.ts < entry.firstSeen) entry.firstSeen = evt.ts;
          if (evt.ts && evt.ts > entry.lastSeen) entry.lastSeen = evt.ts;
        }

        // Score each candidate
        for (const [host, info] of _opHostMap) {
          // Skip hosts that are only targets (never originate outbound)
          const hostInfo = hostSet.get(host);
          if (!hostInfo || !hostInfo.isSource) continue;
          // Skip DCs and servers — they legitimately appear as source across many event types
          if (_DC_PAT.test(host) || _SRV_PAT.test(host)) continue;

          // Scoring criteria:
          //   - Seen across 2+ distinct source field types (workstation + clientName = strong signal)
          //   - Seen in 2+ distinct event ID categories
          //   - Targets 3+ distinct hosts (fan-out)
          //   - Bonus: is outlier hostname, appears in chains as origin
          const fieldTypeDiversity = info.fieldTypes.size;
          const eidDiversity = info.eventTypes.size;
          const fanOut = info.targets.size;

          // Require minimum evidence: 2+ field types OR (2+ EID categories AND 3+ targets)
          if (fieldTypeDiversity < 2 && (eidDiversity < 2 || fanOut < 3)) continue;

          let score = 0;
          // Field type cross-correlation (strongest signal)
          if (info.fieldTypes.has("workstation") && info.fieldTypes.has("clientName")) score += 40;
          else if (fieldTypeDiversity >= 2) score += 25;
          // Event ID diversity
          if (eidDiversity >= 3) score += 20;
          else if (eidDiversity >= 2) score += 10;
          // Target fan-out
          if (fanOut >= 5) score += 20;
          else if (fanOut >= 3) score += 10;
          // Outlier hostname bonus
          if (_outlierHosts.has(host)) score += 15;
          // Chain origin bonus — appears as first hop in any chain
          const isChainOrigin = chains.some((ch) => ch.path[0] === host);
          if (isChainOrigin) score += 15;
          // High event count relative to other sources
          if (info.count >= 20) score += 5;

          // Minimum score threshold
          if (score < 30) continue;

          const severity = score >= 70 ? "critical" : score >= 50 ? "high" : "medium";
          const pills = [];
          if (info.fieldTypes.has("workstation") && info.fieldTypes.has("clientName")) {
            pills.push({ text: "WorkstationName + ClientName match", type: "correlation" });
          }
          pills.push({ text: `${fanOut} target${fanOut !== 1 ? "s" : ""}`, type: "execution" });
          pills.push({ text: `${eidDiversity} event types (${[...info.eventTypes].join(", ")})`, type: "context" });
          if (_outlierHosts.has(host)) pills.push({ text: "outlier hostname", type: "target" });
          if (isChainOrigin) pills.push({ text: "chain origin", type: "correlation" });

          const fieldDesc = [...info.fieldTypes].map((f) => f === "workstation" ? "WorkstationName" : f === "clientName" ? "CLIENTNAME" : "IpAddress").join(", ");
          findings.push({
            id: fid++,
            severity,
            category: "Operator Host",
            mitre: "T1078",
            title: `Likely operator machine: ${host}`,
            description: `${host} appears as remote source across ${eidDiversity} event types (EIDs ${[...info.eventTypes].join(", ")}) via ${fieldDesc} fields, targeting ${fanOut} distinct host${fanOut !== 1 ? "s" : ""} with ${info.count} total events. ${info.users.size > 0 ? `Users: ${[...info.users].slice(0, 5).join(", ")}${info.users.size > 5 ? ` (+${info.users.size - 5} more)` : ""}` : ""}`,
            source: host,
            target: [...info.targets].slice(0, 3).join(", "),
            timeRange: { from: info.firstSeen, to: info.lastSeen },
            eventCount: info.count,
            evidencePills: pills,
            users: [...info.users],
          });
        }
      }

      // === Anomalous Hostname Findings (from convention detection) ===
      if (_conventionOutliers.size > 0) {
        const convResult = generateConventionFindings(_conventionOutliers, hostSet, _outlierHosts, fid, _computerHosts);
        findings.push(...convResult.findings);
        fid = convResult.fid;
      }


  return { fid };
}

module.exports = { clusterCampaignsAndEnrich, clusterCampaigns, enrichEdgesAndChains };
