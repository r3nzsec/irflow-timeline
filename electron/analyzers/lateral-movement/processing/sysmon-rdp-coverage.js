/**
 * processing/sysmon-rdp-coverage.js — Sysmon EID-13 CLIENTNAME detection, RDP
 * session grouping, and telemetry coverage computation for the lateral-movement
 * analyzer. Extracted verbatim from getLateralMovement().
 *
 * Detects RDP client hostnames from Sysmon EID 13 registry writes (multi-source +
 * DB query), adds isolated host nodes, pushes "RDP Client Hostname" findings
 * (advancing fid), groups rdpSessions, and computes per-host + dataset coverage.
 *
 * @param {object} state - { db, meta, columns, options, hostSet, _outlierHosts,
 *   findings, warnings, isHayabusa, _scanEidCol, _dedupeEvidenceRefs,
 *   _rowEvidenceRef, _rowidsFromRefs, _normalizeFindingEvidenceRefs, rdpSessions,
 *   hostTelemetry, datasetEventCounts, _conventionOutliers, fid }
 * @returns {{groupedSessions, hostCoverage, datasetCoverage, datasetEventCountsObj, coverageWarnings, fid}}
 */
const { TELEMETRY_CATEGORIES } = require("../constants");
const { compactGet, parseCompactKeyValues } = require("../../evtx-utils");
const { cmpTs, earlierTs, laterTs } = require("../time");

function computeSysmonRdpAndCoverage(state) {
  const {
    db, meta, columns, options, hostSet, _outlierHosts, findings, warnings, isHayabusa,
    _scanEidCol, _dedupeEvidenceRefs, _rowEvidenceRef, _rowidsFromRefs,
    _normalizeFindingEvidenceRefs, rdpSessions, hostTelemetry, datasetEventCounts, _conventionOutliers,
  } = state;
  let fid = state.fid;

      // === Sysmon EID 13 CLIENTNAME Detection (RDP client hostname from registry) ===
      // Windows writes the RDP client's hostname to HKU\<SID>\Volatile Environment\<SessionId>\CLIENTNAME
      // when an RDP session connects. This captures attacker hostnames that Security logs may miss
      // (4624 WorkstationName is often "-" for RDP sessions).
      try {
        // Multi-source mode: Sysmon CLIENTNAME entries pre-collected by multi-source.js
        if (!db && options._multiSourceSysmonClients && options._multiSourceSysmonClients.length > 0) {
          const _msCnHosts = new Map();
          for (const entry of options._multiSourceSysmonClients) {
            const ch = entry.clientHost;
            if (!_msCnHosts.has(ch)) {
              _msCnHosts.set(ch, { count: 0, targets: new Set(), firstSeen: entry.ts, lastSeen: entry.ts, evidenceRefs: [] });
            }
            const info = _msCnHosts.get(ch);
            info.count++;
            if (entry.target) info.targets.add(entry.target);
            if (entry.ts && entry.ts < info.firstSeen) info.firstSeen = entry.ts;
            if (entry.ts && entry.ts > info.lastSeen) info.lastSeen = entry.ts;
            info.evidenceRefs = _dedupeEvidenceRefs([...(info.evidenceRefs || []), ...(entry.evidenceRefs || [])]);
          }
          for (const [clientHost, info] of _msCnHosts) {
            const targets = [...info.targets];
            const inGraph = hostSet.has(clientHost);
            if (!inGraph || _conventionOutliers.has(clientHost) || _outlierHosts.has(clientHost)) {
              _outlierHosts.add(clientHost);
            }
            const pills = [
              { text: "Sysmon EID 13 registry", type: "execution" },
              { text: `CLIENTNAME: ${clientHost}`, type: "target" },
              { text: `${info.count} registry writes`, type: "context" },
            ];
            if (targets.length > 0) pills.push({ text: `target: ${targets.slice(0, 3).join(", ")}`, type: "target" });
            if (!inGraph) pills.push({ text: "not in logon graph", type: "correlation" });
            findings.push({
              id: fid++, severity: "high", category: "RDP Client Hostname", mitre: "T1021.001",
              title: `RDP client hostname: ${clientHost}`,
              description: `The hostname "${clientHost}" was written to the CLIENTNAME registry key via Sysmon EID 13 on ${targets.join(", ")}. This indicates an RDP session from this machine. ${info.count} registry write(s) detected across multiple tabs.${!inGraph ? " This hostname does not appear in Security logon events." : ""}`,
              source: clientHost, target: targets.join(", "),
              timeRange: { from: info.firstSeen, to: info.lastSeen },
              eventCount: info.count, evidencePills: pills, users: [],
              evidenceRefs: _dedupeEvidenceRefs(info.evidenceRefs || []),
              itemRowids: _rowidsFromRefs(info.evidenceRefs || []),
            });
            if (!hostSet.has(clientHost)) {
              hostSet.set(clientHost, { isSource: true, isTarget: false, eventCount: info.count, _sysmonClientName: true });
            }
          }
        }
        if (db && _scanEidCol) {
          const _cnDetect = (pats) => { for (const p of pats) { const f = meta.headers.find(h => p.test(h)); if (f) return meta.colMap[f]; } return null; };
          const _cnTsCol = columns.ts ? meta.colMap[columns.ts] : null;
          const _cnHostCol = columns.target ? meta.colMap[columns.target] : null;
          // PayloadData5 = TargetObject, PayloadData6 = Details in EvtxECmd
          const _cnTargetObjCol = _cnDetect([/^PayloadData5$/i, /^TargetObject$/i]) || (isHayabusa ? _cnDetect([/^Details$/i]) : null);
          const _cnDetailsCol = _cnDetect([/^PayloadData6$/i]) || (isHayabusa ? _cnDetect([/^Details$/i]) : null);

          if (_cnTargetObjCol) {
            const _cnSelParts = ["data.rowid as _rid"];
            if (_cnTsCol) _cnSelParts.push(`${_cnTsCol} as _ts`);
            if (_cnHostCol) _cnSelParts.push(`${_cnHostCol} as _host`);
            _cnSelParts.push(`${_cnTargetObjCol} as _tgtObj`);
            if (_cnDetailsCol && _cnDetailsCol !== _cnTargetObjCol) _cnSelParts.push(`${_cnDetailsCol} as _details`);

            const _cnSql = `SELECT ${_cnSelParts.join(", ")} FROM data WHERE ${_scanEidCol} = '13' AND ${_cnTargetObjCol} LIKE '%CLIENTNAME%' LIMIT 10000`;
            const _cnRows = db.prepare(_cnSql).all();

            // Extract unique CLIENTNAME values
            const _cnHosts = new Map(); // hostname -> { count, targets: Set, firstSeen, lastSeen }
            for (const row of _cnRows) {
              const tgtObj = (row._tgtObj || "").toString();
              if (!/\\CLIENTNAME$/i.test(tgtObj) && !/CLIENTNAME/i.test(tgtObj)) continue;

              // Extract the hostname from Details field
              let clientHost = null;
              if (row._details) {
                const detailsStr = row._details.toString().trim();
                // EvtxECmd: "Details: CHAOS-CRACK" or just "CHAOS-CRACK"
                const dm = detailsStr.match(/^Details:\s*(.+)$/i);
                clientHost = dm ? dm[1].trim() : detailsStr;
              } else if (isHayabusa) {
                // Hayabusa: may be in compact format
                const compact = parseCompactKeyValues(row._tgtObj);
                clientHost = compactGet(compact, "Details") || null;
              }

              if (!clientHost || clientHost === "-" || clientHost === "(empty)" || /^$/.test(clientHost)) continue;
              clientHost = clientHost.toUpperCase();
              // Skip if it matches the local computer name
              const target = (row._host || "").toString().trim().toUpperCase();
              if (clientHost === target || clientHost === target.split(".")[0]) continue;

              if (!_cnHosts.has(clientHost)) {
                _cnHosts.set(clientHost, { count: 0, targets: new Set(), firstSeen: row._ts || "", lastSeen: row._ts || "", evidenceRefs: [] });
              }
              const entry = _cnHosts.get(clientHost);
              entry.count++;
              if (target) entry.targets.add(target);
              if (row._ts && row._ts < entry.firstSeen) entry.firstSeen = row._ts;
              if (row._ts && row._ts > entry.lastSeen) entry.lastSeen = row._ts;
              const ref = _rowEvidenceRef(row);
              if (ref) entry.evidenceRefs = _dedupeEvidenceRefs([...(entry.evidenceRefs || []), ref]);
            }

            // Generate findings for each unique RDP client hostname
            for (const [clientHost, info] of _cnHosts) {
              const targets = [...info.targets];
              const isConvOutlier = _conventionOutliers.has(clientHost);
              const isExistingOutlier = _outlierHosts.has(clientHost);
              const inGraph = hostSet.has(clientHost);

              // Severity: higher if host is an outlier or not in the logon graph
              let severity = "high";
              if (inGraph && !isConvOutlier && !isExistingOutlier) severity = "medium";

              // A well-known CLIENTNAME already in the logon graph is not an
              // attacker box — only promote unknowns / convention outliers.
              if (!inGraph || isConvOutlier || isExistingOutlier) _outlierHosts.add(clientHost);

              const pills = [
                { text: "Sysmon EID 13 registry", type: "execution" },
                { text: `CLIENTNAME: ${clientHost}`, type: "target" },
                { text: `${info.count} registry writes`, type: "context" },
              ];
              if (targets.length > 0) pills.push({ text: `target: ${targets.slice(0, 3).join(", ")}`, type: "target" });
              if (!inGraph) pills.push({ text: "not in logon graph", type: "correlation" });
              if (isConvOutlier) pills.push({ text: "naming convention outlier", type: "context" });

              findings.push({
                id: fid++,
                severity,
                category: "RDP Client Hostname",
                mitre: "T1021.001",
                title: `RDP client hostname: ${clientHost}`,
                description: `The hostname "${clientHost}" was written to the CLIENTNAME registry key via Sysmon EID 13 on ${targets.join(", ")}. This indicates an RDP session from this machine. ${info.count} registry write(s) detected.${!inGraph ? " This hostname does not appear in Security logon events — Sysmon registry monitoring captured it where Security logs did not." : ""}`,
                source: clientHost,
                target: targets.join(", "),
                timeRange: { from: info.firstSeen, to: info.lastSeen },
                eventCount: info.count,
                evidencePills: pills,
                users: [],
                evidenceRefs: _dedupeEvidenceRefs(info.evidenceRefs || []),
                itemRowids: _rowidsFromRefs(info.evidenceRefs || []),
              });

              // Add as isolated node if not already in hostSet
              if (!hostSet.has(clientHost)) {
                hostSet.set(clientHost, { isSource: true, isTarget: false, eventCount: info.count, _sysmonClientName: true });
              }
            }
          }
        }
      } catch (_cnErr) { warnings.push(`Sysmon CLIENTNAME detector failed: ${_cnErr.message}`); }

      // Evidence refs are normalized once by the orchestrator after every emitter has
      // run; calling it here as well doubled an already O(findings x events) pass.

      // === Session Grouping (Map-based, not adjacency-dependent) ===
      const _groupMap = new Map();
      for (const s of rdpSessions) {
        const gk = `${s.source}|${s.target}|${s.user}|${s.technique || s.status}`;
        let g = _groupMap.get(gk);
        if (!g) {
          // `key` is exposed so the UI can track expansion by identity instead of by
          // position in a sorted array (re-sorting used to open a different group).
          g = { key: gk, sessions: [], count: 0, status: s.status, source: s.source, target: s.target, user: s.user, timeRange: { from: s.startTime || "", to: s.endTime || s.effectiveEnd || s.startTime || "" }, representativeSession: s, evidenceRefs: [], itemRowids: [] };
          _groupMap.set(gk, g);
        }
        g.sessions.push(s);
        g.count++;
        g.evidenceRefs = _dedupeEvidenceRefs([...(g.evidenceRefs || []), ...(s.evidenceRefs || [])]);
        g.itemRowids = _rowidsFromRefs(g.evidenceRefs);
        if (s.startTime) g.timeRange.from = earlierTs(g.timeRange.from, s.startTime);
        // Use effectiveEnd so active/disconnected sessions don't collapse to startTime
        const et = s.endTime || s.effectiveEnd || s.startTime;
        if (et) g.timeRange.to = laterTs(g.timeRange.to, et);
      }
      const groupedSessions = [..._groupMap.values()];
      groupedSessions.forEach(g => g.sessions.sort((a, b) => cmpTs(a.startTime, b.startTime)));

      // === Telemetry Coverage Computation ===
      // Define telemetry categories — each maps an analyst-friendly name to a set of EIDs.
      // A category is "present" on a host if any of its EIDs has count > 0 there.
      // TELEMETRY_CATEGORIES → ./constants

      const _computeCoverage = (eventCounts) => {
        const categories = {};
        let presentCount = 0;
        const weak = [];
        for (const cat of TELEMETRY_CATEGORIES) {
          const sum = cat.eids.reduce((s, e) => s + (eventCounts[e] || 0), 0);
          const present = sum > 0;
          categories[cat.id] = { label: cat.label, count: sum, present, critical: cat.critical };
          if (present) presentCount++;
          else if (cat.critical) weak.push(cat.label);
        }
        const score = Math.round((presentCount / TELEMETRY_CATEGORIES.length) * 100);
        let level;
        if (score >= 70) level = "high";
        else if (score >= 40) level = "medium";
        else level = "low";
        return { score, level, categories, weakCategories: weak };
      };

      // Compute per-host coverage
      const hostCoverage = new Map();
      for (const [host, eidMap] of hostTelemetry) {
        const eventCounts = Object.fromEntries(eidMap);
        hostCoverage.set(host, { eventCounts, ..._computeCoverage(eventCounts) });
      }

      // Compute dataset-wide coverage warnings (replaces frontend lmSkipWarnings)
      const datasetEventCountsObj = Object.fromEntries(datasetEventCounts);
      const datasetCoverage = _computeCoverage(datasetEventCountsObj);
      const coverageWarnings = [];
      const _has = (eids) => eids.some(e => (datasetEventCountsObj[e] || 0) > 0);
      if (!_has(["4624", "4625"])) coverageWarnings.push({ level: "error", category: "auth", text: "No logon events (4624/4625) — core detection unavailable" });
      if (!_has(["1149", "21", "22"])) coverageWarnings.push({ level: "warn", category: "rdp", text: "No RDP events (1149/21/22) — RDP session reconstruction unavailable" });
      if (!_has(["4688", "1"])) coverageWarnings.push({ level: "warn", category: "process", text: "No process events (4688/Sysmon 1) — WMI/WinRM/Impacket/RMM detection limited" });
      if (!_has(["4698"])) coverageWarnings.push({ level: "info", category: "task", text: "No Scheduled Task events (4698) — schtasks lateral movement undetectable" });
      if (!_has(["7045", "4697"])) coverageWarnings.push({ level: "info", category: "service", text: "No service install events (7045/4697) — service execution + RMM install undetectable" });
      if (!_has(["5140", "5145"])) coverageWarnings.push({ level: "info", category: "share", text: "No share access events (5140/5145) — Admin Share detection unavailable" });
      if (!_has(["4648"])) coverageWarnings.push({ level: "info", category: "explicit", text: "No explicit credential events (4648) — RunAs/PsExec credential delegation undetectable" });
      if (!_has(["4769"])) coverageWarnings.push({ level: "info", category: "kerberos", text: "No Kerberos service ticket events (4769) — Kerberoasting detection unavailable" });


  return { groupedSessions, hostCoverage, datasetCoverage, datasetEventCountsObj, coverageWarnings, fid };
}

module.exports = { computeSysmonRdpAndCoverage };
