/**
 * detectors/admin-share-and-execution.js — correlation detectors for the
 * lateral-movement analyzer: Admin Share Access (ADMIN$/C$/IPC$), the ordered
 * auth->share->exec Remote Execution Sequence, service-exec edge relabeling,
 * LSASS Direct Access, and Credential Theft Commands.
 *
 * Extracted verbatim from getLateralMovement(). Pushes findings (advancing fid),
 * relabels edge techniques in edgeMap, and pushes warnings. Consumes the R6
 * correlation closures + accumulators via the state bag.
 *
 * @param {object} state - { timeOrdered, findings, edgeMap, columns, warnings,
 *   chains, meta, _outlierHosts, _dedupeEvidenceRefs, _refsFromHits,
 *   _rowidsFromRefs, _attachEvidenceRefs, _usersFromCorrelation,
 *   _sourcesFromCorrelation, _disabledSet, _lsassAccessHits, _credTheftCmdHits, fid }
 * @returns {{fid: number}}
 */
const { DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT } = require("../constants");
const { normalizeTimestamp } = require("../../../utils/forensic-normalize");
const { tsMs, cmpTs } = require("../time");

function detectAdminShareAndExecution(state) {
  const {
    timeOrdered, findings, edgeMap, columns, warnings, chains, meta, _outlierHosts,
    _dedupeEvidenceRefs, _refsFromHits, _rowidsFromRefs, _attachEvidenceRefs,
    _usersFromCorrelation, _sourcesFromCorrelation, _disabledSet, _lsassAccessHits, _credTheftCmdHits,
  } = state;
  let fid = state.fid;

      // === Admin Share Access (T1021.002) ===
      // Detect ADMIN$, C$, [A-Z]$ access from 5140/5145 events in timeOrdered
      const _adminShareHits = []; // {source, target, user, ts, shareName, shareType, pipe}
      const _ADMIN_SHARE_PAT = /^(ADMIN\$|C\$|[A-Z]\$)$/i;
      const _IPC_PAT = /^IPC\$$/i;
      // Classify a 5145 RelativeTargetName into the lateral-movement technique it implies.
      // Named pipes accessed over IPC$ (svcctl/atsvc/winreg/...) and tool binaries dropped to
      // ADMIN$/C$ (PSEXESVC/RemCom/...) are high-fidelity, process-log-independent signals.
      const _classifyPipe = (rtn) => {
        if (!rtn) return null;
        const r = rtn.replace(/^[\\/]+/, "").toLowerCase();
        if (/^svcctl$/.test(r)) return { name: "svcctl", tech: "remote service control (PsExec/sc)", mitre: "T1569.002" };
        if (/^atsvc$/.test(r)) return { name: "atsvc", tech: "remote scheduled task", mitre: "T1053.005" };
        if (/^winreg$/.test(r)) return { name: "winreg", tech: "remote registry", mitre: "T1112" };
        if (/^(samr|lsarpc|drsuapi|netlogon)$/.test(r)) return { name: r, tech: "SAM/LSA/DRS RPC (recon/cred)", mitre: "T1003" };
        if (/(psexesvc|remcom|paexec|csexec)/.test(r)) return { name: r.replace(/\.exe$/, ""), tech: "PsExec-family service binary", mitre: "T1569.002" };
        return null;
      };
      for (const evt of timeOrdered) {
        if (evt.eventId !== "5140" && evt.eventId !== "5145") continue;
        if (!evt.shareName) continue;
        const sn = evt.shareName.replace(/^\\\\\*\\/, "").toUpperCase();
        const pipe = _classifyPipe(evt.relativeTargetName);
        if (_ADMIN_SHARE_PAT.test(sn)) {
          _adminShareHits.push({ source: evt.source, target: evt.target, user: evt.user, ts: evt.ts, shareName: sn, shareType: "admin", pipe, isWrite: !!evt.shareIsWrite, accessMask: evt.shareAccessMask, evidenceRefs: _dedupeEvidenceRefs(evt.evidenceRefs || []) });
        } else if (_IPC_PAT.test(sn)) {
          _adminShareHits.push({ source: evt.source, target: evt.target, user: evt.user, ts: evt.ts, shareName: sn, shareType: "ipc", pipe, isWrite: !!evt.shareIsWrite, accessMask: evt.shareAccessMask, evidenceRefs: _dedupeEvidenceRefs(evt.evidenceRefs || []) });
        }
      }
      if (_adminShareHits.length > 0) {
        // Cluster by source->target pair, 10-min window
        _adminShareHits.sort((a, b) => cmpTs(a.ts, b.ts));
        const _asClusters = [];
        const _asGrouped = new Map(); // "src->tgt" => [hits]
        for (const h of _adminShareHits) {
          const gk = `${h.source}->${h.target}`;
          if (!_asGrouped.has(gk)) _asGrouped.set(gk, []);
          _asGrouped.get(gk).push(h);
        }
        for (const [, hits] of _asGrouped) {
          // Sub-cluster within each pair by 10-min gap
          hits.sort((a, b) => cmpTs(a.ts, b.ts));
          let cur = [hits[0]];
          for (let hi = 1; hi < hits.length; hi++) {
            const prevMs = tsMs(cur[cur.length - 1].ts);
            const curMs = tsMs(hits[hi].ts);
            if (prevMs != null && curMs != null && curMs - prevMs <= 600000) {
              cur.push(hits[hi]);
            } else {
              _asClusters.push(cur);
              cur = [hits[hi]];
            }
          }
          if (cur.length > 0) _asClusters.push(cur);
        }
        // FP controls
        const _asMgmtSrcPat = /^(JUMP|JMP|PAM|BASTION|MGMT|MANAGE|SCCM|SCOM|WSUS|ANSIBLE|PUPPET|CHEF|SALT|ORCH)[\-_]|^ADMIN[\-_](JUMP|BASTION|PAM|MGMT|SRV|SERVER)/i;
        const _asSvcPat = /^(SVC[_\-]|SERVICE[_\-]|SYSTEM$|LOCALSERVICE$|NETWORKSERVICE$|HEALTH|MONITOR|SCAN|BACKUP)/i;
        for (const cluster of _asClusters) {
          const shares = [...new Set(cluster.map(h => h.shareName))];
          const hasAdmin = shares.some(s => /^(ADMIN\$|C\$|[A-Z]\$)$/i.test(s) && !/^IPC\$/i.test(s));
          const onlyIpc = shares.every(s => /^IPC\$/i.test(s));
          // Named-pipe / tool-drop artifacts from 5145 RelativeTargetName (dedup by name)
          const clusterPipes = [...new Map(cluster.map(h => h.pipe).filter(Boolean).map(p => [p.name, p])).values()];
          const hasExecPipe = clusterPipes.length > 0;
          const sources = [...new Set(cluster.map(h => h.source).filter(Boolean))];
          const targets = [...new Set(cluster.map(h => h.target).filter(Boolean))];
          const users = [...new Set(cluster.map(h => h.user).filter(Boolean))];
          const allTs = cluster.map(h => h.ts).filter(Boolean).sort(cmpTs);
          const allHosts = [...new Set([...sources, ...targets])];
          // FP: skip if all users are service accounts and source is management host
          const allSvc = users.length > 0 && users.every(u => _asSvcPat.test(u) || u.endsWith("$"));
          const allMgmt = sources.length > 0 && sources.every(s => _asMgmtSrcPat.test(s));
          if (allSvc && allMgmt) continue;
          // IPC$-only: only flag if correlated with PsExec/Impacket findings on same pair
          if (onlyIpc) {
            // Check if there's a PsExec/Impacket finding overlapping this pair
            let hasToolCorrelation = false;
            for (const f of findings) {
              if (f.category !== "PsExec Native" && f.category !== "Impacket Execution" && f.category !== "Impacket Summary") continue;
              const fTargets = (f.target || "").split(", ");
              const fSources = (f.source || "").split(", ");
              if (targets.some(t => fTargets.includes(t)) && (sources.some(s => fSources.includes(s)) || !f.source)) {
                hasToolCorrelation = true; break;
              }
            }
            // Keep bare IPC$ if it carries an exec/control named pipe (svcctl/atsvc/...) —
            // that IS the remote-execution signal even without a separate process finding.
            if (!hasToolCorrelation && !hasExecPipe) continue;
          }
          // Severity tiers:
          //   critical: ADMIN$/C$ + correlated PsExec/Impacket finding on same pair
          //   high:     ADMIN$/C$ access (strong lateral movement indicator)
          //   medium:   IPC$ with PsExec/Impacket correlation (passed filter above)
          let severity;
          let hasToolCorrelation = false;
          for (const f of findings) {
            if (f.category !== "PsExec Native" && f.category !== "Impacket Execution" && f.category !== "Impacket Summary" && f.category !== "Remote Service Execution") continue;
            const fTargets = (f.target || "").split(", ");
            const fSources = (f.source || "").split(", ");
            // Require same source->target pair (or source-less finding matching target)
            if (targets.some(t => fTargets.includes(t)) && (sources.some(s => fSources.includes(s)) || !f.source)) { hasToolCorrelation = true; break; }
          }
          // A WRITE to an admin share is a file being placed on the remote host —
          // the tool-drop half of PsExec/Impacket/SMBExec. A read is an inventory or
          // backup agent. The AccessMask that says which is which was never parsed
          // (audit L18), so both scored identically.
          const writeHits = cluster.filter(h => h.isWrite);
          const hasAdminWrite = writeHits.some(h => h.shareType === "admin");
          const dropTargets = [...new Set(cluster.filter(h => h.isWrite && h.pipe).map(h => h.pipe.name))];
          if (hasAdmin && (hasToolCorrelation || hasExecPipe || hasAdminWrite)) severity = "critical";
          else if (hasAdmin) severity = "high";
          else if (hasExecPipe) severity = "high"; // IPC$ + control/exec named pipe = remote exec over SMB
          else severity = "medium"; // IPC$ with tool correlation
          // Dampener: management source reduces severity by one tier
          if (allMgmt && severity === "critical") severity = "high";
          else if (allMgmt && severity === "high") severity = "medium";
          const hostLabel = [];
          if (targets.length > 0) hostLabel.push(`target ${targets.slice(0, 3).join(", ")}${targets.length > 3 ? ` +${targets.length - 3} more` : ""}`);
          if (sources.length > 0) hostLabel.push(`from ${sources.slice(0, 3).join(", ")}${sources.length > 3 ? ` +${sources.length - 3} more` : ""}`);
          const corrLabel = hasToolCorrelation ? " Correlated with execution tool finding." : "";
          // Named-pipe attribution: a control pipe (svcctl/atsvc/...) names the exact technique
          // performed over SMB. Promote the finding's MITRE id to the more specific technique.
          const _pipeMitre = hasExecPipe
            ? (clusterPipes.find(p => p.mitre === "T1569.002") ? "T1569.002"
              : clusterPipes.find(p => p.mitre === "T1053.005") ? "T1053.005"
              : clusterPipes[0].mitre)
            : null;
          const _pipeLabel = hasExecPipe ? ` via \\pipe\\${clusterPipes.map(p => p.name).join(", \\pipe\\")}` : "";
          const _pipeDesc = hasExecPipe ? ` Named-pipe/tool artifacts: ${clusterPipes.map(p => `${p.name} (${p.tech})`).join("; ")}.` : "";
          const _asPills = shares.map(s => ({ text: `${s} access`, type: hasAdmin && !/^IPC\$/i.test(s) ? "execution" : "context" }));
          for (const p of clusterPipes) _asPills.push({ text: `\\pipe\\${p.name}`, type: "execution" });
          if (hasToolCorrelation) _asPills.push({ text: "tool correlation", type: "correlation" });
          if (hasAdminWrite) _asPills.push({ text: `write access (${writeHits.length} file${writeHits.length === 1 ? "" : "s"} placed)`, type: "execution" });
          if (dropTargets.length > 0) _asPills.push({ text: `dropped: ${dropTargets.slice(0, 2).join(", ")}`, type: "execution" });
          if (sources.some(s => _outlierHosts.has(s))) _asPills.push({ text: "outlier source", type: "context" });
          findings.push({ id: fid++, severity, category: "Admin Share Access", mitre: _pipeMitre || "T1021.002",
            title: `Admin share access: ${shares.join(", ")}${_pipeLabel}${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
            description: `${cluster.length} share access event(s) (${shares.join(", ")}) by ${users.join(", ") || "(unknown)"}.${_pipeDesc}${corrLabel}`,
            source: sources.join(", "), target: targets.join(", "),
            filterHosts: allHosts,
            timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
            eventCount: cluster.length, filterEids: ["5140", "5145"], evidencePills: _asPills, users: users.map(u => u.toUpperCase()), evidenceRefs: _refsFromHits(cluster), itemRowids: _rowidsFromRefs(_refsFromHits(cluster)) });
        }
      }

      // === Remote Execution Sequence (T1569.002) — ordered auth → share → exec correlation ===
      // The highest-fidelity lateral-movement evidence is the ordered tuple on ONE target by ONE
      // principal within a short window: authenticate (4648 / 4624 Type 3|9) → touch an admin/IPC$
      // share (5140/5145) → execute (a PsExec/Impacket/WMI/WinRM/service/task finding). Each piece
      // already fires independently; this stitches a genuine ordered sequence into a single
      // high-confidence finding, and ONLY fires when ordering + user continuity actually hold
      // (no time-lucky clustering). Independent detectors are unchanged (no false negatives).
      try {
        const _seqWindowMs = 180000;   // max gap between adjacent steps
        const _seqMaxSpanMs = 600000;  // max total auth→exec span
        const _seqMs = (t) => { const n = normalizeTimestamp(t); return Number.isFinite(n) ? n : null; };
        const _seqNormH = (h) => (h || "").toString().trim().toUpperCase();
        const _seqShareOk = (sn) => /^(ADMIN\$|C\$|[A-Z]\$|IPC\$)$/i.test((sn || "").replace(/^\\\\\*\\/, ""));
        const _execShort = { "PsExec Native": "PsExec", "Impacket Execution": "Impacket", "Impacket Summary": "Impacket", "Remote Service Execution": "Service Exec", "WMI Remote Execution": "WMI", "WinRM Remote Execution": "WinRM", "Scheduled Task Remote Execution": "Sched Task" };

        // Per-target-host auth and share timelines from timeOrdered
        const _seqAuthByHost = new Map();
        const _seqShareByHost = new Map();
        for (const evt of timeOrdered) {
          const tms = _seqMs(evt.ts); if (tms == null) continue;
          const tgt = _seqNormH(evt.target); if (!tgt) continue;
          const isAuth = evt.eventId === "4648" || (evt.eventId === "4624" && (evt.logonType === "3" || evt.logonType === "9"));
          const isShare = (evt.eventId === "5140" || evt.eventId === "5145") && evt.shareName && _seqShareOk(evt.shareName);
          if (isAuth) {
            if (!_seqAuthByHost.has(tgt)) _seqAuthByHost.set(tgt, []);
            _seqAuthByHost.get(tgt).push({ tms, ts: evt.ts, user: (evt.user || "").toUpperCase(), source: evt.source, refs: _dedupeEvidenceRefs(evt.evidenceRefs || []) });
          }
          if (isShare) {
            if (!_seqShareByHost.has(tgt)) _seqShareByHost.set(tgt, []);
            _seqShareByHost.get(tgt).push({ tms, ts: evt.ts, user: (evt.user || "").toUpperCase(), pipe: _classifyPipe(evt.relativeTargetName), share: (evt.shareName || "").replace(/^\\\\\*\\/, "").toUpperCase(), refs: _dedupeEvidenceRefs(evt.evidenceRefs || []) });
          }
        }

        // Exec steps from already-emitted execution findings
        const _seqExecCats = new Set(["PsExec Native", "Impacket Execution", "Impacket Summary", "Remote Service Execution", "WMI Remote Execution", "WinRM Remote Execution", "Scheduled Task Remote Execution", "DCOM Remote Execution"]);
        const _seqExecByHost = new Map();
        for (const f of findings) {
          if (!_seqExecCats.has(f.category)) continue;
          const details = Array.isArray(f.executionDetails) ? f.executionDetails : [];
          const instants = [];
          if (details.length) {
            for (const d of details) {
              const tms = _seqMs(d.timestamp);
              const host = _seqNormH(d.target || f.target);
              if (tms == null || !host) continue;
              instants.push({
                tms, ts: d.timestamp, host, category: f.category,
                users: d.attributedUser ? [String(d.attributedUser).toUpperCase()] : (f.users || []).map(u => (u || "").toUpperCase()),
                refs: _dedupeEvidenceRefs(f.evidenceRefs || []),
              });
            }
          } else {
            const tms = _seqMs(f.timeRange && f.timeRange.from);
            if (tms == null) continue;
            for (const host of (f.target || "").split(", ").map(_seqNormH).filter(Boolean)) {
              instants.push({ tms, ts: f.timeRange.from, host, category: f.category, users: (f.users || []).map(u => (u || "").toUpperCase()), refs: _dedupeEvidenceRefs(f.evidenceRefs || []) });
            }
          }
          for (const inst of instants) {
            if (!_seqExecByHost.has(inst.host)) _seqExecByHost.set(inst.host, []);
            _seqExecByHost.get(inst.host).push(inst);
          }
        }

        for (const [host, execs] of _seqExecByHost) {
          const auths = (_seqAuthByHost.get(host) || []).slice().sort((a, b) => a.tms - b.tms);
          const shares = (_seqShareByHost.get(host) || []).slice().sort((a, b) => a.tms - b.tms);
          if (auths.length === 0 || shares.length === 0) continue;
          execs.sort((a, b) => a.tms - b.tms);
          let best = null;
          for (const e of execs) {
            // latest admin/IPC$ share at/just before exec
            let s = null;
            for (const sh of shares) { if (sh.tms > e.tms) break; if ((e.tms - sh.tms) <= _seqWindowMs) s = sh; }
            if (!s) continue;
            // latest auth at/just before that share, with user continuity when both are known
            let a = null;
            for (const au of auths) {
              if (au.tms > s.tms) break;
              if ((s.tms - au.tms) > _seqWindowMs) continue;
              if (au.user && s.user && au.user !== s.user) continue;
              a = au;
            }
            if (!a) continue;
            if ((e.tms - a.tms) > _seqMaxSpanMs) continue;
            // User continuity on the EXEC step too. The auth->share hop already
            // required one principal, but the exec step was accepted on timing
            // alone: any heuristic execution finding on the host inside the window
            // completed the sequence and the result was published as a CRITICAL
            // "remote exec sequence by <auth user>" even when the execution belonged
            // to a different account entirely. When the exec step carries no user at
            // all (a 7045 service install often does not) the sequence is kept but
            // reported one level down, with the gap stated.
            const _seqUserKey = (a.user || s.user || "").toUpperCase();
            const _execUsers = (e.users || []).filter(Boolean).map((u) => u.toUpperCase());
            if (_seqUserKey && _execUsers.length > 0 && !_execUsers.includes(_seqUserKey)) continue;
            best = { a, s, e, execUserKnown: _execUsers.length > 0 };
            break; // earliest complete sequence — one finding per host
          }
          if (!best) continue;
          const { a, s, e, execUserKnown } = best;
          const seqUser = a.user || s.user || e.users[0] || "(unknown)";
          const _seqRefs = _dedupeEvidenceRefs([...(a.refs || []), ...(s.refs || []), ...(e.refs || [])]);
          const _shareLabel = s.pipe ? `${s.share}\\pipe\\${s.pipe.name}` : s.share;
          const _execLabel = _execShort[e.category] || e.category;
          const _spanSec = Math.round((e.tms - a.tms) / 1000);
          const _seqPills = [
            { text: "auth (4648/Type 3)", type: "credential" },
            { text: `${s.share} share`, type: "execution" },
          ];
          if (s.pipe) _seqPills.push({ text: `\\pipe\\${s.pipe.name}`, type: "execution" });
          _seqPills.push({ text: _execLabel, type: "execution" });
          _seqPills.push({ text: `ordered in ${_spanSec}s`, type: "correlation" });
          if (!execUserKnown) _seqPills.push({ text: "exec step user unknown", type: "context" });
          if (a.source && _outlierHosts.has(a.source)) _seqPills.push({ text: "outlier source", type: "context" });
          findings.push({
            id: fid++, severity: execUserKnown ? "critical" : "high", category: "Remote Execution Sequence", mitre: (s.pipe && s.pipe.mitre) || "T1569.002",
            title: `Remote exec sequence on ${host}: ${seqUser} (auth → ${_shareLabel} → ${_execLabel})`,
            description: `Ordered lateral-movement sequence on ${host} by ${seqUser} within ${_spanSec}s: authentication (${(a.ts || "").slice(0, 19)}) → ${_shareLabel} share access (${(s.ts || "").slice(0, 19)}) → ${_execLabel} execution (${(e.ts || "").slice(0, 19)}). The auth→share→execute ordering by a single principal in a short window is a high-confidence remote-execution signal (PsExec/Impacket/WMI-style).${execUserKnown ? "" : " The execution step carries no account, so the principal is confirmed only for the auth and share steps."}`,
            source: a.source || "", target: host,
            filterHosts: [host, a.source].filter(Boolean),
            timeRange: { from: a.ts, to: e.ts },
            eventCount: 3, filterEids: ["4648", "4624", "5140", "5145", "7045", "4697", "4688"],
            evidencePills: _seqPills, users: [seqUser],
            evidenceRefs: _seqRefs, itemRowids: _rowidsFromRefs(_seqRefs),
          });
        }
      } catch (_seqErr) { warnings.push(`Remote execution sequence detector failed: ${_seqErr.message}`); }

      // === Service-Exec edge technique correlation ===
      // The inline edge-technique rule "Type 3 + 7045/4697 → Service Exec" can never fire because
      // service installs are scanned separately and never enter edge.eventBreakdown. Bridge the two
      // paths: when a destination-side execution finding (PsExec/Impacket/service install) lands on
      // a target within ±5 min of an inbound Type-3 / explicit-cred logon edge, relabel that edge
      // "Service Exec" so the graph and chains reflect the actual technique.
      try {
        const _seCats = new Set(["PsExec Native", "Impacket Execution", "Impacket Summary", "Remote Service Execution"]);
        const _seMs = (t) => { const n = normalizeTimestamp(t); return Number.isFinite(n) ? n : null; };
        const _seExec = [];
        for (const f of findings) {
          if (!_seCats.has(f.category)) continue;
          const details = Array.isArray(f.executionDetails) ? f.executionDetails : [];
          if (details.length) {
            for (const d of details) {
              const tms = _seMs(d.timestamp);
              const host = (d.target || "").trim().toUpperCase();
              if (tms == null || !host) continue;
              _seExec.push({ host, tms, label: f.category });
            }
          } else {
            const tms = _seMs(f.timeRange && f.timeRange.from);
            if (tms == null) continue;
            for (const t of (f.target || "").split(/,\s*/).map(h => h.trim().toUpperCase()).filter(Boolean)) {
              _seExec.push({ host: t, tms, label: f.category });
            }
          }
        }
        if (_seExec.length > 0) {
          const _seLogons = [];
          for (const evt of timeOrdered) {
            const isAuth = evt.eventId === "4648" || (evt.eventId === "4624" && evt.logonType === "3");
            if (!isAuth) continue;
            const tms = _seMs(evt.ts);
            if (tms == null) continue;
            _seLogons.push({
              source: (evt.source || "").toUpperCase(),
              target: (evt.target || "").toUpperCase(),
              tms,
            });
          }
          for (const edge of edgeMap.values()) {
            if (edge.technique === "Service Exec") continue;
            const lt = edge.logonTypes;
            const eb = edge.eventBreakdown;
            const isType3OrExplicit = (lt && lt.has("3")) || (eb && eb.has("4648"));
            if (!isType3OrExplicit) continue;
            const tgt = (edge.target || "").toUpperCase();
            const src = (edge.source || "").toUpperCase();
            const match = _seExec.find((x) => {
              if (x.host !== tgt) return false;
              return _seLogons.some((l) => l.source === src && l.target === tgt && Math.abs(l.tms - x.tms) <= 300000);
            });
            if (!match) continue;
            // Preserve the prior primary technique as a supporting one, then promote.
            if (edge.technique && edge.technique !== "Unknown" && edge.technique !== "Network Logon" && edge.technique !== "Service Exec") {
              edge.otherTechniques = [...new Set([edge.technique, ...(edge.otherTechniques || [])])];
            }
            edge.technique = "Service Exec";
            edge._correlatedTool = match.label;
          }
        }
      } catch (_seErr) { warnings.push(`Service-exec edge correlation failed: ${_seErr.message}`); }

      // === LSASS Direct Access (T1003.001) — Sysmon EID 10 ===
      try {
        if (_lsassAccessHits.length > 0 && !_disabledSet.has("lsass")) {
          // Group by host + caller
          const _lsaByHostCaller = new Map();
          for (const h of _lsassAccessHits) {
            const k = `${h.host}::${h.caller}`;
            if (!_lsaByHostCaller.has(k)) _lsaByHostCaller.set(k, []);
            _lsaByHostCaller.get(k).push(h);
          }
          for (const [, hits] of _lsaByHostCaller) {
            const host = hits[0].host;
            const caller = hits[0].caller;
            const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
            const _lsaPills = [{ text: "LSASS handle open", type: "credential" }, { text: caller, type: "execution" }];
            if (_DC_PAT.test(host)) _lsaPills.push({ text: "DC target", type: "target" });
            const _lsaUsers = _usersFromCorrelation(hits);
            const _lsaSources = _sourcesFromCorrelation(hits);
            findings.push({
              id: fid++, severity: "critical", category: "LSASS Access", mitre: "T1003.001",
              title: `LSASS direct access by ${caller} on ${host}`,
              description: `${hits.length} Sysmon EID 10 (OpenProcess) event(s) targeting lsass.exe by ${caller}. Direct handle opens to LSASS are a primary indicator of credential dumping (Mimikatz, comsvcs.dll, procdump, etc.).`,
              source: _lsaSources.join(", "), target: host,
              filterHosts: [...new Set([host, ..._lsaSources])],
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: hits.length, filterEids: ["10"],
              evidencePills: _lsaPills, users: _lsaUsers,
              itemRowids: hits.map(h => h.rid).filter(r => r != null),
            });
          }
        }
      } catch (_lsaErr) { warnings.push(`LSASS access detector failed: ${_lsaErr.message}`); }

      // === Credential Theft Commands (T1003.002 / T1090.001) ===
      try {
        if (_credTheftCmdHits.length > 0) {
          // reg save SAM/SECURITY findings
          const _regSaveHits = _credTheftCmdHits.filter(h => h.category === "reg_save");
          if (_regSaveHits.length > 0 && !_disabledSet.has("regsave")) {
            // Group by host
            const _rsByHost = new Map();
            for (const h of _regSaveHits) {
              if (!_rsByHost.has(h.host)) _rsByHost.set(h.host, []);
              _rsByHost.get(h.host).push(h);
            }
            for (const [host, hits] of _rsByHost) {
              const targets = [...new Set(hits.map(h => h.target))];
              const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
              const _rsPills = [{ text: "registry credential dump", type: "credential" }, ...targets.map(t => ({ text: `HKLM\\${t}`, type: "execution" }))];
              const _rsUsers = _usersFromCorrelation(hits);
              const _rsSources = _sourcesFromCorrelation(hits);
              findings.push({
                id: fid++, severity: "critical", category: "SAM/LSA Registry Dump", mitre: "T1003.002",
                title: `Registry credential dump: ${targets.map(t => `HKLM\\${t}`).join(", ")} on ${host}`,
                description: `${hits.length} reg save command(s) targeting ${targets.join("/")} registry hives. This extracts local account hashes (SAM) or cached domain credentials (SECURITY) for offline cracking.`,
                source: _rsSources.join(", "), target: host,
                filterHosts: [...new Set([host, ..._rsSources])],
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4688", "1"],
                evidencePills: _rsPills, users: _rsUsers,
                itemRowids: hits.map(h => h.rid).filter(r => r != null),
              });
            }
          }

          // netsh portproxy findings
          const _portproxyHits = _credTheftCmdHits.filter(h => h.category === "portproxy");
          if (_portproxyHits.length > 0 && !_disabledSet.has("portproxy")) {
            const _ppByHost = new Map();
            for (const h of _portproxyHits) {
              if (!_ppByHost.has(h.host)) _ppByHost.set(h.host, []);
              _ppByHost.get(h.host).push(h);
            }
            for (const [host, hits] of _ppByHost) {
              const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
              const _ppPills = [{ text: "port forwarding", type: "execution" }];
              if (_DC_PAT.test(host)) _ppPills.push({ text: "DC target", type: "target" });
              const _ppUsers = _usersFromCorrelation(hits);
              const _ppSources = _sourcesFromCorrelation(hits);
              findings.push({
                id: fid++, severity: "high", category: "Port Forwarding", mitre: "T1090.001",
                title: `netsh portproxy on ${host}`,
                description: `${hits.length} netsh interface portproxy command(s). Port forwarding is used to pivot through compromised hosts, tunnel RDP/SMB through an internal relay, or bypass firewall rules.`,
                source: _ppSources.join(", "), target: host,
                filterHosts: [...new Set([host, ..._ppSources])],
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4688", "1"],
                evidencePills: _ppPills, users: _ppUsers,
                itemRowids: hits.map(h => h.rid).filter(r => r != null),
              });
            }
          }
        }
      } catch (_ctErr) { warnings.push(`Credential theft command detector failed: ${_ctErr.message}`); }

      // Lateral Pivot findings deferred until after chain confidence scoring (below)

      // First Seen (T1021) — contextual signal, not standalone alert
      // Only emit a finding when the new pair has a corroborating suspicious signal:
      // outlier source, DC/server target, chain membership, admin share access, or tool-backed findings
      for (const edge of edgeMap.values()) {
        if (!edge.isFirstSeen) continue;
        const _fsOutlier = edge.source && _outlierHosts.has(edge.source);
        const _fsDC = edge.target && _DC_PAT.test(edge.target);
        const _fsSrv = edge.target && _SRV_PAT.test(edge.target);
        const _fsChain = chains.some(c => { for (let ci = 0; ci < c.path.length - 1; ci++) { if (c.path[ci] === edge.source && c.path[ci + 1] === edge.target) return true; } return false; });
        const _fsHasAdminShare = edge._adminShareCount > 0;
        const _fsToolCats = new Set(["PsExec Native", "Impacket Execution", "Impacket Credential Access", "Remote Service Execution", "WMI Remote Execution", "WinRM Remote Execution", "Scheduled Task Remote Execution", "Admin Share Access", "RMM Suspicious Execution", "RMM Executed", "DCOM Remote Execution", "OpenSSH Inbound Access", "SSH Tunneling"]);
        const _fsTool = findings.some(f => {
          if (!_fsToolCats.has(f.category)) return false;
          const ft = (f.target || "").split(", ");
          const fs = (f.source || "").split(", ");
          return ft.includes(edge.target) && fs.includes(edge.source);
        });
        if (!_fsOutlier && !_fsDC && !_fsSrv && !_fsChain && !_fsHasAdminShare && !_fsTool) continue;
        // FP guard: "first connection to a DC/server" is the baseline for nearly every endpoint
        // (every workstation authenticates to a DC). Don't emit when the ONLY signal is a DC/server
        // target — require a real risk signal (outlier source, chain, admin share, tool-backed),
        // unless the source itself is a DC/server (server→server is more notable) or the logon is
        // RDP/Type-9/failed (inherently more interesting than routine network auth).
        const _fsHasRealSignal = _fsOutlier || _fsChain || _fsHasAdminShare || _fsTool;
        const _fsSrcIsInfra = edge.source && (_DC_PAT.test(edge.source) || _SRV_PAT.test(edge.source));
        const _fsIsRdpOrSpecial = edge.logonTypes && (edge.logonTypes.has("10") || edge.logonTypes.has("12") || edge.logonTypes.has("9"));
        if ((_fsDC || _fsSrv) && !_fsHasRealSignal && !_fsSrcIsInfra && !_fsIsRdpOrSpecial && !edge.hasFailures) continue;
        const _fsPills = [{ text: "new connection pair", type: "context" }];
        if (_fsOutlier) _fsPills.push({ text: "outlier source", type: "context" });
        if (_fsDC) _fsPills.push({ text: "DC target", type: "target" });
        else if (_fsSrv) _fsPills.push({ text: "server target", type: "target" });
        if (_fsChain) _fsPills.push({ text: "in lateral chain", type: "correlation" });
        if (_fsHasAdminShare) _fsPills.push({ text: "admin share access", type: "execution" });
        if (_fsTool) _fsPills.push({ text: "tool-backed", type: "correlation" });
        findings.push({ id: fid++, severity: "low", category: "First Seen", mitre: "T1021", title: `New connection: ${edge.source} \u2192 ${edge.target}`, description: `First observed connection at ${(edge.firstSeen || "").slice(0, 19)}`, source: edge.source, target: edge.target, timeRange: { from: edge.firstSeen, to: edge.firstSeen }, eventCount: 1, evidencePills: _fsPills, users: [...(edge.users || [])] });
      }

      // Credential Compromise severity boost: promote high→critical if post-success tool activity on same pair
      // Requires pair-specific match: both source AND target must match (no source-less fallback)
      const _ccBoostCats = new Set(["PsExec Native", "Impacket Execution", "Admin Share Access", "WMI Remote Execution", "WinRM Remote Execution", "Scheduled Task Remote Execution", "Concurrent RDP Sessions"]);
      for (const f of findings) {
        if (f.category !== "Credential Compromise" || f.severity !== "high") continue;
        const pair = f._ccPair; // "source->target"
        if (!pair) continue;
        const [cs, ct] = pair.split("->");
        const hasToolActivity = findings.some(of => {
          if (!_ccBoostCats.has(of.category)) return false;
          if (!of.source) return false; // require explicit source on the corroborating finding
          const ofTargets = (of.target || "").split(", ");
          const ofSources = (of.source || "").split(", ");
          return ofTargets.includes(ct) && ofSources.includes(cs);
        });
        if (hasToolActivity) {
          f.severity = "critical";
          f.description += ". Post-success tool activity detected on same pair";
          if (!f.evidencePills) f.evidencePills = [];
          f.evidencePills.push({ text: "post-success tool activity", type: "correlation" });
        }
      }


  return { fid };
}

module.exports = { detectAdminShareAndExecution };
