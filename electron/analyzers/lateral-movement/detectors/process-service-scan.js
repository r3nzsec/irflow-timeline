/**
 * detectors/process-service-scan.js — the secondary scan engine for the
 * lateral-movement analyzer: stratified family queries over process/service/
 * task/named-pipe/createthread/openprocess/wmi-subscription events, run through
 * the isolation-grouped detectors (PsExec, Impacket, Remote Service, DCOM,
 * OpenSSH, WMI, WinRM, RMM, scheduled tasks, Cobalt Strike) and their per-
 * technique finding emitters.
 *
 * Extracted verbatim from getLateralMovement(). Pushes findings (advancing fid),
 * accumulates per-host correlation, and returns the artifacts that downstream
 * stages consume (the admin-share/exec detector + Sysmon coverage + result).
 *
 * @param {object} state - { columns, meta, db, isHayabusa, timeOrdered, scanLimits,
 *   scanPageSize, _bumpDatasetEvent, _normLmHost, _bumpHostTelemetry,
 *   requireMicrosoftSignature, findings, _disabledSet, rmmMode, _outlierHosts, hostSet, fid }
 * @returns {{fid, warnings, scanStats, _scanEidCol, _usersFromCorrelation,
 *   _sourcesFromCorrelation, _lsassAccessHits, _credTheftCmdHits}}
 */
const { DC_PAT: _DC_PAT, SRV_PAT: _SRV_PAT } = require("../constants");
const { normalizeTimestamp } = require("../../../utils/forensic-normalize");
const { tsMs, cmpTs, gapMs: _gapMs } = require("../time");

function _hitMs(h) {
  const n = normalizeTimestamp(h && h.ts);
  return Number.isFinite(n) ? n : 0;
}

function _hitTargetKey(h) {
  if (h && h.side === "dest") return h.host || "";
  return (h && (h.remoteTarget || h.host)) || "";
}

/** Split hits into per-host groups, then 10-minute clusters (same idea as Impacket). */
function clusterHitsByHostTime(hits, hostOf = _hitTargetKey, gapMs = 600000) {
  const byHost = new Map();
  for (const h of hits || []) {
    const key = String(hostOf(h) || "").toUpperCase() || "(unknown)";
    if (!byHost.has(key)) byHost.set(key, []);
    byHost.get(key).push(h);
  }
  const clusters = [];
  for (const group of byHost.values()) {
    group.sort((a, b) => _hitMs(a) - _hitMs(b) || cmpTs(a.ts, b.ts));
    let cur = [group[0]];
    for (let i = 1; i < group.length; i++) {
      const prev = _hitMs(cur[cur.length - 1]);
      const next = _hitMs(group[i]);
      if (prev && next && next - prev > gapMs) {
        clusters.push(cur);
        cur = [];
      }
      cur.push(group[i]);
    }
    if (cur.length) clusters.push(cur);
  }
  return clusters;
}

function runProcessServiceScan(state) {
  const {
    columns, meta, db, isHayabusa, timeOrdered, scanLimits, scanPageSize,
    _bumpDatasetEvent, _normLmHost, _bumpHostTelemetry, requireMicrosoftSignature,
    findings, _disabledSet, rmmMode, _outlierHosts, hostSet,
  } = state;
  let fid = state.fid;

      // === Process/Service/Task Scan — Stratified Queries + Per-Detector Isolation ===
      const warnings = [];
      const scanStats = {};
      const _scanEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
      const _scanTsCol = columns.ts ? meta.colMap[columns.ts] : null;
      const _scanChanCol = columns._channel ? meta.colMap[columns._channel] : null;
      const _scanDetect = (pats) => { for (const p of pats) { const f = meta.headers.find(h => p.test(h)); if (f) return meta.colMap[f]; } return null; };
      // Structured (real) process columns, before any Hayabusa blob fallback.
      const _structColImage = _scanDetect([/^Image$/i, /^NewProcessName$/i, /^process_name$/i, /^FileName$/i, /^ImagePath$/i, /^SourceImage$/i]);
      const _structColParent = _scanDetect([/^ParentImage$/i, /^ParentProcessName$/i, /^ParentCommandLine$/i]);
      const _structColCmd = _scanDetect([/^CommandLine$/i, /^command_line$/i, /^ProcessCommandLine$/i, /^cmdline$/i]);
      const _structColSvc = _scanDetect([/^ServiceName$/i, /^Service_Name$/i, /^TargetServiceName$/i]);
      const _structColServiceAccount = _scanDetect([/^ServiceAccount$/i, /^ServiceAccountName$/i, /^AccountName$/i]);
      const _structColActor = _scanDetect([/^SubjectUserName$/i, /^Subject_User_Name$/i, /^SubjectAccountName$/i, /^UserName$/i]);
      const _structColActorDomain = _scanDetect([/^SubjectDomainName$/i, /^Subject_Domain_Name$/i, /^AccountDomain$/i]);
      const _structColExecutableInfo = _scanDetect([/^ExecutableInfo$/i]);
      const _scanColImage = _structColImage || (isHayabusa ? _scanDetect([/^Details$/i]) : null);
      const _scanColParent = _structColParent || (isHayabusa ? _scanDetect([/^ExtraFieldInfo$/i]) : null);
      const _scanColCmd = _structColCmd || (isHayabusa ? _scanDetect([/^CommandLine$/i]) : null) || (isHayabusa ? _scanDetect([/^Details$/i]) : null);
      // Detectors that compare a parent/child BINARY NAME must only take the structured
      // path when the columns really are parent/image fields. On Hayabusa they fall back
      // to the Details / ExtraFieldInfo blobs, so `_parent.split("\\").pop()` compares a
      // whole blob against "wmiprvse.exe" and never matches — which silently disabled
      // dest-side WMI, dest-side WinRM, DCOM and sshd→shell detection on Hayabusa data,
      // because the (correct) blob fallbacks below sat in an unreachable `else`.
      const _hasStructuredProcCols = !!(_structColParent && _structColImage);
      const _scanCols = [
        _scanColCmd, _scanColImage, _scanColParent,
        _structColExecutableInfo,
        _structColSvc,
        _structColServiceAccount,
        _structColActor,
        _structColActorDomain,
        _scanDetect([/^MapDescription$/i]),
        _scanDetect([/^Details$/i]),
        _scanDetect([/^ExtraFieldInfo$/i]),
        _scanDetect([/^RuleTitle$/i]),
        ...[1,2,3,4,5,6].map(n => { const h = meta.headers.find(h => new RegExp(`^PayloadData${n}$`, "i").test(h)); return h ? meta.colMap[h] : null; }),
      ].filter(Boolean);
      // RMM_SIGS: type = "rmm" (remote management) | "tunnel" (network tunneling)
      // exe: exact executable names (matched against _image basename)
      // svc: service names (matched against _svc field)
      // kw: fallback keywords for _alltext (only used when exe/svc don't match)
      const RMM_SIGS = [
        { name: "ConnectWise ScreenConnect", type: "rmm", exe: ["screenconnect.clientservice.exe","screenconnect.windowsclient.exe","screenconnect.service.exe"], svc: ["screenconnect client"], kw: [] },
        { name: "AnyDesk", type: "rmm", exe: ["anydesk.exe"], svc: ["anydesk"], kw: [] },
        { name: "TeamViewer", type: "rmm", exe: ["teamviewer.exe","teamviewer_service.exe"], svc: ["teamviewer"], kw: [] },
        { name: "Atera", type: "rmm", exe: ["ateraagent.exe","alphaagent.exe"], svc: ["ateraagent","aaboragent"], kw: [] },
        { name: "NetSupport Manager", type: "rmm", exe: ["client32.exe"], svc: ["client32"], kw: [] },
        { name: "Splashtop", type: "rmm", exe: ["strwinclt.exe","srservice.exe","splashtop.exe"], svc: ["splashtop","srservice"], kw: [] },
        { name: "RustDesk", type: "rmm", exe: ["rustdesk.exe"], svc: ["rustdesk"], kw: [] },
        { name: "PDQ Connect", type: "rmm", exe: ["pdqconnectagent.exe"], svc: ["pdqconnect"], kw: [] },
        { name: "MeshAgent/MeshCentral", type: "rmm", exe: ["meshagent.exe"], svc: ["meshagent","mesh agent"], kw: [] },
        { name: "Action1", type: "rmm", exe: ["action1_connector.exe","action1_agent.exe"], svc: ["action1_agent","action1_connector"], kw: [] },
        { name: "Ammyy Admin", type: "rmm", exe: ["aa_v3.exe","ammyy_admin.exe"], svc: [], kw: [] },
        { name: "Remote Utilities", type: "rmm", exe: ["rutview.exe","rutserv.exe"], svc: ["rutserv"], kw: [] },
        { name: "SimpleHelp", type: "rmm", exe: ["simplehelp.exe","simpleservice.exe"], svc: ["simplehelp"], kw: [] },
        { name: "TacticalRMM", type: "rmm", exe: ["tacticalrmm.exe"], svc: ["tacticalrmm"], kw: [] },
        { name: "FleetDeck", type: "rmm", exe: ["fleetdeck_agent.exe"], svc: ["fleetdeck"], kw: [] },
        { name: "Level.io", type: "rmm", exe: ["level-windows-amd64.exe"], svc: ["level"], kw: [] },
        { name: "DWService", type: "rmm", exe: ["dwagsvc.exe","dwagent.exe"], svc: ["dwservice","dwagsvc"], kw: [] },
        { name: "ISL Online", type: "rmm", exe: ["isllight.exe"], svc: ["isl online"], kw: [] },
        { name: "HopToDesk", type: "rmm", exe: ["hoptodesk.exe"], svc: ["hoptodesk"], kw: [] },
        { name: "Lite Manager", type: "rmm", exe: ["lmnoipserver.exe","romserver.exe"], svc: ["litemanager"], kw: [] },
        { name: "UltraVNC", type: "rmm", exe: ["uvnc_launch.exe","winvnc.exe","vncviewer.exe"], svc: ["ultravnc","uvnc_service"], kw: [] },
        { name: "TigerVNC", type: "rmm", exe: ["tvnserver.exe","vncviewer.exe"], svc: ["tvnserver"], kw: [] },
        { name: "RAdmin", type: "rmm", exe: ["rserver3.exe","radmin.exe"], svc: ["r_server"], kw: [] },
        { name: "Zoho Assist", type: "rmm", exe: ["zaservice.exe"], svc: ["zoho assist"], kw: [] },
        { name: "Pulseway", type: "rmm", exe: ["pcmonitormanager.exe","pcmonitorsrv.exe"], svc: ["pulseway","pcmonitormanager"], kw: [] },
        { name: "LabTech/Automate", type: "rmm", exe: ["ltsvc.exe","ltsvcmon.exe","lttray.exe"], svc: ["ltservice","ltsvcmon"], kw: [] },
        { name: "Kaseya VSA", type: "rmm", exe: ["agentmon.exe","kagent.exe"], svc: ["kaseya agent"], kw: [] },
        { name: "N-able/SolarWinds", type: "rmm", exe: ["solarwinds.msp.cacheservice.exe","winagent.exe"], svc: ["n-able","solarwinds.msp"], kw: [] },
        // Additional RMM tools — high-abuse in BEC/ransomware
        { name: "GoTo Resolve/LogMeIn", type: "rmm", exe: ["logmein.exe","logmeinrescue.exe","lmi_rescue.exe","goto-opener.exe","g2ax_comm_gotoresolve.exe","gotoresolve-executor.exe"], svc: ["logmein","logmeinrescue","gotoresolve"], kw: [] },
        { name: "BeyondTrust (Bomgar)", type: "rmm", exe: ["bomgar-scc.exe","bomgar-rdp.exe","btservice.exe","beyondtrustclient.exe"], svc: ["bomgar","btservice","beyondtrust"], kw: [] },
        { name: "Dameware", type: "rmm", exe: ["dwrcc.exe","dwrcst.exe","dameware mini remote control.exe"], svc: ["dameware","dwmrcs"], kw: [] },
        { name: "Supremo", type: "rmm", exe: ["supremo.exe","supremoservice.exe","supremohelper.exe"], svc: ["supremoservice"], kw: [] },
        { name: "FixMe.IT", type: "rmm", exe: ["fixmeit_client.exe","fixmeit_expert.exe","fixmeitclient.exe"], svc: ["fixmeit"], kw: [] },
        // Tunnels — separate type
        { name: "ngrok", type: "tunnel", exe: ["ngrok.exe"], svc: [], kw: [] },
        { name: "Tailscale", type: "tunnel", exe: ["tailscale.exe","tailscaled.exe"], svc: ["tailscale"], kw: [] },
        { name: "Cloudflared", type: "tunnel", exe: ["cloudflared.exe"], svc: ["cloudflared"], kw: [] },
        { name: "Chisel", type: "tunnel", exe: ["chisel.exe"], svc: [], kw: [] },
        { name: "ligolo-ng", type: "tunnel", exe: ["ligolo-agent.exe","ligolo-proxy.exe"], svc: [], kw: [] },
        { name: "ZeroTier", type: "tunnel", exe: ["zerotier-one.exe","zerotier_desktop_ui.exe"], svc: ["zerotierone","zerotier one"], kw: [] },
        { name: "WireGuard", type: "tunnel", exe: ["wireguard.exe","wg.exe"], svc: ["wireguard","wgservice"], kw: [] },
      ];
      // Build lookup indexes
      const _rmmByExe = new Map();   // basename -> tool
      const _rmmBySvc = new Map();   // service name -> tool
      for (const tool of RMM_SIGS) {
        for (const e of tool.exe) _rmmByExe.set(e.toLowerCase(), tool);
        for (const s of tool.svc) _rmmBySvc.set(s.toLowerCase(), tool);
      }
      const _isSanctionedCortexPayload = (imagePath, cmd, allText) => {
        const blob = `${imagePath || ""} ${cmd || ""} ${allText || ""}`.toLowerCase();
        if (!blob.includes("cortex-xdr-payload.exe")) return false;
        return blob.includes("palo alto networks")
          || /offline_collector_config\.json|--offline-collector|--collect-artifacts|xdr_collector/i.test(blob);
      };
      // Unusual parents for RMM context scoring
      const _rmmSusParents = new Set(["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","certutil.exe","bitsadmin.exe"]);
      // Normal enterprise parents (services hosting RMM is expected)
      const _rmmNormalParents = new Set(["services.exe","svchost.exe","explorer.exe","userinit.exe","winlogon.exe","msiexec.exe"]);
      // Suspicious paths
      const _rmmSusPaths = /\\(temp|tmp|downloads|appdata\\local\\temp|users\\[^\\]+\\desktop|public|recycle)/i;
      // Microsoft productivity/sync binaries that are common in enterprise environments.
      // Use strict binary + expected path matching to avoid over-allowlisting.
      const _msProductPaths = /(?:\\appdata\\local\\microsoft\\onedrive\\|program files(?:\s*\(x86\))?\\microsoft onedrive\\|program files(?:\s*\(x86\))?\\microsoft\\edgeupdate\\|program files\\common files\\microsoft shared\\clicktorun\\|program files(?:\s*\(x86\))?\\microsoft office\\|\\office\d+\\)/i;
      const _msProductBins = new Set([
        "onedrive.exe", "groove.exe", "officeclicktorun.exe", "microsoftedgeupdate.exe", "microsoftedgeupdatecore.exe",
        "outlook.exe", "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "teams.exe", "ms-teams.exe", "ms-teamsupdate.exe",
      ]);
      const _extractExeCandidate = (blob = "") => {
        const s = String(blob || "").trim().replace(/^[`'"]+|[`'"]+$/g, "");
        if (!s) return "";
        const m = s.match(/^"([^"]+\.exe)"/i) || s.match(/([a-z]:\\[^"'\s|]+\.exe)\b/i) || s.match(/([^\s"'|]+\.exe)\b/i);
        return (m ? m[1] : "").replace(/"/g, "");
      };
      const _isExpectedMicrosoftBinary = (blob = "", signatureBlob = "") => {
        const exe = _extractExeCandidate(blob).toLowerCase();
        if (!exe) return false;
        const base = exe.includes("\\") ? exe.substring(exe.lastIndexOf("\\") + 1) : exe;
        if (!_msProductBins.has(base) || !_msProductPaths.test(exe)) return false;
        const sig = String(signatureBlob || "").toLowerCase();
        const hasSigContext = /(?:signer|signature|signed)\s*:/.test(sig);
        if (requireMicrosoftSignature) {
          return /(?:signer|signature)\s*:\s*.*microsoft/.test(sig) || (/\bsigned\s*:\s*true\b/.test(sig) && /microsoft/.test(sig));
        }
        if (hasSigContext) {
          if (/\bsigned\s*:\s*false\b/.test(sig)) return false;
          if (/(?:signer|signature)\s*:\s*(?!.*microsoft)/.test(sig)) return false;
        }
        return true;
      };
      const COMMON_SVC = new Set([
        // Generic English words common in service names
        "system","service","server","client","agent","local","admin","power","event","setup","shell","start","print","audit","group","share","trust","alert","cache","debug","error","index","input","media","model","panel","patch","proxy","query","queue","route","scene","scope","stack","stage","state","store","style","super","table","theme","timer","token","trace","track","train","trend","union","unity","usage","valid","watch",
        // Virtualization / hypervisor drivers
        "qemu","virtio","spice","vbox","vmware","hyper","xen",
        // Security / EDR / AV vendors and drivers
        "cortex","traps","cyverak","cyvrfsfd","cyvrmtgn","cyeason","cylance","carbon","sentinel","crowdstrike","falcon","defend","defender","mdatp","sense","epdr","eset","sophos","hmpalert","savservice","sophossps","mbam","npcap","winpcap","usbpcap",
        "tedrdrv","tdevflt","trellix","mfemms","mfefire","mfehidk","mfeavfk","mfevtp","enterceptagent",
        "kaspersky","klif","klifks","klflt","klhk","ksld","kneps",
        "avast","avgnt","bdagent","bitdefender","clamav","comodo",
        // Enterprise management / deployment
        "ccmsetup","ccmexec","sccm","intune","landesk","altiris","bigfix","tanium","puppet","chef","ansible","salt",
        // Common vendor services
        "google","mozilla","firefox","chrome","adobe","java","oracle","dell","lenovo","vmtools","splunk","elastic","wazuh",
        // OS / platform services
        "printer","spooler","wuauserv","bits","themes","dnscache","dhcp","winrm","winmgmt","msiserver","office","onedrive","teams",
        // Microsoft built-in services (network, events, devices, logon) — short alpha names that are NOT random
        "netlogon","netman","browser","wecsvc","wecsvr","sysmain","schedule","eaphost","wcmsvc","seclogon","lfsvc","wlansvc","pcasvc","dusmsvc","sgrmbroker","camsvc","vaultsvc","sstpsvc","lanman","workstation","rpcss","rpclocator","gpsvc","wsearch","wbengine","trustedinstaller","appinfo","fdphost","fdrespub","sharedaccess","remoteregistry",
        // Enterprise backup / management / collaboration vendors with short service names
        "macmnsvc","splunkd","veeam","acronis","druva","cohesity","rubrik","datto","zoom","slack","citrix","nxlog","velociraptor","zabbix","nessusd","osquery",
      ]);
      const _lsassAccessHits = []; // Sysmon EID 10 (OpenProcess) on lsass.exe
      const _credTheftCmdHits = []; // reg save SAM/SECURITY, netsh portproxy
      // Shared execution correlation helpers. Several finding emitters run after
      // the scan block, so these must live in the outer analyzer scope.
      const _execLogonByHost = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4624" && evt.eventId !== "4648") continue;
        const h = (evt.target || "").toUpperCase();
        if (!h) continue;
        if (!_execLogonByHost.has(h)) _execLogonByHost.set(h, []);
        _execLogonByHost.get(h).push(evt);
      }
      const _correlatedExecLogon = (host, hitTs, windowMs = 300000) => {
        if (!host || !hitTs) return null;
        const logons = _execLogonByHost.get(host.toUpperCase());
        if (!logons) return null;
        const tMs = tsMs(hitTs);
        if (tMs == null) return null;
        for (const l of logons) {
          if (l.logonType !== "3" && l.eventId !== "4648") continue;
          const lMs = tsMs(l.ts);
          if (lMs != null && Math.abs(lMs - tMs) <= windowMs) return l;
        }
        return null;
      };
      const _usersFromCorrelation = (hits) => {
        const out = new Set();
        for (const h of hits) {
          if (!h) continue;
          const corrHost = h.side === "dest" ? h.host : (h.remoteTarget || h.host);
          const l = _correlatedExecLogon(corrHost, h.ts);
          if (l && l.user) {
            const u = l.user.toUpperCase();
            if (u && !u.endsWith("$") && u !== "SYSTEM" && u !== "LOCAL SERVICE" && u !== "NETWORK SERVICE") out.add(u);
          }
        }
        return [...out];
      };
      const _sourcesFromCorrelation = (hits) => {
        const out = new Set();
        for (const h of hits) {
          if (!h) continue;
          const corrHost = h.side === "dest" ? h.host : (h.remoteTarget || h.host);
          const l = _correlatedExecLogon(corrHost, h.ts);
          if (l && l.source) {
            const s = l.source.toUpperCase().replace(/\s*\(.*\)$/, "").trim();
            if (s && s !== "-" && s !== "LOCALHOST" && s !== "127.0.0.1") out.add(s);
          }
        }
        return [...out];
      };
      if (db && _scanEidCol && _scanCols.length > 0) {
        // Stratified queries: separate budgets per event family to prevent bias
        const _scanConcat = _scanCols.map(c => `COALESCE(${c}, '')`).join(" || '|' || ");
        const _scanSelParts = ["data.rowid as _rid", `(${_scanConcat}) as _alltext`, `${_scanEidCol} as _eid`];
        if (_scanTsCol) _scanSelParts.push(`${_scanTsCol} as _ts`);
        const _scanHostCol = columns.target ? meta.colMap[columns.target] : null;
        if (_scanHostCol) _scanSelParts.push(`${_scanHostCol} as _host`);
        if (_scanColImage) _scanSelParts.push(`${_scanColImage} as _image`);
        if (_scanColParent) _scanSelParts.push(`${_scanColParent} as _parent`);
        if (_scanColCmd) _scanSelParts.push(`${_scanColCmd} as _cmd`);
        const _scanColSvc = _structColSvc || (isHayabusa ? _scanDetect([/^Details$/i, /^ExtraFieldInfo$/i]) : null);
        if (_scanColSvc) _scanSelParts.push(`${_scanColSvc} as _svc`);
        if (_structColServiceAccount) _scanSelParts.push(`${_structColServiceAccount} as _service_account`);
        if (_structColActor) _scanSelParts.push(`${_structColActor} as _actor`);
        if (_structColActorDomain) _scanSelParts.push(`${_structColActorDomain} as _actor_domain`);
        if (_structColExecutableInfo) _scanSelParts.push(`${_structColExecutableInfo} as _exec_info`);
        const _scanChanFilter = _scanChanCol
          ? ` AND (LOWER(${_scanChanCol}) LIKE '%security%' OR LOWER(${_scanChanCol}) LIKE '%sysmon%' OR LOWER(${_scanChanCol}) LIKE '%system%' OR LOWER(${_scanChanCol}) IN ('sec','sysmon','sys'))`
          : "";
        const _scanSelectClause = _scanSelParts.join(", ");
        const _scanOrderClause = " ORDER BY data.rowid ASC";
        // Per-family budgets
        const _limitFromCfg = (k, d) => {
          const v = Number(scanLimits?.[k]);
          return Number.isFinite(v) && v > 0 ? Math.floor(v) : d;
        };
        const _scanFamilies = [
          { eids: ["4688", "1"], limit: _limitFromCfg("process", 30000), label: "process" },
          { eids: ["7045", "4697"], limit: _limitFromCfg("service", 10000), label: "service" },
          { eids: ["4698"], limit: _limitFromCfg("task", 10000), label: "task" },
          { eids: ["17", "18"], limit: _limitFromCfg("namedpipe", 5000), label: "namedpipe" },
          { eids: ["8"], limit: _limitFromCfg("createthread", 5000), label: "createthread" },
          { eids: ["10"], limit: _limitFromCfg("openprocess", 5000), label: "openprocess" },
          { eids: ["19", "20", "21"], limit: _limitFromCfg("wmisub", 5000), label: "wmisub" },
        ];
        let _scanRows = [];
        for (const fam of _scanFamilies) {
          try {
            const placeholders = fam.eids.map(() => "?").join(",");
            const page = Math.max(500, Math.min(Number(scanPageSize) || 5000, 20000));
            let fetched = 0;
            let lastRid = 0;
            const famRows = [];
            while (fetched < fam.limit) {
              const chunk = Math.min(page, fam.limit - fetched);
              const sql = `SELECT ${_scanSelectClause} FROM data WHERE ${_scanEidCol} IN (${placeholders})${_scanChanFilter} AND data.rowid > ?${_scanOrderClause} LIMIT ${chunk}`;
              const rows = db.prepare(sql).all(...fam.eids, lastRid);
              if (rows.length === 0) break;
              famRows.push(...rows);
              fetched += rows.length;
              lastRid = Number(rows[rows.length - 1]._rid || lastRid);
              if (rows.length < chunk) break;
            }
            scanStats[fam.label] = famRows.length;
            if (fetched >= fam.limit) {
              warnings.push(`${fam.label} event scan hit configured limit ${fam.limit} — increase options.scanLimits.${fam.label} for fuller coverage`);
            }
            _scanRows = _scanRows.concat(famRows);
          } catch (qErr) {
            warnings.push(`${fam.label} event query failed: ${qErr.message}`);
          }
        }
        // Sort merged rows by timestamp
        if (_scanTsCol) _scanRows.sort((a, b) => ((a._ts || "") > (b._ts || "") ? 1 : (a._ts || "") < (b._ts || "") ? -1 : 0));
        const _extractHost = (row) => (row._host || "").toString().trim();
        const _escapeRe = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const _extractLabeledValue = (blob, labels) => {
          const source = String(blob || "");
          for (const label of labels) {
            const pattern = new RegExp(`(?:^|[|¦;\\r\\n])\\s*${_escapeRe(label)}\\s*(?::|=)\\s*([^|¦\\r\\n]{1,1000})`, "i");
            const match = source.match(pattern);
            if (match?.[1]) return match[1].trim().replace(/^["']|["']$/g, "");
          }
          return "";
        };

          // Accumulators: PsExec, Impacket, credential access, remote service, WMI, WinRM, RMM, scheduled tasks
          const _psexecNative = [];
          const _psexecImpacket = [];
          const _impCredAccess = [];
          const _remoteSvcExec = [];
          const _wmiHits = [];
          const _winrmHits = [];
          const _rmmHits = []; // structured per-event hits
          const _schedTaskHits = [];
          const _csHits = []; // Cobalt Strike indicators {ts, eid, host, category, detail, confidence}
          const _wmiSubHits = []; // WMI event subscription persistence (Sysmon 19/20/21)
          const _dcomHits = []; // native DCOM lateral execution (T1021.003)
          const _sshHits = []; // OpenSSH inbound access (T1021.004) + tunneling (T1572)

          // Scan loop — isolated so a single bad row doesn't kill all detectors
          try { for (const row of _scanRows) {
            const rawText = String(row._alltext || "");
            const text = rawText.toLowerCase();
            const eid = String(row._eid || "");
            const ts = row._ts || "";
            const host = _extractHost(row);
            const rid = row._rid != null ? Number(row._rid) : null; // source rowid for grid pill mapping
            // Telemetry coverage: count process/service/task/etc. events per host
            if (eid) {
              _bumpDatasetEvent(eid);
              if (host) _bumpHostTelemetry(_normLmHost(host), eid);
            }
            // WMI event subscription persistence (Sysmon 19 filter / 20 consumer / 21 binding).
            // FilterToConsumerBinding with a script/LOLBin consumer is a high-signal persistence +
            // lateral artifact. Known benign vendor/built-in consumers are suppressed ONLY when they
            // carry no script/LOLBin payload — a benign-NAMED consumer that still runs a script/LOLBin
            // is NOT suppressed (defeats name-spoofing evasion).
            // EIDs 19/20/21 are only WMI-subscription events on the Sysmon channel. They
            // collide with TerminalServices-LocalSessionManager 20/21 (session
            // reconnect / logon), so on a dataset with no channel column — where the
            // channel pre-filter is empty and every row reaches this loop — RDP session
            // events were being reported as "WMI Event Subscription". Require WMI-ish
            // corroboration in the row itself when the channel cannot vouch for it.
            const _wmiSubChannelOk = _scanChanCol
              ? true
              : /\b(wmi|wbem|consumer|filtertoconsumerbinding|eventfilter|__instancecreationevent|activescript|commandlineeventconsumer)\b/i.test(text);
            if (_wmiSubChannelOk && (eid === "19" || eid === "20" || eid === "21")) {
              const _wmiSubLol = /(powershell|pwsh|cmd\.exe|cmd\s+\/c|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|perl|python|ruby|\bbash\b|calc\.exe|schtasks|tasklist|netstat|ipconfig|whoami|systeminfo|net\s+(?:user|group|localgroup)|scrcons|activescripteventconsumer|commandlineeventconsumer|\.ps1|\.vbs|\.js\b|\.hta\b|\.bat\b|-enc|encodedcommand|\\temp\\|\\appdata\\|http)/i.test(text);
              // Known benign vendor / built-in WMI consumers (SCCM, BITS, Splunk, Defender, Dell, HP, VMware…)
              const _wmiSubBenign = /scm event(\s?log|\s?provider)?\s*consumer|bvtconsumer|wsceaa|raevent|tpvcgateway|forfilesconsumer|neteventconsumer|ccmeventconsumer|ccmexec|configmgr|sccm|bits.{0,20}(?:transfer|completion)|splunk|defender|\bsense\b|vmware|dell.{0,10}(?:idrac|openmanage|command)|hp.{0,10}(?:insight|proliant)|veeam|nsclient/i;
              if (!(_wmiSubBenign.test(text) && !_wmiSubLol)) {
                const _wmiCmdM = (row._alltext || "").match(/(?:Destination|CommandLineTemplate|ScriptText|ExecutablePath|CommandLine)\s*[:="]+\s*([^|"\n]{4,160})/i);
                const _wmiConsM = (row._alltext || "").match(/(?:Consumer|Name)\s*[:="]+\s*([^|"\n]{2,80})/i);
                const _wmiDetail = _wmiCmdM ? _wmiCmdM[1].trim()
                  : _wmiConsM ? `consumer ${_wmiConsM[1].trim()}`
                  : `WMI ${eid === "19" ? "filter" : eid === "20" ? "consumer" : "binding"} registered`;
                _wmiSubHits.push({ ts, eid, rid, host, detail: _wmiDetail, isConsumer: eid === "20", isBinding: eid === "21", isLol: _wmiSubLol });
              }
            }
            // Structured fields for directional detection (null if column absent)
            const _isServiceEvent = eid === "7045" || eid === "4697";
            const _imageRaw = _structColImage && row._image
              ? String(row._image).trim()
              : _isServiceEvent && row._exec_info
                ? String(row._exec_info).trim()
                : _extractLabeledValue(rawText, ["ServiceFileName", "Service File Name", "ImagePath", "Image Path", "BinaryPathName", "Binary Path Name", "ServiceBinaryPath"]);
            const _cmdRaw = _structColCmd && row._cmd
              ? String(row._cmd).trim()
              : _extractLabeledValue(rawText, ["CommandLine", "Command Line"]);
            const _svcRaw = _structColSvc && row._svc
              ? String(row._svc).trim()
              : _extractLabeledValue(rawText, _isServiceEvent ? ["ServiceName", "Service Name", "TargetServiceName", "Name"] : ["ServiceName", "Service Name", "TargetServiceName"]);
            const _serviceAccountRaw = _structColServiceAccount && row._service_account
              ? String(row._service_account).trim()
              : _isServiceEvent
                ? _extractLabeledValue(rawText, ["ServiceAccount", "Service Account", "AccountName", "Account"])
                : "";
            const _actorName = row._actor
              ? String(row._actor).trim()
              : _extractLabeledValue(rawText, ["SubjectUserName", "Subject User Name", "SubjectAccountName"]);
            const _actorDomain = row._actor_domain
              ? String(row._actor_domain).trim()
              : _extractLabeledValue(rawText, ["SubjectDomainName", "Subject Domain Name", "AccountDomain"]);
            const _actorCombined = _actorName && _actorDomain && _actorDomain !== "-" && !_actorName.includes("\\")
              ? `${_actorDomain}\\${_actorName}`
              : _actorName;
            const _actorRaw = /^(?:-|\\-|-\s*\\\s*-|n\/a|unknown)$/i.test(_actorCombined || "") ? "" : _actorCombined;
            const _image = _imageRaw ? _imageRaw.toLowerCase() : null;
            const _parent = row._parent ? row._parent.toString().toLowerCase() : null;
            const _cmd = _cmdRaw ? _cmdRaw.toLowerCase() : null;
            const _svc = _svcRaw ? _svcRaw.toLowerCase() : null;
            const _isCortexCollector = _isSanctionedCortexPayload(_image, _cmd, text);

            // --- Native PsExec (Sysinternals PSEXESVC) — checked first ---
            let isNativePsExec = false;
            // a) PSEXESVC service install (7045/4697) — destination-side
            if ((eid === "7045" || eid === "4697") && text.includes("psexesvc")) {
              _psexecNative.push({ ts, eid, rid, d: "PSEXESVC service installed", host, side: "dest" });
              isNativePsExec = true;
            }
            // b) PSEXESVC.exe process creation (4688/1) — destination-side
            if (!isNativePsExec && text.includes("psexesvc.exe")) {
              _psexecNative.push({ ts, eid, rid, d: "PSEXESVC.exe process execution", host, side: "dest" });
              isNativePsExec = true;
            }
            // c) psexec.exe / psexec64.exe source-side execution (4688/1)
            if (!isNativePsExec && (eid === "4688" || eid === "1") && (text.includes("psexec.exe") || text.includes("psexec64.exe"))) {
              _psexecNative.push({ ts, eid, rid, d: "psexec.exe process execution", host, side: "source" });
              isNativePsExec = true;
            }

            // --- Impacket pattern matching — confidence: strong/medium per pattern ---
            let isImpacket = false;
            if (!isNativePsExec) {
              // Source-side: python invoking Impacket scripts (strong)
              if (!isImpacket && (eid === "4688" || eid === "1") && text.includes("python")) {
                // Credential access tools → separate category
                if (/secretsdump\.py/.test(text)) {
                  _impCredAccess.push({ ts, eid, rid, host, side: "source", evidence: "python secretsdump.py execution" });
                  isImpacket = true;
                } else {
                  const _impScripts = [
                    { re: /psexec\.py/, v: "psexec.py" }, { re: /smbexec\.py/, v: "smbexec.py" },
                    { re: /wmiexec\.py/, v: "wmiexec.py" }, { re: /dcomexec\.py/, v: "dcomexec.py" },
                    { re: /atexec\.py/, v: "atexec.py" },
                  ];
                  for (const s of _impScripts) {
                    if (s.re.test(text)) {
                      _psexecImpacket.push({ v: s.v, ts, eid, rid, host, side: "source", confidence: "strong", evidence: `python ${s.v} execution on source` });
                      isImpacket = true; break;
                    }
                  }
                }
              }
              // 1. Generic Impacket: cmd.exe /Q /c ... \\127.0.0.1\ADMIN$ — confidence varies by refinement
              if (!isImpacket && text.includes("/q /c") && text.includes("\\\\127.0.0.1\\") && text.includes("admin$")) {
                let v = "Impacket", conf = "medium";
                if (text.includes("__output")) { v = "smbexec.py"; conf = "strong"; }
                else if (text.includes("wmiprvse")) { v = "wmiexec.py"; }
                else if (text.includes("mmc.exe") || text.includes("-embedding")) { v = "dcomexec.py"; }
                else if (text.includes("admin$\\__")) { v = "wmiexec.py"; }
                _psexecImpacket.push({ v, ts, eid, rid, host, side: "dest", confidence: conf, evidence: "cmd.exe /Q /c with ADMIN$ output redirect" }); isImpacket = true;
              }
              // 2. smbexec __output + redirect (strong)
              if (!isImpacket && text.includes("__output") && (text.includes("2^>^&1") || text.includes("2>&1"))) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, rid, host, side: "dest", confidence: "strong", evidence: "__output redirect pattern" }); isImpacket = true;
              }
              // 3. smbexec COMSPEC + triple .bat (medium)
              if (!isImpacket && text.includes("%comspec%") && (text.match(/\.bat/g) || []).length >= 3) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, rid, host, side: "dest", confidence: "medium", evidence: "%COMSPEC% batch execution chain" }); isImpacket = true;
              }
              // 4. wmiexec: wmiprvse.exe spawning cmd.exe /Q (medium)
              if (!isImpacket && text.includes("wmiprvse.exe") && text.includes("cmd.exe") && text.includes("/q")) {
                _psexecImpacket.push({ v: "wmiexec.py", ts, eid, rid, host, side: "dest", confidence: "medium", evidence: "wmiprvse.exe spawning cmd.exe /Q" }); isImpacket = true;
              }
              // 5. dcomexec: mmc.exe -Embedding ONLY with execution indicators
              // Bare mmc.exe -Embedding is normal Windows DCOM snap-in behavior (gpedit, diskmgmt, etc.)
              // Require cmd.exe /c or powershell follow-on to distinguish dcomexec.py from admin tools
              if (!isImpacket && text.includes("mmc.exe") && text.includes("-embedding") && (text.includes("cmd.exe") || text.includes("cmd /c") || text.includes("powershell") || text.includes("pwsh"))) {
                _psexecImpacket.push({ v: "dcomexec.py", ts, eid, rid, host, side: "dest", confidence: "medium", evidence: "MMC DCOM execution with command follow-on" }); isImpacket = true;
              }
              // 6. atexec: output to Windows\Temp\*.tmp + redirect (medium)
              if (!isImpacket && text.includes("\\temp\\") && /\\[a-z]{8}\.tmp/i.test(text) && text.includes("2>&1")) {
                _psexecImpacket.push({ v: "atexec.py", ts, eid, rid, host, side: "dest", confidence: "medium", evidence: "Temp .tmp output file with redirect" }); isImpacket = true;
              }
              // 7. atexec: hardcoded StartBoundary (strong)
              if (!isImpacket && text.includes("2015-07-15t20:35:13")) {
                _psexecImpacket.push({ v: "atexec.py", ts, eid, rid, host, side: "dest", confidence: "strong", evidence: "Hardcoded StartBoundary 2015-07-15T20:35:13" }); isImpacket = true;
              }
              // 8. psexec.py: RemCom named pipes (strong)
              if (!isImpacket && (text.includes("remcom_communicat") || text.includes("remcom_stdin") || text.includes("remcom_stdout") || text.includes("remcom_stderr"))) {
                _psexecImpacket.push({ v: "psexec.py", ts, eid, rid, host, side: "dest", confidence: "strong", evidence: "RemCom named pipe" }); isImpacket = true;
              }
              // 9. smbexec: BTOBTO service name (strong)
              if (!isImpacket && (eid === "7045" || eid === "4697") && text.includes("btobto")) {
                _psexecImpacket.push({ v: "smbexec.py", ts, eid, rid, host, side: "dest", confidence: "strong", evidence: 'Service name "BTOBTO"' }); isImpacket = true;
              }
            }

            // --- Remote Service Execution fallback (suspicious service installs without Impacket anchor) ---
            if (!isImpacket && !isNativePsExec && (eid === "7045" || eid === "4697")) {
              let suspicious = false;
              let reason = "";
              const _sigBlob = `${_image || ""} ${_cmd || ""} ${text}`;
              const _isMsExpectedSvc = _isExpectedMicrosoftBinary(_image || "", _sigBlob)
                || _isExpectedMicrosoftBinary(_cmd || "", _sigBlob)
                || _isExpectedMicrosoftBinary(text, _sigBlob);
              // a) Service binary using command interpreter
              const hasCmdBin = text.includes("cmd /c") || text.includes("cmd.exe /c") || text.includes("%comspec%") || ((text.includes("powershell") || text.includes("pwsh")) && (text.includes("-encodedcommand") || text.includes("-enc ") || /\s-e\s+[A-Za-z0-9+/=]{20,}/.test(text)));
              if (hasCmdBin) {
                suspicious = true;
                reason = "Service binary uses command interpreter";
              }
              // b) Service image in user-writable/temporary path
              if (!suspicious && /\\(?:users\\|appdata\\|temp\\|tmp\\|downloads\\|public\\|programdata\\)/i.test(text)) {
                suspicious = true;
                reason = "Service binary from user-writable path";
              }
              // c) LOLBin used directly as service image
              if (!suspicious && /\b(?:rundll32|regsvr32|mshta|wscript|cscript|powershell|pwsh|cmd\.exe|certutil|bitsadmin|msiexec)\b/i.test(text)) {
                suspicious = true;
                reason = "Service image uses LOLBin";
              }
              // d) Remote-admin-share / UNC service image path
              if (!suspicious && /\\\\[^\\]+\\(?:admin\$|c\$|[a-z]\$)\\[^|"\s]+/i.test(text)) {
                suspicious = true;
                reason = "Service image from remote admin share";
              }
              // e) Random short service name (4-8 alpha chars, not in COMMON_SVC)
              // Use structured ServiceName field when available; fall back to regex on blob
              if (!suspicious && !_isMsExpectedSvc) {
                let _svcName = null;
                if (_svc) {
                  // Structured ServiceName column — use directly
                  const svcTrim = _svc.trim();
                  if (/^[a-z]{4,8}$/i.test(svcTrim)) _svcName = svcTrim;
                } else {
                  // Blob fallback: match "ServiceName: xxx" or "Name: xxx" patterns from EvtxECmd
                  const snMatch = text.match(/\bservice\s*name[:\s]+([a-z]{4,8})\b/i) || text.match(/\bname[:\s]+([a-z]{4,8})\b/i);
                  if (snMatch) _svcName = snMatch[1];
                }
                if (_svcName && !COMMON_SVC.has(_svcName.toLowerCase())) {
                  // Additional FP guard: skip names that look like known vendor driver prefixes
                  const _sn = _svcName.toLowerCase();
                  const _knownPrefixes = /^(cyv[a-z]|ted[a-z]|tde[a-z]|mfe[a-z]|kl[a-z]{2}|sav[a-z]|hmp[a-z]|avg[a-z]|bdl[a-z]|epa[a-z])/;
                  if (!_knownPrefixes.test(_sn)) {
                    suspicious = true;
                    reason = `Random ${_svcName.length}-char service name: ${_svcName}`;
                  }
                }
              }
              if (suspicious) {
                _remoteSvcExec.push({
                  ts, eid, rid, d: reason, host, side: "dest",
                  serviceName: _svcRaw,
                  imagePath: _imageRaw,
                  commandLine: _cmdRaw || _imageRaw,
                  eventActor: _actorRaw,
                  serviceAccount: _serviceAccountRaw,
                });
              }
            }

            // --- Native DCOM lateral execution (T1021.003) ---
            // A DCOM server process (mmc / Office / dllhost) spawning a shell/LOLBin child, where the
            // server was DCOM-activated (-Embedding flag or a {CLSID}). Covers MMC20.Application and
            // Excel/Outlook/Word/Access COM ExecuteShellCommand. The -Embedding/CLSID guard separates
            // DCOM activation from a local Office macro.
            // LIMITATION: ShellWindows / ShellBrowserWindow DCOM is intentionally NOT detected here.
            // Those objects reuse the live user explorer.exe (no -Embedding/CLSID on the child event),
            // so a process-event parent-child rule on explorer.exe would be high-FP; that vector must be
            // caught via auth (Type-3 logon) correlation, not the process scan.
            if (!isNativePsExec && !isImpacket && (eid === "4688" || eid === "1")) {
              const _dcomServers = ["mmc.exe", "excel.exe", "outlook.exe", "winword.exe", "powerpnt.exe", "visio.exe", "msaccess.exe", "dllhost.exe"];
              const _dcomChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "cscript.exe", "wscript.exe", "certutil.exe", "bitsadmin.exe"];
              const _dcomActivated = text.includes("-embedding") || /\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}/i.test(text);
              // Explicit shell-execution pattern — required for dllhost.exe (a legitimate COM surrogate
              // that hosts many benign objects) and for ALL blob-fallback matches (lower confidence),
              // so the detector fires on actual command execution rather than mere COM activation.
              const _dcomExecPat = /(?:\bcmd(?:\.exe)?\s+\/[ck]\b|%comspec%|-enc\b|-encodedcommand\b|-e\s+[A-Za-z0-9+/=]{16,}|-c(?:ommand)?\s|\biex\b|downloadstring|invoke-expression|frombase64string|\/c\s|\/k\s)/i;
              if (_dcomActivated) {
                if (_hasStructuredProcCols && _parent && _image) {
                  const parentBin = _parent.split("\\").pop();
                  const imageBin = _image.split("\\").pop();
                  // dllhost.exe is a COM surrogate for many legitimate objects — require an explicit
                  // shell-exec pattern; mmc/Office spawning ANY shell is already abnormal enough.
                  if (_dcomServers.includes(parentBin) && _dcomChildBins.includes(imageBin)
                      && (parentBin !== "dllhost.exe" || _dcomExecPat.test(text))) {
                    _dcomHits.push({ ts, eid, rid, d: `${parentBin} (DCOM) → ${imageBin}`, host, side: "dest" });
                  }
                } else {
                  // Blob fallback (no structured parent/image): require server + child AND an explicit
                  // execution pattern co-present, to avoid mis-pairing unrelated names in verbose rows.
                  const srv = _dcomServers.find(s => text.includes(s));
                  const child = _dcomChildBins.find(c => text.includes(c));
                  if (srv && child && srv !== child && _dcomExecPat.test(text)) {
                    _dcomHits.push({ ts, eid, rid, d: `${srv} (DCOM) → ${child} (blob)`, host, side: "dest" });
                  }
                }
              }
            }

            // --- OpenSSH on Windows: inbound access (T1021.004) + tunneling (T1572) ---
            // (a) sshd service install = an SSH server stood up (often attacker persistence/access).
            if ((eid === "7045" || eid === "4697") && (text.includes("openssh") || /\bsshd(\.exe)?\b/i.test(text))) {
              _sshHits.push({ ts, eid, rid, host, side: "dest", category: "sshd_install", d: "OpenSSH sshd service installed (inbound SSH server)" });
            }
            if (eid === "4688" || eid === "1") {
              // Only treat these as binary names when they really are parent/image
              // columns; otherwise leave them null so the blob fallback below can run.
              const _sshParentBin = (_hasStructuredProcCols && _parent) ? _parent.split("\\").pop() : null;
              const _sshImageBin = (_hasStructuredProcCols && _image) ? _image.split("\\").pop() : null;
              const _sshChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "wsl.exe"];
              // (b) sshd.exe spawning a shell = inbound remote command execution over SSH.
              if (_sshParentBin === "sshd.exe" && _sshImageBin && _sshChildBins.includes(_sshImageBin)) {
                _sshHits.push({ ts, eid, rid, host, side: "dest", category: "sshd_shell", d: `sshd.exe → ${_sshImageBin} (inbound SSH command execution)` });
              } else if (!_sshParentBin && text.includes("sshd.exe") && (text.includes("cmd.exe") || text.includes("powershell"))) {
                _sshHits.push({ ts, eid, rid, host, side: "dest", category: "sshd_shell", d: "sshd.exe spawning a shell (blob)" });
              }
              // (c) ssh/plink/scp port forwarding = tunneling (T1572). Classify the forward direction:
              //   -R (remote forward) / -D (dynamic SOCKS proxy) = pivot/exposure → high
              //   -L (local forward)                              = common dev/admin use → medium
              // Keyword forms (localforward/remoteforward/dynamicforward) also catch `-o LocalForward=…`
              // and `-oLocalForward=…`. (Config-file-only forwards aren't visible unless the directive
              // appears in the logged command line — an accepted event-logging limitation.)
              const _sshClients = ["ssh.exe", "plink.exe", "scp.exe", "sftp.exe", "pscp.exe", "psftp.exe"];
              const _sshCmdText = _cmd || text;
              const _sshFwd = (txt) => {
                if (/(^|\s)-R\s*\d|remoteforward/i.test(txt)) return "R";
                if (/(^|\s)-D\s*\d|dynamicforward/i.test(txt)) return "D";
                if (/(^|\s)-L\s*\d|localforward/i.test(txt)) return "L";
                return null;
              };
              if (_sshImageBin && _sshClients.includes(_sshImageBin)) {
                const fwd = _sshFwd(_sshCmdText);
                if (fwd) _sshHits.push({ ts, eid, rid, host, side: "source", category: "ssh_tunnel", fwd, d: `${_sshImageBin} ${fwd === "R" ? "reverse" : fwd === "D" ? "dynamic SOCKS" : "local"} port forward` });
              } else if (!_sshImageBin && (text.includes("plink.exe") || text.includes("ssh.exe"))) {
                const fwd = _sshFwd(text);
                if (fwd) _sshHits.push({ ts, eid, rid, host, side: "source", category: "ssh_tunnel", fwd, d: "ssh/plink port forwarding / tunnel (blob)" });
              }
            }

            // --- WMI detection (exec flag separates execution from query/activity) ---
            if (!isNativePsExec && !isImpacket && (eid === "4688" || eid === "1")) {
              // Destination-side: wmiprvse.exe spawning shell/LOLBin — requires directional parent-child evidence
              const _wmiChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe", "cscript.exe", "wscript.exe"];
              if (text.includes("wmiprvse.exe")) {
                if (_hasStructuredProcCols && _parent && _image) {
                  // Structured fields: require ParentImage = wmiprvse.exe, Image = child binary
                  const parentBin = _parent.split("\\").pop();
                  const imageBin = _image.split("\\").pop();
                  if (parentBin === "wmiprvse.exe") {
                    for (const child of _wmiChildBins) {
                      if (imageBin === child) {
                        _wmiHits.push({ ts, eid, rid, d: `wmiprvse.exe \u2192 ${child}`, host, side: "dest", exec: true, _blob: false });
                        break;
                      }
                    }
                  }
                  // else: wmiprvse.exe is the Image (process itself), not parent — not a WMI exec spawn
                } else {
                  // Blob fallback: no structured columns — lower confidence, require stronger co-occurrence
                  if (text.includes("cmd.exe") && (text.includes("/q") || text.includes("/c "))) {
                    _wmiHits.push({ ts, eid, rid, d: "wmiprvse.exe + cmd.exe /c (blob match)", host, side: "dest", exec: true, _blob: true });
                  } else if ((text.includes("powershell") || text.includes("pwsh")) && (text.includes("-c ") || text.includes("-command") || text.includes("-enc"))) {
                    _wmiHits.push({ ts, eid, rid, d: "wmiprvse.exe + powershell (blob match)", host, side: "dest", exec: true, _blob: true });
                  }
                }
              }
              // Source-side: wmic.exe /node:TARGET — exec only if explicit process creation
              else if ((text.includes("wmic.exe") || text.includes("wmic ")) && text.includes("/node:")) {
                const nodeMatch = text.match(/\/node:\s*"?([^\s"]+)"?/i);
                const remoteTarget = nodeMatch ? nodeMatch[1] : null;
                const isWmicExec = text.includes("process call create") || text.includes("win32_process.create");
                _wmiHits.push({ ts, eid, rid, d: `wmic.exe /node:${remoteTarget || "?"}${isWmicExec ? " (process create)" : ""}`, host, side: "source", remoteTarget, exec: isWmicExec });
              }
              // Source-side: PowerShell WMI/CIM methods — split exec vs query
              else {
                // Execution primitives: invoke methods, process creation
                const _wmiExec = ["invoke-wmimethod", "invoke-cimmethod", "win32_process.create"];
                // Query/session primitives: remote access but not execution
                const _wmiQuery = ["get-wmiobject", "gwmi ", "[wmiclass]", "get-ciminstance", "new-cimsession"];
                let matched = false;
                for (const m of _wmiExec) {
                  if (text.includes(m)) {
                    const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                    const remoteTarget = cnMatch ? cnMatch[1] : null;
                    _wmiHits.push({ ts, eid, rid, d: `PowerShell WMI/CIM: ${m.trim()}${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
                    matched = true; break;
                  }
                }
                if (!matched) {
                  for (const m of _wmiQuery) {
                    if (text.includes(m)) {
                      const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                      const remoteTarget = cnMatch ? cnMatch[1] : null;
                      // Only emit query hits with an explicit remote target — local queries are not lateral movement
                      if (remoteTarget) {
                        _wmiHits.push({ ts, eid, rid, d: `PowerShell WMI/CIM: ${m.trim()} → ${remoteTarget}`, host, side: "source", remoteTarget, exec: false });
                      }
                      break;
                    }
                  }
                }
              }
            }

            // --- WinRM detection (exec flag separates execution from session/activity) ---
            if (!isNativePsExec && !isImpacket && (eid === "4688" || eid === "1")) {
              // Destination-side: wsmprovhost.exe — requires directional parent-child evidence
              if (text.includes("wsmprovhost.exe")) {
                const _winrmChildBins = ["cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe", "net1.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe"];
                let childDesc = null;
                if (_hasStructuredProcCols && _parent && _image) {
                  // Structured fields: require ParentImage = wsmprovhost.exe, Image = child
                  const parentBin = _parent.split("\\").pop();
                  const imageBin = _image.split("\\").pop();
                  if (parentBin === "wsmprovhost.exe") {
                    for (const child of _winrmChildBins) {
                      if (imageBin === child) { childDesc = child; break; }
                    }
                    _winrmHits.push({ ts, eid, rid, d: childDesc ? `wsmprovhost.exe \u2192 ${childDesc}` : "wsmprovhost.exe process execution", host, side: "dest", hasChild: !!childDesc, exec: !!childDesc, _blob: false });
                  }
                  // else: wsmprovhost.exe is Image, not parent — skip
                } else {
                  // Blob fallback: lower confidence co-occurrence
                  for (const child of _winrmChildBins) {
                    if (text.includes(child)) { childDesc = child; break; }
                  }
                  if (childDesc) {
                    _winrmHits.push({ ts, eid, rid, d: `wsmprovhost.exe + ${childDesc} (blob match)`, host, side: "dest", hasChild: true, exec: true, _blob: true });
                  }
                }
              }
              // Source-side: winrs.exe — execution (runs commands remotely)
              else if (text.includes("winrs.exe")) {
                const rMatch = text.match(/\/r:\s*([^\s]+)/i) || text.match(/-r:\s*([^\s]+)/i);
                const remoteTarget = rMatch ? rMatch[1] : null;
                _winrmHits.push({ ts, eid, rid, d: `winrs.exe remote shell${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
              }
              // Source-side: PowerShell remoting — Invoke-Command is exec, session setup is activity
              else {
                if (text.includes("invoke-command")) {
                  const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                  const remoteTarget = cnMatch ? cnMatch[1] : null;
                  _winrmHits.push({ ts, eid, rid, d: `PowerShell remoting: Invoke-Command${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: true });
                } else {
                  const _psSession = ["enter-pssession", "new-pssession"];
                  for (const c of _psSession) {
                    if (text.includes(c)) {
                      const cnMatch = text.match(/-computername\s+["']?([^\s"',;]+)/i);
                      const remoteTarget = cnMatch ? cnMatch[1] : null;
                      _winrmHits.push({ ts, eid, rid, d: `PowerShell remoting: ${c}${remoteTarget ? ` → ${remoteTarget}` : ""}`, host, side: "source", remoteTarget, exec: false });
                      break;
                    }
                  }
                }
              }
            }

            // --- RMM structured matching (exe name, service name, command line) ---
            {
              if (_isCortexCollector) {
                // Cortex XDR payload / offline collector is sanctioned security tooling, not RMM.
              } else {
              let _rmmMatch = null;
              let _rmmKind = null; // install | process | service | cmdline
              // 1. Executable name match (most precise)
              if (_image) {
                const basename = _image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image.includes("/") ? _image.substring(_image.lastIndexOf("/") + 1) : _image;
                if (_rmmByExe.has(basename)) {
                  _rmmMatch = _rmmByExe.get(basename);
                  _rmmKind = (eid === "7045" || eid === "4697") ? "install" : "process";
                }
              }
              // 2. Service name match on 7045/4697 — exact match after trim
              if (!_rmmMatch && _svc && (eid === "7045" || eid === "4697")) {
                const svcNorm = _svc.trim();
                if (_rmmBySvc.has(svcNorm)) { _rmmMatch = _rmmBySvc.get(svcNorm); _rmmKind = "install"; }
              }
              // 3. ImagePath in service install — check _alltext for exe names on 7045/4697
              if (!_rmmMatch && (eid === "7045" || eid === "4697")) {
                for (const [exeName, tool] of _rmmByExe) {
                  if (text.includes(exeName)) { _rmmMatch = tool; _rmmKind = "service"; break; }
                }
              }
              // 4. Command-line invocation (process events only)
              if (!_rmmMatch && _cmd && (eid === "4688" || eid === "1")) {
                for (const [exeName, tool] of _rmmByExe) {
                  if (_cmd.includes(exeName)) { _rmmMatch = tool; _rmmKind = "cmdline"; break; }
                }
              }
              if (_rmmMatch) {
                const parentBasename = _parent ? (_parent.includes("\\") ? _parent.substring(_parent.lastIndexOf("\\") + 1) : _parent) : null;
                _rmmHits.push({
                  tool: _rmmMatch.name, toolType: _rmmMatch.type,
                  host: host || "", ts, eid, kind: _rmmKind,
                  image: _image || "", parent: parentBasename || "",
                  cmd: (_cmd || "").substring(0, 300),
                  imagePath: _image || "",
                });
              }
              }
            }

            // --- Scheduled Task Remote Execution (4698) ---
            if (eid === "4698") {
              if (_isCortexCollector) continue;
              // Parse task content from the event text for suspicious actions
              const _suspBins = ["cmd.exe", "cmd /c", "cmd.exe /c", "%comspec%", "powershell", "pwsh", "rundll32", "mshta", "regsvr32", "cscript", "wscript", "certutil", "bitsadmin", "msiexec"];
              const _suspPaths = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\public\\", "admin$", "\\perflogs\\", "\\programdata\\"];
              let taskAction = null;
              let taskName = null;
              let isSuspicious = false;
              let reason = "";
              // Extract task name: <URI> or TaskName: patterns
              const tnMatch = text.match(/<uri>\s*([^<]+)/i) || text.match(/taskname[:\s]+\\?([^\s|<]+)/i) || text.match(/\\([^\s\\|<]+)\s*$/m);
              if (tnMatch) taskName = tnMatch[1].replace(/^\\+/, "").trim();
              // Extract action/command from XML or flat text
              const actMatch = text.match(/<command>\s*([^<]+)/i) || text.match(/<exec>\s*([^<]+)/i) || text.match(/<arguments>\s*([^<]+)/i);
              if (actMatch) taskAction = actMatch[1].trim();
              // Check for suspicious binaries in action or full text
              for (const bin of _suspBins) {
                if (text.includes(bin)) { isSuspicious = true; reason = `Task action contains ${bin}`; break; }
              }
              // Check for suspicious paths
              if (!isSuspicious) {
                for (const sp of _suspPaths) {
                  if (text.includes(sp)) { isSuspicious = true; reason = `Task references suspicious path: ${sp.replace(/\\/g, "")}`; break; }
                }
              }
              // Check for encoded command / base64 patterns
              if (!isSuspicious) {
                const hasPsCtx = text.includes("powershell") || text.includes("pwsh");
                if (text.includes("-encodedcommand") || text.includes("-enc ") || (hasPsCtx && /\s-e\s+[A-Za-z0-9+/=]{20,}/.test(text))) {
                  isSuspicious = true; reason = "Task uses encoded PowerShell command";
                }
              }
              // Check for atexec.py signature (hardcoded StartBoundary or temp output redirect)
              if (!isSuspicious && (text.includes("2015-07-15t20:35:13") || (text.includes("\\temp\\") && text.includes("2>&1")))) {
                isSuspicious = true; reason = "atexec.py task signature";
              }
              // Check for very short/random task names (4-8 alpha chars, not common words)
              if (!isSuspicious && taskName) {
                const shortName = taskName.replace(/^.*\\/, "");
                if (/^[a-z]{4,8}$/i.test(shortName) && !COMMON_SVC.has(shortName.toLowerCase())) {
                  isSuspicious = true; reason = `Random task name: ${shortName}`;
                }
              }
              // FP controls: skip known enterprise management task patterns
              const _mgmtTaskPat = /^(microsoft|windows|google|adobe|mozilla|intel|dell|hp|lenovo|vmware|citrix|sophos|symantec|mcafee|crowdstrike|carbon|sentinel|defender|sccm|configmgr|intune|wsus|omsconfig|gathernetwork|user_feed|automate|patchmypc|nessus|qualys|rapid7|tenable)/i;
              if (isSuspicious && taskName && _mgmtTaskPat.test(taskName.replace(/^.*\\/, ""))) {
                isSuspicious = false; // known vendor/management task
              }
              // Additional FP control: Microsoft OneDrive/SharePoint/Office task action from expected path+binary.
              const _msTaskNamePat = /(?:onedrive|sharepoint|groove|office|microsoft)/i;
              const _msExpectedTaskAction = _isExpectedMicrosoftBinary(taskAction || "") || _isExpectedMicrosoftBinary(text);
              if (isSuspicious && _msExpectedTaskAction && (!taskName || _msTaskNamePat.test(taskName))) {
                isSuspicious = false;
              }
              if (isSuspicious) {
                _schedTaskHits.push({
                  ts, eid, host, side: "dest",
                  d: reason + (taskName ? ` (task: ${taskName})` : "") + (taskAction ? ` [${taskAction.slice(0, 80)}]` : ""),
                  taskName: taskName || "(unnamed)", taskAction,
                });
              }
            }

            // --- Source-side schtasks.exe with /create /s (4688/1) ---
            if ((eid === "4688" || eid === "1") && text.includes("schtasks") && text.includes("/create") && text.includes("/s ")) {
              if (_isCortexCollector) continue;
              const targetMatch = text.match(/\/s\s+["']?([^\s"',;]+)/i);
              const remoteTarget = targetMatch ? targetMatch[1] : null;
              if (remoteTarget && remoteTarget !== "localhost" && remoteTarget !== "127.0.0.1") {
                _schedTaskHits.push({
                  ts, eid, host, side: "source", remoteTarget,
                  d: `schtasks /create /s ${remoteTarget}`,
                  taskName: null, taskAction: null,
                });
              }
            }

            // === Cobalt Strike Detection (T1055 / T1569.002 / T1059.001) ===
            {
              // --- A) Named Pipe detection (Sysmon EID 17/18) ---
              // Default CS pipes: postex_*, MSSE-*-server, msagent_*, status_*, *-server
              if (eid === "17" || eid === "18") {
                const pipeField = text;
                // Default Cobalt Strike named pipes
                const _csPipePatterns = [
                  { re: /\\postex_/i, name: "postex_*", confidence: "high" },
                  { re: /\\postex_ssh_/i, name: "postex_ssh_*", confidence: "high" },
                  { re: /\\msagent_/i, name: "msagent_*", confidence: "high" },
                  { re: /\\MSSE-[0-9a-f]+-server/i, name: "MSSE-*-server", confidence: "high" },
                  { re: /\\status_[0-9a-f]+/i, name: "status_*", confidence: "medium" },
                  // CS 4.2+ default: random hex pipe names — match the {hex}-server pattern
                  { re: /\\[0-9a-f]{7,8}-server/i, name: "hex-server", confidence: "medium" },
                ];
                for (const p of _csPipePatterns) {
                  if (p.re.test(pipeField)) {
                    _csHits.push({ ts, eid, rid, host, category: "named_pipe", detail: `Named pipe: ${p.name}`, confidence: p.confidence });
                    break;
                  }
                }
              }

              // --- B) GetSystem service pattern (7045/4697) ---
              // CS GetSystem creates a service that echoes a token to a named pipe:
              // cmd.exe /c echo XXXX > \\.\pipe\XXXX
              if ((eid === "7045" || eid === "4697") && /\\\\.\\pipe\\/i.test(text) && (text.includes("cmd") || text.includes("%comspec%")) && text.includes("echo")) {
                _csHits.push({ ts, eid, rid, host, category: "getsystem", detail: "GetSystem: service with cmd.exe echo to named pipe", confidence: "high" });
              }

              // --- C) Default spawn-to abuse (4688/1) ---
              // CS default spawn-to: rundll32.exe with no arguments, or dllhost.exe with no arguments
              // These are process hollowing targets
              if ((eid === "4688" || eid === "1") && _image && _cmd) {
                const imageBin = _image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image;
                const cmdTrimmed = _cmd.trim().replace(/^"[^"]*"/, "").trim();
                const isDefaultSpawnTo = (imageBin === "rundll32.exe" || imageBin === "dllhost.exe");
                // No arguments = process hollowing container (CS injects beacon into it)
                if (isDefaultSpawnTo && cmdTrimmed.length === 0) {
                  // Verify it's not a normal rundll32/dllhost invocation by checking parent
                  const parentBin = _parent ? (_parent.includes("\\") ? _parent.substring(_parent.lastIndexOf("\\") + 1) : _parent) : null;
                  // Normal parents for rundll32/dllhost: svchost.exe, services.exe, explorer.exe
                  const _normalSpawnParents = new Set(["svchost.exe", "services.exe", "explorer.exe", "taskeng.exe", "taskhostw.exe", "dllhost.exe", "sihost.exe", "runtimebroker.exe"]);
                  if (!parentBin || !_normalSpawnParents.has(parentBin)) {
                    _csHits.push({ ts, eid, rid, host, category: "spawn_to", detail: `${imageBin} launched with no arguments${parentBin ? ` (parent: ${parentBin})` : ""}`, confidence: "medium" });
                  }
                }
              }

              // --- D) CreateRemoteThread into LSASS or suspicious targets (Sysmon EID 8) ---
              if (eid === "8") {
                const isLsass = text.includes("lsass.exe");
                const isRuntimeBroker = text.includes("runtimebroker.exe");
                if (isLsass) {
                  _csHits.push({ ts, eid, rid, host, category: "injection", detail: "CreateRemoteThread into lsass.exe (credential theft)", confidence: "high" });
                } else if (isRuntimeBroker) {
                  _csHits.push({ ts, eid, rid, host, category: "injection", detail: "CreateRemoteThread into RuntimeBroker.exe", confidence: "medium" });
                }
              }

              // --- E) Encoded PowerShell beacon stager (4688/1) ---
              if ((eid === "4688" || eid === "1") && (text.includes("powershell") || text.includes("pwsh"))) {
                const hasEnc = text.includes("-encodedcommand") || text.includes("-enc ") || /\s-e\s+[A-Za-z0-9+/=]{40,}/.test(text) || /\s-ec\s+[A-Za-z0-9+/=]{40,}/.test(text);
                if (hasEnc) {
                  // Check for shellcode / download cradle indicators in the encoded payload
                  const hasShellcode = /frombase64string|virtualalloc|kernel32|memcpy|createthread|iex\s*\(|downloadstring|downloaddata|downloadfile|invoke-expression|net\.webclient|bitstransfer|start-bitstransfer/i.test(text);
                  const hasLongPayload = /[A-Za-z0-9+/=]{200,}/.test(text);
                  if (hasShellcode || hasLongPayload) {
                    _csHits.push({ ts, eid, rid, host, category: "beacon_stager", detail: `Encoded PowerShell${hasShellcode ? " with shellcode/download cradle" : " with large payload"}`, confidence: hasShellcode ? "high" : "medium" });
                  }
                }
              }

              // --- F) CS service install pattern: %COMSPEC% /b /c start /b /min ... (7045/4697) ---
              if ((eid === "7045" || eid === "4697") && text.includes("%comspec%") && text.includes("/b") && text.includes("start")) {
                _csHits.push({ ts, eid, rid, host, category: "service_beacon", detail: "Service with %COMSPEC% /b /c start pattern (CS lateral move)", confidence: "high" });
              }

              // --- G) PowerShell download cradle without encoding (4688/1) ---
              if ((eid === "4688" || eid === "1") && (text.includes("powershell") || text.includes("pwsh"))) {
                if (!text.includes("-encodedcommand") && !text.includes("-enc ")) {
                  const hasCradle = /iex\s*\(\s*\(?new-object\s+(?:net\.webclient|system\.net\.webclient)\)?\s*\.download(?:string|data|file)/i.test(text)
                    || /invoke-expression.*download/i.test(text)
                    || /\[system\.reflection\.assembly\]::load/i.test(text);
                  if (hasCradle) {
                    _csHits.push({ ts, eid, rid, host, category: "beacon_stager", detail: "PowerShell download cradle (IEX/WebClient/Reflection)", confidence: "high" });
                  }
                }
              }
            }

            // --- Sysmon EID 10: OpenProcess on lsass.exe (T1003.001) ---
            // Direct handle open to LSASS is a strong credential-theft indicator.
            // Legitimate callers (AV, Windows Defender, WerFault) are filtered out.
            if (eid === "10" && text.includes("lsass.exe")) {
              // FP control: skip known legitimate callers
              const _lsassLegit = /svchost\.exe|csrss\.exe|smss\.exe|wininit\.exe|services\.exe|lsm\.exe|mrt\.exe|taskmgr\.exe|procexp|procmon|wmiprvse\.exe|werfault\.exe|msmpeng\.exe|nissrv\.exe|mssense\.exe|securityhealthservice|crowdstrike|falcon|cb\.exe|carbonblack|cylance|sentinel|mdatp|defender/i;
              const callerIsLegit = _lsassLegit.test(text);
              if (!callerIsLegit) {
                // Check access mask: 0x1010 (PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ) or
                // 0x1fffff (PROCESS_ALL_ACCESS) are the suspicious ones
                const accessMatch = text.match(/(?:granted\s*access|accessmask)[:\s]+(0x[0-9a-f]+)/i);
                const access = accessMatch ? parseInt(accessMatch[1], 16) : 0;
                // Credential-dump signal is VM_READ (0x10) or PROCESS_ALL_ACCESS.
                // 0x1000 is PROCESS_QUERY_LIMITED_INFORMATION — Task Manager / inventory, not a dump.
                // Unparseable masks still flag (Mimikatz-style dumps often omit the field).
                const isSuspAccess = access === 0 || access === 0x1fffff || (access & 0x0010) !== 0;
                if (isSuspAccess) {
                  const caller = (_image || "").split("\\").pop() || "(unknown)";
                  _lsassAccessHits.push({ ts, eid, rid, host, side: "dest", d: `${caller} opened lsass.exe (access: ${accessMatch ? accessMatch[1] : "unknown"})`, caller });
                }
              }
            }

            // --- Credential theft commands (4688/1): reg save, netsh portproxy ---
            if (eid === "4688" || eid === "1") {
              // reg save HKLM\SAM or HKLM\SECURITY — SAM/LSA credential dump (T1003.002)
              if (/reg\s+save\s+hklm\\(sam|security|system)\b/i.test(text)) {
                const target = text.match(/hklm\\(sam|security|system)/i)?.[1]?.toUpperCase() || "SAM";
                _credTheftCmdHits.push({ ts, eid, rid, host, side: "dest", d: `reg save HKLM\\${target}`, category: "reg_save", target });
              }
              // netsh interface portproxy — port forwarding for lateral movement (T1090.001)
              if (/netsh\s+interface\s+portproxy/i.test(text)) {
                _credTheftCmdHits.push({ ts, eid, rid, host, side: "dest", d: `netsh portproxy: ${text.slice(0, 120)}`, category: "portproxy" });
              }
            }

          } } catch (_scanLoopErr) { warnings.push(`Scan loop error: ${_scanLoopErr.message}`); console.error("LM scan loop error:", _scanLoopErr); }

          // === Cobalt Strike Discovery Burst Detection ===
          // Detect rapid enumeration commands (net group, nltest, whoami, etc.) within 2-min windows
          // CS aggressor scripts run automated discovery on initial beacon
          try {
            const _discoveryBins = new Set(["whoami.exe", "net.exe", "net1.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "qprocess.exe", "qwinsta.exe", "klist.exe", "cmdkey.exe", "nslookup.exe"]);
            const _discoveryKw = ["net group", "net localgroup", "net user", "net view", "net session", "nltest /domain_trusts", "nltest /dclist", "whoami /priv", "whoami /groups", "whoami /all", "arp -a", "route print", "netstat -an"];
            const _discoveryHits = [];
            for (const row of _scanRows) {
              const eid = String(row._eid || "");
              if (eid !== "4688" && eid !== "1") continue;
              const text = (row._alltext || "").toLowerCase();
              const _image = row._image ? row._image.toString().toLowerCase() : null;
              const imageBin = _image ? (_image.includes("\\") ? _image.substring(_image.lastIndexOf("\\") + 1) : _image) : null;
              let isDiscovery = false;
              if (imageBin && _discoveryBins.has(imageBin)) isDiscovery = true;
              if (!isDiscovery) {
                for (const kw of _discoveryKw) { if (text.includes(kw)) { isDiscovery = true; break; } }
              }
              if (isDiscovery) {
                _discoveryHits.push({ ts: row._ts || "", host: (row._host || "").toString().trim().toUpperCase(), cmd: imageBin || text.substring(0, 80) });
              }
            }
            // Group by host, check for burst (5+ commands in 2 min)
            if (_discoveryHits.length > 0) {
              const _discByHost = new Map();
              for (const h of _discoveryHits) {
                if (!_discByHost.has(h.host)) _discByHost.set(h.host, []);
                _discByHost.get(h.host).push(h);
              }
              for (const [host, hits] of _discByHost) {
                hits.sort((a, b) => cmpTs(a.ts, b.ts));
                // Sliding window: 5+ hits in 2 min
                for (let i = 0; i <= hits.length - 5; i++) {
                  const t0 = tsMs(hits[i].ts);
                  const t4 = tsMs(hits[i + 4].ts);
                  if (t0 != null && t4 != null && (t4 - t0) <= 120000) {
                    // Find full burst extent
                    let burstEnd = i + 4;
                    for (let j = burstEnd + 1; j < hits.length; j++) {
                      const tj = tsMs(hits[j].ts);
                      if (tj != null && (tj - t0) <= 120000) burstEnd = j;
                      else break;
                    }
                    const burstHits = hits.slice(i, burstEnd + 1);
                    const cmds = [...new Set(burstHits.map(h => h.cmd))];
                    // FP guard: a discovery burst is multiple DISTINCT enumeration commands.
                    // 5x the same command (batch jobs, inventory/monitoring agents) is not discovery.
                    // Keep sliding the window to look for a qualifying multi-command burst.
                    if (cmds.length < 3) continue;
                    _csHits.push({
                      ts: hits[i].ts, eid: "4688", host,
                      category: "discovery_burst",
                      detail: `${burstHits.length} enumeration commands in <2 min: ${cmds.slice(0, 8).join(", ")}${cmds.length > 8 ? ` +${cmds.length - 8} more` : ""}`,
                      confidence: cmds.length >= 8 ? "high" : "medium",
                      _burstCount: burstHits.length, _burstCmds: cmds,
                    });
                    break; // one burst finding per host
                  }
                }
              }
            }
          } catch (_discErr) { warnings.push(`Discovery burst detection failed: ${_discErr.message}`); }

          // === Cobalt Strike: Pass the Hash detection (Logon Type 9 = NewCredentials) ===
          // Type 9 is used by runas /netonly and CS pth command — rare in normal operations
          try {
            for (const evt of timeOrdered) {
              if (evt.eventId !== "4624" || evt.logonType !== "9") continue;
              // Skip SYSTEM/service accounts — Type 9 from SYSTEM is common for scheduled tasks
              const u = (evt.user || "").toUpperCase();
              if (u === "SYSTEM" || u === "LOCAL SERVICE" || u === "NETWORK SERVICE" || u.endsWith("$")) continue;
              _csHits.push({
                ts: evt.ts, eid: "4624", host: (evt.target || "").toUpperCase(),
                category: "pass_the_hash",
                detail: `Type 9 (NewCredentials) logon: ${evt.user || "(unknown)"} from ${(evt.source || "local").toUpperCase()}`,
                confidence: "medium",
              });
            }
          } catch (_pthErr) { warnings.push(`Pass the Hash detection failed: ${_pthErr.message}`); }

          // === Emit Cobalt Strike findings ===
          try { if (_csHits.length > 0 && !_disabledSet.has("cobaltstrike")) {
            // Group by host, then by category
            const _csByHost = new Map();
            for (const h of _csHits) {
              const hk = h.host || "(unknown)";
              if (!_csByHost.has(hk)) _csByHost.set(hk, []);
              _csByHost.get(hk).push(h);
            }
            for (const [host, hostHits] of _csByHost) {
              // Group by category
              const _csByCat = new Map();
              for (const h of hostHits) {
                if (!_csByCat.has(h.category)) _csByCat.set(h.category, []);
                _csByCat.get(h.category).push(h);
              }
              const categories = [..._csByCat.keys()];
              const highConfCount = hostHits.filter(h => h.confidence === "high").length;
              const totalIndicators = hostHits.length;
              const uniqueCategories = categories.length;

              // Composite confidence: multiple categories or high-confidence hits = stronger signal
              // Single medium-confidence hit in isolation = suppress (too FP-prone)
              if (totalIndicators === 1 && hostHits[0].confidence === "medium") continue;

              let severity;
              if (uniqueCategories >= 4 || (uniqueCategories >= 3 && highConfCount >= 2)) severity = "critical";
              else if (uniqueCategories >= 3 || highConfCount >= 2) severity = "high";
              else if (uniqueCategories >= 2 || highConfCount >= 1) severity = "high";
              else severity = "medium";

              const allTs = hostHits.map(h => h.ts).filter(Boolean).sort();
              const pills = [];
              const _csCatLabels = {
                named_pipe: "CS named pipe",
                getsystem: "GetSystem",
                spawn_to: "spawn-to hollowing",
                injection: "process injection",
                beacon_stager: "beacon stager",
                service_beacon: "service-based beacon",
                discovery_burst: "automated discovery",
                pass_the_hash: "Pass the Hash",
              };
              for (const cat of categories) {
                const label = _csCatLabels[cat] || cat;
                const count = _csByCat.get(cat).length;
                pills.push({ text: `${label}${count > 1 ? ` (${count})` : ""}`, type: cat === "named_pipe" || cat === "getsystem" || cat === "service_beacon" ? "execution" : cat === "injection" || cat === "pass_the_hash" ? "credential" : cat === "discovery_burst" ? "context" : "execution" });
              }
              if (uniqueCategories >= 3) pills.push({ text: "multi-stage", type: "execution" });
              pills.push({ text: `${totalIndicators} indicator${totalIndicators > 1 ? "s" : ""}`, type: "context" });

              // Build description from category summaries
              const descParts = [];
              for (const [cat, hits] of _csByCat) {
                const label = _csCatLabels[cat] || cat;
                if (hits.length <= 2) {
                  descParts.push(hits.map(h => h.detail).join("; "));
                } else {
                  descParts.push(`${label}: ${hits.length} events (${hits.slice(0, 2).map(h => h.detail).join("; ")} +${hits.length - 2} more)`);
                }
              }

              findings.push({
                id: fid++, severity, category: "Cobalt Strike", mitre: "T1055",
                title: `Cobalt Strike indicators on ${host} (${uniqueCategories} categor${uniqueCategories > 1 ? "ies" : "y"})`,
                description: descParts.join(". "),
                source: "", target: host,
                filterHosts: [host],
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: totalIndicators,
                filterEids: [...new Set(hostHits.map(h => h.eid))],
                evidencePills: pills,
                users: [...new Set(hostHits.filter(h => h.category === "pass_the_hash").map(h => {
                  const m = h.detail.match(/:\s*(\S+)\s+from/); return m ? m[1] : null;
                }).filter(Boolean))],
              });
            }
          } } catch (_csErr) { warnings.push(`Cobalt Strike detector failed: ${_csErr.message}`); }

          // --- Emit Native PsExec findings (one per host / 10-min cluster) ---
          try { if (_psexecNative.length > 0) {
            for (const cluster of clusterHitsByHostTime(_psexecNative)) {
              const destHosts = [...new Set(cluster.filter(h => h.side === "dest" && h.host).map(h => h.host))];
              const srcHosts = [...new Set(cluster.filter(h => h.side === "source" && h.host).map(h => h.host))];
              const allHosts = [...new Set([...destHosts, ...srcHosts])];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const details = [...new Set(cluster.map(h => h.d))];
              const eids = [...new Set(cluster.map(h => h.eid))];
              const hostLabel = [];
              if (destHosts.length > 0) hostLabel.push(`target ${destHosts.slice(0, 3).join(", ")}${destHosts.length > 3 ? ` +${destHosts.length - 3} more` : ""}`);
              if (srcHosts.length > 0) hostLabel.push(`observed on ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""}`);
              const _psPills = [{ text: "PSEXESVC service", type: "execution" }];
              if (destHosts.length > 0) _psPills.push({ text: `target ${destHosts.slice(0, 2).join(", ")}`, type: "target" });
              if (srcHosts.length > 0) _psPills.push({ text: `from ${srcHosts.slice(0, 2).join(", ")}`, type: "context" });
              const _psUsers = _usersFromCorrelation(cluster);
              findings.push({ id: fid++, severity: "critical", category: "PsExec Native", mitre: "T1569.002",
                title: `Sysinternals PsExec detected${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
                description: `${cluster.length} event(s): ${details.join("; ")}`,
                source: srcHosts.join(", "), target: destHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: eids, evidencePills: _psPills, users: _psUsers, itemRowids: cluster.map(h => h.rid).filter(r => r != null) });
            }
          } } catch (_e) { warnings.push(`PsExec detector failed: ${_e.message}`); console.error("PsExec detector error:", _e); }

          // --- Emit Impacket findings: per-variant with confidence-scored severity ---
          try { if (_psexecImpacket.length > 0) {
            // Uses the shared `_correlatedExecLogon` index built above. The previous
            // local `_hasCorrelatedLogon` was a strict-boolean wrapper; the shared
            // helper returns the matching logon event so we can also pull the user.

            // Cluster by (variant, targetHost, timeWindow) for per-hop findings
            // Assign target key: dest-side host IS the target; source-side uses remoteTarget if known
            const _parseTs = (s) => tsMs(s) ?? 0;
            for (const h of _psexecImpacket) {
              if (h.side === "dest") h._tgtKey = (h.host || "").toUpperCase();
              else h._tgtKey = (h.remoteTarget || "").toUpperCase(); // "" if unknown
            }
            // Group by (variant, targetKey)
            const _byVarTgt = new Map();
            for (const h of _psexecImpacket) {
              const k = `${h.v}\0${h._tgtKey}`;
              if (!_byVarTgt.has(k)) _byVarTgt.set(k, []);
              _byVarTgt.get(k).push(h);
            }
            // Within each group, sort by time and split into sub-clusters (>10 min gap)
            const _impClusters = [];
            for (const hits of _byVarTgt.values()) {
              hits.sort((a, b) => cmpTs(a.ts, b.ts));
              let cur = [hits[0]];
              for (let i = 1; i < hits.length; i++) {
                const prevMs = _parseTs(cur[cur.length - 1].ts);
                const curMs = _parseTs(hits[i].ts);
                if (prevMs && curMs && curMs - prevMs > 600000) {
                  _impClusters.push(cur);
                  cur = [];
                }
                cur.push(hits[i]);
              }
              if (cur.length > 0) _impClusters.push(cur);
            }

            // Emit one finding per cluster
            for (const cluster of _impClusters) {
              const variant = cluster[0].v;
              const hasStrong = cluster.some(h => h.confidence === "strong");
              const hasMedium = cluster.some(h => h.confidence === "medium");
              const hasCorrelation = cluster.some(h => h.side === "dest" && _correlatedExecLogon(h.host, h.ts) !== null);
              let severity;
              if (hasStrong) severity = "critical";
              else if (hasMedium && hasCorrelation) severity = "high";
              else severity = "medium";

              const destHosts = [...new Set(cluster.filter(h => h.side === "dest" && h.host).map(h => h.host))];
              const srcHosts = [...new Set(cluster.filter(h => h.side === "source" && h.host).map(h => h.host))];
              const remoteTargets = [...new Set(cluster.map(h => h.remoteTarget).filter(Boolean))];
              const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
              const allHosts = [...new Set([...targetHosts, ...srcHosts])];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const evidence = [...new Set(cluster.map(h => `[${h.confidence}] ${h.evidence}`))];
              const eids = [...new Set(cluster.map(h => h.eid))];

              // Build title: "Impacket wmiexec.py: WS01 → DC01" or "Impacket smbexec.py (target DC02)"
              let hopLabel = "";
              if (srcHosts.length > 0 && targetHosts.length > 0) {
                hopLabel = `: ${srcHosts[0]}${srcHosts.length > 1 ? ` +${srcHosts.length - 1}` : ""} \u2192 ${targetHosts[0]}${targetHosts.length > 1 ? ` +${targetHosts.length - 1}` : ""}`;
              } else if (targetHosts.length > 0) {
                hopLabel = ` (target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""})`;
              } else if (srcHosts.length > 0) {
                hopLabel = ` (from ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""})`;
              }

              const _impPills = [{ text: `Impacket ${variant}`, type: "execution" }];
              if (hasStrong) _impPills.push({ text: "strong indicator", type: "execution" });
              else if (hasMedium) _impPills.push({ text: "medium indicator", type: "context" });
              if (hasCorrelation) _impPills.push({ text: "logon correlation", type: "correlation" });
              const _impUsers = _usersFromCorrelation(cluster);
              findings.push({ id: fid++, severity, category: "Impacket Execution", mitre: "T1569.002",
                title: `Impacket ${variant}${hopLabel}`,
                description: `${cluster.length} event(s): ${evidence.join("; ")}${hasCorrelation ? " [correlated Type 3 logon]" : ""}`,
                evidence, source: srcHosts.join(", "), target: targetHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: eids, evidencePills: _impPills, users: _impUsers, itemRowids: cluster.map(h => h.rid).filter(r => r != null) });
            }

            // Summary card when 2+ clusters
            if (_impClusters.length > 1) {
              const allVariants = [...new Set(_psexecImpacket.map(h => h.v))];
              const allHosts = [...new Set(_psexecImpacket.map(h => h.host).filter(Boolean))];
              const allTs = _psexecImpacket.map(h => h.ts).filter(Boolean).sort();
              const _impSumUsers = _usersFromCorrelation(_psexecImpacket);
              const _impSumSources = _sourcesFromCorrelation(_psexecImpacket);
              findings.push({ id: fid++, severity: "low", category: "Impacket Summary", mitre: "T1569.002",
                title: `Impacket activity: ${allVariants.join(", ")} — ${_impClusters.length} clusters across ${allHosts.length} host(s)`,
                description: `${_psexecImpacket.length} total events across ${_impClusters.length} distinct source/target/time clusters. See individual findings.`,
                source: _impSumSources.join(", "), target: allHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: _psexecImpacket.length, filterEids: [...new Set(_psexecImpacket.map(h => h.eid))],
                evidencePills: allVariants.map(v => ({ text: v, type: "execution" })), users: _impSumUsers, itemRowids: _psexecImpacket.map(h => h.rid).filter(r => r != null) });
            }
          }

          // --- Emit Impacket Credential Access findings (secretsdump.py etc.) ---
          if (_impCredAccess.length > 0) {
            const hosts = [...new Set(_impCredAccess.map(h => h.host).filter(Boolean))];
            const allTs = _impCredAccess.map(h => h.ts).filter(Boolean).sort();
            const evidence = [...new Set(_impCredAccess.map(h => h.evidence))];
            const eids = [...new Set(_impCredAccess.map(h => h.eid))];
            // secretsdump.py is source-side python execution. User attribution comes from a
            // ±5min Type 3/4648 logon to the same host (the operator authenticating to dump).
            const _impCredUsers = _usersFromCorrelation(_impCredAccess);
            const _impCredSources = _sourcesFromCorrelation(_impCredAccess);
            findings.push({ id: fid++, severity: "critical", category: "Impacket Credential Access", mitre: "T1003",
              title: `Impacket credential dumping${hosts.length > 0 ? ` (observed on ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` +${hosts.length - 3} more` : ""})` : ""}`,
              description: `${_impCredAccess.length} event(s): ${evidence.join("; ")}`,
              evidence, source: _impCredSources.join(", "), target: hosts.join(", "),
              filterHosts: hosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: _impCredAccess.length, filterEids: eids,
              evidencePills: [{ text: "credential dumping", type: "execution" }, ...hosts.slice(0, 2).map(h => ({ text: h, type: "target" }))], users: _impCredUsers, itemRowids: _impCredAccess.map(h => h.rid).filter(r => r != null) });
          } } catch (_e) { warnings.push(`Impacket detector failed: ${_e.message}`); console.error("Impacket detector error:", _e); }

          // --- Emit Remote Service Execution findings (one per host / 10-min cluster) ---
          try { if (_remoteSvcExec.length > 0) {
            const _uniqueText = (values) => [...new Set(values.map(v => String(v || "").trim()).filter(Boolean))];
            for (const cluster of clusterHitsByHostTime(_remoteSvcExec, (h) => h.host)) {
              const hosts = [...new Set(cluster.map(h => h.host).filter(Boolean))];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const eids = [...new Set(cluster.map(h => h.eid))];
              const _rsPills = [{ text: "suspicious service", type: "execution" }];
              if (hosts.length > 0) _rsPills.push({ text: `target ${hosts.slice(0, 2).join(", ")}`, type: "target" });
              const _rsReasonGroups = new Map();
              for (const h of cluster) {
                const m = h.d.match(/^Random \d+-char service name: (.+)$/);
                if (m) {
                  if (!_rsReasonGroups.has("random_name")) _rsReasonGroups.set("random_name", []);
                  _rsReasonGroups.get("random_name").push(m[1]);
                } else {
                  if (!_rsReasonGroups.has("other")) _rsReasonGroups.set("other", []);
                  _rsReasonGroups.get("other").push(h.d);
                }
              }
              const _rsDescParts = [];
              const _rsRandomNames = _rsReasonGroups.get("random_name");
              if (_rsRandomNames && _rsRandomNames.length > 0) {
                const uniqueNames = [...new Set(_rsRandomNames)];
                _rsDescParts.push(`${uniqueNames.length} random service name${uniqueNames.length > 1 ? "s" : ""}: ${uniqueNames.join(", ")}`);
              }
              const _rsOther = _rsReasonGroups.get("other");
              if (_rsOther && _rsOther.length > 0) {
                _rsDescParts.push(...[...new Set(_rsOther)]);
              }
              const _rsUsers = _usersFromCorrelation(cluster);
              const _rsSources = _sourcesFromCorrelation(cluster);
              const executionDetails = cluster.map((h) => {
                const correlated = _correlatedExecLogon(h.host, h.ts);
                const attributedUser = correlated?.user ? String(correlated.user).toUpperCase() : "";
                const sourceHost = correlated?.source
                  ? String(correlated.source).toUpperCase().replace(/\s*\(.*\)$/, "").trim()
                  : "";
                return {
                  eventId: h.eid,
                  timestamp: h.ts,
                  target: h.host,
                  serviceName: h.serviceName || "",
                  imagePath: h.imagePath || "",
                  commandLine: h.commandLine || "",
                  eventActor: h.eventActor || "",
                  serviceAccount: h.serviceAccount || "",
                  attributedUser,
                  sourceHost,
                  reason: h.d || "",
                  rowId: h.rid,
                };
              });
              const serviceNames = _uniqueText(executionDetails.map(d => d.serviceName));
              const imagePaths = _uniqueText(executionDetails.map(d => d.imagePath));
              const commandLines = _uniqueText(executionDetails.map(d => d.commandLine));
              const eventActors = _uniqueText(executionDetails.map(d => d.eventActor));
              const serviceAccounts = _uniqueText(executionDetails.map(d => d.serviceAccount));
              const executors = _uniqueText([...eventActors, ..._rsUsers]);
              for (const serviceName of serviceNames.slice(0, 2)) {
                _rsPills.push({ text: `service ${serviceName}`, type: "execution" });
              }
              if (imagePaths.length > 0) _rsDescParts.push(`Image path${imagePaths.length > 1 ? "s" : ""}: ${imagePaths.slice(0, 3).join(", ")}`);
              if (executors.length > 0) _rsDescParts.push(`Account attribution: ${executors.slice(0, 4).join(", ")}`);
              const serviceTitle = serviceNames.length === 1
                ? `: ${serviceNames[0]}`
                : serviceNames.length > 1
                  ? `: ${serviceNames.slice(0, 2).join(", ")}${serviceNames.length > 2 ? ` +${serviceNames.length - 2} more` : ""}`
                  : "";
              findings.push({ id: fid++, severity: "high", category: "Remote Service Execution", mitre: "T1569.002",
                title: `Suspicious service-based execution${serviceTitle}${hosts.length > 0 ? ` (target ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` +${hosts.length - 3} more` : ""})` : ""}`,
                description: `${cluster.length} suspicious service event(s). ${_rsDescParts.join("; ")}. Could indicate remote execution tools.`,
                source: _rsSources.join(", "), target: hosts.join(", "),
                filterHosts: hosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: eids, evidencePills: _rsPills, users: _rsUsers,
                serviceNames, imagePaths, commandLines, eventActors, serviceAccounts, executors, executionDetails,
                itemRowids: cluster.map(h => h.rid).filter(r => r != null) });
            }
          } } catch (_e) { warnings.push(`Remote Service detector failed: ${_e.message}`); console.error("Remote Service detector error:", _e); }

          // --- Emit WMI Event Subscription Persistence findings (Sysmon 19/20/21) ---
          try { if (_wmiSubHits.length > 0 && !_disabledSet.has("wmisub")) {
            const _wsByHost = new Map();
            for (const h of _wmiSubHits) { const k = h.host || "UNKNOWN"; if (!_wsByHost.has(k)) _wsByHost.set(k, []); _wsByHost.get(k).push(h); }
            for (const [wsHost, hits] of _wsByHost) {
              const _wsTs = hits.map(h => h.ts).filter(Boolean).sort();
              const _wsHasConsumer = hits.some(h => h.isConsumer); // EID 20 (consumer carries the payload)
              const _wsHasBinding = hits.some(h => h.isBinding);    // EID 21 (FilterToConsumer binding)
              const _wsHasLol = hits.some(h => h.isLol);
              const _wsDetails = [...new Set(hits.map(h => h.detail).filter(Boolean))].slice(0, 4);
              // script/LOLBin payload = critical; a registered consumer (20) = high;
              // binding/filter-only with no visible payload = medium (needs analyst confirmation).
              const _wsSeverity = _wsHasLol ? "critical" : _wsHasConsumer ? "high" : "medium";
              const _wsPills = [{ text: "WMI subscription", type: "execution" }];
              if (_wsHasConsumer) _wsPills.push({ text: "consumer registered", type: "execution" });
              if (_wsHasBinding) _wsPills.push({ text: "filter→consumer binding", type: "execution" });
              if (_wsHasLol) _wsPills.push({ text: "script/LOLBin payload", type: "credential" });
              if (_DC_PAT.test(wsHost)) _wsPills.push({ text: "DC target", type: "target" });
              findings.push({
                id: fid++, severity: _wsSeverity, category: "WMI Event Subscription", mitre: "T1546.003",
                title: `WMI event subscription persistence on ${wsHost}`,
                description: `${hits.length} WMI subscription event(s) (Sysmon 19/20/21) on ${wsHost}. ${_wsDetails.join("; ")}. WMI FilterToConsumer bindings are a common persistence and lateral-movement mechanism; the consumer command is typically a LOLBin or script that runs on an event trigger.`,
                source: "", target: wsHost, filterHosts: [wsHost],
                timeRange: { from: _wsTs[0] || "", to: _wsTs[_wsTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["19", "20", "21"],
                evidencePills: _wsPills, users: [],
                itemRowids: hits.map(h => h.rid).filter(r => r != null),
              });
            }
          } } catch (_wsErr) { warnings.push(`WMI subscription detector failed: ${_wsErr.message}`); }

          // --- Helper: emit a remote-exec/activity finding from a hit list ---
          // User attribution: WMI/WinRM hits don't carry user inline (they're built from
          // process create events, not logon events), so we correlate each hit's host+ts
          // to the shared logon index and aggregate the resulting users.
          const _emitRemoteFindingCluster = (hits, category, mitre, titlePrefix, severity, extraPills) => {
            const destHosts = [...new Set(hits.filter(h => h.side === "dest" && h.host).map(h => h.host))];
            const srcHosts = [...new Set(hits.filter(h => h.side === "source" && h.host).map(h => h.host))];
            const remoteTargets = [...new Set(hits.map(h => h.remoteTarget).filter(Boolean))];
            const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
            const corrSources = _sourcesFromCorrelation(hits);
            const allSrcHosts = [...new Set([...srcHosts, ...corrSources])];
            const allHosts = [...new Set([...targetHosts, ...allSrcHosts])];
            const allTs = hits.map(h => h.ts).filter(Boolean).sort();
            const details = [...new Set(hits.map(h => h.d))];
            const eids = [...new Set(hits.map(h => h.eid))];
            const hostLabel = [];
            if (targetHosts.length > 0) hostLabel.push(`target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""}`);
            if (allSrcHosts.length > 0) hostLabel.push(`from ${allSrcHosts.slice(0, 3).join(", ")}${allSrcHosts.length > 3 ? ` +${allSrcHosts.length - 3} more` : ""}`);
            const _rfPills = [...(extraPills || [])];
            if (destHosts.length > 0) _rfPills.push({ text: "dest-side", type: "context" });
            if (srcHosts.length > 0) _rfPills.push({ text: "source-side", type: "context" });
            if (targetHosts.some(h => _DC_PAT.test(h))) _rfPills.push({ text: "DC target", type: "target" });
            else if (targetHosts.some(h => _SRV_PAT.test(h))) _rfPills.push({ text: "server target", type: "target" });
            const _rfUsers = _usersFromCorrelation(hits);
            findings.push({ id: fid++, severity, category, mitre,
              title: `${titlePrefix}${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
              description: `${hits.length} event(s): ${details.join("; ")}`,
              source: allSrcHosts.join(", "), target: targetHosts.join(", "),
              filterHosts: allHosts,
              timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
              eventCount: hits.length, filterEids: eids, evidencePills: _rfPills, users: _rfUsers, itemRowids: hits.map(h => h.rid).filter(r => r != null) });
          };
          const _emitRemoteFinding = (hits, category, mitre, titlePrefix, severity, extraPills) => {
            if (!hits.length) return;
            for (const cluster of clusterHitsByHostTime(hits)) {
              _emitRemoteFindingCluster(cluster, category, mitre, titlePrefix, severity, extraPills);
            }
          };

          // --- Emit WMI/WinRM findings ---
          try {
          if (_wmiHits.length > 0) {
            const wmiExec = _wmiHits.filter(h => h.exec);
            const wmiActivity = _wmiHits.filter(h => !h.exec);
            const wmiExecHasDirectional = wmiExec.some(h => h.side === "dest" && !h._blob);
            const wmiExecHasBlobOnly = !wmiExecHasDirectional && wmiExec.some(h => h.side === "dest" && h._blob);
            const wmiSev = wmiExecHasDirectional ? "high" : wmiExecHasBlobOnly ? "medium" : "medium";
            const wmiPills = [{ text: "WMI execution", type: "execution" }];
            if (wmiExecHasBlobOnly) wmiPills.push({ text: "blob match (lower confidence)", type: "context" });
            if (wmiExec.length > 0) _emitRemoteFinding(wmiExec, "WMI Remote Execution", "T1047", "WMI remote execution", wmiSev, wmiPills);
            if (wmiActivity.length > 0) _emitRemoteFinding(wmiActivity, "WMI Remote Activity", "T1047", "WMI remote activity", "low", [{ text: "WMI activity", type: "context" }]);
          }
          if (_winrmHits.length > 0) {
            const winrmExec = _winrmHits.filter(h => h.exec);
            const winrmActivity = _winrmHits.filter(h => !h.exec);
            const winrmExecHasDirectional = winrmExec.some(h => h.side === "dest" && h.hasChild && !h._blob);
            const winrmExecHasBlobOnly = !winrmExecHasDirectional && winrmExec.some(h => h.side === "dest" && h._blob);
            const winrmSev = winrmExecHasDirectional ? "high" : winrmExecHasBlobOnly ? "medium" : "medium";
            const winrmPills = [{ text: "WinRM execution", type: "execution" }];
            if (winrmExecHasBlobOnly) winrmPills.push({ text: "blob match (lower confidence)", type: "context" });
            if (winrmExec.length > 0) _emitRemoteFinding(winrmExec, "WinRM Remote Execution", "T1021.006", "WinRM remote execution", winrmSev, winrmPills);
            if (winrmActivity.length > 0) _emitRemoteFinding(winrmActivity, "WinRM Remote Activity", "T1021.006", "WinRM remote activity", "low", [{ text: "WinRM activity", type: "context" }]);
          }
          } catch (_e) { warnings.push(`WMI/WinRM detector failed: ${_e.message}`); console.error("WMI/WinRM detector error:", _e); }

          // --- Emit native DCOM lateral-execution findings (T1021.003) ---
          try {
            if (_dcomHits.length > 0) {
              _emitRemoteFinding(_dcomHits, "DCOM Remote Execution", "T1021.003", "DCOM remote execution", "high", [{ text: "DCOM", type: "execution" }]);
            }
          } catch (_dcErr) { warnings.push(`DCOM detector failed: ${_dcErr.message}`); }

          // --- Emit OpenSSH findings: inbound access (T1021.004) and tunneling (T1572) ---
          try {
            const _sshInbound = _sshHits.filter(h => h.category === "sshd_install" || h.category === "sshd_shell");
            const _sshTunnel = _sshHits.filter(h => h.category === "ssh_tunnel");
            if (_sshInbound.length > 0) {
              // sshd spawning a shell (inbound RCE) is high; a bare service install (could be sanctioned IT) is medium.
              const _sshInSev = _sshInbound.some(h => h.category === "sshd_shell") ? "high" : "medium";
              _emitRemoteFinding(_sshInbound, "OpenSSH Inbound Access", "T1021.004", "OpenSSH inbound access", _sshInSev, [{ text: "OpenSSH", type: "execution" }]);
            }
            if (_sshTunnel.length > 0) {
              // Remote/dynamic forwards (-R/-D) expose internal services or proxy a pivot → high.
              // Local forwards (-L only) are common benign dev/admin use → medium.
              const _sshTunSev = _sshTunnel.some(h => h.fwd === "R" || h.fwd === "D") ? "high" : "medium";
              _emitRemoteFinding(_sshTunnel, "SSH Tunneling", "T1572", "SSH port forwarding / tunneling", _sshTunSev, [{ text: "SSH tunnel", type: "execution" }]);
            }
          } catch (_sshErr) { warnings.push(`OpenSSH detector failed: ${_sshErr.message}`); }

          // --- Emit RMM findings (clustered per tool+host, scored by context) ---
          try {
          if (_rmmHits.length > 0 && !_disabledSet.has("rmm")) {
            // Cluster by tool+host, then by 30-min time windows
            const _rmmClusters = new Map(); // "tool::HOST" -> [{hit, ...}, ...]
            for (const h of _rmmHits) {
              const key = `${h.tool}::${(h.host || "UNKNOWN").toUpperCase()}`;
              if (!_rmmClusters.has(key)) _rmmClusters.set(key, []);
              _rmmClusters.get(key).push(h);
            }
            for (const [clusterKey, hits] of _rmmClusters) {
              // Sort by timestamp within cluster
              hits.sort((a, b) => (a.ts || "") > (b.ts || "") ? 1 : -1);
              // Sub-cluster by 30-min time gaps
              const windows = [];
              let win = [hits[0]];
              for (let i = 1; i < hits.length; i++) {
                const prev = win[win.length - 1];
                const gap = (_gapMs(prev.ts, hits[i].ts) ?? 0) / 60000;
                if (gap > 30) { windows.push(win); win = [hits[i]]; }
                else win.push(hits[i]);
              }
              windows.push(win);

              for (const winHits of windows) {
                const tool = winHits[0].tool;
                const toolType = winHits[0].toolType;
                const host = winHits[0].host.toUpperCase() || "UNKNOWN";

                // Determine kind hierarchy: process/cmdline > install/service > presence
                const hasProcess = winHits.some(h => h.kind === "process" || h.kind === "cmdline");
                const hasInstall = winHits.some(h => h.kind === "install" || h.kind === "service");

                // Context scoring
                const pills = [];
                let severity = "low";
                const reasons = [];

                // Unusual parent detection
                const susParentHits = winHits.filter(h => h.parent && _rmmSusParents.has(h.parent));
                const hasSusParent = susParentHits.length > 0;
                if (hasSusParent) {
                  const pNames = [...new Set(susParentHits.map(h => h.parent))];
                  pills.push({ text: `unusual parent: ${pNames.join(", ")}`, type: "execution" });
                  reasons.push("unusual parent");
                }

                // Suspicious path detection
                const susPathHits = winHits.filter(h => h.imagePath && _rmmSusPaths.test(h.imagePath));
                if (susPathHits.length > 0) {
                  pills.push({ text: "user-writable/temp path", type: "execution" });
                  reasons.push("suspicious path");
                }

                // DC/server target
                const isDC = _DC_PAT.test(host);
                const isSrv = !isDC && _SRV_PAT.test(host);
                if (isDC) { pills.push({ text: "DC target", type: "target" }); reasons.push("DC target"); }
                else if (isSrv) { pills.push({ text: "server target", type: "target" }); reasons.push("server target"); }

                // Outlier source — this host is unusual
                if (_outlierHosts.has(host)) { pills.push({ text: "outlier host", type: "correlation" }); reasons.push("outlier"); }

                // First-seen check — host never appeared in logon graph
                if (host !== "UNKNOWN" && !hostSet.has(host)) { pills.push({ text: "first-seen host", type: "correlation" }); reasons.push("first-seen"); }

                // Compute severity based on context
                if (toolType === "tunnel") {
                  // Tunnels: always medium for execution, low for install-only
                  severity = hasProcess ? "medium" : "low";
                  if (hasSusParent || susPathHits.length > 0) severity = "high";
                } else {
                  // RMM tools
                  if (hasSusParent || susPathHits.length > 0) {
                    severity = "high"; // suspicious execution context
                  } else if (hasProcess) {
                    severity = "medium"; // executed, but normal parent
                  } else if (hasInstall && (isDC || isSrv)) {
                    severity = "medium"; // installed on high-value target
                  } else {
                    severity = "low"; // installed/present only
                  }
                  // Boost: overlap with credential abuse or admin share on same host
                  const hasOverlap = findings.some(f => {
                    if (f.category !== "Credential Compromise" && f.category !== "Admin Share Access") return false;
                    const fTargets = (f.target || "").split(", ").map(t => t.trim().toUpperCase()).filter(Boolean);
                    return fTargets.includes(host);
                  });
                  if (hasOverlap && severity !== "high") {
                    severity = severity === "low" ? "medium" : "high";
                    pills.push({ text: "overlaps credential/share activity", type: "correlation" });
                  }
                }

                // Dampener: all hits have normal enterprise parents and no other suspicious context
                const allNormalParent = winHits.every(h => !h.parent || _rmmNormalParents.has(h.parent));
                if (allNormalParent && !hasSusParent && susPathHits.length === 0 && reasons.length === 0 && severity === "low") {
                  pills.push({ text: "expected enterprise pattern", type: "context" });
                }

                // Build category and title
                let category, title, desc;
                if (toolType === "tunnel") {
                  category = "Remote Access Tunnel";
                  title = `Remote tunnel: ${tool} on ${host}`;
                  desc = hasProcess ? `${tool} executed on ${host}` : `${tool} service installed on ${host}`;
                } else if (hasSusParent || susPathHits.length > 0) {
                  category = "RMM Suspicious Execution";
                  title = `Suspicious RMM execution: ${tool} on ${host}`;
                  desc = `${tool} launched${hasSusParent ? ` from ${[...new Set(susParentHits.map(h => h.parent))].join("/")}` : ""}${susPathHits.length > 0 ? " from user-writable path" : ""}`;
                } else if (hasProcess) {
                  category = "RMM Executed";
                  title = `RMM tool executed: ${tool} on ${host}`;
                  desc = `${tool} process execution detected on ${host}`;
                } else {
                  category = "RMM Installed";
                  title = `RMM tool installed: ${tool} on ${host}`;
                  desc = `${tool} service installation detected on ${host}`;
                }

                // Add kind/count pills
                pills.unshift({ text: tool, type: toolType === "tunnel" ? "context" : "execution" });
                const kindCounts = {};
                for (const h of winHits) kindCounts[h.kind] = (kindCounts[h.kind] || 0) + 1;
                for (const [k, c] of Object.entries(kindCounts)) {
                  pills.push({ text: `${c} ${k} event${c > 1 ? "s" : ""}`, type: "context" });
                }

                const eids = [...new Set(winHits.map(h => h.eid))].sort();
                const allTs = winHits.map(h => h.ts).filter(Boolean).sort();
                desc += `. ${winHits.length} event(s)${eids.length > 0 ? ` (EID ${eids.join(", ")})` : ""}`;

                // In suspicious-only mode, skip low/medium findings (RMM Installed, RMM Executed, tunnels without suspicious context)
                if (rmmMode === "suspicious" && category !== "RMM Suspicious Execution") continue;

                // Pull users from correlated logons on the same host within the cluster window.
                // RMM hits are process events without user attribution; the operator typically
                // authenticates via Type 3 just before/after running the tool.
                const _rmmUsers = _usersFromCorrelation(winHits);
                const _rmmSources = _sourcesFromCorrelation(winHits);
                findings.push({
                  id: fid++, severity, category, mitre: "T1219",
                  title, description: desc,
                  source: _rmmSources.join(", "), target: host,
                  filterHosts: [...new Set([host, ..._rmmSources])],
                  timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                  eventCount: winHits.length, filterEids: eids.length > 0 ? eids : null,
                  evidencePills: pills, users: _rmmUsers, itemRowids: winHits.map(h => h.rid).filter(r => r != null),
                });
              }
            }
          }
          } catch (_e) { warnings.push(`RMM detector failed: ${_e.message}`); console.error("RMM detector error:", _e); }

          // --- Emit Scheduled Task Remote Execution findings ---
          try { if (_schedTaskHits.length > 0 && !_disabledSet.has("schtask")) {
            const _logonByHostST = new Map();
            for (const evt of timeOrdered) {
              if (evt.eventId !== "4624" && evt.eventId !== "4648") continue;
              const h = (evt.target || "").toUpperCase();
              if (!h) continue;
              if (!_logonByHostST.has(h)) _logonByHostST.set(h, []);
              _logonByHostST.get(h).push(evt);
            }
            const _stHasLogon = (host, hitTs) => {
              if (!host || !hitTs) return null;
              const logons = _logonByHostST.get(host.toUpperCase());
              if (!logons) return null;
              const tMs = tsMs(hitTs);
              if (tMs == null) return null;
              for (const l of logons) {
                if (l.logonType !== "3" && l.eventId !== "4648") continue;
                const lMs = tsMs(l.ts);
                if (lMs != null && Math.abs(lMs - tMs) <= 600000) {
                  return { source: l.source, user: l.user, eventId: l.eventId, logonType: l.logonType };
                }
              }
              return null;
            };
            _schedTaskHits.sort((a, b) => cmpTs(a.ts, b.ts));
            const _stClusters = [];
            let _stCur = [_schedTaskHits[0]];
            for (let si = 1; si < _schedTaskHits.length; si++) {
              const prevMs = tsMs(_stCur[_stCur.length - 1].ts);
              const curMs = tsMs(_schedTaskHits[si].ts);
              const sameTarget = (_schedTaskHits[si].host || "").toUpperCase() === (_stCur[0].host || "").toUpperCase();
              if (sameTarget && prevMs != null && curMs != null && curMs - prevMs <= 600000) {
                _stCur.push(_schedTaskHits[si]);
              } else {
                _stClusters.push(_stCur);
                _stCur = [_schedTaskHits[si]];
              }
            }
            if (_stCur.length > 0) _stClusters.push(_stCur);

            for (const cluster of _stClusters) {
              const destHits = cluster.filter(h => h.side === "dest");
              const srcHits = cluster.filter(h => h.side === "source");
              const destHosts = [...new Set(destHits.map(h => h.host).filter(Boolean))];
              const srcHosts = [...new Set(srcHits.map(h => h.host).filter(Boolean))];
              const remoteTargets = [...new Set(srcHits.map(h => h.remoteTarget).filter(Boolean))];
              const targetHosts = [...new Set([...destHosts, ...remoteTargets])];
              const allHosts = [...new Set([...targetHosts, ...srcHosts])];
              const allTs = cluster.map(h => h.ts).filter(Boolean).sort();
              const details = [...new Set(cluster.map(h => h.d))];
              const taskNames = [...new Set(cluster.map(h => h.taskName).filter(Boolean))];
              let correlatedLogon = null;
              for (const dh of destHosts) {
                const match = _stHasLogon(dh, cluster[0].ts);
                if (match) { correlatedLogon = match; break; }
              }
              if (!correlatedLogon) {
                for (const rt of remoteTargets) {
                  const match = _stHasLogon(rt, cluster[0].ts);
                  if (match) { correlatedLogon = match; break; }
                }
              }
              if (correlatedLogon && correlatedLogon.source && !srcHosts.includes(correlatedLogon.source)) {
                srcHosts.push(correlatedLogon.source);
                allHosts.push(correlatedLogon.source);
              }
              const hasSuspAction = destHits.length > 0;
              const hasSrcCmd = srcHits.length > 0 && remoteTargets.length > 0;
              const hasCorrelation = !!correlatedLogon;
              let severity;
              if (hasSuspAction && (hasSrcCmd || hasCorrelation)) severity = "critical";
              else if (hasSuspAction) severity = "high";
              else if (hasSrcCmd && hasCorrelation) severity = "high";
              else if (hasSrcCmd) severity = "medium";
              else severity = "medium";
              const hostLabel = [];
              if (targetHosts.length > 0) hostLabel.push(`target ${targetHosts.slice(0, 3).join(", ")}${targetHosts.length > 3 ? ` +${targetHosts.length - 3} more` : ""}`);
              if (srcHosts.length > 0) hostLabel.push(`from ${srcHosts.slice(0, 3).join(", ")}${srcHosts.length > 3 ? ` +${srcHosts.length - 3} more` : ""}`);
              const corrDesc = correlatedLogon ? ` Correlated: ${correlatedLogon.eventId === "4648" ? "explicit creds" : "Type 3 logon"} from ${correlatedLogon.source || "?"} (${correlatedLogon.user || "?"}).` : "";
              const _stPills = [];
              if (hasSuspAction) _stPills.push({ text: "dest-side execution", type: "execution" });
              if (hasSrcCmd) _stPills.push({ text: "source-side schtasks", type: "execution" });
              if (hasCorrelation) _stPills.push({ text: "correlated logon", type: "correlation" });
              if (targetHosts.some(h => _DC_PAT.test(h))) _stPills.push({ text: "DC target", type: "target" });
              else if (targetHosts.some(h => _SRV_PAT.test(h))) _stPills.push({ text: "server target", type: "target" });
              findings.push({ id: fid++, severity, category: "Scheduled Task Remote Execution", mitre: "T1053.005",
                title: `Scheduled task remote execution${hostLabel.length > 0 ? ` (${hostLabel.join("; ")})` : ""}`,
                description: `${cluster.length} event(s): ${details.join("; ")}${taskNames.length > 0 ? ` Tasks: ${taskNames.join(", ")}` : ""}${corrDesc}`,
                source: srcHosts.join(", "), target: targetHosts.join(", "),
                filterHosts: allHosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: cluster.length, filterEids: ["4698"], evidencePills: _stPills, itemRowids: cluster.map(h => h.rid).filter(r => r != null), users: correlatedLogon?.user ? [correlatedLogon.user.toUpperCase()] : [] });
            }
          } } catch (_e) { warnings.push(`Scheduled Task detector failed: ${_e.message}`); console.error("Scheduled Task detector error:", _e); }
      }


  return { fid, warnings, scanStats, _scanEidCol, _usersFromCorrelation, _sourcesFromCorrelation, _lsassAccessHits, _credTheftCmdHits };
}

module.exports = { runProcessServiceScan };
