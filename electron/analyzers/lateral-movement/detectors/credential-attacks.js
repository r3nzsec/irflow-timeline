/**
 * detectors/credential-attacks.js — credential-attack detectors for lateral movement.
 *
 * Kerberoasting (T1558.003), AS-REP Roasting (T1558.004), and DCSync (T1003.006).
 * Extracted verbatim from getLateralMovement(). Each detector independently
 * re-queries the tab DB for its anchor event ID (4769 / 4768 / 4662), applies
 * its own false-positive controls, and appends findings. They share NO state with
 * the parse/graph/chain spine — only read-only column metadata + db — and append
 * to the shared findings/warnings arrays.
 *
 * @param {object} state
 *   - db, meta, columns   : data access + resolved column map
 *   - isEvtxECmd          : dataset format flag (EvtxECmd PayloadData parsing)
 *   - disabledSet         : Set of disabled detector ids (kerberoast/asreproast/dcsync)
 *   - findings, warnings  : shared output arrays (mutated in place)
 *   - fid                 : current finding-id counter
 * @returns {number} the updated finding-id counter (fid)
 */
const { DC_PAT: _DC_PAT } = require("../constants");
const { tsMs, cmpTs } = require("../time");

function detectCredentialAttacks(state) {
  const { db, meta, columns, isEvtxECmd, disabledSet: _disabledSet, findings, warnings } = state;
  let fid = state.fid;

      // === Kerberoasting Detection (T1558.003) ===
      // Detect 4769 events with RC4 encryption (0x17) which indicates Kerberoasting.
      // Normal Kerberos uses AES (0x11/0x12); RC4 requests for non-krbtgt SPNs are suspicious.
      try {
        const _krbEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
        const _krbTsCol = columns.ts ? meta.colMap[columns.ts] : null;
        const _krbHostCol = columns.target ? meta.colMap[columns.target] : null;
        const _krbUserCol = columns.user ? meta.colMap[columns.user] : null;
        // Detect encryption type and service name columns (dedicated or PayloadData)
        const _krbEncCol = columns.ticketEncryptionType ? meta.colMap[columns.ticketEncryptionType] : null;
        const _krbSvcCol = columns.serviceName ? meta.colMap[columns.serviceName] : null;
        // Also check PayloadData fields for EvtxECmd format
        const _krbPdCols = [columns._payloadData1, columns._payloadData2, columns._payloadData3, columns._payloadData4, columns._payloadData5]
          .filter(c => c && meta.colMap[c]).map(c => meta.colMap[c]);

        // Also detect ticketOptions column
        const _krbOptsCol = columns.ticketOptions ? meta.colMap[columns.ticketOptions] : null;

        if (db && _krbEidCol && (_krbEncCol || _krbPdCols.length > 0)) {
          const _krbSelParts = ["data.rowid as _rid"];
          if (_krbTsCol) _krbSelParts.push(`${_krbTsCol} as _ts`);
          if (_krbHostCol) _krbSelParts.push(`${_krbHostCol} as _host`);
          if (_krbUserCol) _krbSelParts.push(`${_krbUserCol} as _user`);
          if (_krbEncCol) _krbSelParts.push(`${_krbEncCol} as _enc`);
          if (_krbSvcCol) _krbSelParts.push(`${_krbSvcCol} as _svc`);
          if (_krbOptsCol) _krbSelParts.push(`${_krbOptsCol} as _opts`);
          for (let pi = 0; pi < _krbPdCols.length; pi++) _krbSelParts.push(`${_krbPdCols[pi]} as _pd${pi}`);

          const _krbSql = `SELECT ${_krbSelParts.join(", ")} FROM data WHERE ${_krbEidCol} = '4769' LIMIT 50000`;
          const _krbRows = db.prepare(_krbSql).all();

          const _krbHits = []; // {ts, host, user, serviceName, encType}
          let _krbTotalRows = 0; // total 4769 rows (all encryption types) for ratio check
          const _KRBTGT_PAT = /^krbtgt(?:[\/$@]|$)/i;
          const _MACHINE_SPN_PAT = /\$(?:@|$)/i;
          // Common infrastructure SPNs that legitimately use RC4 in mixed environments
          const _COMMON_SPN_PREFIX = /^(HTTP|CIFS|HOST|LDAP|DNS|NFS|TERMSRV|RestrictedKrbHost|WSMAN|exchangeMDB|exchangeRFR|exchangeAB|SMTP|POP|IMAP)\//i;
          // Service account naming patterns (these accounts legitimately request RC4 tickets)
          const _SVC_ACCOUNT_PAT = /^(svc[_\-]|sql[_\-]|iis[_\-]|app[_\-]|bak[_\-]|msa[_\-]|gms[_\-]|task[_\-]|scan[_\-]|mon[_\-]|noc[_\-]|adm[_\-]|da[_\-]|SA[_\-])/i;
          // Crackable / downgrade encryption types: DES-CBC-CRC (0x1), DES-CBC-MD5 (0x3),
          // RC4-HMAC (0x17), RC4-HMAC-EXP (0x18). DES/RC4-EXP in a modern domain is a strong
          // downgrade-roasting signal; restricting to 0x17 alone misses those attacks.
          const _WEAK_ETYPES = new Set([0x1, 0x3, 0x17, 0x18]);
          const _ENC_NAMES = { 0x1: "DES-CBC-CRC (0x1)", 0x3: "DES-CBC-MD5 (0x3)", 0x17: "RC4 (0x17)", 0x18: "RC4-EXP (0x18)" };

          for (const row of _krbRows) {
            _krbTotalRows++;
            let encType = null;
            let svcName = null;
            let status = null;

            // Try dedicated columns first
            if (row._enc) encType = row._enc.toString().trim();
            if (row._svc) svcName = row._svc.toString().trim();

            // EvtxECmd fallback: parse from PayloadData fields
            if (!encType || !svcName) {
              for (let pi = 0; pi < _krbPdCols.length; pi++) {
                const pd = (row[`_pd${pi}`] || "").toString();
                if (!encType) {
                  const encMatch = pd.match(/(?:Ticket\s*Encryption\s*Type|EncryptionType)[:\s]+(0x[0-9A-Fa-f]+|\d+)/i);
                  if (encMatch) encType = encMatch[1].trim();
                }
                if (!svcName) {
                  const svcMatch = pd.match(/(?:Service\s*Name|ServiceName|TargetServiceName)[:\s]+([^\s|,]+)/i);
                  if (svcMatch) svcName = svcMatch[1].trim();
                }
                // Parse status/result code from PayloadData
                if (!status) {
                  const stMatch = pd.match(/(?:Status|Result)[:\s]+(0x[0-9A-Fa-f]+)/i);
                  if (stMatch) status = stMatch[1].toUpperCase();
                }
              }
            }

            if (!encType) continue;
            // Normalize encryption type: 0x17 = 23 = RC4_HMAC_MD5; also flag DES/RC4-EXP downgrades
            const encNorm = encType.startsWith("0x") ? parseInt(encType, 16) : parseInt(encType, 10);
            if (!_WEAK_ETYPES.has(encNorm)) continue; // flag crackable/downgrade etypes only

            // --- FP Control: skip failed ticket requests ---
            // Only successful requests (status 0x0) yield a ticket to crack offline
            // Failed requests are noise (permission denied, SPN not found, etc.)
            if (status && status !== "0X0") continue;

            // Skip krbtgt (normal TGT requests) and machine accounts
            if (svcName && (_KRBTGT_PAT.test(svcName) || _MACHINE_SPN_PAT.test(svcName))) continue;

            // Parse user from EvtxECmd PayloadData1 if needed
            let user = (row._user || "").trim();
            if (isEvtxECmd && user) {
              const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
              if (pdMatch) user = pdMatch[2].trim();
            }
            if (user && /@/.test(user) && !/\s/.test(user)) user = user.replace(/@[^@]*$/, "");
            // Skip machine accounts requesting tickets (normal behavior)
            if (user && user.endsWith("$")) continue;

            // --- FP Control: skip self-referential SPN requests ---
            // When requester name appears in the SPN, it's the service requesting its own ticket
            if (svcName && user && user !== "(unknown)") {
              const userBase = user.split("@")[0].toLowerCase();
              const svcLower = svcName.toLowerCase();
              if (svcLower.includes(userBase) || svcLower.startsWith(userBase + "/")) continue;
            }

            _krbHits.push({
              ts: row._ts || "",
              host: (row._host || "").toString().trim().toUpperCase(),
              user: user || "(unknown)",
              serviceName: svcName || "(unknown)",
              encType: _ENC_NAMES[encNorm] || `etype 0x${encNorm.toString(16)}`,
              isCommonSPN: svcName ? _COMMON_SPN_PREFIX.test(svcName) : false,
              isSvcAccount: user ? _SVC_ACCOUNT_PAT.test(user) : false,
            });
          }

          if (_krbHits.length > 0 && !_disabledSet.has("kerberoast")) {
            // --- FP Control: RC4 ratio check ---
            // If RC4 is >50% of all 4769 requests, it's likely a legacy/mixed environment
            // where RC4 is the default — dampen severity across the board
            const _krbRc4Ratio = _krbTotalRows > 0 ? _krbHits.length / _krbTotalRows : 1;
            const _krbIsLegacyEnv = _krbRc4Ratio > 0.5;

            // Cluster by user
            _krbHits.sort((a, b) => cmpTs(a.ts, b.ts));
            const _krbByUser = new Map();
            for (const h of _krbHits) {
              const uk = h.user.toUpperCase();
              if (!_krbByUser.has(uk)) _krbByUser.set(uk, []);
              _krbByUser.get(uk).push(h);
            }

            for (const [userKey, hits] of _krbByUser) {
              const spns = [...new Set(hits.map(h => h.serviceName))];
              const hosts = [...new Set(hits.map(h => h.host).filter(Boolean))];
              const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
              const user = hits[0].user;

              // --- FP Control: require minimum 3 unique SPNs ---
              // Single or two RC4 requests are common legitimate fallback
              if (spns.length < 3) continue;

              // --- FP Control: time-window burst detection ---
              // Kerberoasting tools request many tickets in rapid succession
              // Require at least 3 requests within a 10-minute window
              let hasBurst = false;
              if (allTs.length >= 3) {
                for (let i = 0; i <= allTs.length - 3; i++) {
                  const t0 = tsMs(allTs[i]);
                  const t2 = tsMs(allTs[i + 2]);
                  if (t0 != null && t2 != null && (t2 - t0) <= 600000) { // 10 min
                    hasBurst = true;
                    break;
                  }
                }
              }
              // No burst detected — these are spread-out individual requests, likely normal
              if (!hasBurst) continue;

              // --- FP Control: common SPN ratio ---
              // If most targeted SPNs are common infrastructure (HTTP/, CIFS/, HOST/),
              // this is less likely targeted Kerberoasting
              const commonCount = hits.filter(h => h.isCommonSPN).length;
              const commonRatio = hits.length > 0 ? commonCount / hits.length : 0;

              // --- FP Control: service account requester ---
              // Service accounts (svc_*, sql_*, etc.) legitimately request RC4 tickets
              const isSvcAcct = hits[0].isSvcAccount;

              // Severity: base on SPN count, then dampen for legacy env or common SPNs
              let severity;
              if (spns.length >= 10) severity = "critical";
              else if (spns.length >= 5) severity = "high";
              else severity = "medium"; // 3-4 SPNs

              // Dampen severity for legacy RC4 environments
              if (_krbIsLegacyEnv) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Dampen if >80% common infrastructure SPNs
              if (commonRatio > 0.8) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Dampen if requester is a service account
              if (isSvcAcct) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              // Skip low-severity findings entirely (too noisy)
              if (severity === "low") continue;

              const _krbPills = [{ text: "RC4 ticket request", type: "credential" }];
              _krbPills.push({ text: `${spns.length} SPN${spns.length > 1 ? "s" : ""}`, type: "context" });
              if (spns.length >= 10) _krbPills.push({ text: "mass Kerberoasting", type: "execution" });
              if (hasBurst) _krbPills.push({ text: "burst pattern", type: "execution" });
              if (hosts.some(h => _DC_PAT.test(h))) _krbPills.push({ text: "DC target", type: "target" });
              if (_krbIsLegacyEnv) _krbPills.push({ text: "legacy RC4 env", type: "context" });
              if (commonRatio > 0.8) _krbPills.push({ text: `${Math.round(commonRatio * 100)}% common SPNs`, type: "context" });
              if (isSvcAcct) _krbPills.push({ text: "service account", type: "context" });

              findings.push({
                id: fid++, severity, category: "Kerberoasting", mitre: "T1558.003",
                title: `Kerberoasting: ${user} requested ${spns.length} RC4 service ticket${spns.length > 1 ? "s" : ""}`,
                description: `${hits.length} Kerberos service ticket request(s) with RC4 encryption (0x17) by ${user} in a ${allTs.length >= 2 ? "burst" : "short"} pattern. SPNs: ${spns.slice(0, 10).join(", ")}${spns.length > 10 ? ` +${spns.length - 10} more` : ""}. Normal Kerberos uses AES (0x11/0x12); RC4 requests in rapid succession indicate potential Kerberoasting.`,
                source: "", target: hosts.join(", "),
                filterHosts: hosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4769"],
                evidencePills: _krbPills, users: [user],
              });
            }
          }
        }
      } catch (_krbErr) { warnings.push(`Kerberoasting detector failed: ${_krbErr.message}`); }

      // === AS-REP Roasting Detection (T1558.004) ===
      // Detect 4768 events with RC4 encryption. When Kerberos pre-authentication is disabled
      // on an account, an attacker can request an AS-REP encrypted with the account's hash
      // and crack it offline. Normal AS requests use AES; RC4 in 4768 is the signal.
      try {
        const _arEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
        const _arTsCol = columns.ts ? meta.colMap[columns.ts] : null;
        const _arHostCol = columns.target ? meta.colMap[columns.target] : null;
        const _arUserCol = columns.user ? meta.colMap[columns.user] : null;
        const _arEncCol = columns.ticketEncryptionType ? meta.colMap[columns.ticketEncryptionType] : null;
        const _arPreAuthCol = columns.preAuthType ? meta.colMap[columns.preAuthType] : null;
        const _arPdCols = [columns._payloadData1, columns._payloadData2, columns._payloadData3, columns._payloadData4, columns._payloadData5]
          .filter(c => c && meta.colMap[c]).map(c => meta.colMap[c]);

        if (db && _arEidCol && (_arEncCol || _arPreAuthCol || _arPdCols.length > 0) && !_disabledSet.has("asreproast")) {
          // Crackable / downgrade encryption types (when PreAuthType is unavailable in the data)
          const _arWeakEtypes = new Set([0x1, 0x3, 0x17, 0x18]);
          // Service accounts legitimately default to RC4 in many environments — dampen, don't alert
          const _arSvcAcctPat = /^(svc[_\-]|sql[_\-]|iis[_\-]|app[_\-]|bak[_\-]|msa[_\-]|gms[_\-]|task[_\-]|scan[_\-]|mon[_\-]|noc[_\-]|adm[_\-]|da[_\-]|SA[_\-])/i;
          const _arSelParts = ["data.rowid as _rid"];
          if (_arTsCol) _arSelParts.push(`${_arTsCol} as _ts`);
          if (_arHostCol) _arSelParts.push(`${_arHostCol} as _host`);
          if (_arUserCol) _arSelParts.push(`${_arUserCol} as _user`);
          if (_arEncCol) _arSelParts.push(`${_arEncCol} as _enc`);
          if (_arPreAuthCol) _arSelParts.push(`${_arPreAuthCol} as _preauth`);
          for (let pi = 0; pi < _arPdCols.length; pi++) _arSelParts.push(`${_arPdCols[pi]} as _pd${pi}`);

          const _arSql = `SELECT ${_arSelParts.join(", ")} FROM data WHERE ${_arEidCol} = '4768' LIMIT 50000`;
          const _arRows = db.prepare(_arSql).all();

          const _arHits = [];
          let _arSuccessRows = 0; // successful 4768 rows (any etype) — ratio denominator

          for (const row of _arRows) {
            let encType = null;
            let status = null;
            let preAuth = null;

            if (row._enc) encType = row._enc.toString().trim();
            if (row._preauth != null && row._preauth !== "") preAuth = row._preauth.toString().trim();
            if (!encType || !status || !preAuth) {
              for (let pi = 0; pi < _arPdCols.length; pi++) {
                const pd = (row[`_pd${pi}`] || "").toString();
                if (!encType) {
                  const encMatch = pd.match(/(?:Ticket\s*Encryption\s*Type|EncryptionType)[:\s]+(0x[0-9A-Fa-f]+|\d+)/i);
                  if (encMatch) encType = encMatch[1].trim();
                }
                if (!status) {
                  const stMatch = pd.match(/(?:Status|Result)[:\s]+(0x[0-9A-Fa-f]+)/i);
                  if (stMatch) status = stMatch[1].toUpperCase();
                }
                if (!preAuth) {
                  const paMatch = pd.match(/Pre-?Auth(?:entication)?\s*Type[:\s]+(0x[0-9A-Fa-f]+|\d+)/i);
                  if (paMatch) preAuth = paMatch[1].trim();
                }
              }
            }

            // Only successful requests (0x0) yield crackable material — count toward ratio denominator
            if (status && status !== "0X0") continue;
            _arSuccessRows++;

            // PreAuthType=0 (DONT_REQUIRE_PREAUTH) is the DEFINING AS-REP roasting signal.
            // When it's present, trust it regardless of encryption type (catches AES roasts too).
            // When it's absent from the data, fall back to weak-etype (RC4/DES/RC4-EXP) gating.
            const _paNorm = preAuth != null
              ? (preAuth.toLowerCase().startsWith("0x") ? parseInt(preAuth, 16) : parseInt(preAuth, 10))
              : null;
            const preAuthDisabled = _paNorm === 0;
            const encNorm = encType ? (encType.startsWith("0x") ? parseInt(encType, 16) : parseInt(encType, 10)) : null;
            if (!preAuthDisabled) {
              // No confirmed pre-auth-disabled signal — require a weak/crackable etype to flag.
              if (encNorm == null || !_arWeakEtypes.has(encNorm)) continue;
            }

            let user = (row._user || "").trim();
            if (isEvtxECmd && user) {
              const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
              if (pdMatch) user = pdMatch[2].trim();
            }
            if (user && /@/.test(user) && !/\s/.test(user)) user = user.replace(/@[^@]*$/, "");
            if (user && user.endsWith("$")) continue; // skip machine accounts
            // FP control: service accounts legitimately default to RC4 — skip unless pre-auth is
            // explicitly disabled on them (then it is a genuine roastable target).
            if (user && !preAuthDisabled && _arSvcAcctPat.test(user)) continue;

            _arHits.push({
              ts: row._ts || "",
              host: (row._host || "").toString().trim().toUpperCase(),
              user: user || "(unknown)",
              preAuthDisabled,
              rid: row._rid != null ? Number(row._rid) : null,
            });
          }

          if (_arHits.length > 0) {
            // Ratio check: if weak-etype hits are >50% of all SUCCESSFUL 4768 requests, legacy
            // environment (denominator counts only successful rows, not failures).
            const _arRc4Ratio = _arSuccessRows > 0 ? _arHits.length / _arSuccessRows : 1;
            const _arIsLegacy = _arRc4Ratio > 0.5;

            // Cluster by user
            const _arByUser = new Map();
            for (const h of _arHits) {
              const uk = h.user.toUpperCase();
              if (!_arByUser.has(uk)) _arByUser.set(uk, []);
              _arByUser.get(uk).push(h);
            }

            for (const [, hits] of _arByUser) {
              const user = hits[0].user;
              const hosts = [...new Set(hits.map(h => h.host).filter(Boolean))];
              const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
              // Did we observe an explicit PreAuthType=0 for this account? That confirms the
              // account is roastable; without it we are inferring from weak encryption alone.
              const _arConfirmed = hits.some(h => h.preAuthDisabled);

              // Severity: a confirmed pre-auth-disabled account is inherently suspicious even
              // for a single request. Without that confirmation, a lone weak-etype 4768 is a
              // common legacy/FP signal — start at "low" (suppressed) unless there are 2+.
              let severity = _arConfirmed
                ? (hits.length >= 5 ? "critical" : hits.length >= 2 ? "high" : "medium")
                : (hits.length >= 5 ? "high" : hits.length >= 2 ? "medium" : "low");
              if (_arIsLegacy) {
                if (severity === "critical") severity = "high";
                else if (severity === "high") severity = "medium";
                else severity = "low";
              }
              if (severity === "low") continue;

              const _arPills = [{ text: _arConfirmed ? "AS-REP (PreAuth disabled)" : "AS-REP weak-etype", type: "credential" }, { text: `account: ${user}`, type: "execution" }];
              if (hits.length >= 5) _arPills.push({ text: "bulk requests", type: "execution" });
              if (_arIsLegacy) _arPills.push({ text: "legacy/weak-etype env", type: "context" });

              findings.push({
                id: fid++, severity, category: "AS-REP Roasting", mitre: "T1558.004",
                title: `AS-REP Roasting: ${user} (${hits.length} AS request${hits.length > 1 ? "s" : ""})`,
                description: `${hits.length} Kerberos AS request(s) (4768) for ${user}${_arConfirmed ? " with pre-authentication disabled (DONT_REQUIRE_PREAUTH)" : " using weak/crackable encryption"}. This allows an attacker to request the account's AS-REP and crack it offline. ${_arConfirmed ? "PreAuthType=0 confirms the account is roastable." : "Pre-auth-type was not present in the data; flagged on weak encryption type."}`,
                source: "", target: hosts.join(", "),
                filterHosts: hosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4768"],
                evidencePills: _arPills, users: [user],
                itemRowids: hits.map(h => h.rid).filter(r => r != null),
              });
            }
          }
        }
      } catch (_arErr) { warnings.push(`AS-REP Roasting detector failed: ${_arErr.message}`); }

      // === DCSync Detection (T1003.006) ===
      // Detect 4662 events with directory service replication rights (GUIDs).
      // Mimikatz lsadump::dcsync triggers these when a non-DC account requests
      // DS-Replication-Get-Changes / DS-Replication-Get-Changes-All.
      try {
        const _dcEidCol = columns.eventId ? meta.colMap[columns.eventId] : null;
        const _dcTsCol = columns.ts ? meta.colMap[columns.ts] : null;
        const _dcHostCol = columns.target ? meta.colMap[columns.target] : null;
        const _dcUserCol = columns.user ? meta.colMap[columns.user] : null;
        const _dcSubjectCol = columns._subjectUser ? meta.colMap[columns._subjectUser] : null;
        // EvtxECmd maps `user` to PayloadData1, which on a 4662 is object/property text,
        // not "Target: DOMAIN\\user". Without the UserName fallback the account resolved
        // to that junk string, the "machine account" test never matched, and routine
        // DC-to-DC replication was reported as a critical DCSync. Mirrors build-graph.js.
        const _dcUserFallbackCol = columns._userNameFallback ? meta.colMap[columns._userNameFallback] : null;
        const _dcPdCols = [columns._payloadData1, columns._payloadData2, columns._payloadData3, columns._payloadData4, columns._payloadData5]
          .filter(c => c && meta.colMap[c]).map(c => meta.colMap[c]);
        // Also check Details/Extra for non-EvtxECmd formats. Raw EVTX keeps the
        // replication GUIDs in Properties — without that column DCSync is silent.
        const _dcDetailsCol = columns.details ? meta.colMap[columns.details] : null;
        const _dcExtraCol = columns.extra ? meta.colMap[columns.extra] : null;
        const _dcPropsCol = columns._properties ? meta.colMap[columns._properties] : null;

        if (db && _dcEidCol && !_disabledSet.has("dcsync")) {
          const _dcSelParts = ["data.rowid as _rid"];
          if (_dcTsCol) _dcSelParts.push(`${_dcTsCol} as _ts`);
          if (_dcHostCol) _dcSelParts.push(`${_dcHostCol} as _host`);
          if (_dcUserCol) _dcSelParts.push(`${_dcUserCol} as _user`);
          if (_dcSubjectCol) _dcSelParts.push(`${_dcSubjectCol} as _subjectUser`);
          if (_dcUserFallbackCol) _dcSelParts.push(`${_dcUserFallbackCol} as _userFallback`);
          for (let pi = 0; pi < _dcPdCols.length; pi++) _dcSelParts.push(`${_dcPdCols[pi]} as _pd${pi}`);
          if (_dcDetailsCol) _dcSelParts.push(`${_dcDetailsCol} as _details`);
          if (_dcExtraCol) _dcSelParts.push(`${_dcExtraCol} as _extra`);
          if (_dcPropsCol) _dcSelParts.push(`${_dcPropsCol} as _props`);

          const _dcSql = `SELECT ${_dcSelParts.join(", ")} FROM data WHERE ${_dcEidCol} = '4662' LIMIT 50000`;
          let _dcRows = [];
          try { _dcRows = db.prepare(_dcSql).all(); } catch (_) { /* 4662 may not exist */ }

          // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
          // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
          // DS-Replication-Get-Changes-In-Filtered-Set: 89e95b76-444d-4c62-991a-0facbeda640c
          const _REPL_GUIDS = /1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c/i;
          const _dcHits = [];

          for (const row of _dcRows) {
            // Concatenate all text fields to search for GUIDs
            const allText = [
              ..._dcPdCols.map((_, pi) => row[`_pd${pi}`] || ""),
              row._details || "", row._extra || "", row._props || "",
            ].join(" ").toLowerCase();

            if (!_REPL_GUIDS.test(allText)) continue;

            let user = (row._user || "").trim();
            if (isEvtxECmd && user) {
              const pdMatch = user.match(/^Target:\s*(?:([^\\]+)\\)?(.+)$/i);
              if (pdMatch) {
                user = pdMatch[2].trim();
              } else {
                const fallback = String(row._userFallback || "")
                  .replace(/\s*\(S-1-[0-9-]+\)\s*$/i, "")
                  .trim();
                user = (fallback && fallback !== "-\\-" && fallback !== "-") ? fallback : "";
              }
            }
            if (user && user.includes("\\")) user = user.split("\\").pop();
            if (!user && row._subjectUser) user = String(row._subjectUser).trim();
            if (user && user.includes("\\")) user = user.split("\\").pop();
            if (user && /@/.test(user) && !/\s/.test(user)) user = user.replace(/@[^@]*$/, "");
            // FP: domain controllers legitimately replicate — skip machine accounts (covers DC↔DC
            // replication AND gMSA sync accounts, which appear as principals ending in "$").
            if (user && user.endsWith("$")) continue;
            // FP: skip known directory-sync / replication service accounts. Match SPECIFIC, anchored
            // account-name shapes (not broad prefixes) so an attacker cannot evade DCSync detection by
            // naming an account "entra_admin" / "adsync_payroll", and so we don't suppress ordinary
            // business users like "azure_user". Entra/AAD Connect auto-created accounts have fixed shapes.
            if (
              /^msol_[0-9a-f]+$/i.test(user) ||                 // Azure AD Connect auto-created on-prem account (MSOL_<hex>)
              /^aad_[0-9a-f]+$/i.test(user) ||                  // legacy AAD connector account (AAD_<hex>)
              /^sync_.+_[0-9a-f]{6,}$/i.test(user) ||           // Azure AD Connect cloud sync account (Sync_<host>_<hex>)
              /^(adtoaadsync|aadcsvc|aaddssyncserviceaccount|azureadconnect|entracloudsync)$/i.test(user)
            ) continue;

            _dcHits.push({
              ts: row._ts || "",
              host: (row._host || "").toString().trim().toUpperCase(),
              user: user || "(unknown)",
              rid: row._rid != null ? Number(row._rid) : null,
              hasGetChangesAll: /1131f6ad/i.test(allText),
            });
          }

          if (_dcHits.length > 0) {
            // Group by user
            const _dcByUser = new Map();
            for (const h of _dcHits) {
              const uk = h.user.toUpperCase();
              if (!_dcByUser.has(uk)) _dcByUser.set(uk, []);
              _dcByUser.get(uk).push(h);
            }

            for (const [, hits] of _dcByUser) {
              const user = hits[0].user;
              const hosts = [...new Set(hits.map(h => h.host).filter(Boolean))];
              const allTs = hits.map(h => h.ts).filter(Boolean).sort(cmpTs);
              const hasAll = hits.some(h => h.hasGetChangesAll);

              // DCSync with Get-Changes-All is always critical
              const severity = hasAll ? "critical" : "high";

              const _dcPills = [{ text: "directory replication", type: "credential" }];
              if (hasAll) _dcPills.push({ text: "Get-Changes-All", type: "execution" });
              else _dcPills.push({ text: "Get-Changes", type: "execution" });
              if (hosts.some(h => _DC_PAT.test(h))) _dcPills.push({ text: "DC target", type: "target" });

              findings.push({
                id: fid++, severity, category: "DCSync", mitre: "T1003.006",
                title: `DCSync: ${user} requested directory replication${hasAll ? " (Get-Changes-All)" : ""}`,
                description: `${hits.length} directory service access event(s) (4662) by ${user} with replication rights GUIDs. This is the signature of Mimikatz lsadump::dcsync or similar tools extracting domain credentials directly from Active Directory.${hasAll ? " The Get-Changes-All right was requested, which retrieves password data." : ""}`,
                source: "", target: hosts.join(", "),
                filterHosts: hosts,
                timeRange: { from: allTs[0] || "", to: allTs[allTs.length - 1] || "" },
                eventCount: hits.length, filterEids: ["4662"],
                evidencePills: _dcPills, users: [user],
                itemRowids: hits.map(h => h.rid).filter(r => r != null),
              });
            }
          }
        }
      } catch (_dcErr) { warnings.push(`DCSync detector failed: ${_dcErr.message}`); }

  return fid;
}

module.exports = { detectCredentialAttacks };
