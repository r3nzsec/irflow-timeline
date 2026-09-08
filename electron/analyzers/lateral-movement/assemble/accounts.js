/**
 * assemble/accounts.js — per-user account aggregation for the lateral-movement analyzer.
 *
 * Builds the "Accounts" tab profiles (one per user) from the analyzed events,
 * RDP sessions, findings, and raw per-user event counts. Extracted verbatim from
 * getLateralMovement(). Pure producer: reads its inputs, builds the accounts array,
 * and returns it (no mutation of shared structures, no findings pushed).
 *
 * @param {object} state - { timeOrdered, rdpSessions, findings, userEventCounts,
 *                           userEventOriginalName, _outlierHosts }
 * @returns {Array} accounts (sorted by suspicion score, then activity)
 */
const { SERVICE_RE, PRIVILEGED_NAME_RE } = require("../constants");
const { normalizeTimestamp, normalizeLogonId } = require("../../../utils/forensic-normalize");

function aggregateAccounts(state) {
  const { timeOrdered, rdpSessions, findings, userEventCounts, userEventOriginalName, _outlierHosts } = state;
  // Scoped per-user counts (events that survived the lateral-movement exclusion
  // filters). Default to an empty Map so older callers/tests that don't supply it
  // simply get zeroed scoped counts (raw counts still surface).
  const userEventCountsScoped = state.userEventCountsScoped || new Map();
  // 4672 (admin-privilege-assigned) occurrences { userKey, host, ts } for correlating
  // admin privilege to scoped 4624 logons (Pass 4b). Default [] for older callers.
  const privLogonEvents = state.privLogonEvents || [];
  // Earliest 4624 (success) ts per user across ALL events incl. excluded local/service
  // logons — used to measure failures-before-first-success against the TRUE first
  // success. Default empty Map; Pass 1b falls back to the first scoped success.
  const userFirstSuccessTs = state.userFirstSuccessTs || new Map();

  // Extend an account's observed [firstSeen, lastSeen] activity window. Lexical
  // compare is valid for the canonical ISO / "YYYY-MM-DD HH:MM:SS" timestamps used
  // throughout. The window reflects lateral-movement-scoped activity (logon +
  // explicit-cred from timeOrdered, plus RDP sessions) — consistent with the other
  // scoped columns — so a raw-only account (e.g. Kerberos-only on a DC) stays blank.
  const _extendWindow = (acct, ts) => {
    if (!ts) return;
    if (!acct.firstSeen || ts < acct.firstSeen) acct.firstSeen = ts;
    if (!acct.lastSeen || ts > acct.lastSeen) acct.lastSeen = ts;
  };

      // === Accounts Aggregation ===
      // Build per-user identity profiles for the Accounts tab.
      // Sources of truth:
      //   - timeOrdered: per-event source/target/auth-type/success-fail (4672/4769/4634/etc. excluded)
      //   - rdpSessions: hasAdmin (4672 correlated), isConcurrent, suspicionScore, technique
      //   - findings:    f.users[] for findings count per user
      //   - userEventCounts: raw per-user event counts incl. 4648/4776/4769 (pre-filter)
      //   - _outlierHosts: cheap outlier check for source-host-based scoring
      const _accountMap = new Map();
      // Reject strings that are clearly not user accounts — EvtxECmd session metadata
      // that leaked through the user extraction pipeline (e.g. "Session ID: 8",
      // "TargetSession: 9", "Session: 10", "Source: 8", corrupted map descriptions).
      const _notAUser = /^(Session(\s*ID)?|TargetSession|Source)\s*:\s*\d+$|^\s*reason\s+code\b|^PayloadData\d/i;
      const _getAcct = (rawUser) => {
        if (!rawUser) return null;
        const u = rawUser.trim();
        if (!u || u === "-" || _notAUser.test(u)) return null;
        const key = u.toUpperCase();
        if (!_accountMap.has(key)) {
          _accountMap.set(key, {
            user: u,
            sourceHosts: new Set(),
            targetHosts: new Set(),
            // Per-channel host sets (used only to build the source/target breakdown).
            // Sources/Targets aggregate distinct hosts across logon (4624/4625),
            // explicit-cred (4648), and RDP sessions — so the column can legitimately
            // exceed Successes+Failures. The breakdown partitions the aggregate (by
            // precedence logon > explicit > rdp > other) to explain that to analysts.
            logonSourceHosts: new Set(),
            logonTargetHosts: new Set(),
            explicitSourceHosts: new Set(),
            explicitTargetHosts: new Set(),
            rdpSourceHosts: new Set(),
            rdpTargetHosts: new Set(),
            logonTypes: new Set(),
            eids: new Set(),
            successCount: 0,
            failureCount: 0,
            firstSeen: "",
            lastSeen: "",
            firstSuccessTs: "",
            failuresBeforeFirstSuccess: 0,
            outlierSourceHits: 0,      // set to outlierSources.size in Pass 5
            outlierSources: new Set(), // distinct outlier source hosts (not event hits)
            // RDP-specific (filled from rdpSessions)
            rdpSessionCount: 0,
            rdpSuspiciousCount: 0,
            rdpAdminCount: 0,
            rdpConcurrentCount: 0,
            rdpFailedCount: 0,
            rdpFailedAttemptCount: 0,
            rdpReconnectCount: 0,
            // Per-user counts — SCOPED to the lateral-movement population (primary;
            // shown in the table + used for scoring/Class). Filled from userEventCountsScoped.
            kerberosCount: 0,
            ntlmCount: 0,
            explicitCredsCount: 0,
            adminPrivilegeCount: 0, // 4672 events that survived the exclusion filters
            // Raw host-wide counts (pre-filter; surfaced only as a labeled secondary).
            kerberosCountRaw: 0,
            ntlmCountRaw: 0,
            explicitCredsCountRaw: 0,
            adminPrivilegeCountRaw: 0, // all 4672 for the user (incl. local/service)
            // Findings refs
            findingIds: [],
            findingCategories: new Set(),
            // Classification
            isMachineAccount: false,
            isServiceAccount: false,
            isPrivilegedName: false,
          });
        }
        return _accountMap.get(key);
      };

      // Pass 1: walk timeOrdered for source/target/auth/first-last/success-fail
      // PRIVILEGED_NAME_RE → ./constants
      for (const evt of timeOrdered) {
        const acct = _getAcct(evt.user);
        if (!acct) continue;
        const _isLogonEvt = evt.eventId === "4624" || evt.eventId === "4625";
        const _isExplicitEvt = evt.eventId === "4648";
        if (evt.source) {
          acct.sourceHosts.add(evt.source);
          if (_isLogonEvt) acct.logonSourceHosts.add(evt.source);
          else if (_isExplicitEvt) acct.explicitSourceHosts.add(evt.source);
        }
        if (evt.target) {
          acct.targetHosts.add(evt.target);
          if (_isLogonEvt) acct.logonTargetHosts.add(evt.target);
          else if (_isExplicitEvt) acct.explicitTargetHosts.add(evt.target);
        }
        if (evt.logonType) acct.logonTypes.add(evt.logonType);
        if (evt.eventId) acct.eids.add(evt.eventId);
        const isFail = evt.eventId === "4625";
        const isSucc = evt.eventId === "4624";
        if (isFail) acct.failureCount++;
        if (isSucc) {
          acct.successCount++;
          if (!acct.firstSuccessTs && evt.ts) {
            acct.firstSuccessTs = evt.ts;
            // Failures-before-first-success calculated below in Pass 1b
          }
        }
        _extendWindow(acct, evt.ts);
        // Track DISTINCT outlier source hosts (not per-event hits) so the score/flag
        // reflect "how many unusual sources" rather than "how many events".
        if (evt.source && _outlierHosts.has(evt.source)) acct.outlierSources.add(evt.source);
      }

      // Pass 1b: failures-before-first-success. Count scoped 4625 failures that
      // precede the account's TRUE first success — the earliest 4624 anywhere
      // (userFirstSuccessTs, incl. excluded local/service logons), falling back to the
      // first scoped success when that map isn't supplied. Measuring against the true
      // first success means a prior (often local) success correctly zeroes the
      // brute-force signal instead of counting later remote retries as "before first
      // success". Failure-only accounts (no success ever) keep 0, as before.
      const _scopedFirstSucc = new Map();
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4624" || !evt.user || !evt.ts) continue;
        const k = evt.user.toUpperCase();
        const cur = _scopedFirstSucc.get(k);
        if (!cur || evt.ts < cur) _scopedFirstSucc.set(k, evt.ts);
      }
      for (const evt of timeOrdered) {
        if (evt.eventId !== "4625" || !evt.user || !evt.ts) continue;
        const k = evt.user.toUpperCase();
        const trueFirst = userFirstSuccessTs.get(k) || _scopedFirstSucc.get(k);
        if (trueFirst && evt.ts < trueFirst) {
          const acct = _accountMap.get(k);
          if (acct) acct.failuresBeforeFirstSuccess++;
        }
      }

      // Pass 2: walk rdpSessions for RDP-specific stats
      for (const s of rdpSessions) {
        const acct = _getAcct(s.user);
        if (!acct) continue;
        const isFailedActivity = s.status === "failed";
        // Incomplete / connecting = 1149 (or similar) without a proven session start.
        // Keep source/target and the activity window; do not call it an RDP session.
        const isEstablished = !isFailedActivity && s.status !== "incomplete" && s.status !== "connecting";
        if (isEstablished) acct.rdpSessionCount++;
        if (isEstablished && (s.suspicionScore || 0) >= 25) acct.rdpSuspiciousCount++;
        if (isEstablished && s.hasAdmin) acct.rdpAdminCount++;
        if (isEstablished && s.isConcurrent) acct.rdpConcurrentCount++;
        if (isFailedActivity) {
          acct.rdpFailedCount++;
          acct.rdpFailedAttemptCount += s.attemptCount || 1;
        }
        if (isEstablished && s.isReconnect) acct.rdpReconnectCount++;
        if (s.source) { acct.sourceHosts.add(s.source); acct.rdpSourceHosts.add(s.source); }
        if (s.target) { acct.targetHosts.add(s.target); acct.rdpTargetHosts.add(s.target); }
        // RDP sessions are scoped lateral activity — extend the First/Last Seen window
        // so it isn't understated for accounts whose RDP spans beyond their logon events.
        _extendWindow(acct, s.startTime);
        _extendWindow(acct, s.endTime);
      }

      // Pass 3: walk findings for findings refs
      for (const f of findings) {
        const fUsers = Array.isArray(f.users) ? f.users : [];
        for (const u of fUsers) {
          const acct = _getAcct(u);
          if (!acct) continue;
          acct.findingIds.push(f.id);
          if (f.category) acct.findingCategories.add(f.category);
        }
      }

      // Pass 4: pull per-user counts (Kerberos/NTLM/explicit/4672). Two populations:
      //   - raw (userEventCounts): every such event for the user, host-wide and
      //     pre-filter — incl. local logons and service/machine accounts. Kept only
      //     as a clearly-labeled secondary (the *Raw fields).
      //   - scoped (userEventCountsScoped): only events that survived the exclusion
      //     filters (real non-local source, non-service/non-machine user) — the
      //     PRIMARY counts shown in the table and used for scoring/Class.
      // Use _getAcct() (not _accountMap.get) so users that exist ONLY in raw event
      // counts — never produced a graph edge or finding — still appear in the Accounts
      // tab (e.g. domain accounts seen only in Kerberos 4769 / NTLM 4776 on a DC log).
      // By construction scoped ⊆ raw, so iterating the raw map covers every account.
      const _kerb = (m) => (m.get("4769") || 0) + (m.get("4768") || 0) + (m.get("4771") || 0);
      for (const [key, eidMap] of userEventCounts) {
        const originalName = userEventOriginalName.get(key) || key;
        const acct = _getAcct(originalName);
        if (!acct) continue;
        acct.kerberosCountRaw = _kerb(eidMap);
        acct.ntlmCountRaw = eidMap.get("4776") || 0;
        acct.explicitCredsCountRaw = eidMap.get("4648") || 0;
        acct.adminPrivilegeCountRaw = eidMap.get("4672") || 0;
        const scoped = userEventCountsScoped.get(key);
        if (scoped) {
          acct.kerberosCount = _kerb(scoped);
          acct.ntlmCount = scoped.get("4776") || 0;
          acct.explicitCredsCount = scoped.get("4648") || 0;
          // adminPrivilegeCount is NOT taken from the scoped map — 4672 has no source
          // host, so it is scoped via (user, host, time) correlation in Pass 4b below.
        }
        // No scoped entry → scoped counts stay 0 (account had no lateral-movement-
        // relevant privilege/credential events). Raw counts still reflect the total.
      }

      // Pass 4b: correlate 4672 (admin privilege assigned) to SCOPED 4624 logons by
      // (user, host, ~time). Windows writes the 4672 and its 4624 together for one
      // logon session, so a *privileged lateral logon* is a scoped 4624 that has a
      // 4672 for the same user+host in the same second (±1s). This recovers the ADMIN
      // signal for network (type 3) and other non-RDP privileged logons that the
      // source-based scoped filter can't see. adminPrivilegeCount = count of such
      // privileged lateral logons (each backed by one 4672). Host-wide / local /
      // service 4672 never matches (those users have no scoped 4624), so it can't
      // re-inflate the count we fixed in the scoped-counts work.
      if (privLogonEvents.length) {
        const _sec = (ts) => {
          const t = normalizeTimestamp(ts);
          return Number.isFinite(t) ? Math.floor(t / 1000) : null;
        };
        const privSeconds = new Set();
        // Exact identity index: a 4672's SubjectLogonId IS the 4624's TargetLogonId
        // for the same session. When both sides carry it there is nothing to guess.
        const privLogonIds = new Set();
        for (const p of privLogonEvents) {
          const s = _sec(p.ts);
          if (!p.host || !p.userKey) continue;
          if (p.logonId) privLogonIds.add(`${p.userKey}|${p.host}|${p.logonId}`);
          if (s == null) continue;
          privSeconds.add(`${p.userKey}|${p.host}|${s}`);
        }
        if (privSeconds.size || privLogonIds.size) {
          const _privCount = new Map(); // userKey -> correlated privileged-logon count
          for (const evt of timeOrdered) {
            if (evt.eventId !== "4624" || !evt.user || !evt.target) continue;
            const k = evt.user.toUpperCase();
            const evtLogonId = normalizeLogonId(evt.logonId || "");
            // Prefer the exact join. Only fall back to the ±1s window when one of
            // the two sides did not record a logon id at all.
            if (evtLogonId && privLogonIds.size > 0) {
              if (privLogonIds.has(`${k}|${evt.target}|${evtLogonId}`)) {
                _privCount.set(k, (_privCount.get(k) || 0) + 1);
              }
              continue;
            }
            const s = _sec(evt.ts);
            if (s == null) continue;
            if (privSeconds.has(`${k}|${evt.target}|${s}`) ||
                privSeconds.has(`${k}|${evt.target}|${s - 1}`) ||
                privSeconds.has(`${k}|${evt.target}|${s + 1}`)) {
              _privCount.set(k, (_privCount.get(k) || 0) + 1);
            }
          }
          for (const [k, n] of _privCount) {
            const acct = _accountMap.get(k);
            if (acct) acct.adminPrivilegeCount = n;
          }
        }
      }

      // Pass 5: classification + suspicion scoring
      for (const acct of _accountMap.values()) {
        acct.isMachineAccount = acct.user.endsWith("$");
        acct.isServiceAccount = SERVICE_RE.test(acct.user) || /^(SVC[_\-]|SERVICE[_\-])/i.test(acct.user);
        acct.isPrivilegedName = PRIVILEGED_NAME_RE.test(acct.user);
        // Distinct outlier source hosts (collected as a Set in Pass 1).
        acct.outlierSourceHits = acct.outlierSources.size;

        let score = 0;
        const flags = [];
        // Admin signal is SCOPED: a 4672 that survived the exclusion filters, or an
        // RDP session correlated to admin privileges. Host-wide local/service 4672
        // (adminPrivilegeCountRaw) does NOT contribute — that was the main score
        // inflator. The two cases get distinct, accurate flag text (no more printing
        // an RDP session count as "Nx 4672").
        if (acct.adminPrivilegeCount > 0) {
          score += 20;
          flags.push(`Admin privilege (${acct.adminPrivilegeCount}x 4672)`);
        } else if (acct.rdpAdminCount > 0) {
          score += 20;
          flags.push(`Admin via RDP (${acct.rdpAdminCount} session${acct.rdpAdminCount !== 1 ? "s" : ""})`);
        }
        if (acct.failuresBeforeFirstSuccess >= 5) {
          score += 15;
          flags.push(`${acct.failuresBeforeFirstSuccess} failures before first success`);
        } else if (acct.failuresBeforeFirstSuccess >= 2) {
          score += 5;
          flags.push(`${acct.failuresBeforeFirstSuccess} failures before first success`);
        }
        if (acct.rdpConcurrentCount > 0) {
          score += 15;
          flags.push(`Concurrent RDP (${acct.rdpConcurrentCount} sessions)`);
        }
        if (acct.explicitCredsCount > 0) {
          score += 12;
          flags.push(`Explicit creds (${acct.explicitCredsCount}x 4648)`);
        }
        if (acct.targetHosts.size >= 5) {
          score += 10;
          flags.push(`Touched ${acct.targetHosts.size} targets`);
        } else if (acct.targetHosts.size >= 3) {
          score += 5;
          flags.push(`Touched ${acct.targetHosts.size} targets`);
        }
        if (acct.findingIds.length > 0) {
          score += Math.min(15, acct.findingIds.length * 5);
          flags.push(`${acct.findingIds.length} finding${acct.findingIds.length !== 1 ? "s" : ""}`);
        }
        if (acct.outlierSourceHits > 0) {
          score += 8;
          flags.push(`From outlier source${acct.outlierSourceHits > 1 ? "s" : ""}`);
        }
        if (acct.ntlmCount > 0 && acct.kerberosCount === 0) {
          score += 5;
          flags.push("NTLM only (no Kerberos)");
        }
        if (acct.isPrivilegedName) {
          score += 5;
          flags.push("Privileged name");
        }
        if (acct.rdpSuspiciousCount > 0) {
          score += 10;
          flags.push(`${acct.rdpSuspiciousCount} suspicious RDP`);
        }
        // Dampen pure machine accounts that only do network logons
        if (acct.isMachineAccount && acct.rdpSessionCount === 0 && acct.adminPrivilegeCount === 0) {
          score = Math.max(0, Math.floor(score * 0.4));
        }
        // Dampen well-known service accounts unless they have admin or findings
        if (acct.isServiceAccount && acct.adminPrivilegeCount === 0 && acct.findingIds.length === 0) {
          score = Math.max(0, Math.floor(score * 0.5));
        }
        acct.suspicionScore = score;
        acct.flags = flags;
      }

      // Partition the aggregate host set across channels (each distinct host assigned
      // to exactly one channel by precedence logon > explicit > rdp > other), so the
      // four counts sum to the aggregate and explain why Sources/Targets can exceed
      // Successes+Failures. "other" = NTLM (4776) / share (5140/5145) / etc.
      const _breakdown = (agg, logonSet, explicitSet, rdpSet) => {
        let logon = 0, explicit = 0, rdp = 0, other = 0;
        for (const h of agg) {
          if (logonSet.has(h)) logon++;
          else if (explicitSet.has(h)) explicit++;
          else if (rdpSet.has(h)) rdp++;
          else other++;
        }
        return { logon, explicit, rdp, other };
      };

      // Materialize accounts array (Sets → arrays for IPC)
      const accounts = [..._accountMap.values()].map(a => ({
        user: a.user,
        sourceHosts: [...a.sourceHosts],
        targetHosts: [...a.targetHosts],
        sourceBreakdown: _breakdown(a.sourceHosts, a.logonSourceHosts, a.explicitSourceHosts, a.rdpSourceHosts),
        targetBreakdown: _breakdown(a.targetHosts, a.logonTargetHosts, a.explicitTargetHosts, a.rdpTargetHosts),
        logonTypes: [...a.logonTypes],
        eids: [...a.eids],
        successCount: a.successCount,
        failureCount: a.failureCount,
        failuresBeforeFirstSuccess: a.failuresBeforeFirstSuccess,
        firstSeen: a.firstSeen,
        lastSeen: a.lastSeen,
        firstSuccessTs: a.firstSuccessTs,
        outlierSourceHits: a.outlierSourceHits,
        rdpSessionCount: a.rdpSessionCount,
        rdpSuspiciousCount: a.rdpSuspiciousCount,
        rdpAdminCount: a.rdpAdminCount,
        rdpConcurrentCount: a.rdpConcurrentCount,
        rdpFailedCount: a.rdpFailedCount,
        rdpFailedAttemptCount: a.rdpFailedAttemptCount,
        rdpReconnectCount: a.rdpReconnectCount,
        kerberosCount: a.kerberosCount,
        ntlmCount: a.ntlmCount,
        explicitCredsCount: a.explicitCredsCount,
        adminPrivilegeCount: a.adminPrivilegeCount,
        kerberosCountRaw: a.kerberosCountRaw,
        ntlmCountRaw: a.ntlmCountRaw,
        explicitCredsCountRaw: a.explicitCredsCountRaw,
        adminPrivilegeCountRaw: a.adminPrivilegeCountRaw,
        findingIds: a.findingIds,
        findingCategories: [...a.findingCategories],
        isMachineAccount: a.isMachineAccount,
        isServiceAccount: a.isServiceAccount,
        isPrivilegedName: a.isPrivilegedName,
        suspicionScore: a.suspicionScore,
        flags: a.flags,
      }));
      // Sort by suspicion score desc, then by activity (success+failure) desc
      accounts.sort((a, b) => (b.suspicionScore - a.suspicionScore) || ((b.successCount + b.failureCount) - (a.successCount + a.failureCount)));


  return accounts;
}

module.exports = { aggregateAccounts };
