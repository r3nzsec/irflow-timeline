/**
 * lateral-movement/convention-detector.js — Domain Naming Convention Detection
 *
 * Infers the environment's hostname naming convention by analyzing the majority
 * of hosts in the dataset, then flags hosts that don't match as anomalous.
 *
 * In a GFUA-* domain, DESKTOP-V7DR1GC is anomalous. In a DESKTOP-* environment,
 * GFUA-WKS02 would be anomalous. The detection is statistical, not hardcoded.
 *
 * Algorithm:
 *   1. Collect target hosts from hostSet (machines that received logons = environment members)
 *   2. Split each hostname on delimiters (-_.), group by first token (prefix)
 *   3. A prefix is a "convention" if it covers >= 50% of target hosts AND >= minCount
 *   4. Any host NOT matching a detected convention = convention outlier
 *
 * Returns: { conventions, conventionOutliers }
 */

const DC_PAT = /(?:^|[\-_])(DC|PDC|BDC|ADDS|ADCS|ADFS)\d{0,3}(?:$|[\-_])|^AD\d{0,3}$/i;
const SRV_PAT = /^(SVR|SRV|SERVER|FS|SQL|EXCH|MAIL|WEB|APP|DB|CA|WSUS|SCCM|SCOM|PRINT|FILE|DNS|DHCP|NPS|RADIUS|VPN|RDS|RDSH|RDCB|RDGW)(?=[_\-\d]|$)/i;

/**
 * Extract the naming prefix from a hostname.
 * Split on common delimiters (-_.), return the first token uppercased.
 * Skip purely numeric tokens and very short (1-char) tokens.
 */
function extractPrefix(hostname) {
  if (!hostname) return null;
  // Remove domain suffix (.domain.local, etc.)
  const bare = hostname.split(".")[0].toUpperCase();
  // Split on delimiters
  const parts = bare.split(/[-_]/);
  if (parts.length === 0) return null;
  const first = parts[0];
  // Skip purely numeric or single-char prefixes (too generic)
  if (!first || first.length < 2 || /^\d+$/.test(first)) return null;
  return first;
}

// Default Windows random name prefixes — these should NOT form a convention
// but hosts with these prefixes CAN be flagged as convention outliers
const DEFAULT_WIN_PREFIXES = new Set(["DESKTOP", "WIN"]);

/**
 * Detect naming conventions and convention outliers from the host set.
 *
 * @param {Map} hostSet - Map of hostname -> {isSource, isTarget, eventCount}
 * @param {Object} [opts] - Options
 * @param {number} [opts.minFraction=0.4] - Minimum fraction of target hosts for a prefix to be a convention
 * @param {number} [opts.minCount=2] - Minimum number of hosts sharing a prefix
 * @param {Array<{host: string, eventCount: number}>} [opts.computerHosts] - Additional hostnames from Computer column (may not be in hostSet)
 * @returns {{ conventions: Array<{prefix, count, fraction, hosts}>, conventionOutliers: Map<string, {reason, conventionPrefix}> }}
 */
function detectConventions(hostSet, opts = {}) {
  const { minFraction = 0.4, minCount = 2, computerHosts = [] } = opts;

  // Collect target hosts (machines that received logons = environment members)
  // Include all hosts to cover KAPE collections where the Computer column hosts are targets
  const targetHosts = [];
  const seen = new Set();
  const _skipHost = (id) => {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(id)) return true;
    if (id.includes(":") && /^[0-9A-Fa-f.:]+$/.test(id)) return true;
    if (/^(-|--|-:-|LOCAL|LOCALHOST|\*|::1:0)$/i.test(id)) return true;
    return false;
  };
  for (const [id, info] of hostSet) {
    if (_skipHost(id)) continue;
    targetHosts.push(id);
    seen.add(id);
  }
  // Merge Computer column hosts that aren't already in hostSet
  // These are machines where events were logged but that never appeared in logon edges
  for (const ch of computerHosts) {
    const norm = ch.host.toUpperCase();
    if (seen.has(norm) || _skipHost(norm)) continue;
    targetHosts.push(norm);
    seen.add(norm);
  }

  if (targetHosts.length < 3) {
    // Not enough hosts to infer a convention
    return { conventions: [], conventionOutliers: new Map() };
  }

  // Group by prefix — exclude default Windows prefixes from convention formation
  // (DESKTOP-*/WIN-* are random names that shouldn't define a convention)
  const prefixGroups = new Map(); // prefix -> [hostname, ...]
  for (const host of targetHosts) {
    const prefix = extractPrefix(host);
    if (!prefix) continue;
    if (DEFAULT_WIN_PREFIXES.has(prefix)) continue; // don't let random names form a convention
    if (!prefixGroups.has(prefix)) prefixGroups.set(prefix, []);
    prefixGroups.get(prefix).push(host);
  }

  // Identify conventions: prefix covers >= minFraction of convention-eligible hosts
  // (total = hosts with extractable non-default-Windows prefixes)
  let totalHosts = 0;
  for (const host of targetHosts) {
    const p = extractPrefix(host);
    if (p && !DEFAULT_WIN_PREFIXES.has(p)) totalHosts++;
  }
  if (totalHosts < 2) return { conventions: [], conventionOutliers: new Map() };
  const conventions = [];
  for (const [prefix, hosts] of prefixGroups) {
    const fraction = hosts.length / totalHosts;
    if (fraction >= minFraction && hosts.length >= minCount) {
      conventions.push({ prefix, count: hosts.length, fraction, hosts });
    }
  }

  // If no conventions detected, fall back to majority prefix (if one exists with 2+ hosts)
  if (conventions.length === 0) {
    let bestPrefix = null, bestCount = 0;
    for (const [prefix, hosts] of prefixGroups) {
      if (hosts.length > bestCount) { bestPrefix = prefix; bestCount = hosts.length; }
    }
    if (bestPrefix && bestCount >= minCount) {
      const hosts = prefixGroups.get(bestPrefix);
      conventions.push({ prefix: bestPrefix, count: bestCount, fraction: bestCount / totalHosts, hosts });
    }
  }

  if (conventions.length === 0) {
    return { conventions: [], conventionOutliers: new Map() };
  }

  // Build set of convention prefixes
  const conventionPrefixes = new Set(conventions.map(c => c.prefix));

  // Identify outliers: hosts whose prefix doesn't match any convention
  const conventionOutliers = new Map(); // hostname -> { reason, conventionPrefix }
  const primaryConvention = conventions.sort((a, b) => b.count - a.count)[0];

  for (const host of targetHosts) {
    const prefix = extractPrefix(host);
    // No extractable prefix (IP, single token, numeric) — not a naming convention outlier
    if (!prefix) continue;
    // If host has a prefix that matches a convention, it's not an outlier
    if (conventionPrefixes.has(prefix)) continue;
    // Skip DCs and servers — they often have different naming and are expected
    if (DC_PAT.test(host) || SRV_PAT.test(host)) continue;

    const reason = `Does not match ${primaryConvention.prefix}-* convention (${primaryConvention.count}/${totalHosts} hosts)`;
    conventionOutliers.set(host, {
      reason,
      conventionPrefix: primaryConvention.prefix,
    });
  }

  return { conventions, conventionOutliers };
}

/**
 * Generate findings from convention outliers.
 *
 * @param {Map} conventionOutliers - hostname -> {reason, conventionPrefix}
 * @param {Map} hostSet - hostname -> {isSource, isTarget, eventCount}
 * @param {Set} outlierHosts - existing outlier host set (to merge into)
 * @param {number} startFid - starting finding ID
 * @param {Array<{host: string, eventCount: number}>} [computerHosts] - Computer column hosts with event counts
 * @returns {{ findings: Array, fid: number, updatedOutlierHosts: Set }}
 */
function generateConventionFindings(conventionOutliers, hostSet, outlierHosts, startFid, computerHosts = []) {
  let fid = startFid;
  const findings = [];
  const updatedOutlierHosts = new Set(outlierHosts);

  // Build a lookup for Computer-column-only hosts (not in hostSet)
  const computerHostMap = new Map();
  for (const ch of computerHosts) {
    computerHostMap.set(ch.host.toUpperCase(), ch.eventCount);
  }

  for (const [host, info] of conventionOutliers) {
    // Add to outlier set so other detectors (brute force, operator host) can use this signal
    updatedOutlierHosts.add(host);

    const hostInfo = hostSet.get(host);
    const computerEventCount = computerHostMap.get(host) || 0;

    // Severity based on host role:
    //   - Source-only (never a target/Computer): high — likely external attacker machine
    //   - Both source and target in logon graph: medium — could be BYOD or rogue device
    //   - Computer-column-only (not in logon graph): medium — suspicious machine in KAPE collection
    //   - Target-only in logon graph: low — could be a renamed machine
    let severity;
    if (hostInfo) {
      if (hostInfo.isSource && !hostInfo.isTarget) severity = "high";
      else if (hostInfo.isSource && hostInfo.isTarget) severity = "medium";
      else severity = "low";
    } else {
      // Host only appears in Computer column, not in any logon edge
      severity = computerEventCount > 100 ? "medium" : "low";
    }

    const evtCount = hostInfo?.eventCount || computerEventCount || 0;
    const pills = [
      { text: `No match for ${info.conventionPrefix}-*`, type: "target" },
    ];
    if (hostInfo?.isSource) pills.push({ text: "appears as source", type: "correlation" });
    if (hostInfo?.isTarget) pills.push({ text: "appears as target", type: "context" });
    if (!hostInfo && computerEventCount > 0) pills.push({ text: "Computer column only", type: "context" });
    if (evtCount > 10) pills.push({ text: `${evtCount} events`, type: "context" });

    findings.push({
      id: fid++,
      severity,
      category: "Anomalous Hostname",
      mitre: "T1036",
      title: `Non-domain hostname: ${host}`,
      description: `${host} does not match the environment naming convention (${info.conventionPrefix}-*).${!hostInfo && computerEventCount > 0 ? ` Found in Computer column with ${computerEventCount} events but no logon edge participation.` : ""} This may indicate an attacker-controlled machine, rogue device, or BYOD endpoint. ${info.reason}`,
      source: hostInfo?.isSource ? host : "",
      target: (hostInfo?.isTarget || computerEventCount > 0) ? host : "",
      timeRange: { from: "", to: "" },
      eventCount: evtCount,
      evidencePills: pills,
      users: [],
      conventionOutlier: true,
    });
  }

  return { findings, fid, updatedOutlierHosts };
}

module.exports = { detectConventions, generateConventionFindings, extractPrefix };
