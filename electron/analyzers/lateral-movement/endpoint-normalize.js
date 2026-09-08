/**
 * Normalize host/address values before they become graph identities.
 *
 * Windows exports commonly mix short hostnames, FQDNs, bracketed addresses,
 * address:port strings, and collector placeholders. Keeping those raw values
 * produces duplicate hosts and false loopback "connections" in the graph.
 */

const PLACEHOLDER_HOSTS = new Set([
  "", "-", "-:-", "(EMPTY)", "(NULL)", "NULL", "N/A", "NA",
  "LOCAL", "LOCALHOST", "UNKNOWN", "(UNKNOWN)",
]);

function normalizeHostEndpoint(value) {
  let host = String(value == null ? "" : value)
    .trim()
    .replace(/^["']|["']$/g, "")
    .replace(/^\\\\+/, "")
    .trim();

  if (!host) return "";

  // [IPv6]:port and [IPv6] forms.
  const bracketed = host.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) host = bracketed[1];

  // IPv4:port and hostname:port. Unbracketed IPv6 is intentionally left alone,
  // except for the common loopback-with-port collector artifact handled below.
  const hostPort = host.match(/^([^:]+):(\d+)$/);
  if (hostPort) host = hostPort[1];
  else {
    const loopbackPort = host.match(/^(::1):\d+$/);
    if (loopbackPort) host = loopbackPort[1];
  }

  host = host.replace(/\.$/, "").trim().toUpperCase();
  // IPv4-mapped IPv6 (::ffff:10.1.1.5) folds to the IPv4 form so Kerberos 4768/4769
  // and NTLM 4624 of the same client become one node.
  host = host.replace(/^::FFFF:(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/i, "$1");
  return PLACEHOLDER_HOSTS.has(host) ? "" : host;
}

function isExcludedEndpoint(value) {
  const host = normalizeHostEndpoint(value);
  if (!host) return true;
  if (/^127(?:\.\d{1,3}){3}$/.test(host)) return true;
  if (host === "0.0.0.0" || host === "::" || host === "::1") return true;
  return false;
}

function _isIpHost(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

/**
 * True when two host labels name the same machine (exact match, or short vs FQDN).
 * IPs are never treated as equal to a hostname here — that merge happens later via
 * observed aliases. Used to drop console logons whose WorkstationName is NetBIOS
 * while Computer is FQDN.
 */
function hostsAreSameMachine(a, b) {
  const na = normalizeHostEndpoint(a);
  const nb = normalizeHostEndpoint(b);
  if (!na || !nb) return false;
  if (na === nb) return true;
  if (_isIpHost(na) || _isIpHost(nb)) return false;
  return na.split(".")[0] === nb.split(".")[0];
}

/**
 * Build conservative FQDN aliases. We merge only when the short name is also
 * observed and maps to exactly one FQDN, avoiding cross-domain collisions.
 */
function buildObservedHostAliases(hosts) {
  const normalized = [...new Set((hosts || []).map(normalizeHostEndpoint).filter(Boolean))];
  const present = new Set(normalized);
  const fqdnByShort = new Map();

  for (const host of normalized) {
    if (!host.includes(".") || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) continue;
    const short = host.split(".")[0];
    if (!fqdnByShort.has(short)) fqdnByShort.set(short, new Set());
    fqdnByShort.get(short).add(host);
  }

  const aliases = new Map();
  for (const [short, fqdns] of fqdnByShort) {
    if (!present.has(short) || fqdns.size !== 1) continue;
    for (const fqdn of fqdns) aliases.set(fqdn, short);
  }
  return aliases;
}

module.exports = {
  PLACEHOLDER_HOSTS,
  normalizeHostEndpoint,
  isExcludedEndpoint,
  hostsAreSameMachine,
  buildObservedHostAliases,
};
