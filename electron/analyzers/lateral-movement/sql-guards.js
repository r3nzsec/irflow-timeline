/**
 * sql-guards.js — WHERE-clause fragments shared by the single-tab and
 * multi-source row queries.
 */

const { TERMSVC_AMBIGUOUS_EIDS, TERMSVC_CHANNEL_HINTS } = require("./constants");

/**
 * SQL guard that stops Sysmon (and any other provider's) small event IDs from
 * being pulled in as TerminalServices RDP events.
 *
 * build-graph.js applies the same rule per row, but doing it in SQL matters
 * independently: on a consolidated EvtxECmd CSV, Sysmon 22 (DNS query) alone can
 * be millions of rows, and it was consuming the analyzer's maxRows budget before
 * the real logon events were ever read.
 *
 * Rows with an empty channel are kept — a raw single-channel .evtx import has no
 * channel column value, and there the ID is unambiguous.
 *
 * @param {string} eidExpr     - safe SQL expression for the event-id column
 * @param {string} channelExpr - safe SQL expression for the channel column
 * @param {string[]} eventIds  - the event IDs the query is already asking for
 * @returns {{sql: string, params: string[]}|null} null when no guard is needed
 */
function termSvcChannelGuard(eidExpr, channelExpr, eventIds) {
  if (!eidExpr || !channelExpr) return null;
  const ambiguous = (eventIds || []).map(String).filter((id) => TERMSVC_AMBIGUOUS_EIDS.has(id));
  if (ambiguous.length === 0) return null;

  const notLike = TERMSVC_CHANNEL_HINTS.map(() => `LOWER(${channelExpr}) NOT LIKE ?`).join(" AND ");
  const sql = `NOT (${eidExpr} IN (${ambiguous.map(() => "?").join(",")})`
    + ` AND ${channelExpr} IS NOT NULL AND TRIM(${channelExpr}) <> ''`
    + ` AND ${notLike})`;
  return { sql, params: [...ambiguous, ...TERMSVC_CHANNEL_HINTS.map((hint) => `%${hint}%`)] };
}

module.exports = { termSvcChannelGuard };
