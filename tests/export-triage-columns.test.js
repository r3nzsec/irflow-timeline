const test = require("node:test");
const assert = require("node:assert/strict");

const queryStore = require("../electron/db/query-store");

/**
 * exportQuery only needs a column map, an ORDER BY builder, and a statement
 * factory — enough to assert what SQL it emits and what header/column pair the
 * writers will iterate over.
 */
function makeContext({ hasTriage }) {
  let lastSql = null;
  const meta = {
    headers: ["Timestamp", "Message"],
    colMap: { Timestamp: "c0", Message: "c1" },
    reverseColMap: { c0: "Timestamp", c1: "Message" },
    tsColumns: new Set(["Timestamp"]),
    numericColumns: new Set(),
    db: {
      prepare(sql) {
        lastSql = sql;
        return {
          get() { return { any: hasTriage ? 1 : 0 }; },
          iterate() { return [][Symbol.iterator](); },
        };
      },
    },
  };
  const context = Object.create(queryStore);
  context.databases = new Map([["tab", meta]]);
  context._applyStandardFilters = () => {};
  context._buildOrderClause = () => "ORDER BY data.rowid ASC";
  return { context, getSql: () => lastSql };
}

test("export keeps its original shape when the tab carries no triage", () => {
  const { context } = makeContext({ hasTriage: false });
  const out = context.exportQuery("tab", { includeTriage: true });
  assert.deepEqual(out.headers, ["Timestamp", "Message"]);
  assert.deepEqual(out.safeCols, ["c0", "c1"]);
});

test("export appends Tags and Bookmarked when the tab is triaged", () => {
  const { context, getSql } = makeContext({ hasTriage: true });
  const out = context.exportQuery("tab", { includeTriage: true });
  assert.deepEqual(out.headers, ["Timestamp", "Message", "Tags", "Bookmarked"]);
  assert.deepEqual(out.safeCols, ["c0", "c1", "_tle_tags", "_tle_bookmarked"]);
  const sql = getSql();
  assert.match(sql, /group_concat\(t\.tag, '; '\)/);
  assert.match(sql, /ORDER BY tag/);
  assert.match(sql, /EXISTS\(SELECT 1 FROM bookmarks WHERE bookmarks\.rowid = data\.rowid\)/);
});

test("export omits the triage columns unless they are asked for", () => {
  const { context } = makeContext({ hasTriage: true });
  const out = context.exportQuery("tab", {});
  assert.deepEqual(out.headers, ["Timestamp", "Message"]);
  assert.deepEqual(out.safeCols, ["c0", "c1"]);
});

test("visibleHeaders is not mutated by the triage append", () => {
  const { context } = makeContext({ hasTriage: true });
  const visibleHeaders = ["Timestamp"];
  const out = context.exportQuery("tab", { includeTriage: true, visibleHeaders });
  assert.deepEqual(visibleHeaders, ["Timestamp"], "caller's array must be left alone");
  assert.deepEqual(out.headers, ["Timestamp", "Tags", "Bookmarked"]);
});
