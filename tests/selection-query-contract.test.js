const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const queryStore = require("../electron/db/query-store");

test("standard filters support select-all row-ID exclusions", () => {
  const whereConditions = [];
  queryStore._applyExcludedRowIds.call(queryStore, [
    42, "43", 42, 0, -1, "bad",
  ], whereConditions);

  assert.deepEqual(whereConditions, ["data.rowid NOT IN (42,43)"]);
});

test("position queries use deterministic rowid tie-breakers", () => {
  const meta = {
    colMap: { timestamp: "c0", score: "c1", event: "c2" },
    tsColumns: new Set(["timestamp"]),
    numericColumns: new Set(["score"]),
  };
  const context = { _ensureIndex() {} };

  assert.equal(
    queryStore._buildOrderExpression.call(context, meta, "tab", "timestamp", "desc"),
    "sort_datetime(c0) DESC, data.rowid ASC",
  );
  assert.equal(
    queryStore._buildOrderExpression.call(context, meta, "tab", "score", "asc"),
    "CAST(c1 AS REAL) ASC, data.rowid ASC",
  );
  assert.equal(
    queryStore._buildOrderExpression.call(context, meta, "tab", "event", "asc"),
    "c2 COLLATE NOCASE ASC, data.rowid ASC",
  );
});

test("range selection resolves stable IDs from the full SQLite view", () => {
  let captured;
  const meta = {
    colMap: { timestamp: "c0" },
    tsColumns: new Set(["timestamp"]),
    numericColumns: new Set(),
    db: {
      prepare(sql) {
        return {
          all(...params) {
            captured = { sql, params };
            return [{ _rowid: 101 }, { _rowid: 909 }];
          },
        };
      },
    },
  };
  const context = {
    databases: new Map([["tab", meta]]),
    _applyStandardFilters(options, _meta, where, params) {
      where.push("c0 LIKE ?");
      params.push("%2026%");
    },
    _buildOrderExpression: queryStore._buildOrderExpression,
    _ensureIndex() {},
  };

  const result = queryStore.getRowIdsInRange.call(context, "tab", {
    offset: 12_000,
    limit: 2,
    sortCol: "timestamp",
    sortDir: "desc",
  });

  assert.deepEqual(result, { rowIds: [101, 909] });
  assert.match(captured.sql, /ORDER BY sort_datetime\(c0\) DESC, data\.rowid ASC/);
  assert.deepEqual(captured.params, ["%2026%", 2, 12_000]);
});

test("hidden-selection count intersects explicit IDs with current filters", () => {
  let captured;
  const context = {
    databases: new Map([["tab", {
      db: {
        prepare(sql) {
          return {
            get(...params) {
              captured = { sql, params };
              return { cnt: 1 };
            },
          };
        },
      },
    }]]),
    _applyStandardFilters(options, meta, where, params) {
      where.push("c0 = ?");
      params.push("visible");
    },
    _applyRowIdFilter: queryStore._applyRowIdFilter,
    _normalizeRowIdFilter: queryStore._normalizeRowIdFilter,
  };

  const result = queryStore.countRowsByIdsMatching.call(
    context,
    "tab",
    [101, 909],
    {},
  );

  assert.deepEqual(result, { matching: 1 });
  assert.match(captured.sql, /c0 = \? AND data\.rowid IN \(101,909\)/);
  assert.deepEqual(captured.params, ["visible"]);
});

test("unique-value queries expose the complete distinct count and truncation", () => {
  let captured;
  const context = {
    databases: new Map([["tab", {
      colMap: { hostname: "c0" },
      db: {
        prepare(sql) {
          return {
            all(...params) {
              captured = { sql, params };
              return [
                { val: "DC01", cnt: 8, total_distinct: 7 },
                { val: "WS01", cnt: 3, total_distinct: 7 },
              ];
            },
          };
        },
      },
    }]]),
    _applyStandardFilters(_options, _meta, where, params) {
      where.push("c1 = ?");
      params.push("Security");
    },
  };

  const result = queryStore.getColumnUniqueValues.call(context, "tab", "hostname", { limit: 2 });

  assert.deepEqual(result, {
    values: [{ val: "DC01", cnt: 8 }, { val: "WS01", cnt: 3 }],
    totalDistinct: 7,
    truncated: true,
  });
  assert.match(captured.sql, /COUNT\(\*\) OVER\(\) AS total_distinct/);
  // Grouped on the column, but through the empty-bucket expression: NULL, '' and
  // whitespace-only all have to land in the single "(empty)" entry the checkbox filter
  // acts on, so the GROUP BY is the CASE wrapper rather than the bare column.
  assert.match(captured.sql, /GROUP BY CASE WHEN TRIM\(COALESCE\(c0, ''\)/);
  assert.match(captured.sql, /ELSE c0 END/);
  assert.deepEqual(captured.params, ["Security", 2]);
});

test("highlight navigation ranks the full filtered result and wraps", () => {
  const sqlCalls = [];
  const meta = {
    colMap: {},
    tsColumns: new Set(),
    numericColumns: new Set(),
    db: {
      prepare(sql) {
        sqlCalls.push(sql);
        return {
          get() {
            if (sql.includes("WHERE _index > ?")) return undefined;
            return { _rowid: 77, _index: 15_500, _position: 30, _total: 31 };
          },
        };
      },
    },
  };
  const context = {
    databases: new Map([["tab", meta]]),
    _applyStandardFilters(options, _meta, where, params) {
      where.push("c0 = ?");
      params.push("base");
    },
    _applySearch(term, mode, _meta, where, params) {
      where.push("c1 LIKE ?");
      params.push(`%${term}%`);
    },
    _buildOrderExpression() {
      return "data.rowid ASC";
    },
  };

  const result = queryStore.findSearchMatch.call(context, "tab", {
    matchSearchTerm: "needle",
    currentIndex: 20_000,
    direction: 1,
  });

  assert.deepEqual(result, {
    index: 15_500,
    rowId: 77,
    position: 30,
    totalMatches: 31,
  });
  assert.equal(sqlCalls.length, 2);
  assert.match(sqlCalls[0], /ROW_NUMBER\(\) OVER \(ORDER BY data\.rowid ASC\)/);
  assert.match(sqlCalls[0], /COUNT\(\*\) OVER \(\)/);
  assert.match(sqlCalls[1], /WHERE \? IS NOT NULL/);
});

test("renderer wires persistent scoped selection and SQLite-backed navigation", () => {
  const root = path.join(__dirname, "..");
  const appSource = fs.readFileSync(path.join(root, "src", "App.jsx"), "utf8");
  const selectionBarSource = fs.readFileSync(
    path.join(root, "src", "components", "SelectionBar.jsx"),
    "utf8",
  );
  const preloadSource = fs.readFileSync(path.join(root, "electron", "preload.js"), "utf8");

  assert.match(appSource, /selectAllScopeSignature !== currentFilterScopeSignature/);
  assert.match(appSource, /countRowsByIdsMatching\(ct\.id, \[\.\.\.selectedRows\]/);
  assert.match(appSource, /getRowIdsInRange\(ct\.id/);
  assert.match(appSource, /findSearchMatch\(ct\.id/);
  assert.doesNotMatch(appSource, /\bhlMatchIndices\b/);
  assert.match(selectionBarSource, /hidden by current filters/);
  assert.match(selectionBarSource, /Copy selected/);
  assert.match(preloadSource, /get-row-ids-in-range/);
  assert.match(preloadSource, /find-search-match/);
});
