// Registers the app's SQL helper functions on DuckDB.
//
// The JavaScript implementations stay in runtime-functions.js (shared with the tests). This
// module captures them through a small `db.function()` shim and registers each one as a DuckDB
// scalar function with explicit types, because DuckDB needs a signature where SQLite did not.
"use strict";

const duck = require("@duckdb/node-api");
const { registerRuntimeFunctions } = require("../runtime-functions");

// Return types. Every argument is VARCHAR: the timeline stores every cell as text.
const RETURN_TYPES = {
  regexp: "BOOLEAN",
  fuzzy_match: "BOOLEAN",
  extract_date: "VARCHAR",
  extract_datetime_minute: "VARCHAR",
  sort_datetime: "VARCHAR",
  norm_guid: "VARCHAR",
  norm_logon_id: "VARCHAR",
  norm_host: "VARCHAR",
  norm_pid: "VARCHAR",
};

function collectRuntimeFunctions() {
  const fns = new Map();
  registerRuntimeFunctions({
    function(name, _options, fn) {
      fns.set(name, fn);
    },
  });
  return fns;
}

const UDF_NAMES = Object.freeze(Object.keys(RETURN_TYPES));

function registerUdfs(connection) {
  for (const [name, fn] of collectRuntimeFunctions()) {
    const returns = RETURN_TYPES[name];
    if (!returns) throw new Error(`No DuckDB signature for SQL function ${name}`);
    const arity = fn.length;
    const returnType = duck[returns];
    const isBool = returns === "BOOLEAN";
    connection.registerScalarFunction(duck.DuckDBScalarFunction.create({
      name,
      returnType,
      parameterTypes: Array(arity).fill(duck.VARCHAR),
      // The JS functions handle NULL themselves (regexp(NULL) is 0, not NULL, so
      // NOT regexp(...) keeps SQLite's meaning). Without special handling DuckDB
      // would skip the call and return NULL for any NULL argument.
      specialHandling: true,
      mainFunction(_info, input, output) {
        const cols = [];
        for (let c = 0; c < arity; c++) cols.push(input.getColumnVector(c));
        const args = new Array(arity);
        for (let i = 0; i < input.rowCount; i++) {
          for (let c = 0; c < arity; c++) args[c] = cols[c].getItem(i);
          let value;
          try {
            value = fn(...args);
          } catch {
            value = null;
          }
          if (value === undefined) value = null;
          if (value !== null) value = isBool ? !!value : String(value);
          output.setItem(i, value);
        }
        output.flush();
      },
    }));
  }
}

module.exports = { registerUdfs, UDF_NAMES };
