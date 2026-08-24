import { parseDiffDetail, diffStatusColor } from "../utils/diff-tabs.js";

/**
 * Field-level before/after table for a single diff row.
 */
export default function DiffFieldCompare({ th, row, compact = false }) {
  if (!row) {
    return (
      <div style={{ color: th.textMuted, fontSize: 11, padding: compact ? 4 : 10 }}>
        Select a Changed row in the grid to inspect field-level differences.
      </div>
    );
  }
  const status = row._Diff || "";
  const color = diffStatusColor(status, th);
  const pairs = parseDiffDetail(row._DiffDetail);
  const glass = {
    background: th.glassBg,
    border: `1px solid ${th.glassBorder}`,
    borderRadius: 10,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
  };

  if (status === "Added" || status === "Removed") {
    return (
      <div style={{ ...glass, padding: compact ? "8px 10px" : "10px 12px" }}>
        <div style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.04em", textTransform: "uppercase" }}>
          {status}
        </div>
        <div style={{ marginTop: 4, fontSize: 12, color: th.textDim }}>
          {status === "Added"
            ? `Present only in ${row._Compare || "compare"}.`
            : `Present only in ${row._Baseline || "baseline"}.`}
        </div>
        {row._MatchKey ? (
          <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
            Match {row._MatchKey}
          </div>
        ) : null}
      </div>
    );
  }

  if (status === "Unchanged") {
    return (
      <div style={{ ...glass, padding: compact ? "8px 10px" : "10px 12px" }}>
        <div style={{ fontSize: 11, fontWeight: 700, color, letterSpacing: "0.04em", textTransform: "uppercase" }}>Unchanged</div>
        <div style={{ marginTop: 4, fontSize: 12, color: th.textDim }}>Every compared field matches between baseline and compare.</div>
      </div>
    );
  }

  if (!pairs.length) {
    return (
      <div style={{ color: th.textMuted, fontSize: 11, padding: compact ? 4 : 10 }}>
        {row._DiffSummary || "No field-level detail on this row."}
      </div>
    );
  }

  const cell = {
    fontSize: 11,
    fontFamily: "'SF Mono', Menlo, monospace",
    wordBreak: "break-word",
    whiteSpace: "pre-wrap",
    padding: compact ? "4px 6px" : "6px 8px",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{
          display: "inline-flex", alignItems: "center", padding: "2px 8px", borderRadius: 999,
          fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase",
          color, background: `${color}1f`, border: `1px solid ${color}44`,
        }}>{status}</span>
        <span style={{ fontSize: 11, color: th.textDim }}>
          {pairs.length} field{pairs.length === 1 ? "" : "s"} changed
        </span>
        {row._MatchKey ? (
          <span style={{ fontSize: 10, color: th.textMuted, fontFamily: "'SF Mono', Menlo, monospace" }}>
            {row._MatchKey}
          </span>
        ) : null}
      </div>
      <div style={{ ...glass, overflow: "auto", maxHeight: compact ? 220 : 360 }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ color: th.textMuted, fontSize: 10, textTransform: "uppercase", letterSpacing: "0.05em" }}>
              <th style={{ textAlign: "left", padding: "6px 8px", width: "22%" }}>Field</th>
              <th style={{ textAlign: "left", padding: "6px 8px", width: "39%" }}>{row._Baseline || "Baseline"}</th>
              <th style={{ textAlign: "left", padding: "6px 8px", width: "39%" }}>{row._Compare || "Compare"}</th>
            </tr>
          </thead>
          <tbody>
            {pairs.map((p) => (
              <tr key={p.f} style={{ borderTop: `1px solid ${th.glassBorder}` }}>
                <td style={{ ...cell, fontWeight: 600, color: th.textDim, fontFamily: "-apple-system, sans-serif" }}>{p.f}</td>
                <td style={{ ...cell, color: th.danger, background: `${th.danger}10` }}>{p.a || "∅"}</td>
                <td style={{ ...cell, color: th.success, background: `${th.success}10` }}>{p.b || "∅"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
