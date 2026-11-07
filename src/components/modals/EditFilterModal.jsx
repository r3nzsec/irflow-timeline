import { useCallback } from "react";
import {
  headerFilterRows, applyHeaderFilterRows, headerFilterColumnLabel as columnLabel,
  FILTER_OPERATORS, NO_VALUE_OPERATORS, filterOperator,
} from "../../utils/header-filters.js";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { Modal, Button, Input } from "../primitives/index.js";

export default function EditFilterModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ct = useCurrentTab();

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  if (modal?.type !== "editFilter" || !ct) return null;

  const OPERATORS = FILTER_OPERATORS;
  const noValueOps = NO_VALUE_OPERATORS;
  const existing = ct.advancedFilters || [];
  const initConditions = existing.length > 0
    ? existing.map((f, i) => ({ ...f, id: i + 1 }))
    : [{ id: 1, column: "", operator: "contains", value: "", logic: "AND" }];

  const conditions = modal.conditions || initConditions;
  const nextId = modal.nextId || (initConditions.length > 0 ? Math.max(...initConditions.map(c => c.id)) + 1 : 2);

  // Header filters as the dialog opened (to know what to clear) and as edited since.
  const shownHeaderRows = modal.shownHeaderRows || headerFilterRows(ct);
  const headerRows = modal.headerRows || shownHeaderRows;
  const setHeaderRows = (rows) => setModal((p) => p?.type === "editFilter" ? { ...p, headerRows: rows, shownHeaderRows: p.shownHeaderRows || shownHeaderRows } : p);
  const updateHeaderValue = (key, value) => setHeaderRows(headerRows.map((r) => (r.key === key ? { ...r, value } : r)));
  const updateHeaderOp = (key, op) => setHeaderRows(headerRows.map((r) => (r.key === key ? { ...r, op } : r)));
  const removeHeaderRow = (key) => setHeaderRows(headerRows.filter((r) => r.key !== key));
  const headerRowText = (r) => {
    if (r.kind === "text") {
      const label = filterOperator(r.op).label.toUpperCase();
      return NO_VALUE_OPERATORS.has(r.op) ? `${columnLabel(r.column)} ${label}` : `${columnLabel(r.column)} ${label} "${r.value}"`;
    }
    if (r.kind === "values") {
      const shown = r.values.slice(0, 5).map((v) => (String(v ?? "").trim() === "" ? "(empty)" : `"${v}"`));
      return `${columnLabel(r.column)} IS ONE OF (${shown.join(", ")}${r.values.length > 5 ? `, … ${r.values.length - 5} more` : ""})`;
    }
    return `${columnLabel(r.column)} BETWEEN ${r.from || "the start"} AND ${r.to || "the end"}`;
  };

  const setConditions = (newConds) => setModal((p) => p?.type === "editFilter" ? { ...p, conditions: newConds } : p);
  const setNextId = (nid) => setModal((p) => p?.type === "editFilter" ? { ...p, nextId: nid } : p);

  const updateCondition = (id, field, val) => {
    setConditions(conditions.map((c) => c.id === id ? { ...c, [field]: val } : c));
  };
  const removeCondition = (id) => {
    const newC = conditions.filter((c) => c.id !== id);
    if (newC.length === 0) newC.push({ id: nextId, column: "", operator: "contains", value: "", logic: "AND" });
    setConditions(newC);
    if (newC.length === 0) setNextId(nextId + 1);
  };
  const addCondition = () => {
    setConditions([...conditions, { id: nextId, column: "", operator: "contains", value: "", logic: "AND" }]);
    setNextId(nextId + 1);
  };

  const buildPreview = () => {
    const header = headerRows.filter((r) => r.kind !== "text" || r.value || NO_VALUE_OPERATORS.has(r.op)).map(headerRowText);
    const own = buildConditionsPreview();
    if (!own) return header.length ? header.join(" AND ") : "No conditions defined";
    if (!header.length) return own;
    return `${header.join(" AND ")} AND ${/ OR /.test(own) ? `(${own})` : own}`;
  };

  const buildConditionsPreview = () => {
    const valid = conditions.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
    if (valid.length === 0) return null;
    const opLabel = (op) => OPERATORS.find(o => o.value === op)?.label || op;
    const groups = [];
    let currentGroup = [valid[0]];
    for (let i = 1; i < valid.length; i++) {
      if (valid[i].logic === "OR") {
        groups.push(currentGroup);
        currentGroup = [valid[i]];
      } else {
        currentGroup.push(valid[i]);
      }
    }
    groups.push(currentGroup);
    return groups.map((g) => {
      const expr = g.map((c) => {
        if (noValueOps.has(c.operator)) return `${c.column} ${opLabel(c.operator).toUpperCase()}`;
        return `${c.column} ${opLabel(c.operator).toUpperCase()} "${c.value}"`;
      }).join(" AND ");
      return g.length > 1 ? `(${expr})` : expr;
    }).join(" OR ");
  };

  // One update for the conditions and the header filters, so the grid queries once.
  const save = (conds, rows) => {
    const valid = conds.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
    useTabStore.getState().updateActiveTab({
      advancedFilters: valid.map(({ id, ...rest }) => rest),
      ...applyHeaderFilterRows(ct, shownHeaderRows, rows),
    });
    setModal(null);
  };
  const handleApply = () => save(conditions, headerRows);
  // Clears everything the dialog lists: its conditions and the header filters.
  const handleClear = () => save([], []);

  const selectStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, padding: "5px 8px", fontSize: 12, fontFamily: "-apple-system, sans-serif", outline: "none" };
  // A header filter's column and operator: shown like the selects, but fixed.
  const staticStyle = { ...selectStyle, color: th.textDim, boxSizing: "border-box", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" };
  const captionStyle = { fontSize: 11, fontWeight: 600, color: th.textDim, margin: "0 0 8px 2px", fontFamily: "-apple-system, sans-serif" };

  const footer = (
    <>
      <Button variant="secondary" onClick={handleClear} style={{ color: th.danger, marginRight: "auto" }}>Clear All</Button>
      <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
      <Button onClick={handleApply}>Apply</Button>
    </>
  );

  return (
    <Modal
      title="Edit Filter"
      width={720}
      maxHeight="88vh"
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={footer}
    >
      {headerRows.length > 0 && (
        <div style={captionStyle}>Filters under the column headers</div>
      )}
      {headerRows.map((r, idx) => (
        <div key={r.key} data-header-filter={r.column} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
          <span style={{ width: 56, fontSize: 11, color: th.textDim, textAlign: "center", flexShrink: 0 }}>{idx === 0 ? "Where" : "AND"}</span>
          <div title={columnLabel(r.column)} style={{ ...staticStyle, width: 170, flexShrink: 0 }}>{columnLabel(r.column)}</div>
          {r.kind === "text" ? (
            <select value={r.op} aria-label={`Header filter operator ${columnLabel(r.column)}`} onChange={(e) => updateHeaderOp(r.key, e.target.value)} style={{ ...selectStyle, width: 140, flexShrink: 0 }}>
              {OPERATORS.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
            </select>
          ) : (
            <div style={{ ...staticStyle, width: 140, flexShrink: 0 }}>{r.kind === "values" ? "Is one of" : "Between"}</div>
          )}
          {r.kind === "text" && NO_VALUE_OPERATORS.has(r.op) ? (
            <div style={{ flex: 1, minWidth: 80 }} />
          ) : r.kind === "text" ? (
            <Input
              type="text"
              value={r.value}
              aria-label={`Header filter ${columnLabel(r.column)}`}
              onChange={(e) => updateHeaderValue(r.key, e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleApply(); } }}
              placeholder="Value..."
              style={{ flex: 1, minWidth: 80 }}
            />
          ) : (
            <div title={headerRowText(r)} style={{ ...staticStyle, flex: 1, minWidth: 80 }}>
              {r.kind === "values"
                ? r.values.map((v) => (String(v ?? "").trim() === "" ? "(empty)" : v)).join(", ")
                : `${r.from || "…"} → ${r.to || "…"}`}
            </div>
          )}
          <button onClick={() => removeHeaderRow(r.key)} aria-label={`Remove the ${columnLabel(r.column)} header filter`} style={{ background: "none", border: "none", color: th.textDim, fontSize: 14, cursor: "pointer", padding: "2px 6px", flexShrink: 0 }} title="Remove this header filter">✕</button>
        </div>
      ))}
      {headerRows.length > 0 && (
        <div style={{ ...captionStyle, marginTop: 12 }}>Conditions (AND with the filters above)</div>
      )}

      {conditions.map((c, idx) => (
        <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
          {idx === 0 && headerRows.length > 0 ? (
            <span style={{ width: 56, fontSize: 11, color: th.textDim, textAlign: "center", flexShrink: 0 }}>AND</span>
          ) : idx === 0 ? (
            <span style={{ width: 56, fontSize: 11, color: th.textDim, textAlign: "center", flexShrink: 0 }}>Where</span>
          ) : (
            <select value={c.logic} onChange={(e) => updateCondition(c.id, "logic", e.target.value)} style={{ ...selectStyle, width: 56, flexShrink: 0, textAlign: "center" }}>
              <option value="AND">AND</option>
              <option value="OR">OR</option>
            </select>
          )}

          <select value={c.column} onChange={(e) => updateCondition(c.id, "column", e.target.value)} style={{ ...selectStyle, width: 170, flexShrink: 0 }}>
            <option value="">-- Column --</option>
            {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>

          <select value={c.operator} onChange={(e) => updateCondition(c.id, "operator", e.target.value)} style={{ ...selectStyle, width: 140, flexShrink: 0 }}>
            {OPERATORS.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
          </select>

          {!noValueOps.has(c.operator) ? (
            <Input
              type="text"
              value={c.value}
              onChange={(e) => updateCondition(c.id, "value", e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleApply(); }}
              placeholder="Value..."
              style={{ flex: 1, minWidth: 80 }}
            />
          ) : (
            <div style={{ flex: 1 }} />
          )}

          <button onClick={() => removeCondition(c.id)} style={{ background: "none", border: "none", color: th.textDim, fontSize: 14, cursor: "pointer", padding: "2px 6px", flexShrink: 0 }} title="Remove condition">✕</button>
        </div>
      ))}

      <button onClick={addCondition} style={{ background: "none", border: `1px dashed ${th.border}`, borderRadius: 4, color: th.accent, fontSize: 12, padding: "6px 12px", cursor: "pointer", marginTop: 4, fontFamily: "-apple-system, sans-serif" }}>
        + Add Condition
      </button>

      <div style={{ marginTop: 16, padding: "10px 12px", background: th.bgInput, border: `1px solid ${th.border}`, borderRadius: 6, fontSize: 11, fontFamily: "'SF Mono', 'Fira Code', Menlo, monospace", color: th.textDim, wordBreak: "break-word", lineHeight: 1.6 }}>
        {buildPreview()}
      </div>
    </Modal>
  );
}
