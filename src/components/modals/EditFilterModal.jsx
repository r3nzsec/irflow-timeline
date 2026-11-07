import { useCallback } from "react";
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

  const OPERATORS = [
    { value: "contains", label: "Contains" },
    { value: "not_contains", label: "Does not contain" },
    { value: "equals", label: "Equals" },
    { value: "not_equals", label: "Does not equal" },
    { value: "starts_with", label: "Starts with" },
    { value: "ends_with", label: "Ends with" },
    { value: "greater_than", label: "Greater than" },
    { value: "less_than", label: "Less than" },
    { value: "is_empty", label: "Is empty" },
    { value: "is_not_empty", label: "Is not empty" },
    { value: "regex", label: "Matches regex" },
  ];
  const noValueOps = new Set(["is_empty", "is_not_empty"]);
  const existing = ct.advancedFilters || [];
  const initConditions = existing.length > 0
    ? existing.map((f, i) => ({ ...f, id: i + 1 }))
    : [{ id: 1, column: "", operator: "contains", value: "", logic: "AND" }];

  const conditions = modal.conditions || initConditions;
  const nextId = modal.nextId || (initConditions.length > 0 ? Math.max(...initConditions.map(c => c.id)) + 1 : 2);

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
    const valid = conditions.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
    if (valid.length === 0) return "No conditions defined";
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

  const handleApply = () => {
    const valid = conditions.filter((c) => c.column && c.operator && (noValueOps.has(c.operator) || c.value));
    up("advancedFilters", valid.map(({ id, ...rest }) => rest));
    setModal(null);
  };

  const handleClear = () => {
    up("advancedFilters", []);
    setModal(null);
  };

  const selectStyle = { background: th.bgInput, color: th.text, border: `1px solid ${th.border}`, borderRadius: 4, padding: "5px 8px", fontSize: 12, fontFamily: "-apple-system, sans-serif", outline: "none" };

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
      {conditions.map((c, idx) => (
        <div key={c.id} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
          {idx === 0 ? (
            <span style={{ width: 56, fontSize: 11, color: th.textDim, textAlign: "center", flexShrink: 0 }}>Where</span>
          ) : (
            <select value={c.logic} onChange={(e) => updateCondition(c.id, "logic", e.target.value)} style={{ ...selectStyle, width: 56, flexShrink: 0, textAlign: "center" }}>
              <option value="AND">AND</option>
              <option value="OR">OR</option>
            </select>
          )}

          <select value={c.column} onChange={(e) => updateCondition(c.id, "column", e.target.value)} style={{ ...selectStyle, minWidth: 120, maxWidth: 180 }}>
            <option value="">-- Column --</option>
            {ct.headers.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>

          <select value={c.operator} onChange={(e) => updateCondition(c.id, "operator", e.target.value)} style={{ ...selectStyle, minWidth: 130 }}>
            {OPERATORS.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
          </select>

          {!noValueOps.has(c.operator) ? (
            <Input
              type="text"
              value={c.value}
              onChange={(e) => updateCondition(c.id, "value", e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleApply(); } }}
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
