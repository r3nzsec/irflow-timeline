import useTheme from "../../hooks/useTheme.js";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import DraggableResizableModal from "../primitives/DraggableResizableModal.jsx";
import DiffFieldCompare from "../DiffFieldCompare.jsx";
import { formatNumber } from "../../utils/format.js";
import { diffStatusColor, DIFF_STATUSES, isDiffTab } from "../../utils/diff-tabs.js";

export default function DiffExplorerModal({ selectedRowData }) {
  const { th } = useTheme();
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const tabs = useTabStore((s) => s.tabs);
  const setTabs = useTabStore((s) => s.setTabs);
  const activeTab = useTabStore((s) => s.activeTab);

  if (!modal || modal.type !== "diffExplorer") return null;

  const tab = tabs.find((t) => t.id === (modal.tabId || activeTab)) || tabs.find((t) => t.id === activeTab);
  if (!tab || !isDiffTab(tab)) return null;

  const meta = tab.diffMeta || {};
  const stats = meta.stats || {};
  const selected = tab.checkboxFilters?._Diff;
  const selectedSet = Array.isArray(selected) ? new Set(selected) : null;
  const changedFields = stats.changedFields || [];
  const fieldFilter = tab.columnFilters?._ChangedFields || "";

  const glass = (extra = {}) => ({
    background: th.glassBg,
    border: `1px solid ${th.glassBorder}`,
    borderRadius: 12,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
    ...extra,
  });

  const updateTab = (partial) => {
    setTabs((prev) => prev.map((t) => (t.id === tab.id ? { ...t, ...partial } : t)));
  };

  const applyStatus = (status) => {
    if (status === "Unchanged" && !meta.includeUnchanged) return;
    if (status === "all") {
      const next = { ...(tab.checkboxFilters || {}) };
      delete next._Diff;
      updateTab({ checkboxFilters: next });
      return;
    }
    const current = tab.checkboxFilters?._Diff;
    const onlyThis = Array.isArray(current) && current.length === 1 && current[0] === status;
    if (onlyThis) {
      applyStatus("all");
      return;
    }
    updateTab({ checkboxFilters: { ...(tab.checkboxFilters || {}), _Diff: [status] } });
  };

  const applyField = (field) => {
    const filters = { ...(tab.columnFilters || {}) };
    const checks = { ...(tab.checkboxFilters || {}), _Diff: ["Changed"] };
    if (fieldFilter === field) {
      delete filters._ChangedFields;
      updateTab({ columnFilters: filters, checkboxFilters: checks });
      return;
    }
    filters._ChangedFields = field;
    updateTab({ columnFilters: filters, checkboxFilters: checks });
  };

  const totalDeltas = (stats.added || 0) + (stats.removed || 0) + (stats.changed || 0);
  const heroColor = stats.removed ? th.danger : stats.changed ? th.warning : stats.added ? th.success : th.sev.clean;

  return (
    <DraggableResizableModal
      defaultWidth={420}
      defaultHeight={Math.round((typeof window !== "undefined" ? window.innerHeight : 800) * 0.86)}
      defaultX={typeof window !== "undefined" ? Math.max(16, window.innerWidth - 440) : 16}
      defaultY={48}
      minWidth={360}
      minHeight={360}
      onClose={() => setModal(null)}
      clickThrough
      ariaLabel="Diff Explorer"
    >
      {({ startDrag }) => (
        <div style={{ display: "flex", flexDirection: "column", height: "100%", fontFamily: "-apple-system, sans-serif" }}>
          <div
            onMouseDown={startDrag}
            style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              padding: "12px 16px 10px", cursor: "grab",
              borderBottom: `1px solid ${th.glassBorder}`,
            }}
          >
            <div>
              <div style={{ fontSize: 15, fontWeight: 650, color: th.text }}>Diff Explorer</div>
              <div style={{ fontSize: 11, color: th.textMuted, marginTop: 2 }}>
                {meta.baselineName} → {meta.compareName}
              </div>
            </div>
            <button
              type="button"
              onClick={() => setModal(null)}
              style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 16, padding: "2px 6px" }}
            >
              ✕
            </button>
          </div>

          <div style={{ flex: 1, overflow: "auto", padding: 14, display: "flex", flexDirection: "column", gap: 12 }}>
            <div style={{
              ...glass({ padding: 14 }),
            }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: heroColor }}>
                {totalDeltas === 0 ? "No differences" : `${formatNumber(totalDeltas)} differing rows`}
              </div>
              <div style={{ marginTop: 4, fontSize: 12, color: th.textDim }}>
                {totalDeltas === 0
                  ? `${formatNumber(stats.unchanged || 0)} rows are identical under the current match keys.`
                  : "Click a status to filter the grid. Click again to show everything."}
              </div>
              {(meta.matchKeys || []).length ? (
                <div style={{ marginTop: 8, fontSize: 11, color: th.textMuted }}>
                  Matching on {(meta.matchKeys || []).join(" · ")}
                </div>
              ) : (
                <div style={{ marginTop: 8, fontSize: 11, color: th.textMuted }}>Entire-row content match</div>
              )}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 8 }}>
              {DIFF_STATUSES.map((status) => {
                const color = diffStatusColor(status, th);
                const count = stats[status.toLowerCase()] || 0;
                const exclusive = selectedSet && selectedSet.size === 1 && selectedSet.has(status);
                const muted = selectedSet && !selectedSet.has(status);
                return (
                  <button
                    key={status}
                    type="button"
                    onClick={() => applyStatus(status)}
                    style={{
                      ...glass({ padding: "10px 12px", textAlign: "left", cursor: "pointer" }),
                      opacity: muted ? 0.45 : 1,
                      border: `1px solid ${exclusive ? color : th.glassBorder}`,
                    }}
                  >
                    <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color }}>{status}</div>
                    <div style={{ fontSize: 20, fontWeight: 650, color: th.text, fontVariantNumeric: "tabular-nums", marginTop: 2 }}>
                      {formatNumber(count)}
                    </div>
                    {status === "Unchanged" && !meta.includeUnchanged ? (
                      <div style={{ fontSize: 10, color: th.textMuted, marginTop: 2 }}>Omitted from the tab</div>
                    ) : null}
                  </button>
                );
              })}
            </div>

            {(meta.schemaDelta?.onlyA?.length || meta.schemaDelta?.onlyB?.length) ? (
              <div style={glass({ padding: 12 })}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.textMuted, marginBottom: 6 }}>
                  Schema delta
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11 }}>
                  {(meta.schemaDelta.onlyA || []).slice(0, 12).map((h) => (
                    <div key={`a-${h}`} style={{ color: th.danger }}>Only in baseline: {h}</div>
                  ))}
                  {(meta.schemaDelta.onlyB || []).slice(0, 12).map((h) => (
                    <div key={`b-${h}`} style={{ color: th.success }}>Only in compare: {h}</div>
                  ))}
                </div>
              </div>
            ) : null}

            {changedFields.length ? (
              <div style={glass({ padding: 12 })}>
                <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.textMuted, marginBottom: 8 }}>
                  Fields that changed most
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {changedFields.slice(0, 16).map((item) => {
                    const active = fieldFilter === item.field;
                    return (
                      <button
                        key={item.field}
                        type="button"
                        onClick={() => applyField(item.field)}
                        style={{
                          display: "flex", justifyContent: "space-between", gap: 8,
                          padding: "5px 8px", borderRadius: 8, cursor: "pointer",
                          background: active ? `${th.warning}22` : "transparent",
                          border: `1px solid ${active ? th.warning : "transparent"}`,
                          color: th.text, fontSize: 11, textAlign: "left",
                        }}
                      >
                        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.field}</span>
                        <span style={{ color: th.textMuted, fontVariantNumeric: "tabular-nums" }}>{formatNumber(item.count)}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : null}

            <div>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.textMuted, marginBottom: 8 }}>
                Selected row
              </div>
              <DiffFieldCompare th={th} row={selectedRowData && selectedRowData._Diff ? selectedRowData : null} />
            </div>
          </div>
        </div>
      )}
    </DraggableResizableModal>
  );
}
