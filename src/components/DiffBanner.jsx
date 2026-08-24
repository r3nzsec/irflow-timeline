import { formatNumber } from "../utils/format.js";
import { diffStatusColor, DIFF_STATUSES, isDiffTab } from "../utils/diff-tabs.js";
import { openDiffExplorerModal } from "../modals/modalRegistry.js";
import useUIStore from "../store/useUIStore.js";

/**
 * Persistent strip on a Diff result tab: clickable Added/Removed/Changed/Unchanged counts.
 */
export default function DiffBanner({ th, ct, up }) {
  const setModal = useUIStore((s) => s.setModal);
  if (!isDiffTab(ct) || !ct.diffMeta) return null;

  const stats = ct.diffMeta.stats || {};
  const selected = ct.checkboxFilters?._Diff;
  const selectedSet = Array.isArray(selected) ? new Set(selected) : null;
  const matchKeys = ct.diffMeta.matchKeys || [];
  const omitted = !ct.diffMeta.includeUnchanged && (stats.unchanged || 0) > 0;

  const glass = {
    background: th.glassBg,
    border: `1px solid ${th.glassBorder}`,
    borderRadius: 8,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
  };

  const applyStatus = (status) => {
    if (status === "Unchanged" && omitted) return;
    if (status === "all") {
      const next = { ...(ct.checkboxFilters || {}) };
      delete next._Diff;
      up("checkboxFilters", next);
      return;
    }
    const current = ct.checkboxFilters?._Diff;
    const onlyThis = Array.isArray(current) && current.length === 1 && current[0] === status;
    if (onlyThis) {
      applyStatus("all");
      return;
    }
    up("checkboxFilters", { ...(ct.checkboxFilters || {}), _Diff: [status] });
  };

  const pill = (status) => {
    const color = diffStatusColor(status, th);
    const count = stats[status.toLowerCase()] || 0;
    const active = !selectedSet || selectedSet.has(status);
    const exclusive = selectedSet && selectedSet.size === 1 && selectedSet.has(status);
    const muted = selectedSet && !selectedSet.has(status);
    return (
      <button
        key={status}
        type="button"
        onClick={() => applyStatus(status)}
        title={status === "Unchanged" && omitted
          ? "Unchanged rows were omitted from this tab"
          : exclusive ? `Showing only ${status}. Click again to show all.` : `Filter grid to ${status}`}
        style={{
          ...glass,
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "4px 10px",
          cursor: status === "Unchanged" && omitted ? "default" : "pointer",
          opacity: muted ? 0.45 : 1,
          border: `1px solid ${exclusive ? color : th.glassBorder}`,
          background: exclusive ? `${color}22` : th.glassBg,
        }}
      >
        <span style={{
          width: 7, height: 7, borderRadius: 99, background: color, flexShrink: 0,
        }} />
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase", color }}>{status}</span>
        <span style={{ fontSize: 12, fontWeight: 650, color: th.text, fontVariantNumeric: "tabular-nums" }}>{formatNumber(count)}</span>
      </button>
    );
  };

  return (
    <div style={{
      display: "flex",
      alignItems: "center",
      gap: 8,
      padding: "6px 14px",
      borderBottom: `1px solid ${th.border}`,
      background: th.toolbarBg,
      backdropFilter: "blur(20px) saturate(180%)",
      WebkitBackdropFilter: "blur(20px) saturate(180%)",
      flexWrap: "wrap",
      fontFamily: "-apple-system, sans-serif",
    }}>
      <span style={{ fontSize: 11, fontWeight: 650, color: th.text, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        Diff
        <span style={{ color: th.textMuted, fontWeight: 500 }}> {ct.diffMeta.baselineName} → {ct.diffMeta.compareName}</span>
      </span>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {DIFF_STATUSES.map(pill)}
      </div>
      {omitted ? (
        <span style={{ fontSize: 10, color: th.textMuted }}>
          {formatNumber(stats.unchanged)} unchanged omitted
        </span>
      ) : null}
      {matchKeys.length ? (
        <span style={{ fontSize: 10, color: th.textMuted, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={matchKeys.join(", ")}>
          Match {matchKeys.join(" · ")}
        </span>
      ) : (
        <span style={{ fontSize: 10, color: th.textMuted }}>Entire-row match</span>
      )}
      <span style={{ flex: 1 }} />
      <button
        type="button"
        onClick={() => setModal(openDiffExplorerModal({ tabId: ct.id }))}
        style={{
          ...glass,
          padding: "4px 10px",
          fontSize: 11,
          fontWeight: 600,
          color: th.accent,
          cursor: "pointer",
        }}
      >
        Diff Explorer
      </button>
    </div>
  );
}
