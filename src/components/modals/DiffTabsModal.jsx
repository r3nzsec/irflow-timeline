import { useMemo } from "react";
import useTheme from "../../hooks/useTheme.js";
import useUIStore from "../../store/useUIStore.js";
import { toast } from "../../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { formatNumber } from "../../utils/format.js";
import { suggestMatchKeys, schemaDelta } from "../../utils/diff-tabs.js";
import { Modal, Button } from "../primitives/index.js";

export default function DiffTabsModal() {
  const { th } = useTheme();
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const tle = typeof window !== "undefined" ? window.tle : null;

  const tabOptions = modal?.type === "diffTabs" ? (modal.tabOptions || []) : [];
  const baseline = tabOptions.find((t) => t.tabId === modal?.baselineTabId) || null;
  const compare = tabOptions.find((t) => t.tabId === modal?.compareTabId) || null;
  const sameTab = !!(baseline && compare && baseline.tabId === compare.tabId);
  const canRun = !!(baseline && compare && !sameTab);

  const delta = useMemo(
    () => schemaDelta(baseline?.headers || [], compare?.headers || []),
    [baseline?.headers, compare?.headers],
  );
  const autoKeys = useMemo(
    () => suggestMatchKeys(baseline?.headers || [], compare?.headers || []),
    [baseline?.headers, compare?.headers],
  );

  const matchMode = modal?.matchMode || "auto";
  const selectedKeys = matchMode === "row"
    ? []
    : matchMode === "auto"
      ? autoKeys
      : (modal?.matchKeys || autoKeys);
  const keyQuery = (modal?.keyQuery || "").trim().toLowerCase();
  const candidateCols = useMemo(() => {
    const names = [...new Set([...(baseline?.headers || []), ...(compare?.headers || [])])]
      .filter((h) => h && !String(h).startsWith("_") && h !== "datetime");
    names.sort((a, b) => a.localeCompare(b));
    if (!keyQuery) return names;
    return names.filter((h) => h.toLowerCase().includes(keyQuery));
  }, [baseline?.headers, compare?.headers, keyQuery]);

  if (!modal || modal.type !== "diffTabs") return null;

  const glass = (extra = {}) => ({
    background: th.glassBg,
    border: `1px solid ${th.glassBorder}`,
    borderRadius: 12,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
    ...extra,
  });

  const patch = (partial) => setModal((p) => (p?.type === "diffTabs" ? { ...p, ...partial } : p));

  const selectTab = (side, tabId) => {
    if (side === "baseline") patch({ baselineTabId: tabId, matchKeys: null });
    else patch({ compareTabId: tabId, matchKeys: null });
  };

  const swap = () => patch({
    baselineTabId: modal.compareTabId,
    compareTabId: modal.baselineTabId,
    matchKeys: null,
  });

  const toggleKey = (name) => {
    const current = matchMode === "columns" ? (modal.matchKeys || autoKeys) : autoKeys;
    const next = current.includes(name) ? current.filter((k) => k !== name) : [...current, name];
    patch({ matchMode: "columns", matchKeys: next });
  };

  const run = async () => {
    if (!canRun || !tle?.diffTabs) return;
    const diffTabId = `tab_diff_${Date.now()}`;
    const spec = {
      baseline: {
        tabId: baseline.tabId,
        tabName: baseline.tabName,
        tsCol: baseline.selectedTsCol || "",
      },
      compare: {
        tabId: compare.tabId,
        tabName: compare.tabName,
        tsCol: compare.selectedTsCol || "",
      },
      matchKeys: selectedKeys,
      includeUnchanged: !!modal.includeUnchanged,
    };
    setModal(null);
    const result = await tle.diffTabs(diffTabId, spec);
    if (result?.canceled) return;
    if (isIpcError(result) || result?.success === false) {
      toast.error("Diff Tabs failed", { detail: ipcErrorMessage(result) || result?.error || "Diff failed" });
    }
  };

  const tabSelect = (side, currentId) => (
    <select
      value={currentId || ""}
      onChange={(e) => selectTab(side, e.target.value)}
      style={{
        width: "100%", padding: "7px 8px", background: th.bgInput,
        border: `1px solid ${th.btnBorder}`, borderRadius: 8, color: th.text,
        fontSize: 12, outline: "none", fontFamily: "inherit",
      }}
    >
      <option value="">Select a tab…</option>
      {tabOptions.map((t) => (
        <option key={t.tabId} value={t.tabId}>
          {t.tabName} ({formatNumber(t.rowCount)} rows)
        </option>
      ))}
    </select>
  );

  const tsSelect = (tab, side) => {
    if (!tab) return null;
    const cols = tab.tsColumns || [];
    return (
      <label style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 8, fontSize: 11, color: th.textMuted }}>
        Timestamp
        <select
          value={tab.selectedTsCol || ""}
          onChange={(e) => {
            const opts = tabOptions.map((t) => t.tabId === tab.tabId ? { ...t, selectedTsCol: e.target.value } : t);
            patch({ tabOptions: opts });
          }}
          style={{
            flex: 1, background: th.bgInput, border: `1px solid ${th.btnBorder}`,
            borderRadius: 6, color: th.text, fontSize: 11, padding: "3px 6px", outline: "none",
          }}
        >
          <option value="">{cols.length ? "Auto" : "None"}</option>
          {cols.map((c) => <option key={`${side}-${c}`} value={c}>{c}</option>)}
        </select>
      </label>
    );
  };

  const seg = (id, label) => {
    const active = matchMode === id;
    return (
      <button
        type="button"
        onClick={() => patch({
          matchMode: id,
          matchKeys: id === "columns" ? (modal.matchKeys || autoKeys) : modal.matchKeys,
        })}
        style={{
          padding: "5px 11px", borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: "pointer",
          border: "1px solid transparent",
          color: active ? "#fff" : th.textDim,
          background: active ? th.accent : "transparent",
        }}
      >
        {label}
      </button>
    );
  };

  return (
    <Modal
      open
      onClose={() => setModal(null)}
      title="Diff Tabs"
      subtitle="Compare any two imported files. Matching is by identity columns or entire-row content — not limited to one artifact family."
      width={720}
      footer={(
        <>
          <Button variant="secondary" onClick={() => setModal(null)}>Cancel</Button>
          <Button disabled={!canRun} onClick={run}>
            Run Diff
          </Button>
        </>
      )}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 14, fontFamily: "-apple-system, sans-serif" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 10, alignItems: "stretch" }}>
          <div style={glass({ padding: 12 })}>
            <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.danger, marginBottom: 6 }}>Baseline</div>
            {tabSelect("baseline", modal.baselineTabId)}
            {tsSelect(baseline, "baseline")}
            {baseline ? <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted }}>{formatNumber(baseline.rowCount)} rows · {(baseline.headers || []).length} columns</div> : null}
          </div>
          <button
            type="button"
            onClick={swap}
            title="Swap baseline and compare"
            style={{
              alignSelf: "center", width: 36, height: 36, borderRadius: 10, cursor: "pointer",
              background: th.glassBg, border: `1px solid ${th.glassBorder}`, color: th.textDim, fontSize: 16,
            }}
          >
            ⇄
          </button>
          <div style={glass({ padding: 12 })}>
            <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.success, marginBottom: 6 }}>Compare</div>
            {tabSelect("compare", modal.compareTabId)}
            {tsSelect(compare, "compare")}
            {compare ? <div style={{ marginTop: 6, fontSize: 10, color: th.textMuted }}>{formatNumber(compare.rowCount)} rows · {(compare.headers || []).length} columns</div> : null}
          </div>
        </div>

        {sameTab ? (
          <div style={{ color: th.warning, fontSize: 11 }}>Pick two different tabs.</div>
        ) : null}

        {baseline && compare && !sameTab ? (
          <div style={glass({ padding: 12 })}>
            <div style={{ fontSize: 10, color: th.textMuted, marginBottom: 6 }}>
              Schema {delta.common.length} shared
              {delta.onlyA.length ? ` · ${delta.onlyA.length} only in baseline` : ""}
              {delta.onlyB.length ? ` · ${delta.onlyB.length} only in compare` : ""}
            </div>
            {(delta.onlyA.length > 0 || delta.onlyB.length > 0) ? (
              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: th.textDim }}>
                {delta.onlyA.slice(0, 8).map((h) => (
                  <span key={`a-${h}`} style={{ color: th.danger }}>{h}</span>
                ))}
                {delta.onlyB.slice(0, 8).map((h) => (
                  <span key={`b-${h}`} style={{ color: th.success }}>{h}</span>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: 11, color: th.textDim }}>Column names align. Rows still differ if values changed.</div>
            )}
          </div>
        ) : null}

        <div>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: th.textMuted, marginBottom: 6 }}>
            How rows match
          </div>
          <div style={{ display: "inline-flex", padding: 3, gap: 2, ...glass({ borderRadius: 10 }) }}>
            {seg("auto", "Auto keys")}
            {seg("columns", "Choose columns")}
            {seg("row", "Entire row")}
          </div>
          <p style={{ margin: "8px 0 0", fontSize: 11, color: th.textDim, lineHeight: 1.45 }}>
            {matchMode === "row"
              ? "Identical rows are Unchanged. Anything that does not have an exact counterpart is Added or Removed. Field-level Changed is not used."
              : matchMode === "auto"
                ? (autoKeys.length
                  ? `Suggested identity: ${autoKeys.join(" · ")}. Works across EVTX, MFT, Prefetch, AI history, Computer History, and any other imported file with those columns.`
                  : "No strong identity column was found. Falling back to entire-row matching.")
                : "Pick the columns that identify the same event in both files. Remaining columns become the Changed-field comparison."}
          </p>
        </div>

        {matchMode !== "row" && baseline && compare ? (
          <div>
            {matchMode === "columns" ? (
              <input
                value={modal.keyQuery || ""}
                onChange={(e) => patch({ keyQuery: e.target.value })}
                placeholder="Filter columns…"
                style={{
                  width: "100%", marginBottom: 8, padding: "6px 8px", background: th.bgInput,
                  border: `1px solid ${th.btnBorder}`, borderRadius: 8, color: th.text, fontSize: 12,
                  outline: "none", boxSizing: "border-box",
                }}
              />
            ) : null}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, maxHeight: 160, overflow: "auto" }}>
              {(matchMode === "auto" ? autoKeys : candidateCols).map((h) => {
                const on = selectedKeys.includes(h);
                return (
                  <button
                    key={h}
                    type="button"
                    onClick={() => toggleKey(h)}
                    style={{
                      padding: "4px 9px", borderRadius: 999, fontSize: 11, cursor: "pointer",
                      color: on ? "#fff" : th.textDim,
                      background: on ? th.accent : th.glassBg,
                      border: `1px solid ${on ? th.accent : th.glassBorder}`,
                    }}
                  >
                    {h}
                  </button>
                );
              })}
            </div>
          </div>
        ) : null}

        <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12, color: th.text, cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={!!modal.includeUnchanged}
            onChange={(e) => patch({ includeUnchanged: e.target.checked })}
            style={{ accentColor: th.accent }}
          />
          Include Unchanged rows in the result tab
          <span style={{ color: th.textMuted, fontSize: 11 }}>(off by default — the explorer still reports the count)</span>
        </label>
      </div>
    </Modal>
  );
}
