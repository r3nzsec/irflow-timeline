import { useCallback, useEffect, useMemo, useState } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { confirm } from "../../store/useConfirmStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, Button, Input, Card } from "../primitives/index.js";

/**
 * Bulk tag / bookmark.
 *
 * The scope is the whole point of this modal, so it is an explicit, visible
 * choice rather than an invisible consequence of which menu opened it. It used
 * to be implicit: the Actions-menu entry passed no scope, so "Apply Tag" wrote
 * to every row of the tab even when rows were selected — one click after typing
 * a brand-new tag name would tag the entire file.
 */
const SCOPE_SELECTION = "selection";
const SCOPE_FILTERED = "filtered";
const SCOPE_ALL = "all";

export default function BulkActionsModal({
  fetchData,
  selectionFilterOptions = null,
  selectionCount = 0,
}) {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const invalidateRowMeta = useUIStore((s) => s.invalidateRowMeta);
  const { th } = useTheme();
  const ct = useCurrentTab();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  // Inline activeFilters helper
  const activeFilters = (tab) => {
    const dis = tab.disabledFilters || new Set();
    if (dis.size === 0) return { columnFilters: tab.columnFilters, checkboxFilters: tab.checkboxFilters };
    return {
      columnFilters: Object.fromEntries(Object.entries(tab.columnFilters).filter(([k]) => !dis.has(k))),
      checkboxFilters: Object.fromEntries(Object.entries(tab.checkboxFilters).filter(([k]) => !dis.has(k))),
    };
  };

  const isOpen = modal?.type === "bulkActions" && !!ct;
  const modalSelectionOptions = modal?.selectionFilterOptions || selectionFilterOptions;
  const resolvedSelectionCount = modal?.selectionCount ?? selectionCount;
  const hasSelection = !!modalSelectionOptions && resolvedSelectionCount > 0;

  // Live tag vocabulary straight from SQLite, so tags applied by analyzers
  // (Sigma, IOC:, VT:, "Encrypted", …) are suggestable even when nothing ever
  // wrote them into the palette.
  const [dbTags, setDbTags] = useState([]);
  useEffect(() => {
    if (!isOpen || !tle?.getAllTags || !ct?.id) return;
    let cancelled = false;
    tle.getAllTags(ct.id).then((rows) => {
      if (cancelled || isIpcError(rows) || !Array.isArray(rows)) return;
      setDbTags(rows);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [isOpen, tle, ct?.id, modal?.result]);

  // Default to the selection whenever there is one, no matter which entry point
  // opened this modal.
  const scope = modal?.appliedScope || (hasSelection ? SCOPE_SELECTION : SCOPE_FILTERED);
  const setScope = (next) => setModal((p) => (p?.type === "bulkActions" ? { ...p, appliedScope: next, result: null } : p));

  const filteredViewOpts = useMemo(() => {
    if (!ct) return null;
    const af = activeFilters(ct);
    return {
      searchTerm: ct.searchHighlight ? "" : ct.searchTerm,
      searchMode: ct.searchMode, searchCondition: ct.searchCondition || "contains",
      columnFilters: af.columnFilters, checkboxFilters: af.checkboxFilters,
      bookmarkedOnly: ct.showBookmarkedOnly, tagFilter: ct.tagFilter || null,
      rowIdFilter: ct.rowIdFilter || null,
      dateRangeFilters: ct.dateRangeFilters || {}, advancedFilters: ct.advancedFilters || [],
    };
  }, [ct]);

  const viewIsUnfiltered = (ct?.totalFiltered ?? 0) >= (ct?.totalRows ?? 0);

  const filterOpts = scope === SCOPE_SELECTION
    ? modalSelectionOptions
    : scope === SCOPE_ALL
      ? {}
      : filteredViewOpts;

  // Resolve the target population in SQLite. `totalFiltered` is the grid's
  // count for the grid's query; this is the count for the query we are about
  // to WRITE with, which is what the confirmation has to be based on.
  const [resolvedCount, setResolvedCount] = useState(null);
  useEffect(() => {
    if (!isOpen || !tle?.countFilteredRows || !ct?.id || !filterOpts) { setResolvedCount(null); return; }
    let cancelled = false;
    setResolvedCount(null);
    tle.countFilteredRows(ct.id, filterOpts).then((res) => {
      if (cancelled || isIpcError(res)) return;
      setResolvedCount(Number(res?.count) || 0);
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [isOpen, tle, ct?.id, scope, JSON.stringify(filterOpts || {})]);

  if (!isOpen) return null;

  const tagName = modal.tagName || "";
  const tagColor = modal.tagColor || th.accent;
  const result = modal.result;
  const busy = modal.busy || false;
  const paletteTags = Object.keys(ct.tagColors || {});
  const suggestions = [...new Set([...paletteTags, ...dbTags.map((t) => t.tag)])];

  const targetCount = resolvedCount ?? (
    scope === SCOPE_SELECTION ? resolvedSelectionCount
      : scope === SCOPE_ALL ? (ct.totalRows || 0)
        : (ct.totalFiltered || 0)
  );
  // A "filtered" scope that isn't actually filtered is the whole tab — the write
  // needs the same confirmation the explicit "Entire tab" scope does.
  const writesWholeTab = scope === SCOPE_ALL || (scope === SCOPE_FILTERED && viewIsUnfiltered);

  const patch = (next) => setModal((p) => (p?.type === "bulkActions" ? { ...p, ...next } : p));

  const confirmWholeTabWrite = async (verb) => {
    if (!writesWholeTab) return true;
    return confirm({
      title: `${verb} every row?`,
      message: `No selection or filter narrows this down, so this will ${verb.toLowerCase()} all ${formatNumber(ct.totalRows || targetCount)} rows in "${ct.name}". Tags are meant to mark findings — tagging everything makes the tag useless for filtering.`,
      confirmLabel: `${verb} all rows`,
      destructive: true,
    });
  };

  const runWrite = async (verb, fn) => {
    if (busy) return;
    if (!(await confirmWholeTabWrite(verb))) return;
    patch({ busy: true, result: null });
    try {
      const res = await fn({ ...(filterOpts || {}), ...(writesWholeTab ? { confirmWholeTab: true } : {}) });
      if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      if (res?.error) throw new Error(res.error);
      // The cached query windows hold a pre-write rowTags/bookmarkedSet snapshot;
      // refreshing without dropping them re-renders the state we just changed.
      if (typeof invalidateRowMeta === "function") invalidateRowMeta(ct.id);
      await fetchData(ct);
      return res;
    } catch (e) {
      patch({ busy: false, result: { type: "error", msg: e.message } });
      return null;
    }
  };

  const handleTag = async (add = true) => {
    const name = tagName.trim();
    if (!name || busy) return;
    const res = await runWrite(add ? "Tag" : "Untag", (opts) => (
      add ? tle.bulkTagFiltered(ct.id, name, opts) : tle.bulkUntagFiltered(ct.id, name, opts)
    ));
    if (!res) return;
    if (add) up("tagColors", { ...(ct.tagColors || {}), [name]: tagColor });
    const n = add ? res.tagged : res.untagged;
    patch({
      busy: false,
      result: {
        type: "success",
        msg: add
          ? `Tagged ${formatNumber(n)} row${n === 1 ? "" : "s"} as "${name}"${n === 0 ? " (all target rows already had it)" : ""}`
          : `Removed "${name}" from ${formatNumber(n)} row${n === 1 ? "" : "s"}`,
      },
    });
  };

  const handleBookmark = async (add) => {
    const res = await runWrite(add ? "Bookmark" : "Unbookmark", (opts) => tle.bulkBookmarkFiltered(ct.id, add, opts));
    if (!res) return;
    patch({
      busy: false,
      result: {
        type: "success",
        msg: add
          ? `Bookmarked ${formatNumber(res.affected)} rows`
          : `Removed bookmarks from ${formatNumber(res.affected)} rows`,
      },
    });
  };

  // ── Scope selector ────────────────────────────────────────────────
  const scopeOptions = [
    hasSelection && { id: SCOPE_SELECTION, label: "Selected rows", count: resolvedSelectionCount },
    { id: SCOPE_FILTERED, label: viewIsUnfiltered ? "Current view (no filter)" : "Filtered view", count: ct.totalFiltered || 0 },
    { id: SCOPE_ALL, label: "Entire tab", count: ct.totalRows || 0 },
  ].filter(Boolean);

  const segBtn = (active, danger) => ({
    flex: 1,
    padding: "7px 8px",
    borderRadius: 7,
    border: `1px solid ${active ? (danger ? th.danger + "77" : th.accent + "66") : th.glassBorder}`,
    background: active ? (danger ? th.danger + "1c" : th.accent + "1f") : th.glassBg,
    color: active ? (danger ? th.danger : th.accent) : th.textDim,
    boxShadow: active ? "none" : "inset 0 1px 0 rgba(255,255,255,0.05)",
    cursor: "pointer",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
    fontSize: 11,
    fontWeight: active ? 700 : 500,
    display: "flex",
    flexDirection: "column",
    gap: 2,
    alignItems: "center",
    transition: "background var(--m-base) var(--ease-out), border-color var(--m-base) var(--ease-out)",
  });

  const subtitle = (
    <>
      Writes to{" "}
      <b style={{ color: writesWholeTab ? th.warning : th.text }}>
        {resolvedCount === null ? "…" : formatNumber(targetCount)}
      </b>{" "}
      {scope === SCOPE_SELECTION ? "selected" : scope === SCOPE_ALL ? "total" : "filtered"} row
      {targetCount === 1 ? "" : "s"}
    </>
  );

  return (
    <Modal
      title="Bulk Tag / Bookmark"
      subtitle={subtitle}
      width={520}
      onClose={() => setModal(null)}
      bodyPadding="16px 20px"
      footer={true}
    >
      {/* Scope — the first decision, made explicitly */}
      <Card label="Apply to" style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 6 }}>
          {scopeOptions.map((opt) => (
            <button
              key={opt.id}
              type="button"
              onClick={() => setScope(opt.id)}
              style={segBtn(scope === opt.id, opt.id === SCOPE_ALL)}
            >
              <span>{opt.label}</span>
              <span style={{ fontSize: 10, opacity: 0.8, fontVariantNumeric: "tabular-nums" }}>{formatNumber(opt.count)}</span>
            </button>
          ))}
        </div>
        {writesWholeTab && (
          <div style={{ marginTop: 8, fontSize: 11, color: th.warning, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", lineHeight: 1.5 }}>
            ⚠ Nothing narrows this scope — every row in the tab will be written. You'll be asked to confirm.
          </div>
        )}
        {!hasSelection && (
          <div style={{ marginTop: 6, fontSize: 10.5, color: th.textMuted, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" }}>
            Tip: select rows in the grid first to tag just those.
          </div>
        )}
      </Card>

      {/* Tag section */}
      <Card label="Tag" style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <Input
            type="text"
            value={tagName}
            onChange={(e) => patch({ tagName: e.target.value })}
            onKeyDown={(e) => { if (e.key === "Enter") handleTag(true); }}
            placeholder="Tag name…"
            list="bulk-tag-suggestions"
            style={{ flex: 1, background: th.modalBg }}
          />
          <datalist id="bulk-tag-suggestions">
            {suggestions.map((t) => <option key={t} value={t} />)}
          </datalist>
          <input
            type="color"
            value={tagColor}
            onChange={(e) => patch({ tagColor: e.target.value })}
            title="Tag color"
            style={{ width: 30, height: 30, border: `1px solid ${th.border}`, borderRadius: 4, padding: 0, cursor: "pointer", background: "none", flexShrink: 0 }}
          />
          <Button onClick={() => handleTag(true)} disabled={!tagName.trim()} loading={busy}>
            Apply
          </Button>
          <Button variant="dangerSoft" onClick={() => handleTag(false)} disabled={!tagName.trim() || busy}>
            Remove
          </Button>
        </div>
        {dbTags.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 9 }}>
            {dbTags.slice(0, 12).map(({ tag, cnt }) => {
              const color = (ct.tagColors || {})[tag] || th.textMuted;
              return (
                <button
                  key={tag}
                  type="button"
                  onClick={() => patch({ tagName: tag, tagColor: color })}
                  title={`${formatNumber(cnt)} rows already carry this tag`}
                  style={{
                    display: "flex", alignItems: "center", gap: 5, padding: "2px 8px", borderRadius: 999,
                    border: `1px solid ${color}55`, background: color + "1c", color,
                    fontSize: 10.5, cursor: "pointer", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
                  }}
                >
                  {tag}
                  <span style={{ opacity: 0.75, fontVariantNumeric: "tabular-nums" }}>{formatNumber(cnt)}</span>
                </button>
              );
            })}
          </div>
        )}
      </Card>

      {/* Bookmark section */}
      <Card label="Bookmark" style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", gap: 8 }}>
          <Button variant="accentSoft" onClick={() => handleBookmark(true)} disabled={busy} fullWidth>
            ★ Bookmark
          </Button>
          <Button variant="dangerSoft" onClick={() => handleBookmark(false)} disabled={busy} fullWidth>
            ☆ Remove bookmarks
          </Button>
        </div>
      </Card>

      {/* Result message */}
      {result && (
        <div style={{
          padding: "8px 12px", borderRadius: 6, fontSize: 12,
          fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
          background: result.type === "success" ? (th.success + "18") : ((th.danger) + "18"),
          color: result.type === "success" ? th.success : (th.danger),
          border: `1px solid ${result.type === "success" ? th.success : (th.danger)}44`,
        }}>
          {result.type === "success" ? "✓ " : "✗ "}{result.msg}
        </div>
      )}
    </Modal>
  );
}
