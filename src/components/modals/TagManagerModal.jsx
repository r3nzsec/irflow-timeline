import { useCallback, useEffect, useMemo, useState } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useCurrentTab from "../../hooks/useCurrentTab.js";
import useTheme from "../../hooks/useTheme.js";
import { confirm } from "../../store/useConfirmStore.js";
import { toast } from "../../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { formatNumber } from "../../utils/format.js";
import { Modal, Button, Input, Card, Loading } from "../primitives/index.js";

/**
 * Tag manager.
 *
 * The old version edited `tagColors` only — a per-tab colour palette that has
 * nothing to do with what is actually tagged in SQLite. That made three things
 * impossible and one thing misleading:
 *   - tags written by analyzers (Sigma, IOC:, VT:, "Encrypted", …) never showed
 *     up here at all, because nothing registered a colour for them;
 *   - "✕" deleted the swatch and left every row still carrying the tag —
 *     filterable, exported in the report, and no longer removable from the row
 *     menu because the palette no longer listed it;
 *   - there was no rename and no way to collapse look-alike tags
 *     ("Suspicious" / "suspicious" / "Suspicious ").
 *
 * This version is backed by `getAllTags` (live row counts) unioned with the
 * palette, and every destructive action states how many rows it touches.
 */
const canonicalKey = (tag) => String(tag || "").replace(/\s+/g, " ").trim().toLowerCase();

export default function TagManagerModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const refreshCallback = useUIStore((s) => s.refreshCallback);
  const invalidateRowMeta = useUIStore((s) => s.invalidateRowMeta);
  const { th } = useTheme();
  const ct = useCurrentTab();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const up = useCallback((key, value) => {
    useTabStore.getState().updateActiveTab({ [key]: value });
  }, []);

  const isOpen = modal?.type === "tags" && !!ct;

  const [counts, setCounts] = useState(null); // [{ tag, cnt }] | null while loading
  const [renaming, setRenaming] = useState(null); // { tag, draft }
  const [newTag, setNewTag] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    if (!tle?.getAllTags || !ct?.id) return;
    const rows = await tle.getAllTags(ct.id);
    if (isIpcError(rows) || !Array.isArray(rows)) { setCounts([]); return; }
    setCounts(rows);
  }, [tle, ct?.id]);

  useEffect(() => {
    if (!isOpen) return;
    setCounts(null);
    setRenaming(null);
    load().catch(() => setCounts([]));
  }, [isOpen, load]);

  const palette = ct?.tagColors || {};

  // Palette entries with no rows are still real (an analyst can pre-create a
  // vocabulary), so they are listed at count 0 rather than hidden.
  const rows = useMemo(() => {
    const byTag = new Map();
    for (const { tag, cnt } of counts || []) byTag.set(tag, { tag, cnt, inPalette: tag in palette });
    for (const tag of Object.keys(palette)) if (!byTag.has(tag)) byTag.set(tag, { tag, cnt: 0, inPalette: true });
    return [...byTag.values()].sort((a, b) => (b.cnt - a.cnt) || a.tag.localeCompare(b.tag));
  }, [counts, palette]);

  const duplicateGroups = useMemo(() => {
    const groups = new Map();
    for (const r of rows) {
      if (r.cnt === 0) continue;
      const key = canonicalKey(r.tag);
      if (!key) continue;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(r);
    }
    return [...groups.values()].filter((g) => g.length > 1);
  }, [rows]);

  const totalTagged = useMemo(() => (counts || []).reduce((n, r) => n + r.cnt, 0), [counts]);

  if (!isOpen) return null;

  const refreshGrid = async () => {
    await load();
    // Drop the cached query windows FIRST — they carry a rowTags snapshot that
    // predates this write, and refreshCallback would serve it straight back.
    if (typeof invalidateRowMeta === "function" && ct) invalidateRowMeta(ct.id);
    if (typeof refreshCallback === "function" && ct) await refreshCallback(ct);
  };

  const setColor = (tag, color) => up("tagColors", { ...palette, [tag]: color });

  const addTag = () => {
    const name = newTag.replace(/\s+/g, " ").trim();
    if (!name) return;
    if (rows.some((r) => r.tag === name)) { toast.info("That tag already exists"); setNewTag(""); return; }
    // Creating a tag only defines it. Nothing is tagged until you apply it from
    // the row menu or Bulk Tag — creation must never write to rows.
    up("tagColors", { ...palette, [name]: th.sev.low });
    setNewTag("");
  };

  const doRename = async (from, to) => {
    const target = String(to || "").replace(/\s+/g, " ").trim();
    if (!target || target === from) { setRenaming(null); return; }
    const collides = rows.find((r) => r.tag === target);
    if (collides && collides.cnt > 0) {
      const ok = await confirm({
        title: `Merge into "${target}"?`,
        message: `"${target}" already exists on ${formatNumber(collides.cnt)} rows. Renaming merges both tags into it.`,
        confirmLabel: "Merge",
      });
      if (!ok) return;
    }
    setBusy(true);
    try {
      const res = await tle.renameTag(ct.id, from, target);
      if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      if (res && res.ok === false) throw new Error(res.error || "Rename failed");
      const nextPalette = { ...palette };
      const color = nextPalette[from] || nextPalette[target] || th.sev.low;
      delete nextPalette[from];
      nextPalette[target] = nextPalette[target] || color;
      up("tagColors", nextPalette);
      setRenaming(null);
      await refreshGrid();
      toast.success(`Renamed to "${target}"`, { detail: `${formatNumber((res?.renamed || 0) + (res?.merged || 0))} rows updated` });
    } catch (e) {
      toast.error("Rename failed", { detail: String(e?.message || e) });
    } finally {
      setBusy(false);
    }
  };

  const doDelete = async (tag, cnt) => {
    if (cnt > 0) {
      const ok = await confirm({
        title: `Delete "${tag}"?`,
        message: `This removes the tag from ${formatNumber(cnt)} row${cnt === 1 ? "" : "s"} in this tab and from the palette. The rows themselves are untouched.`,
        confirmLabel: `Remove from ${formatNumber(cnt)} rows`,
        destructive: true,
      });
      if (!ok) return;
    }
    setBusy(true);
    try {
      if (cnt > 0) {
        const res = await tle.deleteTag(ct.id, tag);
        if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
        if (res && res.ok === false) throw new Error(res.error || "Delete failed");
      }
      const next = { ...palette };
      delete next[tag];
      up("tagColors", next);
      // A tag filter pinned to the tag we just deleted would leave an empty grid.
      const tf = ct.tagFilter;
      if (Array.isArray(tf) && tf.includes(tag)) {
        const remaining = tf.filter((t) => t !== tag);
        up("tagFilter", remaining.length ? remaining : null);
      } else if (typeof tf === "string" && tf === tag) {
        up("tagFilter", null);
      }
      await refreshGrid();
      if (cnt > 0) toast.success(`Deleted "${tag}"`, { detail: `${formatNumber(cnt)} rows untagged` });
    } catch (e) {
      toast.error("Delete failed", { detail: String(e?.message || e) });
    } finally {
      setBusy(false);
    }
  };

  const doMergeDuplicates = async () => {
    const ok = await confirm({
      title: "Merge look-alike tags?",
      message: `${duplicateGroups.length} group${duplicateGroups.length === 1 ? "" : "s"} of tags differ only by capitalisation or spacing. Each group collapses into its most-used spelling.`,
      confirmLabel: "Merge",
    });
    if (!ok) return;
    setBusy(true);
    try {
      const res = await tle.mergeDuplicateTags(ct.id);
      if (isIpcError(res)) throw new Error(ipcErrorMessage(res));
      const merges = res?.merges || [];
      if (merges.length) {
        const next = { ...palette };
        for (const m of merges) {
          if (next[m.from] && !next[m.to]) next[m.to] = next[m.from];
          delete next[m.from];
        }
        up("tagColors", next);
      }
      await refreshGrid();
      toast.success(`Merged ${merges.length} tag${merges.length === 1 ? "" : "s"}`);
    } catch (e) {
      toast.error("Merge failed", { detail: String(e?.message || e) });
    } finally {
      setBusy(false);
    }
  };

  const filterByTag = (tag) => {
    up("tagFilter", [tag]);
    setModal(null);
  };

  const rowStyle = {
    display: "flex", alignItems: "center", gap: 8, padding: "6px 8px", borderRadius: 8,
    border: `1px solid ${th.glassBorder}`, background: th.glassBg,
    boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)",
  };

  const subtitle = counts === null
    ? "Loading tag usage…"
    : `${rows.length} tag${rows.length === 1 ? "" : "s"} · ${formatNumber(totalTagged)} tagged row${totalTagged === 1 ? "" : "s"}`;

  return (
    <Modal title="Manage Tags" subtitle={subtitle} width={560} onClose={() => setModal(null)} footer={true}>
      {duplicateGroups.length > 0 && (
        <div style={{
          display: "flex", alignItems: "center", gap: 10, marginBottom: 12, padding: "9px 12px", borderRadius: 8,
          background: th.warning + "14", border: `1px solid ${th.warning}44`, color: th.warning,
          fontSize: 11.5, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
        }}>
          <span style={{ flex: 1 }}>
            {duplicateGroups.length} tag group{duplicateGroups.length === 1 ? "" : "s"} differ only by case or spacing
            {" — "}{duplicateGroups.map((g) => g.map((r) => `"${r.tag}"`).join(" / ")).slice(0, 2).join(", ")}
          </span>
          <Button size="sm" variant="accentSoft" onClick={doMergeDuplicates} disabled={busy}>Merge</Button>
        </div>
      )}

      <Card label="Tags in this tab" style={{ marginBottom: 12 }} padding="10px 10px">
        {counts === null ? (
          <Loading label="Reading tags…" />
        ) : rows.length === 0 ? (
          <div style={{ padding: "14px 4px", color: th.textMuted, fontSize: 12, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" }}>
            No tags yet. Create one below, then apply it from a row's right-click menu or Bulk Tag.
          </div>
        ) : (
          <div style={{ maxHeight: "44vh", overflow: "auto", display: "flex", flexDirection: "column", gap: 5 }}>
            {rows.map(({ tag, cnt }) => {
              const color = palette[tag] || th.textMuted;
              const isRenaming = renaming?.tag === tag;
              return (
                <div key={tag} style={rowStyle}>
                  <input
                    type="color"
                    value={/^#[0-9a-f]{6}$/i.test(color) ? color : "#8b949e"}
                    onChange={(e) => setColor(tag, e.target.value)}
                    title="Tag colour"
                    style={{ width: 20, height: 18, border: "none", cursor: "pointer", borderRadius: 3, padding: 0, background: "none", flexShrink: 0 }}
                  />
                  {isRenaming ? (
                    <Input
                      autoFocus
                      value={renaming.draft}
                      onChange={(e) => setRenaming({ tag, draft: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") doRename(tag, renaming.draft);
                        if (e.key === "Escape") setRenaming(null);
                      }}
                      style={{ flex: 1 }}
                    />
                  ) : (
                    <span style={{ flex: 1, color: th.text, fontSize: 12, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {tag}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => cnt > 0 && filterByTag(tag)}
                    disabled={cnt === 0}
                    title={cnt > 0 ? "Filter the grid to these rows" : "Not applied to any row yet"}
                    style={{
                      minWidth: 62, textAlign: "right", background: "none", border: "none", padding: "2px 4px",
                      color: cnt > 0 ? th.accent : th.textMuted, fontSize: 11, fontVariantNumeric: "tabular-nums",
                      cursor: cnt > 0 ? "pointer" : "default", fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
                    }}
                  >
                    {cnt > 0 ? `${formatNumber(cnt)} rows` : "unused"}
                  </button>
                  {isRenaming ? (
                    <>
                      <Button size="sm" onClick={() => doRename(tag, renaming.draft)} disabled={busy}>Save</Button>
                      <Button size="sm" variant="ghost" onClick={() => setRenaming(null)}>Cancel</Button>
                    </>
                  ) : (
                    <>
                      <Button size="sm" variant="ghost" onClick={() => setRenaming({ tag, draft: tag })} disabled={busy}>Rename</Button>
                      <button
                        type="button"
                        onClick={() => doDelete(tag, cnt)}
                        disabled={busy}
                        title={cnt > 0 ? `Remove from ${formatNumber(cnt)} rows and delete` : "Delete from palette"}
                        style={{ background: "none", border: "none", color: th.danger, cursor: busy ? "not-allowed" : "pointer", fontSize: 12, padding: "2px 6px" }}
                      >
                        ✕
                      </button>
                    </>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      <Card label="New tag">
        <div style={{ display: "flex", gap: 6 }}>
          <Input
            value={newTag}
            onChange={(e) => setNewTag(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") addTag(); }}
            placeholder="Tag name…"
            style={{ flex: 1 }}
          />
          <Button onClick={addTag} disabled={!newTag.trim()}>Add</Button>
        </div>
        <div style={{ marginTop: 6, fontSize: 10.5, color: th.textMuted, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" }}>
          Creating a tag only defines it. No rows are tagged until you apply it from a row's right-click menu or from Bulk Tag / Bookmark.
        </div>
      </Card>
    </Modal>
  );
}
