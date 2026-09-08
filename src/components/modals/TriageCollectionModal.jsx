import { useEffect, useRef } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import useModalChrome from "../../hooks/useModalChrome.js";
import { DraggableResizableModal } from "../primitives/index.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { toast } from "../../store/useToastStore.js";
import { updateModal } from "../../modals/modalRegistry.js";

/**
 * TriageCollectionModal — "Open Triage Collection".
 *
 * The analyst points at a KAPE/triage folder — or a KAPE `--vhdx` image, whose artifacts
 * are first copied out of the embedded NTFS volume into a scratch folder — and this shows
 * what is inside, ranked by lateral-movement relevance, and imports the selection as
 * timeline tabs.
 *
 * Two independent lanes, because they answer different questions and an analyst may want
 * either, both, or neither:
 *   • Lateral Movement — imports the LM-relevant channels as tabs (pre-checked), then
 *     hands off to the Lateral Movement Tracker.
 *   • EVTX → Sigma     — the existing Hayabusa flow over the whole winevt directory.
 *
 * Artifacts this branch has no parser for are listed but never silently dropped: telling
 * the analyst "290 prefetch files are here, run PECmd" beats pretending they don't exist.
 */
const humanBytes = (b) => {
  const n = Number(b) || 0;
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} GB`;
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
};

export default function TriageCollectionModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const ms = useModalChrome();
  const tle = typeof window !== "undefined" ? window.tle : null;

  const isActive = modal?.type === "triageCollection";
  const patch = (p) => setModal(updateModal("triageCollection", p));

  // Open the folder picker immediately — the modal has nothing to show until a folder is
  // chosen, so making the analyst click "Browse" first would be a wasted step.
  const pickedRef = useRef(false);
  const genRef = useRef(0);
  useEffect(() => {
    if (!isActive) {
      pickedRef.current = false;
      genRef.current += 1;
      return undefined;
    }
    if (pickedRef.current || modal.phase !== "picking") return undefined;
    pickedRef.current = true;
    const gen = ++genRef.current;
    const stillThisRun = () => genRef.current === gen;
    (async () => {
      if (!tle?.triageSelectRoot) { if (stillThisRun()) patch({ phase: "manifest", error: "Triage import is not available in this window." }); return; }
      const res = await tle.triageSelectRoot();
      if (!stillThisRun()) return;
      if (isIpcError(res)) { setModal(null); toast.error("Could not open that folder", { detail: ipcErrorMessage(res) }); return; }
      if (!res || res.canceled) { setModal(null); return; }
      if (res.error) { patch({ phase: "manifest", error: res.error }); return; }

      let dir = res.dir;
      let vhdx = null;
      if (res.vhdx) {
        // A VHDX image: copy the artifacts out of the embedded NTFS volume first. The
        // handler resolves when extraction finishes; progress arrives on its own channel.
        patch({ phase: "extracting", dir: "", vhdx: { path: res.vhdx, name: res.vhdx.split("/").pop(), size: res.size }, extract: { phase: "starting", percent: 0 } });
        const out = await tle.triageOpenVhdx(res.vhdx);
        if (!stillThisRun()) return;
        if (isIpcError(out)) { patch({ phase: "manifest", error: ipcErrorMessage(out), extract: null }); return; }
        if (out?.cancelled) { setModal(null); return; }
        if (out?.error) { patch({ phase: "manifest", error: out.error, extract: null }); return; }
        dir = out.dir;
        vhdx = { path: res.vhdx, name: out.vhdx?.name || res.vhdx.split("/").pop(), ...out };
      }
      if (!dir) { setModal(null); return; }

      patch({ phase: "scanning", dir, vhdx, extract: null, discover: { phase: "starting", percent: 0 } });
      const manifest = await tle.triageDiscover(dir);
      if (!stillThisRun()) return;
      if (isIpcError(manifest)) { patch({ phase: "manifest", error: ipcErrorMessage(manifest) }); return; }
      if (manifest?.error) { patch({ phase: "manifest", error: manifest.error, manifest: null }); return; }
      // Seed the selection from the manifest's own defaults.
      const selected = new Set(manifest.lanes.lateralMovement.items.filter((i) => i.defaultChecked).map((i) => i.id));
      patch({ phase: "manifest", manifest, selected, error: null });
    })();
    return undefined;
  }, [isActive, modal?.phase]);

  // Extraction progress (VHDX only). Subscribed for the modal's lifetime; the payload is
  // tiny and only lands while phase === "extracting".
  useEffect(() => {
    if (!isActive || !tle?.onTriageVhdxProgress) return undefined;
    return tle.onTriageVhdxProgress((p) => {
      if (!p) return;
      patch((prev) => (prev.phase === "extracting" ? { extract: { ...(prev.extract || {}), ...p } } : {}));
    });
  }, [isActive]);

  useEffect(() => {
    if (!isActive || !tle?.onTriageDiscoverProgress) return undefined;
    return tle.onTriageDiscoverProgress((p) => {
      if (!p) return;
      patch((prev) => (prev.phase === "scanning" ? { discover: { ...(prev.discover || {}), ...p } } : {}));
    });
  }, [isActive]);

  // Closing the modal mid-extraction must stop the worker: it would otherwise keep
  // filling the scratch volume with nothing waiting for the result.
  const closeModal = () => {
    genRef.current += 1;
    if (modal?.phase === "extracting" && modal?.extract?.jobId && tle?.triageCancelVhdx) {
      tle.triageCancelVhdx(modal.extract.jobId).catch?.(() => {});
    }
    if (modal?.phase === "scanning" && modal?.discover?.jobId && tle?.triageCancelDiscover) {
      tle.triageCancelDiscover(modal.discover.jobId).catch?.(() => {});
    }
    setModal(null);
  };

  if (!isActive) return null;

  const { phase, dir, manifest, error, selected, showAllEvtx, vhdx, extract, discover } = modal;
  const lm = manifest?.lanes?.lateralMovement;
  const sel = selected instanceof Set ? selected : new Set();

  const toggle = (id) => patch((p) => {
    const s = new Set(p.selected || []);
    s.has(id) ? s.delete(id) : s.add(id);
    return { selected: s };
  });

  const startImport = async () => {
    const paths = [...sel];
    if (paths.length === 0) { toast.info("Nothing selected", { detail: "Pick at least one artifact to import." }); return; }
    patch({ phase: "importing" });
    const res = await tle.triageImport(dir, paths, {
      analyzeAfter: modal.analyzeAfter,
      hostLabel: manifest?.host?.hostname || "",
      // Only ask for a Sigma grant when the analyst actually chose that lane.
      sigmaEvtxDir: modal.includeSigmaLane ? (manifest?.lanes?.evtxSigma?.dir || "") : "",
    });
    if (isIpcError(res) || res?.error) {
      patch({ phase: "manifest" });
      toast.error("Import failed", { detail: isIpcError(res) ? ipcErrorMessage(res) : res.error });
      return;
    }
    if (res.rejectedCount > 0) {
      toast.warning(`${res.rejectedCount} path${res.rejectedCount === 1 ? "" : "s"} skipped`, {
        detail: "They resolved outside the folder you selected.",
      });
    }
    // A persistent toast with a Cancel action: a collection can queue several multi-GB
    // files, so a mis-click must be recoverable. App.jsx dismisses it once the batch
    // settles (see _settleTriageBatch), so it cannot linger after the work is done.
    const toastId = toast.info("Importing collection", {
      detail: `${res.items.length} artifact${res.items.length === 1 ? "" : "s"} queued.`,
      ttl: 0,
      actionLabel: "Cancel remaining",
      onAction: async () => {
        const r = await tle.triageCancelBatch(res.batchId, (res.items || []).map((i) => i.tabId));
        if (isIpcError(r)) { toast.error("Could not cancel", { detail: ipcErrorMessage(r) }); return; }
        toast.warning("Import cancelled", {
          detail: `${r.dropped || 0} queued, ${r.cancelledJobs || 0} in progress.`,
        });
      },
    });

    // App.jsx watches these tab ids and hands off to the Lateral Movement Tracker once
    // every one is terminal. Published in a single write, with the toast id, so the
    // watcher can never consume a half-built batch.
    useUIStore.getState().setPendingTriageBatch({
      ...res,
      analyzeAfter: modal.analyzeAfter,
      hostLabel: manifest?.host?.hostname || "",
      toastId,
    });
    setModal(null);
  };

  const dot = (tier) => "●".repeat(Math.max(1, tier));
  const lbl = { fontSize: 10, color: th.textMuted, fontFamily: "-apple-system, sans-serif" };

  return (
    <DraggableResizableModal
      defaultWidth={720}
      defaultHeight={Math.round(window.innerHeight * 0.8)}
      minWidth={520}
      minHeight={380}
      ariaLabel="Open Triage Collection"
      onClose={closeModal}
    >
      {({ startDrag, height }) => (<>
        <div onMouseDown={startDrag} style={{ padding: "14px 18px 10px", borderBottom: `1px solid ${th.border}22`, display: "flex", alignItems: "center", justifyContent: "space-between", flexShrink: 0, background: `linear-gradient(135deg, ${th.panelBg}ee, ${th.modalBg}dd)`, cursor: "grab" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Open Triage Collection</h3>
            <p style={{ margin: "2px 0 0", ...lbl }}>{vhdx?.path || dir || "Select a KAPE / triage folder or VHDX image"}</p>
          </div>
          <button onClick={closeModal} style={{ width: 24, height: 24, borderRadius: 12, background: th.textMuted + "15", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 13 }}>{"✕"}</button>
        </div>

        <div style={{ flex: 1, overflow: "auto", padding: "14px 18px" }}>
          {phase === "extracting" && (
            <div style={{ padding: "18px 16px", borderRadius: 12, background: th.glassBg, border: `1px solid ${th.glassBorder}`, boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}>
              <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 6 }}>
                <strong style={{ fontSize: 12.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>
                  {extract?.phase === "extracting" ? "Extracting artifacts from image" : extract?.phase === "finalizing" ? "Finishing" : "Reading the NTFS volume inside the image"}
                </strong>
                <span style={{ ...lbl, marginLeft: "auto", fontVariantNumeric: "tabular-nums" }}>{Number.isFinite(extract?.percent) ? `${extract.percent}%` : ""}</span>
              </div>
              <div style={{ height: 6, borderRadius: 3, background: th.bgInput, overflow: "hidden" }}>
                <div style={{ height: "100%", width: `${Math.max(2, Math.min(100, extract?.percent || 0))}%`, borderRadius: 3, background: `linear-gradient(90deg, ${th.accent}, ${th.accentHover})`, boxShadow: `0 0 10px ${th.accent}66`, transition: "width 160ms var(--ease-out, ease-out)" }} />
              </div>
              <div style={{ ...lbl, marginTop: 8, display: "flex", gap: 8 }}>
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{extract?.statusDetail || "Opening image…"}</span>
              </div>
              {extract?.current && <div style={{ ...lbl, marginTop: 3, fontFamily: "monospace", fontSize: 9.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{extract.current}</div>}
              <div style={{ ...lbl, marginTop: 10, lineHeight: 1.5 }}>
                Only recognized artifacts are copied out (event logs, $MFT/$J, hives, Prefetch, LNK, Jump Lists, browser and Defender data, EZ-Tools CSVs). The image itself is never modified.
              </div>
            </div>
          )}

          {phase === "scanning" && (
            <div style={{ padding: "18px 16px", borderRadius: 12, background: th.glassBg, border: `1px solid ${th.glassBorder}` }}>
              <div style={{ fontSize: 12.5, color: th.text, fontFamily: "-apple-system, sans-serif", fontWeight: 600, marginBottom: 8 }}>
                Scanning collection
              </div>
              <div style={{ ...lbl }}>{discover?.statusDetail || "Walking the folder tree…"}</div>
              {Number.isFinite(discover?.scanned) && (
                <div style={{ ...lbl, marginTop: 6, fontVariantNumeric: "tabular-nums" }}>
                  {Number(discover.scanned).toLocaleString()} files scanned
                  {Number.isFinite(discover.classified) ? ` · ${Number(discover.classified).toLocaleString()} artifacts` : ""}
                </div>
              )}
            </div>
          )}

          {error && (
            <div style={{ padding: 12, borderRadius: 8, background: th.danger + "12", border: `1px solid ${th.danger}44`, color: th.text, fontSize: 12, fontFamily: "-apple-system, sans-serif", lineHeight: 1.5 }}>
              {error}
              <div style={{ marginTop: 10 }}>
                <button
                  onClick={() => {
                    pickedRef.current = false;
                    genRef.current += 1;
                    patch({ phase: "picking", error: null, manifest: null, dir: "", vhdx: null, extract: null });
                  }}
                  style={{ ...ms.bs, borderRadius: 8 }}
                >
                  Choose again
                </button>
              </div>
            </div>
          )}

          {phase === "manifest" && manifest && (<>
            {/* Provenance */}
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <span style={{ padding: "2px 8px", borderRadius: 4, background: th.accent + "18", color: th.accent, fontSize: 10, fontWeight: 700, fontFamily: "-apple-system, sans-serif" }}>{manifest.kind.toUpperCase()}</span>
              <span style={{ fontSize: 12, color: th.text, fontWeight: 600, fontFamily: "-apple-system, sans-serif" }}>{manifest.host?.hostname}</span>
              <span style={{ ...lbl }}>host confidence: {manifest.host?.confidence} ({manifest.host?.source})</span>
              <span style={{ ...lbl, marginLeft: "auto" }}>{manifest.stats?.classified} artifacts · {manifest.stats?.elapsedMs}ms</span>
            </div>

            {vhdx && (
              <div style={{ padding: "7px 10px", marginBottom: 8, borderRadius: 8, background: th.glassBg, border: `1px solid ${th.glassBorder}`, fontSize: 10.5, color: th.textDim, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>
                <span style={{ color: th.text, fontWeight: 600 }}>{vhdx.name}</span>
                {vhdx.extracted ? ` · ${vhdx.extracted.count.toLocaleString()} artifact${vhdx.extracted.count === 1 ? "" : "s"} (${humanBytes(vhdx.extracted.bytes)}) copied out of the image` : ""}
                {vhdx.volume?.layout === "volume" ? " · full Windows volume, not a KAPE package" : ""}
                {vhdx.notSelected ? ` · ${vhdx.notSelected.toLocaleString()} other files left in the image` : ""}
                {vhdx.skipped?.failed?.length ? ` · ${vhdx.skipped.failed.length} could not be copied` : ""}
              </div>
            )}

            {/* Anything the analyst must know before trusting the attribution. */}
            {(manifest.host?.notes || []).concat(manifest.warnings || []).concat(vhdx?.warnings || []).map((n, i) => (
              <div key={i} style={{ padding: "7px 10px", marginBottom: 6, borderRadius: 6, background: th.warning + "10", border: `1px solid ${th.warning}33`, color: th.textDim, fontSize: 10.5, fontFamily: "-apple-system, sans-serif", lineHeight: 1.45 }}>{n}</div>
            ))}

            {/* Lane 1 — Lateral Movement */}
            <div style={{ marginTop: 12, border: `1px solid ${th.border}`, borderRadius: 8, overflow: "hidden" }}>
              <div style={{ padding: "8px 12px", background: th.panelBg, borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", gap: 8 }}>
                <strong style={{ fontSize: 12, color: th.text, fontFamily: "-apple-system, sans-serif" }}>Lateral Movement</strong>
                <span style={lbl}>{sel.size} selected of {lm.items.length} relevant · {lm.totalEvtx} EVTX in collection</span>
              </div>
              {lm.items.length === 0 && <div style={{ ...lbl, padding: 12 }}>No lateral-movement channels found in this collection.</div>}
              {lm.items.filter((i) => showAllEvtx || i.lmTier >= 2 || i.defaultChecked).map((i) => (
                <label key={i.id} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 12px", borderBottom: `1px solid ${th.border}22`, cursor: i.empty ? "default" : "pointer", opacity: i.empty ? 0.55 : 1 }}>
                  <input type="checkbox" checked={sel.has(i.id)} onChange={() => toggle(i.id)} style={{ accentColor: th.accent, cursor: "pointer" }} />
                  <span style={{ width: 26, color: i.lmTier === 3 ? th.sev.critical : i.lmTier === 2 ? th.sev.high : th.textMuted, fontSize: 9 }}>{dot(i.lmTier)}</span>
                  <span style={{ width: 74, textAlign: "right", ...lbl, fontFamily: "monospace" }}>{i.sizeLabel}</span>
                  <span style={{ flex: 1, fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{i.name}</span>
                  {i.note && <span style={{ ...lbl, fontSize: 9.5 }}>{i.note}</span>}
                </label>
              ))}
              {lm.items.some((i) => i.lmTier < 2 && !i.defaultChecked) && (
                <button onClick={() => patch({ showAllEvtx: !showAllEvtx })} style={{ ...ms.bs, border: "none", background: "transparent", color: th.accent, fontSize: 10, padding: "6px 12px" }}>
                  {showAllEvtx ? "Show fewer channels" : `Show all ${lm.totalEvtx} channels`}
                </button>
              )}
            </div>

            {/* Lane 2 — Sigma (unchanged existing flow) */}
            <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 10, padding: "8px 12px", border: `1px solid ${th.border}`, borderRadius: 8, cursor: "pointer" }}>
              <input type="checkbox" checked={!!modal.includeSigmaLane} onChange={() => patch((p) => ({ includeSigmaLane: !p.includeSigmaLane }))} style={{ accentColor: th.accent, cursor: "pointer" }} />
              <span style={{ fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>EVTX logs → Sigma scan</span>
              <span style={lbl}>{manifest.lanes.evtxSigma.count} files · heavy · opens the Sigma wizard after import</span>
            </label>

            {/* Other importable artifacts */}
            {manifest.artifacts.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ ...lbl, marginBottom: 5 }}>Also importable</div>
                {manifest.artifacts.map((a) => (
                  <label key={a.kind} style={{ display: "flex", alignItems: "center", gap: 8, padding: "4px 2px", cursor: "pointer" }}>
                    <input type="checkbox"
                      checked={(a.paths || []).every((p) => sel.has(p)) && a.paths.length > 0}
                      onChange={() => patch((p) => {
                        const s = new Set(p.selected || []);
                        const all = (a.paths || []).every((x) => s.has(x));
                        for (const x of a.paths || []) { all ? s.delete(x) : s.add(x); }
                        return { selected: s };
                      })}
                      style={{ accentColor: th.accent, cursor: "pointer" }} />
                    <span style={{ fontSize: 11.5, color: th.text, fontFamily: "-apple-system, sans-serif" }}>{a.label}</span>
                    <span style={lbl}>{a.count > 1 ? `${a.count} files · ` : ""}{a.sizeLabel}{a.heavy ? " · heavy" : ""}</span>
                  </label>
                ))}
              </div>
            )}

            {/* Present but unparseable — informational, never silently dropped */}
            {manifest.info.length > 0 && (
              <div style={{ marginTop: 12, padding: "8px 12px", borderRadius: 8, background: th.bgAlt, border: `1px solid ${th.border}55` }}>
                <div style={{ ...lbl, marginBottom: 4 }}>Present in the collection, no parser in this build</div>
                {manifest.info.slice(0, 10).map((a) => (
                  <div key={a.kind} style={{ display: "flex", gap: 8, fontSize: 10.5, color: th.textDim, fontFamily: "-apple-system, sans-serif", padding: "1px 0" }}>
                    <span style={{ flex: 1 }}>{a.label}</span>
                    <span style={{ ...lbl }}>{a.count > 1 ? `${a.count} · ` : ""}{a.sizeLabel}</span>
                    {a.hint && <span style={{ ...lbl, color: th.accent, minWidth: 150 }}>{a.hint}</span>}
                  </div>
                ))}
                {manifest.info.length > 10 && (
                  <div style={{ ...lbl, paddingTop: 4 }}>+{manifest.info.length - 10} more</div>
                )}
              </div>
            )}
          </>)}

          {phase === "importing" && <div style={{ ...lbl, padding: 20, textAlign: "center" }}>Queuing imports…</div>}
        </div>

        <div style={{ padding: "10px 18px", borderTop: `1px solid ${th.border}22`, display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", ...lbl }}>
            <input type="checkbox" checked={!!modal.analyzeAfter} onChange={() => patch((p) => ({ analyzeAfter: !p.analyzeAfter }))} style={{ accentColor: th.accent, cursor: "pointer" }} />
            Run Lateral Movement analysis after import
          </label>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button onClick={closeModal} style={{ ...ms.bs, borderRadius: 8 }}>{phase === "extracting" ? "Cancel extraction" : "Cancel"}</button>
            <button onClick={startImport} disabled={phase !== "manifest" || sel.size === 0}
              style={{ ...ms.bp, borderRadius: 8, opacity: phase === "manifest" && sel.size > 0 ? 1 : 0.5 }}>
              Import {sel.size || ""}{modal.analyzeAfter ? " + Analyze" : ""}
            </button>
          </div>
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
