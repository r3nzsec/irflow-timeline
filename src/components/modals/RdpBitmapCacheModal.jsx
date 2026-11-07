import { useEffect, useMemo, useState } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import { Modal } from "../primitives/index.js";
import { formatBytes } from "../../utils/format.js";

const emptySummary = {
  fileCount: 0,
  bcacheCount: 0,
  cacheBinCount: 0,
  totalBytes: 0,
  users: [],
  cacheDirectories: [],
};

function shortPath(value) {
  const text = String(value || "");
  if (text.length <= 86) return text;
  return `${text.slice(0, 34)}...${text.slice(-48)}`;
}

function fileName(value) {
  return String(value || "").split(/[\\/]+/).filter(Boolean).pop() || String(value || "");
}

function formatDateTime(value) {
  if (!value) return "unknown";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function inputSummaryFromManifest(manifest) {
  if (!manifest) return null;
  const inputs = manifest.inputs || [];
  const summary = { ...emptySummary, fileCount: manifest.inputCount || inputs.length, totalBytes: 0, users: [], cacheDirectories: [] };
  const users = new Set();
  const dirs = new Set();
  for (const input of inputs) {
    if (input.kind === "bcache") summary.bcacheCount += 1;
    if (input.kind === "cache-bin") summary.cacheBinCount += 1;
    summary.totalBytes += Number(input.size) || 0;
    if (input.user) users.add(input.user);
    if (input.directory) dirs.add(input.directory);
  }
  summary.users = [...users].sort((a, b) => a.localeCompare(b));
  summary.cacheDirectories = [...dirs].sort((a, b) => a.localeCompare(b));
  return summary;
}

function toFileUrl(filePath) {
  const raw = String(filePath || "");
  if (!raw) return "";
  if (/^file:\/\//i.test(raw)) return raw;
  const normalized = raw.replace(/\\/g, "/");
  const encoded = normalized.split("/").map((part) => encodeURIComponent(part)).join("/");
  if (/^[A-Za-z]:\//.test(normalized)) return `file:///${encoded}`;
  return `file://${encoded.startsWith("/") ? "" : "/"}${encoded}`;
}

function sortOutputImage(a, b) {
  const kindA = a?.kind === "collage" ? 0 : 1;
  const kindB = b?.kind === "collage" ? 0 : 1;
  if (kindA !== kindB) return kindA - kindB;
  const tileA = Number.isFinite(a?.tileIndex) ? a.tileIndex : Number.MAX_SAFE_INTEGER;
  const tileB = Number.isFinite(b?.tileIndex) ? b.tileIndex : Number.MAX_SAFE_INTEGER;
  if (tileA !== tileB) return tileA - tileB;
  return String(a?.relativePath || a?.path || a?.name || "").localeCompare(String(b?.relativePath || b?.path || b?.name || ""));
}

function statCard(th, label, value, sub, color) {
  return (
    <div style={{ minWidth: 0, padding: "12px 14px", border: `1px solid ${th.border}66`, borderRadius: 8, background: th.panelBg }}>
      <div style={{ color: th.textMuted, fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 5 }}>{label}</div>
      <div style={{ color: color || th.text, fontSize: 20, fontWeight: 800, letterSpacing: "-0.02em" }}>{value}</div>
      {sub && <div style={{ color: th.textDim, fontSize: 11, marginTop: 4, overflowWrap: "anywhere" }}>{sub}</div>}
    </div>
  );
}

function pill(th, text, color) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", maxWidth: "100%", padding: "3px 8px", borderRadius: 999, border: `1px solid ${(color || th.accent)}55`, color: color || th.accent, background: `${color || th.accent}14`, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace", overflowWrap: "anywhere", whiteSpace: "normal" }}>
      {text}
    </span>
  );
}

export default function RdpBitmapCacheModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const [selectedImagePath, setSelectedImagePath] = useState(null);
  const [previewPaths, setPreviewPaths] = useState({});
  const [previewPending, setPreviewPending] = useState({});
  const [previewErrors, setPreviewErrors] = useState({});
  const tle = typeof window !== "undefined" ? window.tle : null;
  const isOpen = modal?.type === "rdpBitmapCache";
  const modalState = isOpen ? modal : {};

  const preflight = modalState.preflight;
  const tool = modalState.toolStatus;
  const selectedPaths = modalState.paths || [];
  const result = modalState.result;
  const resultSummary = result?.output?.summary || result?.manifest?.outputSummary || null;
  const summary = preflight?.summary || inputSummaryFromManifest(result?.manifest) || emptySummary;
  const ready = !!preflight?.ready || !!result?.ok;

  useEffect(() => {
    if (!isOpen || !tle?.rdpBitmapToolStatus) return;
    let mounted = true;
    tle.rdpBitmapToolStatus()
      .then((status) => {
        if (!mounted) return;
        setModal((p) => p?.type === "rdpBitmapCache" ? {
          ...p,
          toolStatus: status,
          toolPath: status?.source === "selected" ? status.toolPath : p.toolPath || null,
        } : p);
      })
      .catch((err) => {
        if (!mounted) return;
        setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, error: err?.message || "Could not check bmc-tools status" } : p);
      });
    return () => { mounted = false; };
  }, [isOpen, tle, setModal]);

  useEffect(() => {
    if (!isOpen || !tle?.onRdpBitmapProgress) return undefined;
    const cleanup = tle.onRdpBitmapProgress((progress) => {
      setModal((p) => {
        if (p?.type !== "rdpBitmapCache") return p;
        if (p.jobId && progress?.jobId && p.jobId !== progress.jobId) return p;
        return { ...p, progress };
      });
    });
    return typeof cleanup === "function" ? cleanup : undefined;
  }, [isOpen, tle, setModal]);

  useEffect(() => {
    if (!isOpen || !tle?.rdpBitmapListHistory) return;
    let cancelled = false;
    setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, historyLoading: true } : p);
    tle.rdpBitmapListHistory({ limit: 8 })
      .then((history) => {
        if (cancelled) return;
        setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, historyRecords: history?.records || [], historyLoading: false } : p);
      })
      .catch((err) => {
        if (cancelled) return;
        setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, historyLoading: false, error: err?.message || "Could not load RDP Bitmap Cache history" } : p);
      });
    return () => { cancelled = true; };
  }, [isOpen, tle, setModal]);

  const filesPreview = useMemo(() => (preflight?.files || []).slice(0, 12), [preflight]);
  const outputImages = useMemo(() => {
    const images = result?.output?.images || result?.manifest?.outputs || [];
    return [...images].sort(sortOutputImage);
  }, [result]);
  const previewImages = useMemo(() => outputImages.slice(0, 72), [outputImages]);
  const selectedImage = outputImages.find((image) => image.path === selectedImagePath) || outputImages[0] || null;
  const sourcePaths = selectedPaths.length ? selectedPaths : (result?.sourcePaths || []);
  const sourceText = sourcePaths.length ? sourcePaths.map(shortPath).join("\n") : "No cache source selected";
  const canExtract = ready && selectedPaths.length === 1 && (tool?.installed || modalState.toolPath) && !modalState.extracting;

  useEffect(() => {
    if (!isOpen) return;
    setSelectedImagePath(null);
    setPreviewPaths({});
    setPreviewPending({});
    setPreviewErrors({});
  }, [isOpen, result?.jobId]);

  const setPatch = (patch) => setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, ...patch } : p);
  const setOption = (key, value) => setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, options: { ...(p.options || {}), [key]: value } } : p);

  const selectSource = async () => {
    if (!tle?.rdpBitmapSelectSource) return;
    setPatch({ selecting: true, error: null, result: null, packageResult: null });
    try {
      const selected = await tle.rdpBitmapSelectSource();
      if (selected) {
        setPatch({
          paths: selected.paths || [],
          preflight: selected.preflight || null,
          phase: "input",
          selecting: false,
          progress: null,
          result: null,
        });
      } else {
        setPatch({ selecting: false });
      }
    } catch (err) {
      setPatch({ selecting: false, error: err?.message || "Could not select RDP Bitmap Cache source" });
    }
  };

  const selectTool = async () => {
    if (!tle?.rdpBitmapSelectTool) return;
    setPatch({ selectingTool: true, error: null });
    try {
      const status = await tle.rdpBitmapSelectTool();
      setPatch({ selectingTool: false, toolStatus: status || tool, toolPath: status?.toolPath || modalState.toolPath || null });
    } catch (err) {
      setPatch({ selectingTool: false, error: err?.message || "Could not select bmc-tools" });
    }
  };

  const runExtraction = async () => {
    if (!tle?.rdpBitmapExtract || !selectedPaths.length) return;
    const jobId = `rdp-bitmap-ui-${Date.now()}`;
    setPatch({ extracting: true, jobId, progress: { jobId, phase: "starting", text: "Starting extraction" }, error: null, result: null, packageResult: null });
    try {
      const explicitToolPath = tool?.source === "selected" ? (modalState.toolPath || tool?.toolPath || null) : null;
      const res = await tle.rdpBitmapExtract(selectedPaths, {
        ...(modalState.options || {}),
        jobId,
        toolPath: explicitToolPath,
      });
      setPatch({
        extracting: false,
        phase: res?.ok ? "results" : "input",
        result: res?.ok ? res : null,
        error: res?.ok ? null : (res?.error || "RDP Bitmap Cache extraction failed"),
        progress: res?.ok ? { jobId, phase: "completed", text: "Extraction complete", imageCount: res?.output?.summary?.imageCount || 0 } : null,
        jobId: null,
      });
      if (res?.ok && tle?.rdpBitmapListHistory) {
        tle.rdpBitmapListHistory({ limit: 8 })
          .then((history) => setModal((p) => p?.type === "rdpBitmapCache" ? { ...p, historyRecords: history?.records || [] } : p))
          .catch(() => {});
      }
    } catch (err) {
      setPatch({ extracting: false, jobId: null, error: err?.message || "RDP Bitmap Cache extraction failed", progress: null });
    }
  };

  const cancelExtraction = async () => {
    const jobId = modalState.jobId;
    if (!jobId || !tle?.rdpBitmapCancel) return;
    await tle.rdpBitmapCancel(jobId);
    setPatch({ extracting: false, jobId: null, progress: null, error: "Extraction cancelled" });
  };

  const openOutput = async () => {
    if (!result?.outputDir || !tle?.rdpBitmapOpenOutputFolder) return;
    const opened = await tle.rdpBitmapOpenOutputFolder(result.outputDir);
    if (opened?.error) setPatch({ error: opened.error });
  };

  const exportEvidencePackage = async () => {
    if (!result?.outputDir || !tle?.rdpBitmapExportPackage) return;
    setPatch({ packageExporting: true, packageResult: null, error: null });
    try {
      const exported = await tle.rdpBitmapExportPackage(result.outputDir);
      if (exported?.__ipcError || exported?.error) throw new Error(exported.message || exported.error || "Could not export RDP Bitmap Cache evidence package");
      setPatch({ packageExporting: false, packageResult: exported });
    } catch (err) {
      setPatch({ packageExporting: false, error: err?.message || "Could not export RDP Bitmap Cache evidence package" });
    }
  };

  const openPackage = async () => {
    const packageDir = modalState.packageResult?.packageDir;
    if (!packageDir || !tle?.rdpBitmapOpenOutputFolder) return;
    const opened = await tle.rdpBitmapOpenOutputFolder(packageDir);
    if (opened?.error) setPatch({ error: opened.error });
  };

  const refreshHistory = async () => {
    if (!tle?.rdpBitmapListHistory) return;
    setPatch({ historyLoading: true });
    try {
      const history = await tle.rdpBitmapListHistory({ limit: 8 });
      setPatch({ historyLoading: false, historyRecords: history?.records || [] });
    } catch (err) {
      setPatch({ historyLoading: false, error: err?.message || "Could not refresh RDP Bitmap Cache history" });
    }
  };

  const loadHistoryRecord = async (record) => {
    if (!record?.outputDir || !tle?.rdpBitmapLoadHistory) return;
    setPatch({ historyLoading: true, error: null });
    try {
      const loaded = await tle.rdpBitmapLoadHistory(record.outputDir);
      setPatch({
        historyLoading: false,
        result: loaded?.ok ? loaded : null,
        preflight: loaded?.preflight || null,
        paths: [],
        packageResult: null,
        phase: loaded?.ok ? "results" : "input",
        error: loaded?.ok ? null : (loaded?.error || "Could not load RDP Bitmap Cache history item"),
        progress: loaded?.ok ? { phase: "loaded", text: "Loaded previous extraction", imageCount: loaded?.output?.summary?.imageCount || 0 } : null,
      });
    } catch (err) {
      setPatch({ historyLoading: false, error: err?.message || "Could not load RDP Bitmap Cache history item" });
    }
  };

  const openHistoryOutput = async (record) => {
    if (!record?.outputDir || !tle?.rdpBitmapOpenOutputFolder) return;
    const opened = await tle.rdpBitmapOpenOutputFolder(record.outputDir);
    if (opened?.error) setPatch({ error: opened.error });
  };

  const ensurePreviewImage = async (image) => {
    if (!image?.path || !tle?.rdpBitmapPreviewImage) return null;
    if (previewPaths[image.path]) return previewPaths[image.path];
    if (previewPending[image.path] || previewErrors[image.path]) return null;
    setPreviewPending((p) => ({ ...p, [image.path]: true }));
    try {
      const converted = await tle.rdpBitmapPreviewImage(image.path, {
        maxDimension: image.kind === "collage" ? 0 : 512,
      });
      if (converted?.ok && converted.previewPath) {
        setPreviewPaths((p) => ({ ...p, [image.path]: converted.previewPath }));
        setPreviewErrors((p) => {
          const next = { ...p };
          delete next[image.path];
          return next;
        });
        return converted.previewPath;
      }
      throw new Error(converted?.error || "Could not prepare image preview");
    } catch (err) {
      setPreviewErrors((p) => ({ ...p, [image.path]: err?.message || "Could not prepare image preview" }));
      return null;
    } finally {
      setPreviewPending((p) => {
        const next = { ...p };
        delete next[image.path];
        return next;
      });
    }
  };

  const imageSrc = (image) => toFileUrl(previewPaths[image?.path] || image?.path);

  const openImage = async (image) => {
    if (!image?.path || !tle?.rdpBitmapOpenOutputFolder) return;
    const previewPath = previewPaths[image.path] || await ensurePreviewImage(image);
    const opened = await tle.rdpBitmapOpenOutputFolder(previewPath || image.path);
    if (opened?.error) setPatch({ error: opened.error });
  };

  const copyImagePath = async (image) => {
    if (!image?.path) return;
    await navigator.clipboard?.writeText(image.path);
  };

  const copySummary = async () => {
    if (!result) return;
    const lines = [
      "RDP Bitmap Cache Extraction",
      `Source: ${(result.sourcePaths || []).join("; ")}`,
      `Output: ${result.outputDir || ""}`,
      `Inputs: ${summary.fileCount} cache files (${formatBytes(summary.totalBytes || 0)})`,
      `Images: ${resultSummary?.imageCount || 0} total, ${resultSummary?.tileCount || 0} tiles, ${resultSummary?.collageCount || 0} collages`,
      `Snapshot: ${result.manifest?.snapshotHash || ""}`,
    ];
    await navigator.clipboard?.writeText(lines.join("\n"));
  };

  const buttonBase = {
    border: `1px solid ${th.border}`,
    borderRadius: 8,
    padding: "9px 14px",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer",
    fontFamily: "-apple-system, sans-serif",
  };
  const primaryButton = { ...buttonBase, background: th.fillAccent, color: th.onAccent, borderColor: th.accent };
  const secondaryButton = { ...buttonBase, background: th.panelBg, color: th.text };
  const disabledButton = { ...primaryButton, opacity: 0.45, cursor: "default" };
  const sectionTitle = { margin: "0 0 10px", color: th.textDim, fontSize: 11, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.1em" };

  if (!isOpen) return null;

  return (
    <Modal
      open
      title="RDP Bitmap Cache"
      subtitle="Recover bitmap cache images from Windows profile artifacts"
      width={920}
      maxHeight="88vh"
      // Hard-lock the modal against accidental dismissal — an extraction can hold a
      // large recovered-image session (thousands of tiles/collages). Neither a stray
      // click on the dimmed backdrop nor an errant Escape keypress closes it; only the
      // ✕ / Close buttons do.
      closeOnOverlay={false}
      closeOnEscape={false}
      onClose={() => setModal(null)}
      footer={(
        <div style={{ display: "flex", gap: 10, justifyContent: "space-between", alignItems: "center", width: "100%" }}>
      <div style={{ color: th.textMuted, fontSize: 11, overflowWrap: "anywhere" }}>
            {modalState.packageResult?.packageDir ? `package: ${shortPath(modalState.packageResult.packageDir)}` : result?.outputDir ? shortPath(result.outputDir) : tool?.installed ? `bmc-tools: ${fileName(tool.toolPath)}` : "bmc-tools not configured"}
          </div>
          <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
            {modalState.extracting ? (
              <button onClick={cancelExtraction} style={{ ...secondaryButton, color: th.warning }}>Cancel Extraction</button>
            ) : (
              <button onClick={() => setModal(null)} style={secondaryButton}>Close</button>
            )}
            {modalState.packageResult?.packageDir && <button onClick={openPackage} style={secondaryButton}>Open Package</button>}
            {result?.outputDir && <button onClick={openOutput} style={secondaryButton}>Open Output Folder</button>}
            {!result?.outputDir && <button onClick={runExtraction} disabled={!canExtract} style={canExtract ? primaryButton : disabledButton}>Extract Images</button>}
          </div>
        </div>
      )}
      bodyPadding="18px 22px"
    >
      {modalState.error && (
        <div style={{ padding: "10px 12px", border: `1px solid ${th.danger}55`, background: `${th.danger}18`, color: th.danger, borderRadius: 8, marginBottom: 14, fontSize: 13, overflowWrap: "anywhere" }}>
          {modalState.error}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.2fr) minmax(260px, 0.8fr)", gap: 14, alignItems: "stretch", marginBottom: 16 }}>
        <div style={{ minWidth: 0, border: `1px solid ${ready ? th.success + "66" : th.border}`, borderRadius: 10, padding: 16, background: ready ? `${th.success}0d` : th.panelBg }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start", marginBottom: 10 }}>
            <div style={{ minWidth: 0 }}>
              <h4 style={{ margin: 0, color: th.text, fontSize: 16, fontWeight: 800 }}>Cache Source</h4>
              <div style={{ marginTop: 5, color: th.textDim, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{sourceText}</div>
            </div>
            <button onClick={selectSource} disabled={modalState.selecting || modalState.extracting} style={secondaryButton}>{modalState.selecting ? "Selecting..." : selectedPaths.length ? "Change Source" : "Select Source"}</button>
          </div>
	          {preflight?.warnings?.length > 0 && (
	            <div style={{ display: "grid", gap: 6, marginTop: 10 }}>
	              {preflight.warnings.slice(0, 4).map((warning, i) => (
	                <div key={i} style={{ color: th.warning, fontSize: 12, overflowWrap: "anywhere" }}>{warning}</div>
	              ))}
	            </div>
	          )}
	          {selectedPaths.length > 1 && (
	            <div style={{ color: th.warning, fontSize: 12, overflowWrap: "anywhere", marginTop: 10 }}>
	              Select a parent folder or one cache file before extraction.
	            </div>
	          )}
        </div>

        <div style={{ minWidth: 0, border: `1px solid ${tool?.installed || modalState.toolPath ? th.success + "66" : th.warning + "66"}`, borderRadius: 10, padding: 16, background: tool?.installed || modalState.toolPath ? `${th.success}0d` : `${th.warning}0d` }}>
          <h4 style={{ margin: 0, color: th.text, fontSize: 16, fontWeight: 800 }}>bmc-tools</h4>
          <div style={{ marginTop: 5, color: tool?.installed || modalState.toolPath ? th.success : th.warning, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace", overflowWrap: "anywhere" }}>
            {tool?.installed || modalState.toolPath ? shortPath(modalState.toolPath || tool.toolPath) : "Not configured"}
          </div>
          <button onClick={selectTool} disabled={modalState.selectingTool || modalState.extracting} style={{ ...secondaryButton, marginTop: 12, width: "100%" }}>{modalState.selectingTool ? "Selecting..." : "Select bmc-tools"}</button>
        </div>
      </div>

      <h4 style={sectionTitle}>Preflight</h4>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 10, marginBottom: 16 }}>
        {statCard(th, "Cache Files", summary.fileCount.toLocaleString(), `${summary.bcacheCount || 0} bmc / ${summary.cacheBinCount || 0} bin`, ready ? th.success : th.textMuted)}
        {statCard(th, "Input Size", formatBytes(summary.totalBytes || 0), `${summary.scannedFileCount || 0} files checked`, th.accent)}
        {statCard(th, "Profiles", (summary.users || []).length.toLocaleString(), (summary.users || []).slice(0, 3).join(", ") || "none detected", th.warning)}
        {statCard(th, "Output", resultSummary ? (resultSummary.imageCount || 0).toLocaleString() : "pending", resultSummary ? `${resultSummary.tileCount || 0} tiles / ${resultSummary.collageCount || 0} collages` : "not extracted", resultSummary ? th.success : th.textMuted)}
      </div>

      {(modalState.historyLoading || (modalState.historyRecords || []).length > 0) && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
            <h4 style={{ ...sectionTitle, margin: 0 }}>Previous Extractions</h4>
            <button onClick={refreshHistory} disabled={modalState.historyLoading} style={{ ...secondaryButton, padding: "6px 10px", fontSize: 11 }}>{modalState.historyLoading ? "Loading..." : "Refresh"}</button>
          </div>
          <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, overflow: "hidden", background: th.panelBg }}>
            {(modalState.historyRecords || []).length === 0 ? (
              <div style={{ padding: 14, color: th.textMuted, fontSize: 12 }}>No previous RDP Bitmap Cache extractions found.</div>
            ) : (modalState.historyRecords || []).slice(0, 5).map((record, i) => (
              <div key={record.outputDir || i} style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) auto", gap: 10, alignItems: "center", padding: "9px 10px", borderTop: i ? `1px solid ${th.border}55` : "none" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <strong style={{ color: th.text, fontSize: 13 }}>{formatDateTime(record.completedAt || record.modifiedAt)}</strong>
                    {pill(th, `${record.imageCount || 0} images`, th.accent)}
                    {record.snapshotHash && <span style={{ color: th.textDim, fontSize: 10, fontFamily: "'SF Mono',Menlo,monospace" }}>{String(record.snapshotHash).slice(0, 12)}</span>}
                  </div>
                  <div style={{ color: th.textMuted, fontSize: 11, marginTop: 3, overflowWrap: "anywhere", fontFamily: "'SF Mono',Menlo,monospace" }}>
                    {(record.sourcePaths || []).map(shortPath).join("; ") || shortPath(record.outputDir)}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={() => loadHistoryRecord(record)} style={{ ...secondaryButton, padding: "6px 10px", fontSize: 11 }}>Load</button>
                  <button onClick={() => openHistoryOutput(record)} style={{ ...secondaryButton, padding: "6px 10px", fontSize: 11 }}>Open</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 260px", gap: 14 }}>
        <div style={{ minWidth: 0 }}>
          <h4 style={sectionTitle}>Detected Cache Files</h4>
          <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, overflow: "hidden", background: th.panelBg, maxHeight: 210, overflowY: "auto" }}>
            {filesPreview.length === 0 ? (
              <div style={{ padding: 18, color: th.textMuted, textAlign: "center", fontSize: 13 }}>No cache files loaded</div>
            ) : filesPreview.map((file, i) => (
              <div key={file.path || i} style={{ display: "grid", gridTemplateColumns: "120px minmax(0, 1fr) 90px", gap: 10, padding: "8px 10px", borderTop: i ? `1px solid ${th.border}55` : "none", alignItems: "center", fontSize: 12 }}>
                <div>{pill(th, file.kind || "cache", file.kind === "bcache" ? th.accent : th.warning)}</div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: th.text, fontWeight: 700, overflowWrap: "anywhere" }}>{file.name}</div>
                  <div style={{ color: th.textMuted, fontSize: 10, overflowWrap: "anywhere", marginTop: 2 }}>{shortPath(file.path)}</div>
                </div>
                <div style={{ color: th.textDim, fontFamily: "'SF Mono',Menlo,monospace", textAlign: "right" }}>{formatBytes(file.size || 0)}</div>
              </div>
            ))}
            {(preflight?.files || []).length > filesPreview.length && (
              <div style={{ padding: "8px 10px", borderTop: `1px solid ${th.border}55`, color: th.textMuted, fontSize: 12 }}>+{(preflight.files.length - filesPreview.length).toLocaleString()} more</div>
            )}
          </div>
        </div>

        <div style={{ minWidth: 0 }}>
          <h4 style={sectionTitle}>Options</h4>
          <div style={{ display: "grid", gap: 10, border: `1px solid ${th.border}`, borderRadius: 8, padding: 12, background: th.panelBg }}>
            <label style={{ display: "flex", alignItems: "center", gap: 8, color: th.text, fontSize: 13 }}>
              <input type="checkbox" checked={!!modalState.options?.includeOld} onChange={(e) => setOption("includeOld", e.target.checked)} disabled={modalState.extracting} />
              Include old tiles
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 8, color: th.text, fontSize: 13 }}>
              <input type="checkbox" checked={modalState.options?.collage !== false} onChange={(e) => setOption("collage", e.target.checked)} disabled={modalState.extracting} />
              Generate collage
            </label>
            <label style={{ display: "grid", gap: 5, color: th.text, fontSize: 13 }}>
              Collage width
              <input type="number" min="16" max="512" value={modalState.options?.width || 64} onChange={(e) => setOption("width", Number(e.target.value) || 64)} disabled={modalState.extracting} style={{ padding: "7px 8px", borderRadius: 6, border: `1px solid ${th.border}`, background: th.bg, color: th.text }} />
            </label>
            <label style={{ display: "flex", alignItems: "center", gap: 8, color: th.text, fontSize: 13 }}>
              <input type="checkbox" checked={!!modalState.options?.verbose} onChange={(e) => setOption("verbose", e.target.checked)} disabled={modalState.extracting} />
              Verbose log
            </label>
          </div>
        </div>
      </div>

      {(modalState.extracting || modalState.progress) && (
        <div style={{ marginTop: 16, border: `1px solid ${th.accent}55`, background: `${th.accent}10`, borderRadius: 8, padding: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 8 }}>
            <strong style={{ color: th.text, fontSize: 13 }}>{modalState.progress?.phase || "running"}</strong>
            {modalState.progress?.imageCount !== undefined && <span style={{ color: th.success, fontSize: 12 }}>{modalState.progress.imageCount.toLocaleString()} images</span>}
          </div>
          <div style={{ color: th.textDim, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace", whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 120, overflowY: "auto" }}>{modalState.progress?.text || "Running bmc-tools..."}</div>
        </div>
      )}

      {result?.ok && (
        <div style={{ marginTop: 16, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, border: `1px solid ${th.success}66`, background: `${th.success}10`, borderRadius: 8, padding: 12 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{ color: th.success, fontSize: 13, fontWeight: 800 }}>Extraction complete</div>
            <div style={{ color: th.textDim, fontSize: 12, marginTop: 4, overflowWrap: "anywhere" }}>
              Snapshot {result.manifest?.snapshotHash?.slice(0, 16) || "recorded"} · {resultSummary?.imageCount || 0} images
              {modalState.packageResult?.packageDir ? ` · package exported (${formatBytes(modalState.packageResult.packageBytes || 0)})` : ""}
            </div>
            {modalState.packageResult?.packageDir && (
              <div style={{ color: th.textMuted, fontSize: 11, marginTop: 4, overflowWrap: "anywhere", fontFamily: "'SF Mono',Menlo,monospace" }}>
                {shortPath(modalState.packageResult.packageDir)}
              </div>
            )}
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
            <button onClick={copySummary} style={secondaryButton}>Copy Summary</button>
            <button onClick={exportEvidencePackage} disabled={modalState.packageExporting} style={modalState.packageExporting ? { ...secondaryButton, opacity: 0.55, cursor: "default" } : secondaryButton}>
              {modalState.packageExporting ? "Exporting..." : "Export Evidence Package"}
            </button>
          </div>
        </div>
      )}

      {result?.ok && (
        <div style={{ marginTop: 16 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 10 }}>
            <h4 style={{ ...sectionTitle, margin: 0 }}>Recovered Image Preview</h4>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "flex-end" }}>
              {pill(th, `${resultSummary?.collageCount || 0} collages`, th.success)}
              {pill(th, `${resultSummary?.tileCount || 0} tiles`, th.accent)}
              {outputImages.length > previewImages.length && pill(th, `showing ${previewImages.length} of ${outputImages.length}`, th.warning)}
            </div>
          </div>
          {outputImages.length === 0 ? (
            <div style={{ border: `1px solid ${th.border}`, borderRadius: 8, padding: 18, color: th.textMuted, textAlign: "center", fontSize: 13, background: th.panelBg }}>
              No images were found in the extraction output.
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1.1fr) minmax(260px, 0.9fr)", gap: 14, alignItems: "stretch" }}>
              <div style={{ minWidth: 0, border: `1px solid ${th.border}`, borderRadius: 8, background: th.panelBg, overflow: "hidden" }}>
                <div style={{ position: "relative", height: 310, display: "flex", alignItems: "center", justifyContent: "center", background: "#050607", borderBottom: `1px solid ${th.border}`, padding: 10 }}>
                  {selectedImage ? (
                    <img
                      src={imageSrc(selectedImage)}
                      alt={selectedImage.name || "Recovered bitmap cache image"}
                      onError={() => ensurePreviewImage(selectedImage)}
                      style={{ maxWidth: "100%", maxHeight: "100%", objectFit: "contain", imageRendering: selectedImage.kind === "tile" ? "pixelated" : "auto" }}
                    />
                  ) : null}
                  {selectedImage && previewPending[selectedImage.path] && (
                    <div style={{ position: "absolute", color: th.textMuted, fontSize: 12, fontFamily: "'SF Mono',Menlo,monospace" }}>Preparing PNG preview...</div>
                  )}
                </div>
                <div style={{ padding: 12, display: "grid", gap: 8 }}>
                  <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: th.text, fontWeight: 800, fontSize: 13, overflowWrap: "anywhere" }}>{selectedImage?.name || "No image selected"}</div>
                      <div style={{ color: th.textMuted, fontSize: 11, marginTop: 3, overflowWrap: "anywhere", fontFamily: "'SF Mono',Menlo,monospace" }}>{selectedImage?.relativePath || selectedImage?.path || ""}</div>
                    </div>
                    {selectedImage && pill(th, selectedImage.kind || "image", selectedImage.kind === "collage" ? th.success : th.accent)}
                  </div>
                  {selectedImage && (
                    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                      <span style={{ color: th.textDim, fontSize: 11 }}>{formatBytes(selectedImage.size || 0)}</span>
                      {selectedImage.tileIndex !== null && selectedImage.tileIndex !== undefined && <span style={{ color: th.textDim, fontSize: 11 }}>tile #{selectedImage.tileIndex}</span>}
                      {selectedImage.sha256 && <span style={{ color: th.textDim, fontSize: 11, fontFamily: "'SF Mono',Menlo,monospace" }}>sha256 {String(selectedImage.sha256).slice(0, 12)}</span>}
                      {selectedImage && previewPaths[selectedImage.path] && <span style={{ color: th.success, fontSize: 11 }}>PNG preview</span>}
                      {selectedImage && previewErrors[selectedImage.path] && <span style={{ color: th.danger, fontSize: 11, overflowWrap: "anywhere" }}>{previewErrors[selectedImage.path]}</span>}
                      <span style={{ flex: 1 }} />
                      <button onClick={() => copyImagePath(selectedImage)} style={{ ...secondaryButton, padding: "6px 9px", fontSize: 11 }}>Copy Path</button>
                      <button onClick={() => openImage(selectedImage)} style={{ ...secondaryButton, padding: "6px 9px", fontSize: 11 }}>Open Image</button>
                    </div>
                  )}
                </div>
              </div>

              <div style={{ minWidth: 0, border: `1px solid ${th.border}`, borderRadius: 8, background: th.panelBg, overflow: "hidden" }}>
                <div style={{ padding: "9px 10px", borderBottom: `1px solid ${th.border}`, color: th.textMuted, fontSize: 11, fontWeight: 800, textTransform: "uppercase", letterSpacing: "0.08em" }}>Thumbnails</div>
                <div style={{ maxHeight: 382, overflowY: "auto", padding: 10, display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(82px, 1fr))", gap: 8 }}>
                  {previewImages.map((image) => {
                    const active = selectedImage?.path === image.path;
                    return (
                      <button
                        key={image.path || image.relativePath || image.name}
                        type="button"
                        onClick={() => setSelectedImagePath(image.path)}
                        title={image.relativePath || image.path || image.name}
                        style={{
                          minWidth: 0,
                          display: "grid",
                          gap: 5,
                          padding: 6,
                          border: `1px solid ${active ? th.accent : th.border}`,
                          borderRadius: 7,
                          background: active ? `${th.accent}18` : th.bg,
                          color: th.text,
                          cursor: "pointer",
                          textAlign: "left",
                          fontFamily: "-apple-system, sans-serif",
                        }}
                      >
                        <span style={{ height: 68, display: "flex", alignItems: "center", justifyContent: "center", background: "#050607", borderRadius: 5, overflow: "hidden" }}>
                          <img
                            src={imageSrc(image)}
                            alt={image.name || "Recovered bitmap cache thumbnail"}
                            loading="lazy"
                            onError={() => ensurePreviewImage(image)}
                            style={{ maxWidth: "100%", maxHeight: "100%", objectFit: "contain", imageRendering: image.kind === "tile" ? "pixelated" : "auto" }}
                          />
                        </span>
                        <span style={{ color: active ? th.accent : th.textMuted, fontSize: 10, lineHeight: 1.2, overflowWrap: "anywhere" }}>{image.name}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
