import { useEffect, useRef, useCallback } from "react";
import useUIStore from "../../store/useUIStore.js";
import useTabStore from "../../store/useTabStore.js";
import useTheme from "../../hooks/useTheme.js";
import { toast } from "../../store/useToastStore.js";
import { isIpcError, ipcErrorMessage } from "../../utils/ipc-result.js";
import { formatNumber } from "../../utils/format.js";
import { clearIpcSubscription, replaceIpcSubscription } from "../../utils/ipc-subscriptions.js";
import { Modal } from "../primitives/index.js";
import { updateModal } from "../../modals/modalRegistry.js";

const MAX_LOG_LINES = 250;

function sourceKey(root) {
  return `${root.tool}:${root.path}`;
}

function shortenPath(p, max = 72) {
  if (!p || p.length <= max) return p || "";
  const tail = p.slice(-max);
  const slash = tail.indexOf("/");
  return slash >= 0 ? `…${tail.slice(slash)}` : `…${tail}`;
}

function phaseTitle(phase) {
  switch (phase) {
    case "discovering": return "Discovering sources";
    case "extracting": return "Extracting messages";
    case "merging": return "Merging timeline";
    case "complete": return "Complete";
    default: return "Scanning";
  }
}

function appendLog(prev, line) {
  if (!line) return prev;
  const next = [...prev, line];
  return next.length > MAX_LOG_LINES ? next.slice(-MAX_LOG_LINES) : next;
}

/**
 * AiHistoryProfileScanModal — verbose in-progress UI for Tools → AI Artifacts → Collect AI Artifacts.
 */
export default function AiHistoryProfileScanModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const logEndRef = useRef(null);
  const discoverStartedRef = useRef(false);
  const tle = typeof window !== "undefined" ? window.tle : null;

  const patch = useCallback((p) => {
    setModal(updateModal("aiHistoryProfileScan", p));
  }, [setModal]);

  const applyProgress = useCallback((prog) => {
    setModal((p) => {
      if (!p || p.type !== "aiHistoryProfileScan") return p;
      const log = appendLog(p.progress?.log || [], prog.logLine);
      const sourceStatus = { ...p.sourceStatus };
      const idxRoot = prog.sourceIndex && p.roots?.[prog.sourceIndex - 1];
      const statusRoot = idxRoot || (prog.rootPath ? { tool: prog.tool, path: prog.rootPath } : null);
      if (statusRoot) {
        const key = sourceKey(statusRoot);
        if (prog.logLine?.startsWith("✗")) sourceStatus[key] = "error";
        else if (prog.logLine?.startsWith("✓")) sourceStatus[key] = "done";
        else if (prog.phase === "extracting") sourceStatus[key] = "active";
      }
      return {
        ...p,
        scanning: prog.phase !== "complete",
        sourceStatus,
        progress: {
          ...p.progress,
          phase: prog.phase || p.progress?.phase,
          percent: Number.isFinite(prog.percent) ? prog.percent : p.progress?.percent,
          statusDetail: prog.statusDetail || p.progress?.statusDetail,
          rowsSoFar: prog.rowsSoFar ?? p.progress?.rowsSoFar,
          filePath: prog.filePath,
          fileIndex: prog.fileIndex,
          fileCount: prog.fileCount,
          sourceIndex: prog.sourceIndex,
          sourceCount: prog.sourceCount,
          label: prog.label,
          log,
        },
      };
    });
  }, [setModal]);

  // Auto-scroll activity log — DEBOUNCED. During extraction the log grows ~10+ lines/sec; firing a
  // smooth scrollIntoView per line forced a layout recalc on every line and janked the modal. Coalesce
  // a burst into a single scroll once lines settle (~150ms).
  useEffect(() => {
    const id = setTimeout(() => {
      logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
    }, 150);
    return () => clearTimeout(id);
  }, [modal?.progress?.log?.length]);

  // Live progress from main process (discovery + extraction)
  useEffect(() => {
    if (!tle?.onAiHistoryProfileProgress || modal?.type !== "aiHistoryProfileScan") return;
    if (modal.phase !== "discovering" && modal.phase !== "scanning") return;
    return replaceIpcSubscription("ai-history-profile-progress", tle.onAiHistoryProfileProgress, applyProgress);
  }, [modal?.type, modal?.phase, tle, applyProgress]);

  // Phase 1: discover roots (local Mac or forensic folder)
  useEffect(() => {
    if (!tle || modal?.type !== "aiHistoryProfileScan" || modal.phase !== "discovering") return;
    if (discoverStartedRef.current) return;
    if (!modal.scanMode) return;
    discoverStartedRef.current = true;
    let cancelled = false;

    const discoverOpts = {
      scanMode: modal.scanMode,
      scanRoot: modal.scanMode === "folder" ? modal.scanRoot : undefined,
    };

    (async () => {
      setModal((p) => (p?.type === "aiHistoryProfileScan"
        ? {
          ...p,
          progress: {
            ...p.progress,
            log: appendLog(p.progress?.log || [], "Contacting main process…"),
          },
        }
        : p));

      try {
        let r;
        let ipcDiscoverFallback = false;
        if (typeof tle.discoverAiHistoryProfile === "function") {
          r = await tle.discoverAiHistoryProfile(discoverOpts);
        } else if (typeof tle.extractAiHistoryProfile === "function") {
          ipcDiscoverFallback = true;
          r = await tle.extractAiHistoryProfile({ discoverOnly: true, ...discoverOpts });
        } else {
          throw new Error(
            "Scan API is unavailable in this session. Quit IRFlow Timeline completely and run npm run dev again (preload must reload).",
          );
        }
        if (cancelled) return;
        if (isIpcError(r)) {
          setModal((p) => (p?.type === "aiHistoryProfileScan"
            ? { ...p, phase: "error", error: ipcErrorMessage(r), scanning: false }
            : p));
          return;
        }
        setModal((p) => {
          if (!p || p.type !== "aiHistoryProfileScan") return p;
          const isFolder = p.scanMode === "folder";
          if (!r?.roots?.length) {
            const report = r.scanReport;
            const errText = report?.summary || (isFolder
              ? "No AI history artifacts found in this folder."
              : "No AI history artifacts found on this machine.");
            const log = appendLog(p.progress?.log || [], isFolder
              ? `Indexed ${r?.candidateCount ?? "?"} folders — no AI stores matched.`
              : `Checked ${r?.candidateCount ?? "?"} standard paths — none contained readable history.`);
            if (report?.detail) {
              for (const line of report.detail.split("\n")) log.push(line);
            }
            return {
              ...p,
              phase: "error",
              scanning: false,
              error: errText,
              scanReport: report || null,
              ipcDiscoverFallback,
              progress: {
                percent: 0,
                phase: "discovering",
                statusDetail: "No validated sources found",
                rowsSoFar: 0,
                log,
              },
            };
          }
          const log = appendLog(
            p.progress?.log || [],
            isFolder
              ? `Found ${r.roots.length} source(s) in collection (${r.candidateCount?.toLocaleString?.() ?? r.candidateCount} dirs indexed).`
              : `Found ${r.roots.length} source(s) on this computer.`,
          );
          for (const root of r.roots) log.push(`• ${root.label}: ${root.path}`);
          return {
            ...p,
            phase: "config",
            scanning: false,
            roots: r.roots,
            candidateCount: r.candidateCount,
            hasScopeChoice: !!r.hasScopeChoice,
            scanRoot: r.scanRoot || p.scanRoot,
            scanMode: r.scanMode || p.scanMode,
            ipcDiscoverFallback,
            progress: {
              percent: 100,
              phase: "discovering",
              statusDetail: `${r.roots.length} source(s) ready to parse`,
              rowsSoFar: 0,
              log,
            },
          };
        });
      } catch (e) {
        if (cancelled) return;
        setModal((p) => (p?.type === "aiHistoryProfileScan"
          ? { ...p, phase: "error", scanning: false, error: e?.message || String(e) }
          : p));
      }
    })();

    return () => {
      cancelled = true;
      discoverStartedRef.current = false;
    };
  }, [modal?.type, modal?.phase, modal?.scanMode, modal?.scanRoot, tle, setModal]);

  if (modal?.type !== "aiHistoryProfileScan") return null;

  const {
    phase,
    scanMode,
    scanRoot,
    roots = [],
    candidateCount = 0,
    hasScopeChoice,
    includeSubagents,
    scanning,
    error,
    scanReport,
    ipcDiscoverFallback = false,
    progress = {},
    sourceStatus = {},
  } = modal;

  const busy = scanning || phase === "discovering";
  const isFolderScan = scanMode === "folder";
  const discoverApiReady = typeof tle?.discoverAiHistoryProfile === "function";
  const showPreloadBanner = !discoverApiReady && typeof tle?.extractAiHistoryProfile === "function";

  const beginDiscover = (mode, rootPath = null) => {
    discoverStartedRef.current = false;
    patch({
      phase: "discovering",
      scanMode: mode,
      scanRoot: rootPath,
      scanning: true,
      error: null,
      roots: [],
      progress: {
        percent: 0,
        phase: "discovering",
        statusDetail: mode === "folder"
          ? `Scanning collection…`
          : "Scanning this Mac…",
        rowsSoFar: 0,
        log: [
          mode === "folder"
            ? `Collection folder: ${rootPath}`
            : "Target: this computer (local analyst profile)",
        ],
      },
    });
  };

  const pickFolderAndScan = async () => {
    if (!tle?.pickAiHistoryScanFolder) {
      toast.error("Folder picker unavailable", { detail: "Restart the app to load the latest build." });
      return;
    }
    const pick = await tle.pickAiHistoryScanFolder();
    if (pick?.canceled) return;
    if (!pick?.path) {
      toast.warning("No folder selected");
      return;
    }
    beginDiscover("folder", pick.path);
  };

  const goBackToOptions = () => {
    clearIpcSubscription("ai-history-profile-progress");
    discoverStartedRef.current = false;
    setModal((p) => (p?.type === "aiHistoryProfileScan"
      ? {
        ...p,
        phase: "choose-target",
        scanMode: null,
        scanRoot: null,
        roots: [],
        candidateCount: 0,
        hasScopeChoice: false,
        scanning: false,
        error: null,
        sourceStatus: {},
        progress: {
          percent: 0,
          statusDetail: "Choose where to scan for AI assistant artifacts",
          phase: "choose-target",
          rowsSoFar: 0,
          log: [],
        },
      }
      : p));
  };

  const showBack = !busy && phase !== "choose-target";
  const percent = Math.max(0, Math.min(100, Number(progress.percent) || 0));
  const indeterminate = busy && percent < 3;
  const logLines = progress.log || [];

  const startScan = async () => {
    if (!tle || !roots.length) return;
    replaceIpcSubscription("ai-history-profile-progress", tle.onAiHistoryProfileProgress, applyProgress);

    const initialStatus = { ...sourceStatus };
    for (const r of roots) initialStatus[sourceKey(r)] = "pending";

    patch({
      phase: "scanning",
      scanning: true,
      error: null,
      sourceStatus: initialStatus,
      progress: {
        percent: 2,
        phase: "extracting",
        statusDetail: "Starting extraction…",
        rowsSoFar: 0,
        log: appendLog(logLines, includeSubagents
          ? "User chose: include subagent session folders"
          : "User chose: main sessions only (faster triage)"),
      },
    });

    try {
      const r = await tle.extractAiHistoryProfile({
        roots,
        includeSubagents: !!includeSubagents,
        scanRoot: scanRoot || undefined,
        scanMode: scanMode || "local",
      });
      clearIpcSubscription("ai-history-profile-progress");

      if (r?.needsScopeChoice) {
        patch({
          phase: "config",
          scanning: false,
          roots: r.roots || roots,
          hasScopeChoice: true,
          scanRoot: r.scanRoot || scanRoot,
          scanMode: r.scanMode || scanMode,
        });
        toast.info("Choose session scope", { detail: "Select main sessions or include subagents, then Start scan." });
        return;
      }
      if (r?.canceled) {
        patch({ phase: "config", scanning: false, progress: { ...progress, statusDetail: "Extraction canceled" } });
        return;
      }
      if (isIpcError(r)) {
        patch({ phase: "error", scanning: false, error: ipcErrorMessage(r) });
        return;
      }
      if (r?.error) {
        patch({
          phase: "error",
          scanning: false,
          error: r.error,
          scanReport: r.scanReport || null,
        });
        return;
      }
      const rowCount = r?.count ?? r?.rows?.length ?? 0;
      const tabOpenedOnMain = !!(r?.openedTab && r?.tabId);
      if (!tabOpenedOnMain && !rowCount) {
        patch({ phase: "error", scanning: false, error: "Sources were found but contained no message rows." });
        return;
      }

      patch({
        progress: {
          ...progress,
          percent: 100,
          phase: "complete",
          statusDetail: tabOpenedOnMain ? "Timeline tab ready" : "Opening timeline tab…",
          log: appendLog(logLines, tabOpenedOnMain
            ? `Opened tab with ${rowCount.toLocaleString()} merged messages`
            : `Opening tab with ${rowCount.toLocaleString()} merged messages…`),
        },
      });

      if (tabOpenedOnMain) {
        useTabStore.getState().setActiveTab(r.tabId);
      } else if (r.rows?.length) {
        await tle.sigmaOpenAsTab(r.rows, r.name, null, {
          sourceFormat: r.sourceFormat || "ai-history-merged",
          importNotice: r.importNotice || null,
        });
      }

      if (r.importNotice) toast.info("AI history import", { detail: r.importNotice });
      const sources = r.sourcesLabel || (r.sources || []).map((s) => s.label).join(", ");
      toast.success("AI Query History", {
        detail: r.partial
          ? `${rowCount.toLocaleString()} messages from ${sources}. Some sources could not be read.`
          : `${rowCount.toLocaleString()} messages merged from ${sources}.`,
      });
      setModal(null);
    } catch (e) {
      clearIpcSubscription("ai-history-profile-progress");
      patch({ phase: "error", scanning: false, error: e?.message || String(e) });
    }
  };

  const statusIcon = (st) => {
    if (st === "done") return <span style={{ color: th.sev?.clean || "#4ade80" }}>✓</span>;
    if (st === "error") return <span style={{ color: th.danger }}>✗</span>;
    if (st === "active") return <span style={{ color: th.accent }}>●</span>;
    return <span style={{ color: th.textMuted }}>○</span>;
  };

  const btn = (primary, disabled) => ({
    padding: "6px 14px",
    borderRadius: 6,
    fontSize: 13,
    cursor: disabled ? "default" : "pointer",
    border: primary ? "none" : `1px solid ${th.border}`,
    background: primary ? th.accent : th.bg,
    color: primary ? "#fff" : th.text,
    opacity: disabled ? 0.5 : 1,
  });

  return (
    <Modal
      open
      title="Collect AI Artifacts — Query History"
      subtitle={
        phase === "choose-target"
          ? "This Mac, or a KAPE / triage / mounted disk folder"
          : phase === "config"
            ? `${roots.length} source(s)${isFolderScan && scanRoot ? ` in ${scanRoot.split("/").pop()}` : " ready"}`
            : progress.statusDetail
      }
      width={720}
      maxHeight="88vh"
      onClose={() => { if (!busy) setModal(null); }}
      footer={(
        <div style={{ display: "flex", gap: 8, justifyContent: "space-between", alignItems: "center", width: "100%", flexWrap: "wrap" }}>
          {phase === "choose-target" ? (
            <span style={{ fontSize: 11, color: th.textMuted }}>
              Windows, Linux, and macOS user-profile layouts are detected automatically under the folder you pick.
            </span>
          ) : phase === "config" && hasScopeChoice ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12, color: th.textMuted }}>
              <span style={{ fontWeight: 600, color: th.text, fontSize: 11, textTransform: "uppercase", letterSpacing: "0.05em" }}>Session scope</span>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", color: th.text }}>
                <input
                  type="radio"
                  name="ai-scope"
                  checked={!includeSubagents}
                  onChange={() => patch({ includeSubagents: false })}
                  style={{ accentColor: th.accent }}
                />
                Main sessions only (recommended for triage)
              </label>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer", color: th.text }}>
                <input
                  type="radio"
                  name="ai-scope"
                  checked={!!includeSubagents}
                  onChange={() => patch({ includeSubagents: true })}
                  style={{ accentColor: th.accent }}
                />
                Include sub-agent / sidechain messages (Claude Code, Cursor, Codex forks)
              </label>
            </div>
          ) : (
            <span style={{ fontSize: 11, color: th.textMuted }}>
              {busy ? "Do not close until extraction finishes." : error ? "Scan failed." : ""}
            </span>
          )}
          <div style={{ display: "flex", gap: 8, marginLeft: "auto", flexWrap: "wrap" }}>
            {showBack && (
              <button type="button" onClick={goBackToOptions} style={btn(false, false)}>Back</button>
            )}
            <button
              type="button"
              onClick={() => {
                if (busy && tle?.cancelAiHistoryExtract) tle.cancelAiHistoryExtract();
                setModal(null);
              }}
              disabled={false}
              style={btn(false, false)}
            >
              {busy ? "Stop scan" : "Cancel"}
            </button>
            {phase === "config" && (
              <button type="button" onClick={startScan} disabled={!roots.length} style={btn(true, !roots.length)}>
                Start scan ({roots.length} source{roots.length === 1 ? "" : "s"})
              </button>
            )}
          </div>
        </div>
      )}
    >
      {(showPreloadBanner || ipcDiscoverFallback) && (
        <div
          style={{
            marginBottom: 12,
            padding: "8px 12px",
            borderRadius: 6,
            fontSize: 11,
            lineHeight: 1.45,
            color: th.text,
            background: `${th.sev?.high || "#f59e0b"}18`,
            border: `1px solid ${th.sev?.high || "#f59e0b"}44`,
          }}
        >
          Discovery is using a compatibility IPC path. Quit IRFlow Timeline completely and restart
          (<code style={{ fontSize: 10 }}>npm run dev</code>) so preload loads <code style={{ fontSize: 10 }}>discoverAiHistoryProfile</code>.
        </div>
      )}

      {phase === "choose-target" && (
        <div style={{ marginBottom: 14 }}>
          <p style={{ fontSize: 12, color: th.textMuted, margin: "0 0 10px", lineHeight: 1.5 }}>
            Merge every AI assistant store into one timeline tab. Use <strong style={{ color: th.text }}>This Mac</strong> for
            live triage on your analyst machine, or <strong style={{ color: th.text }}>Browse folder</strong> for KAPE output,
            Velociraptor zips, E01-mounted images, external drives, or any path that contains <code style={{ fontSize: 10 }}>Users\</code> or <code style={{ fontSize: 10 }}>home/</code> trees.
          </p>
          <p style={{ fontSize: 11, color: th.textDim, margin: "0 0 14px", lineHeight: 1.45 }}>
            Profile scan extracts <strong style={{ color: th.textMuted }}>all</strong> discovered AI assistant tools into one AI Query History tab. Use the source selection step if you need to limit heavy local stores.
          </p>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 14 }}>
            <button
              type="button"
              onClick={() => beginDiscover("local")}
              style={{
                textAlign: "left",
                padding: "14px 16px",
                borderRadius: 8,
                border: `1px solid ${th.border}`,
                background: `${th.accent}10`,
                cursor: "pointer",
                color: th.text,
              }}
            >
              <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>This Mac</div>
              <div style={{ fontSize: 11, color: th.textMuted, lineHeight: 1.45 }}>
                Scan the logged-in user profile on this computer (default).
              </div>
            </button>
            <button
              type="button"
              onClick={pickFolderAndScan}
              style={{
                textAlign: "left",
                padding: "14px 16px",
                borderRadius: 8,
                border: `1px solid ${th.accent}66`,
                background: `${th.accent}18`,
                cursor: "pointer",
                color: th.text,
              }}
            >
              <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6, color: th.accent }}>Browse folder</div>
              <div style={{ fontSize: 11, color: th.textMuted, lineHeight: 1.45 }}>
                KAPE collection, triage package, mounted compromised disk, or USB image.
              </div>
            </button>
          </div>
          <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
            Paths searched inside your folder (all platforms)
          </div>
          <div style={{ fontSize: 10, color: th.textDim, fontFamily: "SF Mono, Menlo, monospace", lineHeight: 1.5, maxHeight: 100, overflow: "auto", border: `1px solid ${th.border}44`, borderRadius: 6, padding: "8px 10px" }}>
            <div style={{ marginBottom: 6 }}><span style={{ color: th.textMuted }}>Windows: </span>Users\&lt;user&gt;\.claude, .codex, .grok, .grokbot, .cursor, .copilot, .gemini, AppData\Roaming\Cursor\User, AppData\Roaming\Grok Bot, OpenAI\ChatGPT, Code\User\workspaceStorage…</div>
            <div style={{ marginBottom: 6 }}><span style={{ color: th.textMuted }}>Linux: </span>home/&lt;user&gt;/.claude, .codex, .copilot, .config/Cursor/User, .config/com.openai.chat, .config/Code/User/workspaceStorage…</div>
            <div><span style={{ color: th.textMuted }}>macOS: </span>Users/&lt;user&gt;/.claude, .copilot, Library/Application Support/Cursor/User, com.openai.chat, Code/User/workspaceStorage…</div>
          </div>
        </div>
      )}

      {(phase === "discovering" || phase === "scanning") && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6, gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: th.text }}>{phaseTitle(progress.phase || phase)}</span>
            <span style={{ fontSize: 11, color: th.accent, fontFamily: "SF Mono, Menlo, monospace" }}>{percent}%</span>
          </div>
          <div style={{ height: 8, background: th.border, borderRadius: 4, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: indeterminate ? "35%" : `${percent}%`,
                background: `linear-gradient(90deg, ${th.accent}, ${th.accent}cc)`,
                borderRadius: 4,
                transition: indeterminate ? "none" : "width 0.25s ease-out",
                animation: indeterminate ? "tle-pulse 1.2s ease-in-out infinite" : "none",
              }}
            />
          </div>
          <p style={{ margin: "8px 0 0", fontSize: 12, color: th.textMuted }}>{progress.statusDetail}</p>
          {progress.filePath && (
            <p style={{ margin: "4px 0 0", fontSize: 10, color: th.textDim, fontFamily: "SF Mono, Menlo, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {progress.label}: {progress.fileIndex}/{progress.fileCount} — {progress.filePath.split("/").pop()}
            </p>
          )}
          <div style={{ display: "flex", gap: 20, marginTop: 12, flexWrap: "wrap" }}>
            {[
              { label: "Sources", value: progress.sourceCount || roots.length || "—" },
              { label: "Current", value: progress.sourceIndex ? `${progress.sourceIndex} / ${progress.sourceCount || roots.length}` : "—" },
              { label: "Rows so far", value: formatNumber(progress.rowsSoFar || 0) },
              { label: "Candidates checked", value: progress.candidatesChecked != null
                ? `${progress.candidatesChecked} / ${progress.candidateCount || candidateCount || "?"}`
                : (phase === "discovering" ? "…" : candidateCount) },
            ].map((s) => (
              <div key={s.label} style={{ textAlign: "center", minWidth: 72 }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: th.accent, fontFamily: "SF Mono, Menlo, monospace" }}>{s.value}</div>
                <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em" }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {roots.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
            Sources
          </div>
          <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, maxHeight: 140, overflow: "auto" }}>
            {roots.map((r, idx) => {
              const st = sourceStatus[sourceKey(r)] || (phase === "discovering" ? "pending" : "pending");
              return (
                <div
                  key={`${r.tool}-${idx}`}
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 8,
                    padding: "8px 10px",
                    borderBottom: idx < roots.length - 1 ? `1px solid ${th.border}44` : "none",
                    fontSize: 12,
                    background: st === "active" ? `${th.accent}12` : "transparent",
                  }}
                >
                  <span style={{ width: 14, flexShrink: 0, marginTop: 1 }}>{statusIcon(st)}</span>
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ color: th.text, fontWeight: 600 }}>{r.label}</span>
                    <br />
                    <span style={{ color: th.textDim, fontSize: 10, fontFamily: "SF Mono, Menlo, monospace" }} title={r.path}>
                      {shortenPath(r.path)}
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div>
        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
          Activity log
        </div>
        <div
          style={{
            border: `1px solid ${th.border}`,
            borderRadius: 6,
            background: th.bgInput || th.bg,
            maxHeight: 220,
            overflow: "auto",
            padding: "8px 10px",
            fontFamily: "SF Mono, Menlo, monospace",
            fontSize: 10,
            lineHeight: 1.55,
            color: th.textDim,
            whiteSpace: "pre-wrap",
            wordBreak: "break-word",
          }}
        >
          {logLines.length === 0 ? (
            <span style={{ color: th.textMuted }}>Waiting…</span>
          ) : (
            logLines.map((line, i) => (
              <div key={i} style={{ marginBottom: line.startsWith("▶") || line.startsWith("✓") || line.startsWith("✗") ? 6 : 2 }}>
                {line}
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      </div>

      {error && (
        <div style={{ marginTop: 12 }}>
          <div style={{ color: th.danger, fontSize: 12, padding: "10px 12px", background: `${th.danger}15`, borderRadius: 6 }}>
            {error}
          </div>
          {scanReport?.collectionIncomplete && (
            <p style={{ marginTop: 8, fontSize: 11, color: th.textMuted, lineHeight: 1.5 }}>
              User profiles were detected in this folder, but none of the standard AI assistant paths were collected.
              Re-run KAPE with targets that include <code style={{ fontSize: 10 }}>.claude</code>, <code style={{ fontSize: 10 }}>.cursor</code>, <code style={{ fontSize: 10 }}>.copilot</code>, Cursor <code style={{ fontSize: 10 }}>User/globalStorage</code>, ChatGPT app data, or VS Code <code style={{ fontSize: 10 }}>workspaceStorage</code>.
            </p>
          )}
          {Array.isArray(scanReport?.checklist) && scanReport.checklist.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
                Expected paths checklist
              </div>
              {scanReport.checklist.map((section) => (
                <div key={section.platform} style={{ marginBottom: 8 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: th.text, marginBottom: 4 }}>{section.label}</div>
                  <ul style={{ margin: 0, paddingLeft: 18, fontSize: 10, color: th.textDim, fontFamily: "SF Mono, Menlo, monospace", lineHeight: 1.55 }}>
                    {(section.paths || []).map((hint) => (
                      <li key={hint}>{hint}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
          {scanReport?.detail && (
            <pre
              style={{
                marginTop: 8,
                fontSize: 10,
                lineHeight: 1.5,
                color: th.textMuted,
                whiteSpace: "pre-wrap",
                fontFamily: "SF Mono, Menlo, monospace",
                padding: "10px 12px",
                border: `1px solid ${th.border}44`,
                borderRadius: 6,
                maxHeight: 160,
                overflow: "auto",
              }}
            >
              {scanReport.detail}
            </pre>
          )}
        </div>
      )}
    </Modal>
  );
}
