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
import {
  appendLog,
  mergeAiHistoryProgressState,
  phaseTitle,
  shortenPath,
  sourceKey,
} from "./ai-history-extract-progress.js";

/**
 * Verbose in-progress UI for Tools → AI Artifacts → AI Apps → individual tool extracts.
 */
export default function AiHistoryExtractModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  const logEndRef = useRef(null);
  const invokedRunIdRef = useRef(null);
  const stopRequestedRef = useRef(false);
  const tle = typeof window !== "undefined" ? window.tle : null;

  const patch = useCallback((p) => {
    setModal(updateModal("aiHistoryExtract", p));
  }, [setModal]);

  const applyProgress = useCallback((prog) => {
    setModal((p) => {
      if (!p || p.type !== "aiHistoryExtract") return p;
      const roots = [{ tool: p.tool, path: p.extractTarget || p.target, label: p.label }];
      return mergeAiHistoryProgressState(p, prog, roots);
    });
  }, [setModal]);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [modal?.progress?.log?.length]);

  useEffect(() => {
    if (!tle?.onAiHistoryProfileProgress || modal?.type !== "aiHistoryExtract") return;
    if (modal.phase !== "extracting") return;
    return replaceIpcSubscription("ai-history-profile-progress", tle.onAiHistoryProfileProgress, applyProgress);
  }, [modal?.type, modal?.phase, tle, applyProgress]);

  useEffect(() => {
    if (!tle || modal?.type !== "aiHistoryExtract" || modal.phase !== "extracting") return;
    const runId = modal.extractRunId;
    if (!runId) return;
    // React Strict Mode remounts this effect; never start a second IPC or cancel on cleanup.
    if (invokedRunIdRef.current === runId) return;
    invokedRunIdRef.current = runId;
    stopRequestedRef.current = false;

    const {
      tool,
      target,
      label,
      includeSubagents = false,
      progress: startProgress = {},
    } = modal;

    // Computer History rows are activity events, not conversation turns — keep the copy honest.
    const noun = tool === "computer-history" ? "activity event" : "message";
    const plural = (n) => `${n.toLocaleString()} ${noun}${n === 1 ? "" : "s"}`;

    const finishSuccess = (r) => {
      const rowCount = r?.count ?? r?.rows?.length ?? 0;
      if (r?.openedTab && r.tabId) {
        useTabStore.getState().setActiveTab(r.tabId);
      } else if (r?.rows?.length) {
        return tle.sigmaOpenAsTab(r.rows, r.name, null, {
          sourceFormat: r.sourceFormat || `ai-history-${tool}`,
          importNotice: r.importNotice || null,
        }).then(() => rowCount);
      }
      if (!rowCount) {
        patch({ phase: "error", scanning: false, error: `No ${noun}s found at this path.` });
        return Promise.resolve();
      }
      patch({
        phase: "complete",
        scanning: false,
        progress: {
          percent: 100,
          phase: "complete",
          statusDetail: "Timeline tab ready",
          rowsSoFar: rowCount,
          log: appendLog(startProgress.log || [], `Opened tab with ${plural(rowCount)}`),
        },
      });
      if (r.importNotice) toast.info(`${label} import`, { detail: r.importNotice });
      toast.success(label, { detail: `Loaded ${plural(rowCount)}.` });
      setTimeout(() => setModal(null), 400);
      return Promise.resolve();
    };

    const isStaleRun = () => invokedRunIdRef.current !== runId || stopRequestedRef.current;

    (async () => {
      try {
        // Computer History is a different artifact family with its own column schema and its own
        // extractor; it shares this progress UI (same progress channel) but not the ai-history
        // extract path, whose dedupe/sink assumes conversation-shaped rows.
        const r = tool === "computer-history"
          ? await tle.decodeComputerHistory(target, {})
          : await tle.decodeAiHistory(target, tool, { includeSubagents });
        clearIpcSubscription("ai-history-profile-progress");
        if (isStaleRun()) return;

        if (r?.canceled) {
          patch({ phase: "error", scanning: false, error: "Extraction canceled" });
          return;
        }
        if (isIpcError(r)) {
          patch({ phase: "error", scanning: false, error: ipcErrorMessage(r) });
          return;
        }
        if (r?.error) {
          patch({ phase: "error", scanning: false, error: r.error });
          return;
        }

        await finishSuccess(r);
    } catch (e) {
        clearIpcSubscription("ai-history-profile-progress");
        if (!isStaleRun()) {
          patch({ phase: "error", scanning: false, error: e?.message || String(e) });
        }
      }
    })();

    // Strict Mode cleanup must not cancel the worker or clear invokedRunIdRef — that
    // caused the modal to stay open at 98% while import-complete still opened the tab.
    return undefined;
  }, [modal?.extractRunId, modal?.phase, modal?.type, tle, patch, setModal, modal?.tool, modal?.target, modal?.label, modal?.includeSubagents, modal?.progress?.log]);

  if (modal?.type !== "aiHistoryExtract") return null;

  const {
    tool,
    target,
    extractTarget,
    label,
    includeSubagents,
    phase,
    scanning,
    error,
    progress = {},
    sourceStatus = {},
  } = modal;

  const busy = scanning || phase === "extracting";
  const rootPath = extractTarget || target;
  const roots = [{ tool, path: rootPath, label }];
  const percent = Math.max(0, Math.min(100, Number(progress.percent) || 0));
  const indeterminate = busy && percent < 3;
  const logLines = progress.log || [];

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

  const scopeNote = includeSubagents
    ? "Including subagent / sidechain sessions"
    : "Main sessions only";

  return (
    <Modal
      open
      title={`${label} — Extract`}
      subtitle={progress.statusDetail || "Parsing artifacts and building timeline…"}
      width={680}
      maxHeight="88vh"
      onClose={() => {
        if (busy) {
          stopRequestedRef.current = true;
          invokedRunIdRef.current = null;
          tle?.cancelAiHistoryExtract?.();
        }
        setModal(null);
      }}
      footer={(
        <div style={{ display: "flex", gap: 8, justifyContent: "space-between", alignItems: "center", width: "100%" }}>
          <span style={{ fontSize: 11, color: th.textMuted }}>
            {busy ? "Extraction runs in a background worker — safe to watch the log below." : error ? "Extraction failed." : ""}
          </span>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="button"
              onClick={() => {
                if (busy) {
                  stopRequestedRef.current = true;
                  invokedRunIdRef.current = null;
                  tle?.cancelAiHistoryExtract?.();
                }
                setModal(null);
              }}
              style={btn(false, false)}
            >
              {busy ? "Stop" : "Close"}
            </button>
          </div>
        </div>
      )}
    >
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
            {progress.label}: {progress.fileIndex}/{progress.fileCount} — {String(progress.filePath).split("/").pop()}
          </p>
        )}
        <div style={{ display: "flex", gap: 20, marginTop: 12, flexWrap: "wrap" }}>
          {[
            { label: "Scope", value: scopeNote },
            { label: "Rows so far", value: formatNumber(progress.rowsSoFar || 0) },
            { label: "Files", value: progress.fileCount ? `${progress.fileIndex || 0} / ${progress.fileCount}` : "—" },
          ].map((s) => (
            <div key={s.label} style={{ textAlign: "center", minWidth: 72 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: th.accent, fontFamily: "SF Mono, Menlo, monospace" }}>{s.value}</div>
              <div style={{ fontSize: 9, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.05em" }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
          Source
        </div>
        <div style={{ border: `1px solid ${th.border}`, borderRadius: 6, padding: "8px 10px", display: "flex", gap: 8, alignItems: "flex-start" }}>
          <span style={{ width: 14, flexShrink: 0 }}>{statusIcon(sourceStatus[sourceKey(roots[0])] || "active")}</span>
          <span style={{ flex: 1, minWidth: 0 }}>
            <span style={{ color: th.text, fontWeight: 600, fontSize: 12 }}>{label}</span>
            <br />
            <span style={{ color: th.textDim, fontSize: 10, fontFamily: "SF Mono, Menlo, monospace" }} title={rootPath}>
              {shortenPath(rootPath)}
            </span>
          </span>
        </div>
      </div>

      <div>
        <div style={{ fontSize: 10, fontWeight: 700, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 6 }}>
          Activity log
        </div>
        <div
          style={{
            border: `1px solid ${th.border}`,
            borderRadius: 6,
            background: th.bgInput || th.bg,
            maxHeight: 240,
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
            <span style={{ color: th.textMuted }}>Waiting for worker…</span>
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
        <div style={{ marginTop: 12, color: th.danger, fontSize: 12, padding: "10px 12px", background: `${th.danger}15`, borderRadius: 6 }}>
          {error}
        </div>
      )}
    </Modal>
  );
}
