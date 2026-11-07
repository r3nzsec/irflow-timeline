import { Fragment } from "react";
import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

export default function SigmaModalFooter() {
  const {
    phase,
    modal,
    setModal,
    handleCloseModal,
    ms,
    hasTargetReady,
    hasPresetReady,
    scanMode,
    ct,
    hasRules,
    handleScan,
    handleScanKapeOutput,
    handleScanDirectory,
    handleCancelScan,
    results,
    handleExportCSV,
    handleExportJSON,
    tle,
    handleOpenAsTab,
    th,
  } = useSigmaModalContext();

  return (
    <>
        {/* Footer */}
        <div style={{ padding: "12px 20px", borderTop: `1px solid ${th.border}`, display: "flex", gap: 8, justifyContent: "flex-end", flexShrink: 0 }}>
          {phase === "config" && (modal.scanHistoryView || modal.detectionSettingsView) && (
            <Fragment>
              <button onClick={() => setModal((p) => ({ ...p, scanHistoryView: false, detectionSettingsView: false }))} style={ms.bs}>New Scan</button>
              <button onClick={handleCloseModal} style={ms.bp}>Done</button>
            </Fragment>
          )}
          {phase === "config" && !modal.scanHistoryView && !modal.detectionSettingsView && (
            <Fragment>
              <button onClick={handleCloseModal} style={ms.bs}>Cancel</button>
              {/* Single mode-aware launch button — preflight runs inside handleScanDirectory,
                  so the old "Check Setup" step is no longer needed. */}
              {scanMode === "tab" && (() => {
                const ready = hasRules && ct?.dataReady && hasPresetReady;
                return (
                  <button onClick={handleScan} disabled={!ready} style={{ ...ms.bp, opacity: ready ? 1 : 0.4, cursor: ready ? "pointer" : "not-allowed" }}>
                    {modal.largeJsSigmaScanConfirmed ? "Continue JS Sigma Scan" : "Scan Imported Tab"}
                  </button>
                );
              })()}
              {scanMode === "kape-output" && (() => {
                const ready = hasRules && hasTargetReady && hasPresetReady;
                return (
                  <button onClick={handleScanKapeOutput} disabled={!ready} style={{ ...ms.bp, background: th.fillAccent, color: th.onAccent, opacity: ready ? 1 : 0.4, cursor: ready ? "pointer" : "not-allowed" }}>
                    Scan {formatNumber(modal.kapeOutput?.fileCount || 0)} EvtxECmd File{(modal.kapeOutput?.fileCount || 0) === 1 ? "" : "s"}
                  </button>
                );
              })()}
              {scanMode === "evtx-dir" && (() => {
                const busy = modal.preflightChecking;
                const ready = hasTargetReady && !busy && hasPresetReady;
                return (
                  <button onClick={handleScanDirectory} disabled={!ready} style={{ ...ms.bp, background: th.fillAccent, color: th.onAccent, opacity: ready ? 1 : 0.4, cursor: ready ? "pointer" : "not-allowed" }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ marginRight: 5, verticalAlign: "middle" }}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    {busy ? "Checking Scan Setup..." : `Scan ${modal.evtxDir?.fileCount || 0} EVTX File${(modal.evtxDir?.fileCount || 0) !== 1 ? "s" : ""}`}
                  </button>
                );
              })()}
            </Fragment>
          )}
          {phase === "scanning" && (
            <button onClick={handleCancelScan} style={ms.bs}>Cancel Scan</button>
          )}
          {phase === "results" && (
            <Fragment>
              <button onClick={handleExportCSV} style={ms.bs}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ marginRight: 4, verticalAlign: "middle" }}><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Export Timeline CSV
              </button>
              <button onClick={handleExportJSON} style={ms.bs}>Export JSON</button>
              {results.hasHtmlReport && (
                <button onClick={() => tle?.sigmaExportHtmlReport?.(modal.jobId)} style={ms.bs}>Export Report</button>
              )}
              <button onClick={handleOpenAsTab} disabled={!(results?.eventRowCount > 0) || modal.openingTab || modal.sourceAction === "open"} style={{ ...ms.bs, background: `${th.accent}15`, color: th.accent, border: `1px solid ${th.accent}33`, fontWeight: 600, opacity: results?.eventRowCount > 0 && !modal.openingTab && modal.sourceAction !== "open" ? 1 : 0.4 }}>
                {modal.openingTab ? (
                  <span>Loading {formatNumber(results?.eventRowCount || 0)} rows...</span>
                ) : (
                  <Fragment>
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="2" strokeLinecap="round" style={{ marginRight: 4, verticalAlign: "middle" }}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    Open All Results as Tab
                  </Fragment>
                )}
              </button>
              <button onClick={() => setModal((p) => ({ ...p, phase: "config" }))} style={ms.bs}>Back</button>
              <button onClick={handleCloseModal} style={ms.bp}>Done</button>
            </Fragment>
          )}
        </div>

    </>
  );
}
