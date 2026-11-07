import { Fragment } from "react";
import SigmaDetectionSettings from "./SigmaDetectionSettings.jsx";
import SigmaPresetStep from "./SigmaPresetStep.jsx";
import SigmaTargetStep from "./SigmaTargetStep.jsx";
import SigmaValidateStep from "./SigmaValidateStep.jsx";
import { formatNumber } from "../../../utils/format.js";
import { useSigmaModalContext } from "./SigmaModalContext.js";

export default function SigmaConfigWizard() {
  const {
    modal,
    setModal,
    th,
    ms,
    phase,
    renderWizardProgress,
    renderScanHistoryList,
    refreshScanHistory,
    handleShowScanHistory,
  } = useSigmaModalContext();

  return (
    <>
          {/* ── CONFIG PHASE ──────────────────────────────────────── */}
          {phase === "config" && (
            <Fragment>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8, marginBottom: 12 }}>
                <div style={{ display: "inline-flex", background: th.panelBg, borderRadius: 6, padding: 2, border: `1px solid ${th.border}44`, gap: 1 }}>
                  <button onClick={() => setModal((p) => ({ ...p, scanHistoryView: false, detectionSettingsView: false }))} style={{ padding: "4px 14px", background: !modal.scanHistoryView && !modal.detectionSettingsView ? th.fillAccent : "transparent", color: !modal.scanHistoryView && !modal.detectionSettingsView ? th.onAccent : th.textDim, border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontWeight: !modal.scanHistoryView && !modal.detectionSettingsView ? 600 : 400, fontFamily: "-apple-system,sans-serif" }}>New Scan</button>
                  <button onClick={handleShowScanHistory} style={{ padding: "4px 14px", background: modal.scanHistoryView ? th.fillAccent : "transparent", color: modal.scanHistoryView ? th.onAccent : th.textDim, border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontWeight: modal.scanHistoryView ? 600 : 400, fontFamily: "-apple-system,sans-serif" }}>
                    Previous Scans ({formatNumber((modal.scanHistory || []).length)})
                  </button>
                  <button onClick={() => setModal((p) => ({ ...p, scanHistoryView: false, detectionSettingsView: true }))} style={{ padding: "4px 14px", background: modal.detectionSettingsView ? th.fillAccent : "transparent", color: modal.detectionSettingsView ? th.onAccent : th.textDim, border: "none", borderRadius: 4, fontSize: 10, cursor: "pointer", fontWeight: modal.detectionSettingsView ? 600 : 400, fontFamily: "-apple-system,sans-serif" }}>
                    Detection Settings
                  </button>
                </div>
                {modal.scanHistoryView && (
                  <button onClick={refreshScanHistory} disabled={modal.scanHistoryLoading} style={{ ...ms.bsm, opacity: modal.scanHistoryLoading ? 0.55 : 1 }}>
                    {modal.scanHistoryLoading ? "Refreshing..." : "Refresh"}
                  </button>
                )}
              </div>
              {modal.scanHistoryView ? renderScanHistoryList() : modal.detectionSettingsView ? <SigmaDetectionSettings /> : (
              <Fragment>
              {renderWizardProgress()}
              <SigmaTargetStep />
              <SigmaPresetStep />
              <SigmaValidateStep />
              </Fragment>
              )}
            </Fragment>
          )}


    </>
  );
}
