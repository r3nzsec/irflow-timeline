import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import { DraggableResizableModal } from "../primitives/index.js";

const INCOMPLETE = new Set(["partial", "malformed", "unsupported", "excluded", "unavailable"]);

function shortPath(value, max = 110) {
  const text = String(value || "");
  return text.length > max ? `…${text.slice(-(max - 1))}` : text;
}

export default function AiHistoryCoverageModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();
  if (modal?.type !== "aiHistoryCoverage") return null;

  const meta = modal.importMeta || {};
  const coverage = Array.isArray(meta.sourceCoverage) ? meta.sourceCoverage : [];
  const failures = Array.isArray(modal.failures) ? modal.failures : [];
  const counts = coverage.reduce((acc, entry) => {
    const status = entry?.status || "unknown";
    acc[status] = (acc[status] || 0) + 1;
    return acc;
  }, {});
  const incomplete = coverage.filter((entry) => INCOMPLETE.has(entry?.status));
  const credentialExcluded = [meta.claudeContext, meta.codexContext, meta.cursor?.context]
    .reduce((sum, item) => sum + Number(item?.credentialExcluded || 0), 0);
  const grok = meta.grokBot || {};
  const attachmentScope = grok.attachmentRecovery?.includeUserFolders
    ? "selected Grok Bot roots plus explicitly opted-in user folders"
    : "selected Grok Bot data roots only";
  const complete = !meta.capped && incomplete.length === 0 && failures.length === 0;

  const card = { background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 8, padding: "10px 12px" };
  const badge = (status) => ({
    display: "inline-flex", padding: "2px 7px", borderRadius: 10, fontSize: 10, fontWeight: 700,
    color: INCOMPLETE.has(status) ? th.danger : status === "empty" ? th.textMuted : th.success,
    border: `1px solid ${INCOMPLETE.has(status) ? th.danger : status === "empty" ? th.textMuted : th.success}55`,
  });

  return (
    <DraggableResizableModal defaultWidth={820} defaultHeight={Math.min(760, Math.round(window.innerHeight * 0.9))} minWidth={560} minHeight={420} onClose={() => setModal(null)}>
      {({ startDrag }) => (<>
        <div onMouseDown={startDrag} style={{ padding: "14px 20px", borderBottom: `1px solid ${th.glassBorder}`, display: "flex", justifyContent: "space-between", cursor: "grab", userSelect: "none" }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: th.text }}>AI Extraction Coverage</div>
            <div style={{ fontSize: 11, color: th.textDim, marginTop: 3 }}>{modal.tabName}</div>
          </div>
          <button onClick={() => setModal(null)} aria-label="Close" style={{ background: "none", border: "none", color: th.textMuted, cursor: "pointer", fontSize: 18 }}>✕</button>
        </div>
        <div style={{ padding: "16px 20px", overflow: "auto", flex: 1, color: th.text, fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" }}>
          <div style={{ ...card, borderColor: complete ? `${th.success}66` : `${th.danger}66`, marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: complete ? th.success : th.danger }}>{complete ? "Complete for the qualified source inventory" : "Partial extraction — review the sources below"}</div>
            {modal.importNotice && <div style={{ fontSize: 11, color: th.textDim, lineHeight: 1.5, marginTop: 6 }}>{modal.importNotice}</div>}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 8, marginBottom: 12 }}>
            {Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)).map(([status, count]) => (
              <div key={status} style={card}><div style={{ fontSize: 18, fontWeight: 700 }}>{count}</div><div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase" }}>{status}</div></div>
            ))}
          </div>

          {(credentialExcluded > 0 || Number(grok.attachments || 0) > 0) && (
            <div style={{ ...card, marginBottom: 12, fontSize: 11, lineHeight: 1.55 }}>
              {credentialExcluded > 0 && <div><strong>{credentialExcluded}</strong> credential store/value set(s) were inventoried without copying secret values.</div>}
              {Number(grok.attachments || 0) > 0 && <div><strong>{grok.attachments}</strong> Grok Bot attachment reference(s); {Number(grok.attachmentsRecovered || 0)} SHA-256 verified local original(s). Recovery scope: {attachmentScope}.</div>}
            </div>
          )}

          {meta.capped && <div style={{ ...card, borderColor: `${th.danger}66`, marginBottom: 12, fontSize: 11 }}>Global row cap reached: {Number(meta.capped.rowCount || 0).toLocaleString()} of {Number(meta.capped.maxRows || 0).toLocaleString()} rows retained. Remaining sources are listed as excluded.</div>}

          <div style={{ fontSize: 10, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.06em", margin: "14px 0 6px" }}>Source ledger ({coverage.length})</div>
          {coverage.map((entry) => (
            <div key={`${entry.tool}:${entry.sourceFile}`} style={{ ...card, padding: "8px 10px", marginBottom: 6 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={badge(entry.status)}>{entry.status || "unknown"}</span>
                <span style={{ fontSize: 11, fontWeight: 600 }}>{entry.tool || "AI source"}</span>
                <span style={{ marginLeft: "auto", fontSize: 10, color: th.textMuted }}>{Number(entry.rows || 0).toLocaleString()} row(s)</span>
              </div>
              <div title={entry.sourceFile} style={{ fontSize: 10, color: th.textDim, fontFamily: "'SF Mono', Menlo, monospace", marginTop: 5 }}>{shortPath(entry.sourceFile)}</div>
              {entry.reason && <div style={{ fontSize: 10, color: th.textMuted, marginTop: 4 }}>{entry.reason}</div>}
            </div>
          ))}
          {!coverage.length && <div style={{ color: th.textMuted, fontSize: 12 }}>No per-source ledger was recorded for this tab.</div>}
          {failures.map((failure, index) => <div key={index} style={{ ...card, borderColor: `${th.danger}55`, marginTop: 6, fontSize: 11 }}>{failure.label || failure.tool || "Source"}: {failure.error || String(failure)}</div>)}
        </div>
        <div style={{ padding: "10px 20px", borderTop: `1px solid ${th.glassBorder}`, display: "flex", justifyContent: "flex-end" }}>
          <button onClick={() => setModal(null)} style={{ padding: "6px 14px", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, borderRadius: 6, cursor: "pointer" }}>Close</button>
        </div>
      </>)}
    </DraggableResizableModal>
  );
}
