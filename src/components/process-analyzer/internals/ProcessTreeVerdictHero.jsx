import { useState } from "react";
import { buildProcessVerdictHero } from "../../../utils/process-verdict-hero.js";
import { PI_TYPOGRAPHY } from "../constants.js";

/**
 * Verdict-first results banner for Process Inspector.
 * Optional scoped-rebuild controls when the tree was truncated.
 */
export default function ProcessTreeVerdictHero({
  data,
  detMap,
  stories,
  clusters,
  th,
  ptMitreBadge,
  scoring = false,
  scorePercent = 0,
  // Scoped rebuild (truncation recovery)
  truncated = false,
  rebuildHost = "",
  rebuildFrom = "",
  rebuildTo = "",
  hostOptions = [],
  onRebuildChange,
  onRebuild,
  scoringLabel = "Scoring detections…",
}) {
  const [coverageOpen, setCoverageOpen] = useState(false);
  const hero = buildProcessVerdictHero({ data, detMap, stories, clusters });
  const tone = th.accent;
  const tel = hero.telemetry;
  const telChips = [
    tel.processCreate, tel.terminate, tel.processAccess, tel.privilegeUse,
    tel.network, tel.dns, tel.imageLoad, tel.fileCreate,
  ].filter(Boolean);
  const isTruncated = truncated || hero.truncated;

  return (
    <div style={{
      margin: "0",
      padding: "12px 20px 10px",
      borderBottom: `1px solid ${th.border}44`,
      background: th.modalBg,
      flexShrink: 0,
    }}>
      {scoring && (
        <div style={{ marginBottom: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: PI_TYPOGRAPHY.body, fontWeight: 600, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
              {scoringLabel} {scorePercent > 0 ? `${scorePercent}%` : ""}
            </span>
          </div>
          <div style={{ height: 4, borderRadius: 2, background: `${th.border}44`, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${Math.max(4, scorePercent)}%`, background: th.accent, transition: "width 120ms linear" }} />
          </div>
        </div>
      )}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
        <div style={{ flex: "1 1 280px", minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap", marginBottom: 4 }}>
            <span style={{
              fontSize: PI_TYPOGRAPHY.control, fontWeight: 800, letterSpacing: "0.08em", textTransform: "uppercase",
              color: tone, fontFamily: "'SF Mono', Menlo, monospace",
              padding: "2px 8px", borderRadius: 4, background: `${tone}22`, border: `1px solid ${tone}44`,
            }}>{scoring ? "scoring" : hero.verdict}</span>
            <span style={{ fontSize: PI_TYPOGRAPHY.heading, fontWeight: 700, color: th.text, fontFamily: "-apple-system, sans-serif", lineHeight: 1.3 }}>
              {scoring ? "Building detection map…" : hero.verdictText}
            </span>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: PI_TYPOGRAPHY.body, fontFamily: "'SF Mono', Menlo, monospace", color: th.textDim }}>
            <span>{hero.counts.total.toLocaleString()} processes</span>
            {!scoring && hero.counts.critical > 0 && <span style={{ color: th.accent }}>{hero.counts.critical} critical</span>}
            {!scoring && hero.counts.high > 0 && <span style={{ color: th.accent }}>{hero.counts.high} high</span>}
            {!scoring && hero.counts.medium > 0 && <span>{hero.counts.medium} medium</span>}
            {!scoring && <span style={{ color: th.textMuted }}>{hero.counts.detected} detected</span>}
            {isTruncated && (
              <span style={{ color: th.danger, fontWeight: 700 }} title="Max process limit reached — raise the limit or rebuild scoped to host/time">
                Truncated
              </span>
            )}
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end", flex: "0 1 auto" }}>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap", justifyContent: "flex-end" }}>
            <span title={hero.linkQuality.label} style={{
              fontSize: PI_TYPOGRAPHY.badge, padding: "2px 7px", borderRadius: 4, fontWeight: 700, fontFamily: "'SF Mono', Menlo, monospace",
              background: `${th.accent}10`,
              color: th.accent,
              border: `1px solid ${th.accent}33`,
            }}>{hero.linkQuality.mode === "guid" && hero.linkQuality.total > 0 ? `${hero.linkQuality.guidPct}% GUID links` : hero.linkQuality.label}</span>
            {!scoring && (
              <button
                type="button"
                aria-expanded={coverageOpen}
                onClick={() => setCoverageOpen((v) => !v)}
                style={{
                  fontSize: PI_TYPOGRAPHY.badge, padding: "2px 7px", borderRadius: 4, cursor: "pointer",
                  fontFamily: "-apple-system, sans-serif", fontWeight: 600,
                  background: coverageOpen ? `${th.accent}16` : th.btnBg,
                  color: coverageOpen ? th.accent : th.textDim,
                  border: `1px solid ${coverageOpen ? th.accent + "44" : th.border}`,
                }}
              >
                Evidence coverage {coverageOpen ? "▴" : "▾"}
              </button>
            )}
          </div>
        </div>
      </div>
      {!scoring && coverageOpen && (
        <div style={{
          marginTop: 8,
          paddingTop: 8,
          borderTop: `1px solid ${th.border}55`,
          display: "grid",
          gridTemplateColumns: "minmax(260px, 1fr) minmax(220px, auto)",
          gap: 10,
          alignItems: "start",
        }}>
          <div>
            <div style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 5, fontFamily: "-apple-system, sans-serif" }}>
              Telemetry sources
            </div>
            <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
              {telChips.map((c) => (
                <span key={c.id} title={`Sysmon ${c.id}: ${c.count.toLocaleString()} matched`} style={{
                  fontSize: PI_TYPOGRAPHY.meta, padding: "2px 6px", borderRadius: 4, fontFamily: "'SF Mono', Menlo, monospace",
                  background: c.present ? `${th.accent}0d` : `${th.textMuted}08`,
                  color: c.present ? th.textDim : th.textMuted,
                  border: `1px solid ${c.present ? th.accent + "22" : th.border + "55"}`,
                }}>{c.label}{c.present ? ` · ${c.count.toLocaleString()}` : " · unavailable"}</span>
              ))}
            </div>
          </div>
          {hero.techniques.length > 0 && (
            <div>
              <div style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 5, fontFamily: "-apple-system, sans-serif" }}>
                ATT&amp;CK observed
              </div>
              <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                {hero.techniques.map((t) => (
                  <span key={t.tid} style={{ display: "inline-flex" }}>{ptMitreBadge(t.tid)}{t.count > 1 ? <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, marginLeft: 2 }}>×{t.count}</span> : null}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      {isTruncated && onRebuild && (
        <div style={{
          marginTop: 10, padding: "8px 10px", borderRadius: 8,
          background: `${th.danger}0c`, border: `1px solid ${th.danger}33`,
          display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
        }}>
          <span style={{ fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, color: th.danger, fontFamily: "-apple-system, sans-serif" }}>
            Max process limit hit — rebuild scoped:
          </span>
          <select
            value={rebuildHost || ""}
            onChange={(e) => onRebuildChange?.({ host: e.target.value })}
            style={{
              fontSize: PI_TYPOGRAPHY.control, padding: "3px 6px", borderRadius: 4, maxWidth: 180,
              background: th.bgInput, color: th.text, border: `1px solid ${th.border}`,
              fontFamily: "'SF Mono', Menlo, monospace",
            }}
          >
            <option value="">All hosts</option>
            {hostOptions.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
          <input
            type="text"
            placeholder="From (YYYY-MM-DD HH:MM:SS)"
            value={rebuildFrom || ""}
            onChange={(e) => onRebuildChange?.({ from: e.target.value })}
            style={{
              fontSize: PI_TYPOGRAPHY.control, padding: "3px 6px", borderRadius: 4, width: 160,
              background: th.bgInput, color: th.text, border: `1px solid ${th.border}`,
              fontFamily: "'SF Mono', Menlo, monospace",
            }}
          />
          <input
            type="text"
            placeholder="To (YYYY-MM-DD HH:MM:SS)"
            value={rebuildTo || ""}
            onChange={(e) => onRebuildChange?.({ to: e.target.value })}
            style={{
              fontSize: PI_TYPOGRAPHY.control, padding: "3px 6px", borderRadius: 4, width: 160,
              background: th.bgInput, color: th.text, border: `1px solid ${th.border}`,
              fontFamily: "'SF Mono', Menlo, monospace",
            }}
          />
          <button
            type="button"
            onClick={onRebuild}
            style={{
              fontSize: PI_TYPOGRAPHY.control, fontWeight: 700, padding: "4px 10px", borderRadius: 5, cursor: "pointer",
              background: th.accent, color: "#fff", border: "none", fontFamily: "-apple-system, sans-serif",
            }}
          >
            Rebuild scoped
          </button>
        </div>
      )}
    </div>
  );
}
