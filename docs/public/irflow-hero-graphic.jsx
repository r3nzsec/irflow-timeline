import { useState, useEffect, useRef } from "react";

const ORANGE = "#E8613A";
const ORANGE_DARK = "#D4472A";
const ORANGE_LIGHT = "#F0845A";
const BG_DARK = "#0D0D0D";
const BG_CARD = "#161616";
const BG_PANEL = "#1C1C1C";
const GRID_LINE = "#222222";
const TEXT_DIM = "#555";
const TEXT_MID = "#888";
const TEXT_LIGHT = "#CCC";
const WHITE = "#F5F5F5";

// Simulated timeline data
const TIMELINE_EVENTS = [
  { time: "2025-02-14 03:12:41", source: "Security.evtx", event: "4624", detail: "Logon Type 10 - RDP", severity: "high" },
  { time: "2025-02-14 03:12:58", source: "Sysmon.evtx", event: "1", detail: "cmd.exe → powershell.exe", severity: "critical" },
  { time: "2025-02-14 03:13:05", source: "Sysmon.evtx", event: "1", detail: "powershell.exe → whoami.exe", severity: "medium" },
  { time: "2025-02-14 03:13:12", source: "Sysmon.evtx", event: "1", detail: "powershell.exe → net.exe group", severity: "high" },
  { time: "2025-02-14 03:13:28", source: "Sysmon.evtx", event: "3", detail: "C2 beacon → 185.220.101.42:443", severity: "critical" },
  { time: "2025-02-14 03:14:01", source: "Sysmon.evtx", event: "1", detail: "powershell.exe → mimikatz.exe", severity: "critical" },
  { time: "2025-02-14 03:14:33", source: "Security.evtx", event: "4648", detail: "Explicit creds → DC01", severity: "critical" },
  { time: "2025-02-14 03:15:02", source: "Sysmon.evtx", event: "11", detail: "ransomware.exe dropped", severity: "critical" },
  { time: "2025-02-14 03:15:18", source: "MFTECmd", event: "CREATE", detail: "C:\\Windows\\Temp\\enc.exe", severity: "high" },
  { time: "2025-02-14 03:15:44", source: "Sysmon.evtx", event: "1", detail: "PsExec → WORKSTATION-07", severity: "critical" },
  { time: "2025-02-14 03:16:01", source: "Hayabusa", event: "ALERT", detail: "Lateral Movement Detected", severity: "critical" },
  { time: "2025-02-14 03:16:22", source: "Security.evtx", event: "4625", detail: "Failed logon → SRV-DB01", severity: "medium" },
];

const HISTOGRAM_DATA = [2,5,3,8,15,28,42,38,55,72,48,35,62,45,30,22,18,12,8,5,15,25,38,52,68,45,32,20,14,8,4,2,6,12,18,25,35,28,20,15];

const PROCESS_TREE = [
  { name: "explorer.exe", pid: 1204, depth: 0, suspicious: false },
  { name: "cmd.exe", pid: 5528, depth: 1, suspicious: true },
  { name: "powershell.exe", pid: 6744, depth: 2, suspicious: true },
  { name: "whoami.exe", pid: 7012, depth: 3, suspicious: false },
  { name: "net.exe", pid: 7180, depth: 3, suspicious: true },
  { name: "mimikatz.exe", pid: 7344, depth: 3, suspicious: true },
  { name: "PsExec.exe", pid: 7520, depth: 2, suspicious: true },
];

const LATERAL_NODES = [
  { id: "WS01", x: 60, y: 55, type: "workstation", compromised: true },
  { id: "DC01", x: 200, y: 35, type: "dc", compromised: true },
  { id: "SRV-FS", x: 320, y: 25, type: "server", compromised: true },
  { id: "SRV-DB", x: 320, y: 75, type: "server", compromised: false },
  { id: "WS07", x: 200, y: 80, type: "workstation", compromised: true },
  { id: "185.220.*", x: 60, y: 15, type: "external", compromised: false },
];

const LATERAL_EDGES = [
  { from: 0, to: 5, label: "C2", type: "c2" },
  { from: 0, to: 1, label: "RDP", type: "rdp" },
  { from: 1, to: 2, label: "SMB", type: "smb" },
  { from: 1, to: 4, label: "PsExec", type: "psexec" },
  { from: 4, to: 3, label: "4625", type: "failed" },
];

function SeverityDot({ severity }) {
  const color = severity === "critical" ? "#FF3B3B" : severity === "high" ? ORANGE : severity === "medium" ? "#FFB020" : TEXT_MID;
  return <span style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: color, marginRight: 8, flexShrink: 0 }} />;
}

function AnimatedNumber({ target, duration = 1200 }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = target / (duration / 16);
    const iv = setInterval(() => {
      start += step;
      if (start >= target) { setVal(target); clearInterval(iv); }
      else setVal(Math.floor(start));
    }, 16);
    return () => clearInterval(iv);
  }, [target, duration]);
  return <span>{val.toLocaleString()}</span>;
}

export default function IRFlowHeroGraphic() {
  const [visibleRows, setVisibleRows] = useState(0);
  const [histogramAnim, setHistogramAnim] = useState(0);
  const [showTree, setShowTree] = useState(false);
  const [showNetwork, setShowNetwork] = useState(false);
  const [scanLine, setScanLine] = useState(0);

  useEffect(() => {
    // Stagger animations
    const t1 = setTimeout(() => setHistogramAnim(1), 300);
    const t2 = setTimeout(() => setShowTree(true), 600);
    const t3 = setTimeout(() => setShowNetwork(true), 900);
    
    // Timeline rows animate in
    const rowTimers = TIMELINE_EVENTS.map((_, i) =>
      setTimeout(() => setVisibleRows(i + 1), 400 + i * 120)
    );

    // Scan line
    let scanPos = 0;
    const scanIv = setInterval(() => {
      scanPos = (scanPos + 0.3) % 100;
      setScanLine(scanPos);
    }, 30);

    return () => {
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      rowTimers.forEach(clearTimeout);
      clearInterval(scanIv);
    };
  }, []);

  const maxHist = Math.max(...HISTOGRAM_DATA);

  return (
    <div style={{
      width: "100%", maxWidth: 1200, margin: "0 auto",
      background: BG_DARK, borderRadius: 16, overflow: "hidden",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace",
      position: "relative", border: `1px solid #222`,
    }}>
      {/* Scan line effect */}
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, bottom: 0,
        pointerEvents: "none", zIndex: 20,
        background: `linear-gradient(180deg, transparent ${scanLine - 1}%, ${ORANGE}08 ${scanLine}%, transparent ${scanLine + 1}%)`,
      }} />

      {/* Title bar */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "16px 24px", borderBottom: `1px solid #222`,
        background: BG_CARD,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", gap: 6 }}>
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#FF5F57" }} />
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#FFBD2E" }} />
            <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#28C840" }} />
          </div>
          <span style={{ color: TEXT_MID, fontSize: 12, marginLeft: 8 }}>IRFlow Timeline — forensic_timeline_2025-02-14.csv</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ color: ORANGE, fontSize: 11, fontWeight: 700, letterSpacing: 1.5 }}>IRFlow</span>
          <span style={{ color: TEXT_DIM, fontSize: 11 }}>v2.1.1</span>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{
        display: "flex", gap: 0, borderBottom: `1px solid #222`, background: BG_CARD,
      }}>
        {[
          { label: "EVENTS", value: 847293, color: WHITE },
          { label: "SOURCES", value: 14, color: ORANGE_LIGHT },
          { label: "TIME SPAN", value: "72h", color: WHITE, isText: true },
          { label: "ALERTS", value: 342, color: "#FF3B3B" },
          { label: "BOOKMARKS", value: 28, color: "#FFB020" },
        ].map((stat, i) => (
          <div key={i} style={{
            flex: 1, padding: "10px 20px", borderRight: i < 4 ? `1px solid #222` : "none",
            display: "flex", flexDirection: "column", gap: 2,
          }}>
            <span style={{ fontSize: 9, color: TEXT_DIM, letterSpacing: 1.5 }}>{stat.label}</span>
            <span style={{ fontSize: 16, color: stat.color, fontWeight: 600 }}>
              {stat.isText ? stat.value : <AnimatedNumber target={stat.value} />}
            </span>
          </div>
        ))}
      </div>

      {/* Histogram */}
      <div style={{ padding: "12px 24px 0px", borderBottom: `1px solid #222` }}>
        <div style={{ display: "flex", alignItems: "flex-end", height: 52, gap: 1.5 }}>
          {HISTOGRAM_DATA.map((v, i) => {
            const h = (v / maxHist) * 48;
            const intensity = v / maxHist;
            return (
              <div key={i} style={{
                flex: 1,
                height: histogramAnim ? h : 0,
                background: intensity > 0.7 ? ORANGE : intensity > 0.4 ? ORANGE_DARK : `${ORANGE}44`,
                borderRadius: "2px 2px 0 0",
                transition: `height 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) ${i * 15}ms`,
                position: "relative",
              }}>
                {intensity > 0.8 && (
                  <div style={{
                    position: "absolute", top: -2, left: "50%", transform: "translateX(-50%)",
                    width: 4, height: 4, borderRadius: "50%",
                    background: "#FF3B3B", boxShadow: "0 0 6px #FF3B3B88",
                  }} />
                )}
              </div>
            );
          })}
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", padding: "4px 0 8px" }}>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>03:00</span>
          <span style={{ fontSize: 9, color: ORANGE, fontWeight: 600 }}>▲ BURST DETECTED 03:13–03:16</span>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>04:00</span>
        </div>
      </div>

      {/* Main content: Timeline + Side panels */}
      <div style={{ display: "flex", minHeight: 380 }}>
        
        {/* Timeline table */}
        <div style={{ flex: 1, borderRight: `1px solid #222`, overflow: "hidden" }}>
          {/* Column headers */}
          <div style={{
            display: "grid", gridTemplateColumns: "170px 100px 50px 1fr",
            padding: "8px 16px", borderBottom: `1px solid #222`,
            background: BG_PANEL, position: "sticky", top: 0,
          }}>
            {["TIMESTAMP", "SOURCE", "ID", "DETAIL"].map(h => (
              <span key={h} style={{ fontSize: 9, color: TEXT_DIM, letterSpacing: 1.2, fontWeight: 600 }}>{h}</span>
            ))}
          </div>

          {/* Rows */}
          {TIMELINE_EVENTS.map((evt, i) => {
            const visible = i < visibleRows;
            const isCritical = evt.severity === "critical";
            return (
              <div key={i} style={{
                display: "grid", gridTemplateColumns: "170px 100px 50px 1fr",
                padding: "6px 16px", borderBottom: `1px solid #1A1A1A`,
                background: isCritical ? `${ORANGE}08` : "transparent",
                borderLeft: isCritical ? `2px solid ${ORANGE}` : "2px solid transparent",
                opacity: visible ? 1 : 0,
                transform: visible ? "translateX(0)" : "translateX(-20px)",
                transition: `all 0.3s ease ${i * 40}ms`,
                alignItems: "center",
              }}>
                <span style={{ fontSize: 11, color: TEXT_LIGHT, fontVariantNumeric: "tabular-nums" }}>{evt.time.split(" ")[1]}</span>
                <span style={{ fontSize: 10, color: evt.source.includes("Sysmon") ? "#6BA3E8" : evt.source.includes("Hayabusa") ? ORANGE : TEXT_MID }}>
                  {evt.source}
                </span>
                <span style={{ fontSize: 10, color: TEXT_MID }}>{evt.event}</span>
                <div style={{ display: "flex", alignItems: "center" }}>
                  <SeverityDot severity={evt.severity} />
                  <span style={{ fontSize: 11, color: isCritical ? ORANGE_LIGHT : TEXT_LIGHT }}>{evt.detail}</span>
                </div>
              </div>
            );
          })}

          {/* Fade out hint */}
          <div style={{
            height: 40,
            background: `linear-gradient(transparent, ${BG_DARK})`,
          }} />
        </div>

        {/* Right side panels */}
        <div style={{ width: 340, display: "flex", flexDirection: "column" }}>
          
          {/* Process Tree */}
          <div style={{
            flex: 1, padding: 16, borderBottom: `1px solid #222`,
            opacity: showTree ? 1 : 0, transform: showTree ? "translateY(0)" : "translateY(10px)",
            transition: "all 0.5s ease",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
              <span style={{ fontSize: 10, color: TEXT_DIM, letterSpacing: 1.2, fontWeight: 600 }}>PROCESS TREE</span>
              <span style={{ fontSize: 9, color: ORANGE, background: `${ORANGE}15`, padding: "2px 8px", borderRadius: 3 }}>SYSMON EID 1</span>
            </div>
            {PROCESS_TREE.map((proc, i) => (
              <div key={i} style={{
                display: "flex", alignItems: "center", paddingLeft: proc.depth * 18,
                marginBottom: 3,
                opacity: showTree ? 1 : 0,
                transition: `opacity 0.3s ease ${i * 80}ms`,
              }}>
                {proc.depth > 0 && (
                  <span style={{ color: "#333", fontSize: 11, marginRight: 6 }}>
                    {"│ ".repeat(proc.depth - 1)}├─
                  </span>
                )}
                <span style={{
                  fontSize: 11,
                  color: proc.suspicious ? (proc.name === "mimikatz.exe" ? "#FF3B3B" : ORANGE) : TEXT_MID,
                  fontWeight: proc.suspicious ? 600 : 400,
                }}>
                  {proc.name}
                </span>
                <span style={{ fontSize: 9, color: TEXT_DIM, marginLeft: 8 }}>:{proc.pid}</span>
                {proc.suspicious && proc.name === "mimikatz.exe" && (
                  <span style={{ fontSize: 8, color: "#FF3B3B", marginLeft: 8, background: "#FF3B3B18", padding: "1px 6px", borderRadius: 2, fontWeight: 700 }}>
                    LOLBIN
                  </span>
                )}
              </div>
            ))}
          </div>

          {/* Lateral Movement Network */}
          <div style={{
            flex: 1, padding: 16,
            opacity: showNetwork ? 1 : 0, transform: showNetwork ? "translateY(0)" : "translateY(10px)",
            transition: "all 0.5s ease 0.2s",
          }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
              <span style={{ fontSize: 10, color: TEXT_DIM, letterSpacing: 1.2, fontWeight: 600 }}>LATERAL MOVEMENT</span>
              <span style={{ fontSize: 9, color: "#FF3B3B", background: "#FF3B3B15", padding: "2px 8px", borderRadius: 3 }}>3 HOPS</span>
            </div>
            <svg viewBox="0 0 380 100" style={{ width: "100%", height: 120 }}>
              {/* Edges */}
              {LATERAL_EDGES.map((edge, i) => {
                const from = LATERAL_NODES[edge.from];
                const to = LATERAL_NODES[edge.to];
                const color = edge.type === "c2" ? "#FF3B3B" : edge.type === "rdp" ? "#4A90D9" : edge.type === "failed" ? "#FF3B3B44" : ORANGE;
                const dashArr = edge.type === "failed" ? "4 3" : "none";
                return (
                  <g key={i}>
                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={color} strokeWidth={edge.type === "failed" ? 1 : 1.5}
                      strokeDasharray={dashArr} opacity={0.6}
                    />
                    <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 5}
                      fill={color} fontSize="7" textAnchor="middle" fontFamily="monospace" opacity={0.8}>
                      {edge.label}
                    </text>
                  </g>
                );
              })}
              {/* Nodes */}
              {LATERAL_NODES.map((node, i) => {
                const isExt = node.type === "external";
                const isDC = node.type === "dc";
                return (
                  <g key={i}>
                    {isDC ? (
                      <rect x={node.x - 14} y={node.y - 10} width={28} height={20} rx={3}
                        fill={node.compromised ? `${ORANGE}30` : `${TEXT_DIM}20`}
                        stroke={node.compromised ? ORANGE : TEXT_DIM} strokeWidth={1.2}
                      />
                    ) : isExt ? (
                      <circle cx={node.x} cy={node.y} r={10}
                        fill="#FF3B3B15" stroke="#FF3B3B" strokeWidth={1} strokeDasharray="3 2"
                      />
                    ) : (
                      <rect x={node.x - 12} y={node.y - 8} width={24} height={16} rx={6}
                        fill={node.compromised ? `${ORANGE}25` : `${TEXT_DIM}15`}
                        stroke={node.compromised ? ORANGE_LIGHT : TEXT_DIM} strokeWidth={1}
                      />
                    )}
                    <text x={node.x} y={node.y + 3} fill={isExt ? "#FF3B3B" : node.compromised ? WHITE : TEXT_MID}
                      fontSize="7" textAnchor="middle" fontFamily="monospace" fontWeight={node.compromised ? 600 : 400}>
                      {node.id}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      </div>

      {/* Bottom status bar */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "8px 24px", borderTop: `1px solid #222`,
        background: BG_CARD,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>
            <span style={{ color: "#28C840", marginRight: 4 }}>●</span>
            SQLite WAL Mode
          </span>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>
            847,293 rows indexed
          </span>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>
            FTS5 search ready
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 9, color: ORANGE }}>
            ⚡ 12ms query time
          </span>
          <span style={{ fontSize: 9, color: TEXT_DIM }}>
            CSV • EVTX • XLSX • Plaso
          </span>
        </div>
      </div>

      {/* Floating branding overlay */}
      <div style={{
        position: "absolute", bottom: 50, right: 24,
        display: "flex", flexDirection: "column", alignItems: "flex-end",
        gap: 4, pointerEvents: "none",
      }}>
        <div style={{
          background: `${BG_DARK}DD`, backdropFilter: "blur(8px)",
          padding: "12px 20px", borderRadius: 10,
          border: `1px solid #333`,
        }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 6 }}>
            <span style={{ fontSize: 22, fontWeight: 800, color: WHITE, letterSpacing: -1 }}>IR</span>
            <span style={{ fontSize: 22, fontWeight: 300, color: ORANGE, letterSpacing: -1 }}>Flow</span>
            <span style={{ fontSize: 13, fontWeight: 300, color: TEXT_DIM, marginLeft: 4 }}>Timeline</span>
          </div>
          <div style={{ fontSize: 9, color: TEXT_DIM, marginTop: 2, letterSpacing: 0.5 }}>
            DFIR Timeline Analysis for macOS
          </div>
        </div>
      </div>

      {/* Active filters tag bar */}
      <div style={{
        position: "absolute", top: 106, left: 24,
        display: "flex", gap: 6, pointerEvents: "none",
      }}>
        {[
          { label: "Search: mimikatz OR psexec", color: ORANGE },
          { label: "Tag: Lateral Movement", color: "#4A90D9" },
          { label: "Bookmarked", color: "#FFB020" },
        ].map((tag, i) => (
          <span key={i} style={{
            fontSize: 9, color: tag.color, background: `${tag.color}15`,
            border: `1px solid ${tag.color}33`, padding: "3px 10px", borderRadius: 4,
            opacity: 0.9,
          }}>
            {tag.label}
          </span>
        ))}
      </div>
    </div>
  );
}
