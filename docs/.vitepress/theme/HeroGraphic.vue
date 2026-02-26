<template>
  <div class="hero-graphic" ref="container">
    <!-- Scan line effect -->
    <div class="scan-line" :style="{ background: `linear-gradient(180deg, transparent ${scanLine - 1}%, #E8613A08 ${scanLine}%, transparent ${scanLine + 1}%)` }" />

    <!-- Title bar -->
    <div class="title-bar">
      <div class="title-left">
        <div class="traffic-lights">
          <span class="dot dot-red" />
          <span class="dot dot-yellow" />
          <span class="dot dot-green" />
        </div>
        <span class="title-text">IRFlow Timeline — forensic_timeline_2025-02-14.csv</span>
      </div>
      <div class="title-right">
        <span class="brand-name">IRFlow</span>
        <span class="brand-version">v2.1.2</span>
      </div>
    </div>

    <!-- Stats bar -->
    <div class="stats-bar">
      <div v-for="(stat, i) in stats" :key="i" class="stat-item" :class="{ 'stat-last': i === stats.length - 1 }">
        <span class="stat-label">{{ stat.label }}</span>
        <span class="stat-value" :style="{ color: stat.color }">{{ stat.display }}</span>
      </div>
    </div>

    <!-- Histogram -->
    <div class="histogram-section">
      <div class="histogram-bars">
        <div v-for="(v, i) in histogramData" :key="i" class="hist-bar-wrapper">
          <div class="hist-bar" :style="{
            height: histogramAnim ? `${(v / maxHist) * 48}px` : '0px',
            background: v / maxHist > 0.7 ? '#E8613A' : v / maxHist > 0.4 ? '#D4472A' : '#E8613A44',
            transitionDelay: `${i * 15}ms`,
          }">
            <div v-if="v / maxHist > 0.8" class="hist-alert-dot" />
          </div>
        </div>
      </div>
      <div class="histogram-labels">
        <span class="hist-label">03:00</span>
        <span class="hist-alert">▲ BURST DETECTED 03:13–03:16</span>
        <span class="hist-label">04:00</span>
      </div>
    </div>

    <!-- Main content -->
    <div class="main-content">
      <!-- Timeline table -->
      <div class="timeline-table">
        <div class="table-header">
          <span v-for="h in ['TIMESTAMP', 'SOURCE', 'ID', 'DETAIL']" :key="h" class="header-cell">{{ h }}</span>
        </div>
        <div v-for="(evt, i) in timelineEvents" :key="i" class="table-row" :class="{ 'row-critical': evt.severity === 'critical' }" :style="{
          opacity: i < visibleRows ? 1 : 0,
          transform: i < visibleRows ? 'translateX(0)' : 'translateX(-20px)',
          transitionDelay: `${i * 40}ms`,
        }">
          <span class="cell-time">{{ evt.time.split(' ')[1] }}</span>
          <span class="cell-source" :class="{
            'source-sysmon': evt.source.includes('Sysmon'),
            'source-hayabusa': evt.source.includes('Hayabusa'),
          }">{{ evt.source }}</span>
          <span class="cell-id">{{ evt.event }}</span>
          <div class="cell-detail">
            <span class="severity-dot" :class="`sev-${evt.severity}`" />
            <span :class="{ 'detail-critical': evt.severity === 'critical' }">{{ evt.detail }}</span>
          </div>
        </div>
        <div class="table-fade" />
      </div>

      <!-- Right side panels -->
      <div class="side-panels">
        <!-- Process Tree -->
        <div class="panel process-tree" :style="{ opacity: showTree ? 1 : 0, transform: showTree ? 'translateY(0)' : 'translateY(10px)' }">
          <div class="panel-header">
            <span class="panel-title">PROCESS TREE</span>
            <span class="panel-badge badge-orange">SYSMON EID 1</span>
          </div>
          <div v-for="(proc, i) in processTree" :key="i" class="tree-node" :style="{ paddingLeft: `${proc.depth * 18}px`, opacity: showTree ? 1 : 0, transitionDelay: `${i * 80}ms` }">
            <span v-if="proc.depth > 0" class="tree-branch">{{ '│ '.repeat(proc.depth - 1) }}├─</span>
            <span class="tree-name" :class="{
              'tree-suspicious': proc.suspicious,
              'tree-danger': proc.name === 'mimikatz.exe',
            }">{{ proc.name }}</span>
            <span class="tree-pid">:{{ proc.pid }}</span>
            <span v-if="proc.suspicious && proc.name === 'mimikatz.exe'" class="tree-lolbin">LOLBIN</span>
          </div>
        </div>

        <!-- Lateral Movement -->
        <div class="panel lateral-panel" :style="{ opacity: showNetwork ? 1 : 0, transform: showNetwork ? 'translateY(0)' : 'translateY(10px)' }">
          <div class="panel-header">
            <span class="panel-title">LATERAL MOVEMENT</span>
            <span class="panel-badge badge-red">3 HOPS</span>
          </div>
          <svg viewBox="0 0 380 100" class="network-svg">
            <g v-for="(edge, i) in lateralEdges" :key="'e' + i">
              <line :x1="lateralNodes[edge.from].x" :y1="lateralNodes[edge.from].y"
                :x2="lateralNodes[edge.to].x" :y2="lateralNodes[edge.to].y"
                :stroke="edgeColor(edge.type)" :stroke-width="edge.type === 'failed' ? 1 : 1.5"
                :stroke-dasharray="edge.type === 'failed' ? '4 3' : 'none'" opacity="0.6" />
              <text :x="(lateralNodes[edge.from].x + lateralNodes[edge.to].x) / 2"
                :y="(lateralNodes[edge.from].y + lateralNodes[edge.to].y) / 2 - 5"
                :fill="edgeColor(edge.type)" font-size="7" text-anchor="middle" font-family="monospace" opacity="0.8">
                {{ edge.label }}
              </text>
            </g>
            <g v-for="(node, i) in lateralNodes" :key="'n' + i">
              <rect v-if="node.type === 'dc'" :x="node.x - 14" :y="node.y - 10" width="28" height="20" rx="3"
                :fill="node.compromised ? '#E8613A30' : '#55555520'"
                :stroke="node.compromised ? '#E8613A' : '#555'" stroke-width="1.2" />
              <circle v-else-if="node.type === 'external'" :cx="node.x" :cy="node.y" r="10"
                fill="#FF3B3B15" stroke="#FF3B3B" stroke-width="1" stroke-dasharray="3 2" />
              <rect v-else :x="node.x - 12" :y="node.y - 8" width="24" height="16" rx="6"
                :fill="node.compromised ? '#E8613A25' : '#55555515'"
                :stroke="node.compromised ? '#F0845A' : '#555'" stroke-width="1" />
              <text :x="node.x" :y="node.y + 3"
                :fill="node.type === 'external' ? '#FF3B3B' : node.compromised ? '#F5F5F5' : '#888'"
                font-size="7" text-anchor="middle" font-family="monospace"
                :font-weight="node.compromised ? 600 : 400">
                {{ node.id }}
              </text>
            </g>
          </svg>
        </div>
      </div>
    </div>

    <!-- Filter tags -->
    <div class="filter-tags">
      <span v-for="(tag, i) in filterTags" :key="i" class="filter-tag" :style="{
        color: tag.color,
        background: `${tag.color}15`,
        borderColor: `${tag.color}33`,
      }">{{ tag.label }}</span>
    </div>

    <!-- Bottom status bar -->
    <div class="status-bar">
      <div class="status-left">
        <span class="status-item"><span class="status-green">●</span> SQLite WAL Mode</span>
        <span class="status-item">847,293 rows indexed</span>
        <span class="status-item">FTS5 search ready</span>
      </div>
      <div class="status-right">
        <span class="status-accent">⚡ 12ms query time</span>
        <span class="status-item">CSV • EVTX • XLSX • Plaso</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const scanLine = ref(0)
const visibleRows = ref(0)
const histogramAnim = ref(false)
const showTree = ref(false)
const showNetwork = ref(false)

const stats = [
  { label: 'EVENTS', display: '847,293', color: '#F5F5F5' },
  { label: 'SOURCES', display: '14', color: '#F0845A' },
  { label: 'TIME SPAN', display: '72h', color: '#F5F5F5' },
  { label: 'ALERTS', display: '342', color: '#FF3B3B' },
  { label: 'BOOKMARKS', display: '28', color: '#FFB020' },
]

const histogramData = [2,5,3,8,15,28,42,38,55,72,48,35,62,45,30,22,18,12,8,5,15,25,38,52,68,45,32,20,14,8,4,2,6,12,18,25,35,28,20,15]
const maxHist = Math.max(...histogramData)

const timelineEvents = [
  { time: '2025-02-14 03:12:41', source: 'Security.evtx', event: '4624', detail: 'Logon Type 10 - RDP', severity: 'high' },
  { time: '2025-02-14 03:12:58', source: 'Sysmon.evtx', event: '1', detail: 'cmd.exe → powershell.exe', severity: 'critical' },
  { time: '2025-02-14 03:13:05', source: 'Sysmon.evtx', event: '1', detail: 'powershell.exe → whoami.exe', severity: 'medium' },
  { time: '2025-02-14 03:13:12', source: 'Sysmon.evtx', event: '1', detail: 'powershell.exe → net.exe group', severity: 'high' },
  { time: '2025-02-14 03:13:28', source: 'Sysmon.evtx', event: '3', detail: 'C2 beacon → 185.220.101.42:443', severity: 'critical' },
  { time: '2025-02-14 03:14:01', source: 'Sysmon.evtx', event: '1', detail: 'powershell.exe → mimikatz.exe', severity: 'critical' },
  { time: '2025-02-14 03:14:33', source: 'Security.evtx', event: '4648', detail: 'Explicit creds → DC01', severity: 'critical' },
  { time: '2025-02-14 03:15:02', source: 'Sysmon.evtx', event: '11', detail: 'ransomware.exe dropped', severity: 'critical' },
  { time: '2025-02-14 03:15:18', source: 'MFTECmd', event: 'CREATE', detail: 'C:\\Windows\\Temp\\enc.exe', severity: 'high' },
  { time: '2025-02-14 03:15:44', source: 'Sysmon.evtx', event: '1', detail: 'PsExec → WORKSTATION-07', severity: 'critical' },
  { time: '2025-02-14 03:16:01', source: 'Hayabusa', event: 'ALERT', detail: 'Lateral Movement Detected', severity: 'critical' },
  { time: '2025-02-14 03:16:22', source: 'Security.evtx', event: '4625', detail: 'Failed logon → SRV-DB01', severity: 'medium' },
]

const processTree = [
  { name: 'explorer.exe', pid: 1204, depth: 0, suspicious: false },
  { name: 'cmd.exe', pid: 5528, depth: 1, suspicious: true },
  { name: 'powershell.exe', pid: 6744, depth: 2, suspicious: true },
  { name: 'whoami.exe', pid: 7012, depth: 3, suspicious: false },
  { name: 'net.exe', pid: 7180, depth: 3, suspicious: true },
  { name: 'mimikatz.exe', pid: 7344, depth: 3, suspicious: true },
  { name: 'PsExec.exe', pid: 7520, depth: 2, suspicious: true },
]

const lateralNodes = [
  { id: 'WS01', x: 60, y: 55, type: 'workstation', compromised: true },
  { id: 'DC01', x: 200, y: 35, type: 'dc', compromised: true },
  { id: 'SRV-FS', x: 320, y: 25, type: 'server', compromised: true },
  { id: 'SRV-DB', x: 320, y: 75, type: 'server', compromised: false },
  { id: 'WS07', x: 200, y: 80, type: 'workstation', compromised: true },
  { id: '185.220.*', x: 60, y: 15, type: 'external', compromised: false },
]

const lateralEdges = [
  { from: 0, to: 5, label: 'C2', type: 'c2' },
  { from: 0, to: 1, label: 'RDP', type: 'rdp' },
  { from: 1, to: 2, label: 'SMB', type: 'smb' },
  { from: 1, to: 4, label: 'PsExec', type: 'psexec' },
  { from: 4, to: 3, label: '4625', type: 'failed' },
]

const filterTags = [
  { label: 'Search: mimikatz OR psexec', color: '#E8613A' },
  { label: 'Tag: Lateral Movement', color: '#4A90D9' },
  { label: 'Bookmarked', color: '#FFB020' },
]

function edgeColor(type) {
  if (type === 'c2') return '#FF3B3B'
  if (type === 'rdp') return '#4A90D9'
  if (type === 'failed') return '#FF3B3B44'
  return '#E8613A'
}

let scanIv = null
let timers = []

onMounted(() => {
  timers.push(setTimeout(() => { histogramAnim.value = true }, 300))
  timers.push(setTimeout(() => { showTree.value = true }, 600))
  timers.push(setTimeout(() => { showNetwork.value = true }, 900))

  timelineEvents.forEach((_, i) => {
    timers.push(setTimeout(() => { visibleRows.value = i + 1 }, 400 + i * 120))
  })

  let scanPos = 0
  scanIv = setInterval(() => {
    scanPos = (scanPos + 0.3) % 100
    scanLine.value = scanPos
  }, 30)
})

onUnmounted(() => {
  timers.forEach(clearTimeout)
  if (scanIv) clearInterval(scanIv)
})
</script>

<style scoped>
.hero-graphic {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  background: #0D0D0D;
  border-radius: 16px;
  overflow: hidden;
  font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace;
  position: relative;
  border: 1px solid #222;
}

.scan-line {
  position: absolute;
  top: 0; left: 0; right: 0; bottom: 0;
  pointer-events: none;
  z-index: 20;
}

/* Title bar */
.title-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 24px;
  border-bottom: 1px solid #222;
  background: #161616;
}
.title-left { display: flex; align-items: center; gap: 12px; }
.traffic-lights { display: flex; gap: 6px; }
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot-red { background: #FF5F57; }
.dot-yellow { background: #FFBD2E; }
.dot-green { background: #28C840; }
.title-text { color: #888; font-size: 12px; margin-left: 8px; }
.title-right { display: flex; align-items: center; gap: 16px; }
.brand-name { color: #E8613A; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; }
.brand-version { color: #555; font-size: 11px; }

/* Stats bar */
.stats-bar {
  display: flex;
  gap: 0;
  border-bottom: 1px solid #222;
  background: #161616;
}
.stat-item {
  flex: 1;
  padding: 10px 20px;
  border-right: 1px solid #222;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.stat-last { border-right: none; }
.stat-label { font-size: 9px; color: #555; letter-spacing: 1.5px; }
.stat-value { font-size: 16px; font-weight: 600; }

/* Histogram */
.histogram-section {
  padding: 12px 24px 0;
  border-bottom: 1px solid #222;
}
.histogram-bars {
  display: flex;
  align-items: flex-end;
  height: 52px;
  gap: 1.5px;
}
.hist-bar-wrapper { flex: 1; display: flex; align-items: flex-end; }
.hist-bar {
  width: 100%;
  border-radius: 2px 2px 0 0;
  transition: height 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
  position: relative;
}
.hist-alert-dot {
  position: absolute;
  top: -2px;
  left: 50%;
  transform: translateX(-50%);
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: #FF3B3B;
  box-shadow: 0 0 6px #FF3B3B88;
}
.histogram-labels {
  display: flex;
  justify-content: space-between;
  padding: 4px 0 8px;
}
.hist-label { font-size: 9px; color: #555; }
.hist-alert { font-size: 9px; color: #E8613A; font-weight: 600; }

/* Main content */
.main-content {
  display: flex;
  min-height: 380px;
}

/* Timeline table */
.timeline-table {
  flex: 1;
  border-right: 1px solid #222;
  overflow: hidden;
}
.table-header {
  display: grid;
  grid-template-columns: 170px 100px 50px 1fr;
  padding: 8px 16px;
  border-bottom: 1px solid #222;
  background: #1C1C1C;
  position: sticky;
  top: 0;
}
.header-cell {
  font-size: 9px;
  color: #555;
  letter-spacing: 1.2px;
  font-weight: 600;
}
.table-row {
  display: grid;
  grid-template-columns: 170px 100px 50px 1fr;
  padding: 6px 16px;
  border-bottom: 1px solid #1A1A1A;
  border-left: 2px solid transparent;
  transition: all 0.3s ease;
  align-items: center;
}
.row-critical {
  background: #E8613A08;
  border-left-color: #E8613A;
}
.cell-time { font-size: 11px; color: #CCC; font-variant-numeric: tabular-nums; }
.cell-source { font-size: 10px; color: #888; }
.source-sysmon { color: #6BA3E8; }
.source-hayabusa { color: #E8613A; }
.cell-id { font-size: 10px; color: #888; }
.cell-detail { display: flex; align-items: center; }
.cell-detail span:last-child { font-size: 11px; color: #CCC; }
.detail-critical { color: #F0845A !important; }

.severity-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  margin-right: 8px;
  flex-shrink: 0;
}
.sev-critical { background: #FF3B3B; }
.sev-high { background: #E8613A; }
.sev-medium { background: #FFB020; }
.sev-low { background: #888; }

.table-fade {
  height: 40px;
  background: linear-gradient(transparent, #0D0D0D);
}

/* Side panels */
.side-panels {
  width: 340px;
  display: flex;
  flex-direction: column;
}
.panel {
  flex: 1;
  padding: 16px;
  transition: all 0.5s ease;
}
.process-tree { border-bottom: 1px solid #222; }
.lateral-panel { transition-delay: 0.2s; }

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.panel-title { font-size: 10px; color: #555; letter-spacing: 1.2px; font-weight: 600; }
.panel-badge { font-size: 9px; padding: 2px 8px; border-radius: 3px; }
.badge-orange { color: #E8613A; background: #E8613A15; }
.badge-red { color: #FF3B3B; background: #FF3B3B15; }

/* Process tree */
.tree-node {
  display: flex;
  align-items: center;
  margin-bottom: 3px;
  transition: opacity 0.3s ease;
}
.tree-branch { color: #333; font-size: 11px; margin-right: 6px; white-space: pre; }
.tree-name { font-size: 11px; color: #888; }
.tree-suspicious { color: #E8613A; font-weight: 600; }
.tree-danger { color: #FF3B3B !important; }
.tree-pid { font-size: 9px; color: #555; margin-left: 8px; }
.tree-lolbin {
  font-size: 8px;
  color: #FF3B3B;
  margin-left: 8px;
  background: #FF3B3B18;
  padding: 1px 6px;
  border-radius: 2px;
  font-weight: 700;
}

/* Network graph */
.network-svg { width: 100%; height: 120px; }

/* Filter tags */
.filter-tags {
  position: absolute;
  top: 106px;
  left: 24px;
  display: flex;
  gap: 6px;
  pointer-events: none;
}
.filter-tag {
  font-size: 9px;
  border: 1px solid;
  padding: 3px 10px;
  border-radius: 4px;
  opacity: 0.9;
}

/* Status bar */
.status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px;
  border-top: 1px solid #222;
  background: #161616;
}
.status-left, .status-right { display: flex; align-items: center; gap: 16px; }
.status-right { gap: 12px; }
.status-item { font-size: 9px; color: #555; }
.status-green { color: #28C840; margin-right: 4px; }
.status-accent { font-size: 9px; color: #E8613A; }

/* Responsive - hide on small screens */
@media (max-width: 960px) {
  .side-panels { display: none; }
  .stats-bar { flex-wrap: wrap; }
  .stat-item { min-width: 80px; }
  .table-header, .table-row {
    grid-template-columns: 80px 80px 40px 1fr;
  }
  .filter-tags { display: none; }
  .hero-graphic { border-radius: 8px; }
}

@media (max-width: 640px) {
  .title-text { display: none; }
  .stats-bar { display: none; }
  .histogram-section { display: none; }
  .table-header, .table-row {
    grid-template-columns: 70px 1fr;
  }
  .cell-source, .cell-id { display: none; }
}
</style>
