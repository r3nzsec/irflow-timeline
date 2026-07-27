<template>
  <div class="hero-graphic"
    :class="{ 'tour-active': tourActive && tourStep >= 0 }"
    ref="container"
    @mouseenter="pauseTour"
    @mouseleave="resumeTour"
  >
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
        <span class="brand-version">v1.0.9</span>
      </div>
    </div>

    <!-- Stats bar -->
    <div class="stats-bar" :class="{ 'tour-focus': tourStep === 0 }">
      <div v-for="(stat, i) in stats" :key="i" class="stat-item" :class="{ 'stat-last': i === stats.length - 1 }">
        <span class="stat-label">{{ stat.label }}</span>
        <span class="stat-value" :style="{ color: stat.color }">{{ stat.display }}</span>
      </div>
    </div>

    <!-- Filter tags -->
    <div class="filter-tags" :class="{ 'tour-focus': tourStep === 1 || tourStep === 4 }">
      <span v-for="(tag, i) in displayedFilterTags" :key="i" class="filter-tag" :style="{
        color: tag.color,
        background: `${tag.color}15`,
        borderColor: `${tag.color}33`,
      }">{{ tag.label }}</span>
    </div>

    <!-- Histogram -->
    <div class="histogram-section" :class="{ 'tour-focus': tourStep === 0 }">
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
      <div class="timeline-table" :class="{ 'tour-focus': tourStep === 0 || tourStep === 1 || tourStep === 4 }">
        <div class="table-header">
          <span v-for="h in ['TIMESTAMP', 'SOURCE', 'ID', 'DETAIL']" :key="h" class="header-cell">{{ h }}</span>
        </div>
        <div v-for="(evt, i) in displayedEvents" :key="i" class="table-row" :class="{ 'row-critical': evt.severity === 'critical', 'row-ai': evt.source.includes('AI') }" :style="{
          opacity: i < Math.min(visibleRows, displayedRowCount) ? 1 : 0,
          transform: i < Math.min(visibleRows, displayedRowCount) ? 'translateX(0)' : 'translateX(-20px)',
          transitionDelay: `${i * 40}ms`,
        }">
          <span class="cell-time">{{ evt.time.split(' ')[1] }}</span>
          <span class="cell-source" :class="{
            'source-sysmon': evt.source.includes('Sysmon'),
            'source-hayabusa': evt.source.includes('Hayabusa'),
            'source-ai': evt.source.includes('AI'),
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
        <!-- Process Inspector -->
        <div class="panel process-tree" :class="{ 'tour-focus': tourStep === 2 }" :style="{ opacity: sectionOpacity(2, showTree), transform: showTree ? 'translateY(0)' : 'translateY(10px)' }">
          <div class="panel-header">
            <span class="panel-title">PROCESS INSPECTOR</span>
            <span class="panel-badge badge-orange">SYSMON EID 1</span>
          </div>
          <div v-for="(proc, i) in processTree" :key="i" class="tree-node" :style="{ paddingLeft: `${proc.depth * 18}px`, opacity: showTree ? 1 : 0, transitionDelay: `${i * 80}ms` }">
            <span v-if="proc.depth > 0" class="tree-branch">{{ '│ '.repeat(proc.depth - 1) }}├─</span>
            <span class="tree-name" :class="{
              'tree-suspicious': proc.suspicious,
              'tree-danger': proc.name === 'mimikatz.exe',
            }">{{ proc.name }}</span>
            <span class="tree-pid">:{{ proc.pid }}</span>
            <span v-if="proc.suspicious && proc.name === 'mimikatz.exe'" class="tree-lolbin">CREDENTIAL DUMP</span>
          </div>
        </div>

        <!-- AI Apps scan -->
        <div class="panel ai-apps-panel" :class="{ 'tour-focus': tourStep === 4 }" :style="{ opacity: sectionOpacity(4, showAiApps), transform: showAiApps ? 'translateY(0)' : 'translateY(10px)' }">
          <div class="panel-header">
            <span class="panel-title">AI APPS SCAN</span>
            <span class="panel-badge badge-orange">{{ aiApps.length }} APPS</span>
          </div>
          <svg viewBox="0 0 380 140" class="ai-apps-svg" aria-hidden="true">
            <defs>
              <linearGradient id="aiHubGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stop-color="#E8613A" stop-opacity="0.35" />
                <stop offset="100%" stop-color="#E8613A" stop-opacity="0.08" />
              </linearGradient>
            </defs>
            <!-- Scan rays from apps to hub -->
            <g v-for="(app, i) in aiApps" :key="'ray' + i">
              <line :x1="app.x" :y1="app.y" x2="190" y2="70"
                stroke="#E8613A" stroke-width="0.8" stroke-opacity="0.22"
                :stroke-dasharray="tourStep === 4 ? '3 2' : '0'"
              />
            </g>
            <!-- Central merge target -->
            <rect x="148" y="52" width="84" height="36" rx="4" fill="url(#aiHubGrad)" stroke="#E8613A" stroke-width="1" stroke-opacity="0.7" />
            <text x="190" y="67" fill="#F0845A" font-size="5.5" text-anchor="middle" font-family="monospace" font-weight="700">AI QUERY</text>
            <text x="190" y="78" fill="#CCC" font-size="5" text-anchor="middle" font-family="monospace">HISTORY TAB</text>
            <!-- App nodes -->
            <g v-for="(app, i) in aiApps" :key="'app' + i">
              <circle :cx="app.x" :cy="app.y" r="13" :fill="app.color + '18'" :stroke="app.color" stroke-width="0.9" stroke-opacity="0.75" />
              <text :x="app.x" :y="app.y + 1" :fill="app.color" font-size="4.5" text-anchor="middle" font-family="monospace" font-weight="700">{{ app.abbr }}</text>
              <text :x="app.x" :y="app.y + 22" fill="#AAA" font-size="4.5" text-anchor="middle" font-family="monospace">{{ app.label }}</text>
            </g>
            <!-- Collect badge -->
            <rect x="262" y="10" width="108" height="18" rx="3" fill="#E8613A12" stroke="#E8613A" stroke-width="0.7" stroke-opacity="0.5" />
            <text x="316" y="21" fill="#E8613A" font-size="5" text-anchor="middle" font-family="monospace" font-weight="600">COLLECT AI ARTIFACTS</text>
          </svg>
        </div>

        <!-- Lateral Movement -->
        <div class="panel lateral-panel" :class="{ 'tour-focus': tourStep === 3 }" :style="{ opacity: sectionOpacity(3, showNetwork), transform: showNetwork ? 'translateY(0)' : 'translateY(10px)' }">
          <div class="panel-header">
            <span class="panel-title">LATERAL MOVEMENT</span>
            <span class="panel-badge badge-red">3 HOPS</span>
          </div>
          <svg viewBox="0 0 380 140" class="network-svg">
            <!-- Edges -->
            <g v-for="(edge, i) in lateralEdges" :key="'e' + i">
              <line :x1="lateralNodes[edge.from].x" :y1="lateralNodes[edge.from].y"
                :x2="lateralNodes[edge.to].x" :y2="lateralNodes[edge.to].y"
                :stroke="edge.green ? '#28C840' : '#555'" :stroke-width="edge.w || 1"
                :stroke-opacity="edge.green ? 0.5 : 0.3" />
              <text v-if="edge.count"
                :x="(lateralNodes[edge.from].x + lateralNodes[edge.to].x) / 2"
                :y="(lateralNodes[edge.from].y + lateralNodes[edge.to].y) / 2 - 4"
                :fill="edge.green ? '#28C840' : '#888'" font-size="6" text-anchor="middle" font-family="monospace" opacity="0.7">
                {{ edge.count }}
              </text>
            </g>
            <!-- Nodes -->
            <template v-for="(node, i) in lateralNodes" :key="'n' + i">
              <!-- Suspicious host: dashed red circle + glow + warning triangle -->
              <g v-if="node.type === 'suspicious'">
                <circle :cx="node.x" :cy="node.y" r="15" fill="#FF3B3B" opacity="0.06" />
                <circle :cx="node.x" :cy="node.y" r="15" fill="none" stroke="#FF3B3B" stroke-width="1" stroke-dasharray="4 2" opacity="0.5" />
                <rect :x="node.x - 5" :y="node.y - 5" width="10" height="10" rx="1.5" fill="#FF3B3B25" stroke="#FF3B3B" stroke-width="0.8" />
                <polygon :points="`${node.x+13},${node.y-16} ${node.x+10},${node.y-10} ${node.x+16},${node.y-10}`" fill="#E8613A" />
                <text :x="node.x+13" :y="node.y-12" fill="#0D0D0D" font-size="5" text-anchor="middle" font-weight="800">!</text>
                <text :x="node.x" :y="node.y + 25" fill="#CCC" font-size="5" text-anchor="middle" font-family="monospace">{{ node.label }}</text>
              </g>
              <!-- Named host: colored rect + label -->
              <g v-else-if="node.type === 'host'">
                <rect :x="node.x - 10" :y="node.y - 7" width="20" height="14" rx="2"
                  :fill="(node.color || '#28C840') + '25'" :stroke="node.color || '#28C840'" stroke-width="1" />
                <text :x="node.x" :y="node.y + 18" fill="#AAA" font-size="5.5" text-anchor="middle" font-family="monospace">{{ node.label }}</text>
              </g>
              <!-- IP address node: small green rect -->
              <g v-else>
                <rect :x="node.x - 7" :y="node.y - 5" width="14" height="10" rx="2"
                  fill="#28C84018" stroke="#28C840" stroke-width="0.7" />
                <text :x="node.x" :y="node.y + 13" fill="#28C840" font-size="5" text-anchor="middle" font-family="monospace" opacity="0.7">{{ node.label }}</text>
              </g>
            </template>
          </svg>
        </div>
      </div>
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
        <span class="status-item">CSV • EVTX • XLSX • Plaso • $MFT • <span class="status-ai">AI Apps</span> • AI history</span>
      </div>
    </div>

    <!-- Tour caption -->
    <Transition name="tour-caption">
      <div v-if="tourActive && tourStep >= 0" :key="tourStep" class="tour-caption">
        <span class="tour-caption-icon">{{ tourSteps[tourStep].icon }}</span>
        <span class="tour-caption-text">{{ tourSteps[tourStep].caption }}</span>
      </div>
    </Transition>

    <!-- Tour step indicator dots -->
    <div v-if="tourActive" class="tour-dots">
      <button v-for="step in visibleTourSteps" :key="step.index"
        class="tour-dot" :class="{ 'tour-dot-active': tourStep === step.index }"
        @click="goToStep(step.index)">
        <span class="tour-dot-label">{{ step.shortLabel }}</span>
        <span class="tour-dot-pip" />
        <span v-if="tourStep === step.index" class="tour-dot-progress"
          :style="{ animationDuration: `${TOUR_INTERVAL}ms` }" />
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'

const scanLine = ref(0)
const visibleRows = ref(0)
const histogramAnim = ref(false)
const showTree = ref(false)
const showNetwork = ref(false)
const showAiApps = ref(false)

// Tour state
const tourActive = ref(false)
const tourStep = ref(-1)
const tourPaused = ref(false)
const isMobile = ref(false)
const TOUR_INTERVAL = 5000
const TOUR_START_DELAY = 2400

const tourSteps = [
  { index: 0, shortLabel: 'Import', icon: '\u26A1', caption: 'Stream 30GB+ forensic timelines without loading into memory' },
  { index: 1, shortLabel: 'Search', icon: '\uD83D\uDD0D', caption: '5 search modes: text, regex, fuzzy, FTS, mixed' },
  { index: 2, shortLabel: 'Processes', icon: '\uD83C\uDF33', caption: 'Reconstruct attack chains with MITRE ATT&CK mapping', desktopOnly: true },
  { index: 3, shortLabel: 'Network', icon: '\uD83D\uDD17', caption: 'Track multi-hop lateral movement across your network', desktopOnly: true },
  { index: 4, shortLabel: 'AI Apps', icon: '\uD83E\uDD16', caption: 'Collect AI history from Grok Build, Claude, Codex, ChatGPT, Copilot, Gemini, Cursor, and more' },
]

const visibleTourSteps = computed(() => {
  if (isMobile.value) {
    return tourSteps.filter(s => !s.desktopOnly)
  }
  return tourSteps
})

function sectionOpacity(stepN, baseVisible) {
  if (!baseVisible) return 0
  if (!tourActive.value || tourStep.value < 0) return 1
  return tourStep.value === stepN ? 1 : 0.2
}

let tourIv = null

function advanceTour() {
  const visible = visibleTourSteps.value
  const currentIdx = visible.findIndex(s => s.index === tourStep.value)
  const nextIdx = (currentIdx + 1) % visible.length
  tourStep.value = visible[nextIdx].index
}

function startTourCycle() {
  if (tourIv) clearInterval(tourIv)
  tourIv = setInterval(() => {
    if (!tourPaused.value) advanceTour()
  }, TOUR_INTERVAL)
}

function goToStep(n) {
  tourStep.value = n
  startTourCycle()
}

function pauseTour() {
  tourPaused.value = true
}

function resumeTour() {
  tourPaused.value = false
}

function checkMobile() {
  isMobile.value = window.innerWidth <= 960
}

const stats = [
  { label: 'EVENTS', display: '847,293', color: '#F5F5F5' },
  { label: 'SOURCES', display: '14', color: '#F0845A' },
  { label: 'TIME SPAN', display: '72h', color: '#F5F5F5' },
  { label: 'ALERTS', display: '342', color: '#FF3B3B' },
  { label: 'BOOKMARKS', display: '28', color: '#FFB020' },
]

const histogramData = [2,5,3,8,15,28,42,38,55,72,48,35,62,45,30,22,18,12,8,5,15,25,38,52,68,45,32,20,14,8,4,2,6,12,18,25,35,28,20,15]
const maxHist = Math.max(...histogramData)

const aiTimelineEvents = [
  { time: '2025-02-14 03:11:02', source: 'AI: Cursor', event: 'USER', detail: 'paste AWS key into agent prompt', severity: 'critical' },
  { time: '2025-02-14 03:11:18', source: 'AI: Codex', event: 'TOOL', detail: 'shell: whoami /priv', severity: 'high' },
  { time: '2025-02-14 03:11:31', source: 'AI: Grok', event: 'TOOL', detail: 'run_terminal_command: systeminfo', severity: 'high' },
  { time: '2025-02-14 03:11:44', source: 'AI: Claude', event: 'ASST', detail: 'powershell lateral movement steps', severity: 'high' },
  { time: '2025-02-14 03:12:05', source: 'AI: Copilot', event: 'USER', detail: 'decrypt mimikatz output', severity: 'critical' },
  { time: '2025-02-14 03:12:22', source: 'AI: ChatGPT', event: 'USER', detail: 'ransomware recovery script', severity: 'medium' },
  { time: '2025-02-14 03:12:41', source: 'AI: Gemini', event: 'ASST', detail: 'exfil via DNS tunneling', severity: 'high' },
  { time: '2025-02-14 03:12:58', source: 'AI: Windsurf', event: 'USER', detail: 'workspace: C:\\Prod\\finance-api', severity: 'medium' },
  { time: '2025-02-14 03:13:12', source: 'AI: Continue', event: 'USER', detail: 'review .env for secrets', severity: 'critical' },
]

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
  // Source hosts (left)
  { x: 45, y: 28, type: 'host', label: 'U42-TECH.S…', color: '#4A90D9' },
  { x: 42, y: 115, type: 'host', label: 'U42-TECH', color: '#9B59B6' },
  // Center hosts
  { x: 135, y: 62, type: 'host', label: 'TEST-VM-CTI', color: '#28C840' },
  { x: 208, y: 48, type: 'host', label: 'U42-HR', color: '#28C840' },
  // IP nodes
  { x: 108, y: 16, type: 'ip', label: '10.2.10.13' },
  { x: 85, y: 40, type: 'ip', label: '.182:445' },
  { x: 160, y: 30, type: 'ip', label: '.19:49690' },
  { x: 82, y: 88, type: 'ip', label: '.10.234' },
  { x: 155, y: 88, type: 'ip', label: '.13:445' },
  { x: 188, y: 100, type: 'ip', label: '.19:49701' },
  { x: 248, y: 78, type: 'ip', label: '127.0.0.1' },
  { x: 258, y: 32, type: 'ip', label: '10.2.10.159' },
  // Suspicious outlier hosts (right)
  { x: 328, y: 22, type: 'suspicious', label: 'DESKTOP-M458NRQ' },
  { x: 328, y: 68, type: 'suspicious', label: 'DESKTOP-F7153U5' },
  { x: 328, y: 115, type: 'suspicious', label: 'WIN-DN3C3GPH…' },
]

const lateralEdges = [
  // From U42-TECH.S…
  { from: 0, to: 4, green: true, count: '1' },
  { from: 0, to: 5, green: true, count: '5' },
  { from: 0, to: 2, green: true, count: '102', w: 2 },
  { from: 0, to: 6, green: true, count: '2' },
  { from: 0, to: 11, green: false },
  // Center connections
  { from: 2, to: 8, green: true, count: '12' },
  { from: 2, to: 7, green: false, count: '1' },
  { from: 3, to: 10, green: false },
  { from: 3, to: 6, green: true, count: '10' },
  { from: 5, to: 6, green: true, count: '1' },
  // To suspicious outliers
  { from: 11, to: 12, green: false, w: 1.5 },
  { from: 10, to: 13, green: false, count: '24', w: 2 },
  { from: 13, to: 14, green: true, count: '21' },
  { from: 10, to: 14, green: false, count: '3' },
  // From U42-TECH
  { from: 1, to: 7, green: true, count: '392', w: 2 },
  { from: 1, to: 9, green: true, count: '1' },
  { from: 9, to: 8, green: false },
]

const filterTags = [
  { label: 'Search: mimikatz OR psexec', color: '#E8613A' },
  { label: 'Tag: Lateral Movement', color: '#4A90D9' },
  { label: 'Bookmarked', color: '#FFB020' },
]

const aiFilterTags = [
  { label: 'AI Apps: 9 sources merged', color: '#E8613A' },
  { label: 'Tag: Secret Hunt', color: '#FF3B3B' },
  { label: 'Workspace: finance-api', color: '#9B59B6' },
]

const displayedEvents = computed(() => tourStep.value === 4 ? aiTimelineEvents : timelineEvents)
const displayedFilterTags = computed(() => tourStep.value === 4 ? aiFilterTags : filterTags)
const displayedRowCount = computed(() => displayedEvents.value.length)

watch(tourStep, (step) => {
  visibleRows.value = step === 4 ? aiTimelineEvents.length : timelineEvents.length
})

const aiApps = [
  { label: 'Claude', abbr: 'CL', color: '#D4A574', x: 42, y: 28 },
  { label: 'Codex', abbr: 'CX', color: '#10A37F', x: 42, y: 112 },
  { label: 'Grok', abbr: 'GK', color: '#F5F5F5', x: 190, y: 16 },
  { label: 'Cursor', abbr: 'CU', color: '#6BA3E8', x: 108, y: 18 },
  { label: 'Copilot', abbr: 'CP', color: '#4A90D9', x: 108, y: 122 },
  { label: 'ChatGPT', abbr: 'GPT', color: '#74AA9C', x: 272, y: 28 },
  { label: 'Gemini', abbr: 'GM', color: '#4285F4', x: 338, y: 70 },
  { label: 'Windsurf', abbr: 'WS', color: '#00C2B2', x: 272, y: 112 },
  { label: 'Continue', abbr: 'CT', color: '#9B59B6', x: 338, y: 122 },
]

const prefersReducedMotion = typeof window !== 'undefined'
  && window.matchMedia('(prefers-reduced-motion: reduce)').matches

let scanIv = null
let timers = []

onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)

  if (prefersReducedMotion) {
    // Show everything immediately without animation
    histogramAnim.value = true
    showTree.value = true
    showNetwork.value = true
    showAiApps.value = true
    visibleRows.value = timelineEvents.length
    // Still start tour (cycles content without transitions)
    tourActive.value = true
    tourStep.value = 0
    startTourCycle()
    return
  }

  timers.push(setTimeout(() => { histogramAnim.value = true }, 300))
  timers.push(setTimeout(() => { showTree.value = true }, 600))
  timers.push(setTimeout(() => { showNetwork.value = true }, 900))
  timers.push(setTimeout(() => { showAiApps.value = true }, 1050))

  timelineEvents.forEach((_, i) => {
    timers.push(setTimeout(() => { visibleRows.value = i + 1 }, 400 + i * 120))
  })

  let scanPos = 0
  scanIv = setInterval(() => {
    scanPos = (scanPos + 0.3) % 100
    scanLine.value = scanPos
  }, 30)

  // Start tour after entrance animation completes
  timers.push(setTimeout(() => {
    tourActive.value = true
    tourStep.value = 0
    startTourCycle()
  }, TOUR_START_DELAY))
})

onUnmounted(() => {
  timers.forEach(clearTimeout)
  if (scanIv) clearInterval(scanIv)
  if (tourIv) clearInterval(tourIv)
  window.removeEventListener('resize', checkMobile)
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
  /* Isolate from VitePress global styles */
  line-height: 1.3;
  box-sizing: border-box;
  text-align: left;
}
.hero-graphic *,
.hero-graphic *::before,
.hero-graphic *::after {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
  line-height: inherit;
  font-family: inherit;
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
  padding: 16px 24px !important;
  border-bottom: 1px solid #222;
  background: #161616;
}
.title-left { display: flex; align-items: center; gap: 12px; }
.traffic-lights { display: flex; gap: 6px; }
.dot { width: 12px; height: 12px; border-radius: 50%; }
.dot-red { background: #FF5F57; }
.dot-yellow { background: #FFBD2E; }
.dot-green { background: #28C840; }
.title-text { color: #999; font-size: 12px; margin-left: 8px !important; line-height: 1; }
.title-right { display: flex; align-items: center; gap: 16px; }
.brand-name { color: #E8613A; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; line-height: 1; }
.brand-version { color: #777; font-size: 11px; line-height: 1; }

/* Stats bar */
.stats-bar {
  display: flex;
  gap: 0;
  border-bottom: 1px solid #222;
  background: #161616;
}
.stat-item {
  flex: 1;
  padding: 10px 20px !important;
  border-right: 1px solid #222;
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.stat-last { border-right: none; }
.stat-label { font-size: 9px; color: #777; letter-spacing: 1.5px; line-height: 1; }
.stat-value { font-size: 16px; font-weight: 600; line-height: 1.2; }

/* Histogram */
.histogram-section {
  padding: 12px 24px 0 !important;
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
  align-items: center;
  padding: 4px 0 8px !important;
}
.hist-label { font-size: 9px; color: #777; line-height: 1; }
.hist-alert { font-size: 9px; color: #E8613A; font-weight: 600; line-height: 1; }

/* Main content */
.main-content {
  display: flex;
  min-height: 420px;
}

/* Timeline table */
.timeline-table {
  flex: 1;
  border-right: 1px solid #222;
  overflow: hidden;
}
.table-header {
  display: grid;
  grid-template-columns: 100px 100px 50px 1fr;
  padding: 8px 16px !important;
  border-bottom: 1px solid #222;
  background: #1C1C1C;
  position: sticky;
  top: 0;
  align-items: center;
}
.header-cell {
  font-size: 9px;
  color: #777;
  letter-spacing: 1.2px;
  font-weight: 600;
  line-height: 1;
}
.table-row {
  display: grid;
  grid-template-columns: 100px 100px 50px 1fr;
  padding: 6px 16px !important;
  border-bottom: 1px solid #1A1A1A;
  border-left: 2px solid transparent;
  transition: all 0.3s ease;
  align-items: center;
}
.row-critical {
  background: #E8613A08;
  border-left-color: #E8613A;
}
.cell-time { font-size: 11px; color: #CCC; font-variant-numeric: tabular-nums; line-height: 1.2; white-space: nowrap; }
.cell-source { font-size: 10px; color: #888; line-height: 1.2; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.source-sysmon { color: #6BA3E8; }
.source-hayabusa { color: #E8613A; }
.source-ai { color: #F0845A; }
.row-ai { background: #E8613A06; }
.cell-id { font-size: 10px; color: #888; line-height: 1.2; }
.cell-detail { display: flex; align-items: center; }
.cell-detail span:last-child { font-size: 11px; color: #CCC; line-height: 1.2; }
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
  padding: 16px !important;
  transition: all 0.5s ease;
}
.process-tree { border-bottom: 1px solid #222; flex: 1.1; }
.ai-apps-panel { border-bottom: 1px solid #222; flex: 0 0 148px; }
.lateral-panel { transition-delay: 0.2s; flex: 1; }

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}
.panel-title { font-size: 10px; color: #777; letter-spacing: 1.2px; font-weight: 600; line-height: 1; }
.panel-badge { font-size: 9px; padding: 2px 8px !important; border-radius: 3px; line-height: 1; }
.badge-orange { color: #E8613A; background: #E8613A15; }
.badge-red { color: #FF3B3B; background: #FF3B3B15; }

/* Process tree */
.tree-node {
  display: flex;
  align-items: center;
  margin-bottom: 3px;
  transition: opacity 0.3s ease;
}
.tree-branch { color: #555; font-size: 11px; margin-right: 6px !important; white-space: pre; line-height: 1; }
.tree-name { font-size: 11px; color: #888; line-height: 1; }
.tree-suspicious { color: #E8613A; font-weight: 600; }
.tree-danger { color: #FF3B3B !important; }
.tree-pid { font-size: 9px; color: #777; margin-left: 8px !important; line-height: 1; }
.tree-lolbin {
  font-size: 8px;
  color: #FF3B3B;
  margin-left: 8px !important;
  background: #FF3B3B18;
  padding: 1px 6px !important;
  border-radius: 2px;
  font-weight: 700;
  line-height: 1;
}

/* Network + AI Apps graphs */
.network-svg,
.ai-apps-svg { width: 100%; }
.status-ai { color: #F0845A; }

/* Filter tags */
.filter-tags {
  display: flex;
  gap: 6px;
  padding: 8px 24px !important;
  background: #161616;
  border-bottom: 1px solid #222;
}
.filter-tag {
  font-size: 9px;
  border: 1px solid;
  padding: 3px 10px !important;
  border-radius: 4px;
  opacity: 0.9;
  line-height: 1;
  white-space: nowrap;
}

/* Status bar */
.status-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 24px !important;
  border-top: 1px solid #222;
  background: #161616;
}
.status-left, .status-right { display: flex; align-items: center; gap: 16px; }
.status-right { gap: 12px; }
.status-item { font-size: 9px; color: #777; line-height: 1; white-space: nowrap; }
.status-green { color: #28C840; margin-right: 4px !important; }
.status-accent { font-size: 9px; color: #E8613A; line-height: 1; white-space: nowrap; }

/* ===== Tour: Section Dimming ===== */
.hero-graphic.tour-active .stats-bar,
.hero-graphic.tour-active .histogram-section,
.hero-graphic.tour-active .filter-tags,
.hero-graphic.tour-active .timeline-table,
.hero-graphic.tour-active .ai-apps-panel {
  opacity: 0.2;
  transition: opacity 0.5s ease;
}
.hero-graphic.tour-active .tour-focus {
  opacity: 1 !important;
  box-shadow: inset 0 0 0 1px rgba(232, 97, 58, 0.25);
}
.hero-graphic.tour-active .title-bar { opacity: 0.6; transition: opacity 0.5s ease; }
.hero-graphic.tour-active .status-bar { opacity: 0.4; transition: opacity 0.5s ease; }

/* ===== Tour: Caption ===== */
.tour-caption {
  position: absolute;
  bottom: 44px;
  left: 50%;
  transform: translateX(-50%);
  background: rgba(13, 13, 13, 0.92);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid rgba(232, 97, 58, 0.3);
  border-radius: 8px;
  padding: 10px 18px !important;
  display: flex;
  align-items: center;
  gap: 10px;
  z-index: 25;
  white-space: nowrap;
  pointer-events: none;
}
.tour-caption-icon {
  font-size: 16px;
  line-height: 1;
  flex-shrink: 0;
}
.tour-caption-text {
  font-size: 11px;
  color: #CCC;
  line-height: 1.3;
}

/* Caption transition */
.tour-caption-enter-active {
  transition: opacity 0.35s cubic-bezier(0.34, 1.56, 0.64, 1), transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.tour-caption-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.tour-caption-enter-from {
  opacity: 0;
  transform: translateX(-50%) translateY(8px);
}
.tour-caption-leave-to {
  opacity: 0;
  transform: translateX(-50%) translateY(-6px);
}

/* ===== Tour: Step Dots ===== */
.tour-dots {
  position: absolute;
  bottom: 10px;
  left: 50%;
  transform: translateX(-50%);
  display: flex;
  gap: 20px;
  z-index: 25;
}
.tour-dot {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px 2px !important;
  position: relative;
  font-family: inherit;
}
.tour-dot-label {
  font-size: 8px;
  color: #555;
  letter-spacing: 0.8px;
  text-transform: uppercase;
  line-height: 1;
  transition: color 0.3s ease;
}
.tour-dot-active .tour-dot-label {
  color: #E8613A;
}
.tour-dot-pip {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #555;
  transition: background 0.3s ease, box-shadow 0.3s ease;
}
.tour-dot-active .tour-dot-pip {
  background: #E8613A;
  box-shadow: 0 0 8px rgba(232, 97, 58, 0.5);
}
.tour-dot-progress {
  position: absolute;
  bottom: 0;
  left: 0;
  height: 2px;
  background: #E8613A;
  border-radius: 1px;
  width: 0%;
  animation: tour-fill linear forwards;
}
@keyframes tour-fill {
  from { width: 0%; }
  to { width: 100%; }
}

/* ===== Light mode adjustments ===== */
/* Give the dark app mockup a subtle lift off light backgrounds */
:root:not(.dark) .hero-graphic {
  box-shadow: 0 4px 24px rgba(0, 0, 0, 0.15), 0 1px 4px rgba(0, 0, 0, 0.1);
}
/* Tour caption: keep dark glass style but boost contrast on light pages */
:root:not(.dark) .tour-caption {
  background: rgba(13, 13, 13, 0.95);
  border-color: rgba(232, 97, 58, 0.4);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);
}
/* Tour dots: darken inactive pips so they're visible on light pages */
:root:not(.dark) .tour-dot-label {
  color: #999;
}
:root:not(.dark) .tour-dot-pip {
  background: #999;
}
:root:not(.dark) .tour-dot-active .tour-dot-label {
  color: #E8613A;
}
:root:not(.dark) .tour-dot-active .tour-dot-pip {
  background: #E8613A;
}

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
  .tour-caption { white-space: normal; max-width: 90%; }
}

@media (max-width: 640px) {
  .title-text { display: none; }
  .stats-bar { display: none; }
  .histogram-section { display: none; }
  .table-header, .table-row {
    grid-template-columns: 70px 1fr;
  }
  .cell-source, .cell-id { display: none; }
  .tour-dot-label { display: none; }
  .tour-caption { font-size: 10px; padding: 8px 14px !important; }
  .tour-caption-text { font-size: 10px; }
}

/* Accessibility: disable animations for users who prefer reduced motion */
@media (prefers-reduced-motion: reduce) {
  .scan-line { display: none; }
  .hist-bar { transition: none !important; }
  .table-row { transition: none !important; }
  .panel { transition: none !important; }
  .tree-node { transition: none !important; }
  .hist-alert-dot { box-shadow: none; }
  /* Tour: disable animated transitions but keep content cycling */
  .hero-graphic.tour-active .stats-bar,
  .hero-graphic.tour-active .histogram-section,
  .hero-graphic.tour-active .filter-tags,
  .hero-graphic.tour-active .timeline-table,
  .hero-graphic.tour-active .tour-focus,
  .hero-graphic.tour-active .title-bar,
  .hero-graphic.tour-active .status-bar {
    transition: none !important;
  }
  .tour-caption-enter-active,
  .tour-caption-leave-active {
    transition: none !important;
  }
  .tour-dot-pip,
  .tour-dot-label {
    transition: none !important;
  }
  .tour-dot-progress {
    animation: none;
    width: 100%;
  }
}
</style>
