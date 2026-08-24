export function updateModal(type, updater) {
  return (prev) => {
    if (!prev || prev.type !== type) return prev;
    const patch = typeof updater === "function" ? updater(prev) : updater;
    if (!patch) return prev;
    return patch.type ? patch : { ...prev, ...patch };
  };
}

export function openSimpleModal(type, extra = {}) {
  return { type, ...extra };
}

/** Collect AI Artifacts — discover local AI roots, then extract with live progress. */
export function openAiHistoryScopeModal({
  tool,
  target,
  label,
  includeSubagents = false,
  mode = "extract",
  scopeQueue = [],
} = {}) {
  return {
    type: "aiHistoryScope",
    tool,
    target,
    label: label || "AI history",
    includeSubagents,
    mode,
    scopeQueue,
    busy: false,
  };
}

export function openAiWorkspaceCorrelateModal({ path, targets }) {
  return { type: "aiWorkspaceCorrelate", path, targets: targets || [] };
}

/** AI Secret Hunt (AI Secret & Leak Scan) — credential/key/PII detector over an AI history tab. */
export function openAiSecretsModal({ tabId, tabName, ...extra } = {}) {
  return {
    type: "aiSecrets",
    phase: "input",
    autoStart: true, // launch straight into a Quick scan (fewer clicks); Deep is one toggle in results
    tabId: tabId || null,
    tabName: tabName || "",
    scanMode: "quick",
    showFilters: false,
    data: null,
    error: null,
    reveal: null,
    fSev: "all",
    fCat: "all",
    fConf: "all",
    fTool: "all",
    fRole: "all",
    fSession: "all",
    fWorkspace: "all",
    fSource: "all",
    fTag: "all",
    q: "",
    evidenceQ: "",
    viewMode: "incidents",
    expandedGroup: null,
    secretTags: {},
    tagDraft: "",
    tagMenuGroup: null,
    showColumnTools: false,
    incidentColumnWidths: {},
    timelineColumnWidths: {},
    evidenceColumnWidths: {},
    evidenceColumnVisibility: { context: true, secret: true, source: true, actions: true },
    ...extra,
  };
}

/** Single-tool extract with verbose progress (Tools → AI Artifacts → AI Apps → …). */
export function openAiHistoryExtractModal({
  tool,
  target,
  extractTarget,
  label,
  includeSubagents = false,
} = {}) {
  const path = extractTarget || target;
  return {
    type: "aiHistoryExtract",
    phase: "extracting",
    extractRunId: `${tool}:${path}:${Date.now()}`,
    tool,
    target,
    extractTarget: path,
    label: label || "AI history",
    includeSubagents: !!includeSubagents,
    scanning: true,
    error: null,
    sourceStatus: path ? { [sourceKey({ tool, path, label })]: "active" } : {},
    progress: {
      percent: 2,
      phase: "extracting",
      statusDetail: "Starting extraction worker…",
      rowsSoFar: 0,
      log: [
        `Tool: ${label || tool}`,
        path ? `Path: ${path}` : "",
        includeSubagents ? "Scope: main + subagent sessions" : "Scope: main sessions only",
      ].filter(Boolean),
    },
  };
}

function sourceKey(root) {
  return `${root.tool}:${root.path}`;
}

export function openAiHistoryProfileScanModal(extra = {}) {
  return {
    type: "aiHistoryProfileScan",
    phase: "choose-target",
    scanMode: null,
    scanRoot: null,
    roots: [],
    candidateCount: 0,
    hasScopeChoice: false,
    includeSubagents: false,
    scanning: false,
    error: null,
    progress: {
      percent: 0,
      statusDetail: "Choose where to scan for AI assistant artifacts",
      phase: "choose-target",
      rowsSoFar: 0,
      log: [],
    },
    sourceStatus: {},
    ...extra,
  };
}

export function openStackingModal(colName, extra = {}) {
  return { type: "stacking", colName, data: null, loading: true, filterText: "", sortBy: "count", ...extra };
}

export function openColumnStatsModal(colName, extra = {}) {
  return { type: "columnStats", colName, data: null, loading: true, ...extra };
}

export function openGapAnalysisModal(colName, extra = {}) {
  return { type: "gapAnalysis", phase: "config", colName, gapThreshold: 60, data: null, loading: false, ...extra };
}

export function openLogSourceCoverageModal({ sourceCol, tsCol, sourceCols = [], ...extra } = {}) {
  return { type: "logSourceCoverage", phase: "config", sourceCol, tsCol, sourceCols, data: null, loading: false, ...extra };
}

export function openBurstAnalysisModal(colName, extra = {}) {
  return { type: "burstAnalysis", phase: "config", colName, windowMinutes: 5, thresholdMultiplier: 5, data: null, loading: false, ...extra };
}

export function openProcessTreeModal(columns = {}, extra = {}) {
  return {
    type: "processTree",
    phase: "config",
    columns,
    eventIdValue: "1,4688",
    ptTelemetry: { sysmon: true, security: true },
    ptPreview: null,
    ptPreviewLoading: true,
    _ptNeedsPreview: true,
    _ptPreviewSeq: 0,
    ptIntent: "balanced",
    ptDisabledRules: new Set(),
    ptCustomRules: [],
    ptShowMapping: false,
    ptShowAdvanced: false,
    showPtRules: false,
    ptSourceEvent: null,
    ptSourceEventLoading: false,
    ptRelatedEvents: null,
    ptRelatedEventsLoading: false,
    ptRelatedEventsError: null,
    ptRelatedEventsKey: null,
    ptRelatedEventsReqKey: null,
    maxRows: 200000,
    ptViewMode: null,
    data: null,
    loading: false,
    expandedNodes: {},
    searchText: "",
    error: null,
    ...extra,
  };
}

export function openTriageCollectionModal(extra = {}) {
  return {
    type: "triageCollection",
    phase: "picking",        // picking -> scanning -> manifest -> importing
    dir: "",
    manifest: null,
    error: null,
    selected: null,          // Set<path>; null until the manifest seeds the defaults
    includeSigmaLane: false,
    analyzeAfter: true,
    showAllEvtx: false,
    batch: null,
    ...extra,
  };
}

export function openLateralMovementModal(columns = {}, extra = {}) {
  return {
    type: "lateralMovement",
    phase: "config",
    columns,
    excludeLocal: true,
    excludeService: true,
    lmDisabledRules: new Set(),
    lmCustomRules: [],
    showLmRules: false,
    lmShowMapping: false,
    lmIntent: "balanced",
    lmPreview: null,
    lmPreviewLoading: true,
    _lmNeedsPreview: true,
    chainsawSyntheticTarget: "",
    data: null,
    loading: false,
    error: null,
    selectedNode: null,
    selectedEdge: null,
    viewTab: "graph",
    lmGraphMode: "machines",
    findingsView: "alerts",
    findingsSortBy: "triage",
    findingsGroupBy: "default",
    positions: null,
    ...extra,
  };
}

export function openPersistenceModal(extra = {}) {
  return {
    type: "persistence",
    phase: "config",
    mode: "auto",
    columns: {},
    data: null,
    loading: false,
    error: null,
    viewTab: "grouped",
    searchText: "",
    severityFilter: "all",
    categoryFilter: "all",
    disabledRules: new Set(),
    customRules: [],
    showRules: false,
    addingRule: false,
    newRule: {},
    modalW: 1100,
    paShowMapping: false,
    paIntent: "balanced",
    paPreview: null,
    paPreviewLoading: true,
    _paNeedsPreview: true,
    paFindingsView: "alerts",
    paSortBy: "triage",
    paGroupBy: "incident",
    expandedIncident: null,
    tlMode: "triage",
    tlCatFilter: null,
    tblMode: "triage",
    ...extra,
  };
}

export function openSigmaModal(extra = {}) {
  return {
    type: "sigma",
    phase: "config",
    scanMode: "evtx-dir",
    // Low-noise high-confidence default profile: critical/high severity, stable
    // status only — broaden any time via the collapsible Detection profile section.
    // Seeding `levels` also shields this default from the detection-settings bootstrap,
    // which only fills levels when none is set (see applyDetectionSettingsToModal).
    levels: { critical: true, high: true, medium: false, low: false, informational: false },
    statuses: { stable: true, test: false, experimental: false },
    hayabusaMinSeverity: "high",
    data: null,
    loading: false,
    error: null,
    ...extra,
  };
}

export function openRdpBitmapCacheModal(extra = {}) {
  return {
    type: "rdpBitmapCache",
    phase: "input",
    paths: [],
    preflight: null,
    toolStatus: null,
    toolPath: null,
    options: {
      includeOld: false,
      collage: true,
      width: 64,
      verbose: false,
    },
    progress: null,
    result: null,
    packageResult: null,
    packageExporting: false,
    historyRecords: [],
    historyLoading: false,
    error: null,
    selecting: false,
    extracting: false,
    jobId: null,
    ...extra,
  };
}

export function openRansomwareModal(extra = {}) {
  return {
    type: "ransomware",
    phase: "input",
    encryptedExt: "",
    ransomNotePattern: "",
    noteMatchMode: "exact",
    usnTabId: "__none__",
    data: null,
    loading: false,
    ...extra,
  };
}

export function openTimestompingModal(extra = {}) {
  return { type: "timestomping", data: null, loading: true, ...extra };
}

export function openHeatmapModal(extra = {}) {
  return { type: "heatmap", data: null, loading: true, hmProgress: null, ...extra };
}

export function openAdsModal(extra = {}) {
  return { type: "ads", data: null, loading: true, ...extra };
}

export function openUsnAnalysisModal(extra = {}) {
  const analyses = {
    renames: true,
    deletions: true,
    creations: true,
    exfil: true,
    execution: true,
    persistence: true,
    suspiciousPaths: true,
    securityChanges: true,
    dataOverwrite: true,
    streamChanges: true,
    closePatterns: true,
  };
  return {
    type: "usnAnalysis",
    phase: "input",
    startTime: "",
    endTime: "",
    pathFilter: "",
    analyses,
    data: null,
    loading: false,
    error: null,
    mftTabId: null,
    usnExpanded: { ...analyses },
    usnIncidentsExpanded: false,
    usnTimelineExpanded: false,
    usnLikelyFindingsExpanded: false,
    usnShowSuppressed: {},
    usnSelected: {},
    usnSort: {},
    usnColWidths: {},
    usnCheckboxFilters: {},
    usnScopeDir: "",
    usnSiblingDir: "",
    usnFocusEntry: "",
    usnTimelineIncident: "",
    usnTimelineLimit: 120,
    ...extra,
  };
}

export function openIocLoadModal(extra = {}) {
  return { type: "ioc", phase: "load", iocText: "", iocName: "", parsedIocs: [], fileName: null, ...extra };
}

export function openIocResultsModal(extra = {}) {
  return { type: "ioc", phase: "results", iocText: "", iocName: "", parsedIocs: [], fileName: null, ...extra };
}

export function openBulkActionsModal(extra = {}) {
  return { type: "bulkActions", tagName: "", tagColor: "#E85D2A", result: null, ...extra };
}

export function openProximityModal({ pivotRow, pivotCol, ...extra } = {}) {
  return { type: "proximity", pivotRow, pivotCol, ...extra };
}

export function openFindDuplicatesModal(selCol, extra = {}) {
  return { type: "findDuplicates", selCol, result: null, loading: false, ...extra };
}

export function openMergeTabsModal(tabOptions, extra = {}) {
  return { type: "mergeTabs", tabOptions, ...extra };
}

export function openDiffTabsModal(tabOptions, extra = {}) {
  const tabs = tabOptions || [];
  const { compareTabId: extraCompare, baselineTabId: extraBaseline, ...rest } = extra;
  const compareId = extraCompare || tabs[1]?.tabId || tabs[0]?.tabId || "";
  const baselineId = extraBaseline
    || tabs.find((t) => t.tabId !== compareId)?.tabId
    || "";
  return {
    type: "diffTabs",
    tabOptions: tabs,
    baselineTabId: baselineId,
    compareTabId: compareId,
    matchMode: "auto",
    matchKeys: null,
    includeUnchanged: false,
    keyQuery: "",
    ...rest,
  };
}

export function openDiffExplorerModal(extra = {}) {
  return { type: "diffExplorer", tabId: extra.tabId || null, ...extra };
}
