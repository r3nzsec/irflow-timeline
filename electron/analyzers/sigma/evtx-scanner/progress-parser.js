const path = require("path");

function stripAnsi(text) {
  return String(text || "").replace(/\x1b\[[0-9;]*m/g, "");
}

/**
 * Turn Hayabusa's own reported rule counts into a human explanation for the
 * common "scan returned no hits and the analyst has no idea why" case.
 *
 * Guarded on matchCount===0 so it never fires when a scan actually produced
 * hits (which proves rules loaded, even if the stderr count regex missed).
 *
 * @param {object} p
 * @param {number} p.rulesLoaded        rules Hayabusa reported loading (0 if unknown/none)
 * @param {number} p.rulesAfterFilter   rules remaining after the channel filter
 * @param {string|null} p.rulesPath     custom rules path, if the analyst set one
 * @param {number} p.matchCount         rules that matched in this scan
 * @returns {{ warnings: string[] }}
 */
function ruleLoadDiagnostics({ rulesLoaded, rulesAfterFilter, rulesPath, matchCount } = {}) {
  const warnings = [];
  const loaded = Number(rulesLoaded) || 0;
  const afterFilter = Number(rulesAfterFilter) || 0;
  const matches = Number(matchCount) || 0;

  if (matches > 0) return { warnings }; // hits prove rules loaded — nothing to explain

  if (loaded === 0) {
    warnings.push(rulesPath
      ? `Hayabusa loaded 0 detection rules from the custom rules path "${rulesPath}" — that is almost certainly why this scan returned no hits. Confirm the path points at a Hayabusa/Sigma rules directory of .yml files, or clear it to use the bundled rules.`
      : "Hayabusa reported 0 detection rules loaded — this scan returned no hits because no rules were active. Run Update Rules, then rescan.");
  } else if (afterFilter === 0) {
    warnings.push(`Hayabusa loaded ${loaded.toLocaleString()} rules but none remained after the channel filter — none apply to the channels in these EVTX files, so no hits were possible.`);
  }
  return { warnings };
}

function cleanOutputLines(text) {
  return stripAnsi(text)
    .replace(/\r/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function formatDuration(ms) {
  if (!isFinite(ms) || ms < 0) return "";
  const secs = Math.floor(ms / 1000);
  const mins = Math.floor(secs / 60);
  const hours = Math.floor(mins / 60);
  if (hours > 0) return `${hours}h ${mins % 60}m`;
  if (mins > 0) return `${mins}m ${secs % 60}s`;
  return `${secs}s`;
}

function lastMatch(text, pattern) {
  let last = null;
  const re = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
  for (const match of text.matchAll(re)) last = match;
  return last;
}

function createHayabusaProgressParser({ onProgress, evtxFiles, totalBytes, startTime = Date.now() }) {
  let stderrBuf = "";
  const hbInfo = {
    stage: "starting",
    totalRules: 0,
    hayabusaRules: 0,
    sigmaRules: 0,
    filesAfterFilter: 0,
    rulesAfterFilter: 0,
    totalEvents: 0,
    eventsWithHits: 0,
    totalDetections: 0,
    uniqueDetections: 0,
    dataReduction: "",
  };
  const scanProgress = {
    pct: 0,
    rate: "",
    etaMs: null,
    currentFile: "",
  };

  const emit = (fallbackText = "Hayabusa running...") => {
    const elapsed = Date.now() - startTime;
    const timeStr = formatDuration(elapsed);
    const etaStr = scanProgress.etaMs != null ? formatDuration(scanProgress.etaMs) : "";

    let text;
    if (hbInfo.stage === "loading-rules") {
      text = hbInfo.totalRules > 0
        ? `Loaded ${hbInfo.totalRules.toLocaleString()} detection rules (${hbInfo.sigmaRules.toLocaleString()} Sigma + ${hbInfo.hayabusaRules} Hayabusa)`
        : "Loading detection rules...";
    } else if (hbInfo.stage === "channel-filter") {
      text = hbInfo.filesAfterFilter > 0
        ? `Channel filter: ${hbInfo.filesAfterFilter}/${evtxFiles.length} EVTX files relevant, ${hbInfo.rulesAfterFilter.toLocaleString()} rules active`
        : "Creating channel filter...";
    } else if (hbInfo.stage === "scanning") {
      const fileBit = scanProgress.currentFile ? ` - ${scanProgress.currentFile}` : "";
      const pctBit = scanProgress.pct > 0 ? ` (${scanProgress.pct.toFixed(1)}%)` : "";
      const etaBit = etaStr ? ` - ETA ${etaStr}` : "";
      const rateBit = scanProgress.rate ? ` - ${scanProgress.rate}` : "";
      text = `Scanning ${hbInfo.filesAfterFilter || evtxFiles.length} EVTX files${pctBit}${fileBit}${etaBit}${rateBit}`;
    } else if (hbInfo.stage === "results") {
      text = `Scan complete - ${hbInfo.eventsWithHits.toLocaleString()} hits from ${hbInfo.totalEvents.toLocaleString()} events (${hbInfo.dataReduction || "processing"})`;
    } else {
      text = fallbackText;
    }

    onProgress?.({
      phase: hbInfo.stage === "results" ? "hayabusa-done" : "hayabusa-running",
      text,
      timeStr,
      etaStr,
      elapsed,
      scanPct: scanProgress.pct,
      scanEtaMs: scanProgress.etaMs,
      currentFile: scanProgress.currentFile,
      fileCount: evtxFiles.length,
      totalBytes,
      ...hbInfo,
    });
  };

  const handleChunk = (chunk) => {
    stderrBuf += chunk.toString();
    if (stderrBuf.length > 262144) stderrBuf = stderrBuf.slice(-262144);
    const clean = stripAnsi(stderrBuf);

    if (clean.includes("Loading detection rules")) hbInfo.stage = "loading-rules";
    if (clean.includes("Creating the channel filter")) hbInfo.stage = "channel-filter";
    if (clean.includes("Scanning in progress")) hbInfo.stage = "scanning";
    if (clean.includes("Results Summary")) hbInfo.stage = "results";

    let match;
    if ((match = clean.match(/Total detection rules:\s*([\d,]+)/))) hbInfo.totalRules = parseInt(match[1].replace(/,/g, ""), 10);
    if ((match = clean.match(/Hayabusa rules:\s*(\d+)/))) hbInfo.hayabusaRules = parseInt(match[1], 10);
    if ((match = clean.match(/Sigma rules:\s*([\d,]+)/))) hbInfo.sigmaRules = parseInt(match[1].replace(/,/g, ""), 10);
    if ((match = clean.match(/Evtx files loaded after channel filter:\s*(\d+)/))) hbInfo.filesAfterFilter = parseInt(match[1], 10);
    if ((match = clean.match(/Detection rules enabled after channel filter:\s*([\d,]+)/))) hbInfo.rulesAfterFilter = parseInt(match[1].replace(/,/g, ""), 10);
    if ((match = clean.match(/Events with hits.*?:\s*([\d,]+)\s*\/\s*([\d,]+)/))) {
      hbInfo.eventsWithHits = parseInt(match[1].replace(/,/g, ""), 10);
      hbInfo.totalEvents = parseInt(match[2].replace(/,/g, ""), 10);
    }
    if ((match = clean.match(/Total \| Unique detections:\s*([\d,]+)\s*\|\s*([\d,]+)/))) {
      hbInfo.totalDetections = parseInt(match[1].replace(/,/g, ""), 10);
      hbInfo.uniqueDetections = parseInt(match[2].replace(/,/g, ""), 10);
    }
    if ((match = clean.match(/Data reduction:\s*([\d,]+)\s*events\s*\(([\d.]+%)\)/))) {
      hbInfo.dataReduction = match[2];
    }

    if (hbInfo.stage === "scanning") {
      const pctMatch = lastMatch(clean, /(\d+(?:\.\d+)?)\s*%/g);
      if (pctMatch) {
        const pct = parseFloat(pctMatch[1]);
        if (isFinite(pct) && pct >= 0 && pct <= 100) scanProgress.pct = pct;
      }
      const rateMatch = lastMatch(clean, /(\d[\d.,]*\s*[KMGT]?B\/s)/g);
      if (rateMatch) scanProgress.rate = rateMatch[1];
      const etaMatch = lastMatch(clean, /ETA:?\s*(\d+(?:\.\d+)?[smh])/g);
      if (etaMatch) {
        const value = etaMatch[1];
        const amount = parseFloat(value);
        const unit = value.slice(-1);
        const multiplier = unit === "h" ? 3600000 : unit === "m" ? 60000 : 1000;
        scanProgress.etaMs = amount * multiplier;
      } else if (scanProgress.pct > 1) {
        const elapsedNow = Date.now() - startTime;
        scanProgress.etaMs = Math.round(elapsedNow * (100 - scanProgress.pct) / scanProgress.pct);
      }
      const fileMatch = lastMatch(clean, /([A-Za-z0-9_\-.\\\/]+\.evtx)/g);
      if (fileMatch) scanProgress.currentFile = path.basename(fileMatch[1]);
    } else {
      scanProgress.pct = hbInfo.stage === "loading-rules" ? 5
        : hbInfo.stage === "channel-filter" ? 10
          : hbInfo.stage === "results" ? 100 : 0;
      scanProgress.etaMs = null;
    }

    emit("Starting Hayabusa...");
  };

  const startTicker = (onError) => setInterval(() => {
    try {
      emit("Hayabusa running...");
    } catch (err) {
      onError?.(err);
    }
  }, 1000);

  return {
    handleChunk,
    startTicker,
    getStderr: () => stderrBuf,
    getInfo: () => ({ ...hbInfo, ...scanProgress }),
  };
}

module.exports = {
  stripAnsi,
  cleanOutputLines,
  formatDuration,
  createHayabusaProgressParser,
  ruleLoadDiagnostics,
};
