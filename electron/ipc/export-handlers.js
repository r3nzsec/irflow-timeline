const path = require("path");
const fs = require("fs");
const fsp = require("fs/promises");
const os = require("os");
const crypto = require("crypto");
const { dialog, BrowserWindow } = require("electron");
const { openDialogOptions } = require("../utils/open-dialog");
const { dbg } = require("../logger");
const {
  sanitizeExportBaseName,
  enrichSourceManifest,
  buildPackageManifest,
  buildReadmeText,
  buildSourcesOnlyManifest,
  buildSourcesOnlyReadmeText,
} = require("../parsers/ai-history/export-package");
const { findMatchesInText, COMPILED_RULES } = require("../analyzers/ai-history");
const { redactValue } = require("../analyzers/ai-history/validators");

const MAX_AI_SECRET_EXPORT_BYTES = 128 * 1024 * 1024;

/** Defense-in-depth boundary for AI Secret exports, independent of renderer reveal state. */
function redactAiSecretExportText(input) {
  let text = String(input ?? "");
  const candidates = findMatchesInText(text, "", COMPILED_RULES)
    .map((hit) => ({ start: hit.index, end: hit.index + hit.value.length, replacement: redactValue(hit.value) }))
    .filter((span) => span.start >= 0 && span.end > span.start && span.end <= text.length)
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const selected = [];
  for (const span of candidates) {
    const previous = selected[selected.length - 1];
    if (previous && span.start < previous.end) continue;
    selected.push(span);
  }
  for (let i = selected.length - 1; i >= 0; i--) {
    const span = selected[i];
    text = `${text.slice(0, span.start)}${span.replacement}${text.slice(span.end)}`;
  }
  return text;
}

function buildAiSecretPrintDocument(html) {
  const csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; font-src data:; base-uri \'none\'; form-action \'none\'; frame-src \'none\'">';
  const redacted = redactAiSecretExportText(html);
  if (/<head(?:\s[^>]*)?>/i.test(redacted)) {
    return redacted.replace(/<head(?:\s[^>]*)?>/i, (head) => `${head}${csp}`);
  }
  return `<!DOCTYPE html><html><head>${csp}</head><body>${redacted}</body></html>`;
}

function hardenAiSecretPdfWindow(win, expectedUrl) {
  const contents = win.webContents;
  contents.setWindowOpenHandler?.(() => ({ action: "deny" }));
  contents.on?.("will-attach-webview", (event) => event.preventDefault());
  contents.on?.("will-redirect", (event) => event.preventDefault());
  contents.on?.("will-navigate", (event, url) => {
    if (url !== expectedUrl) event.preventDefault();
  });
  contents.session?.webRequest?.onBeforeRequest?.(
    { urls: ["http://*/*", "https://*/*", "file://*/*", "ftp://*/*", "ws://*/*", "wss://*/*"] },
    (_details, callback) => callback({ cancel: true }),
  );
}

async function writeDelimitedExportToPath(exportData, filePath, safeSend) {
  const ext = path.extname(filePath).toLowerCase();
  const delimiter = ext === ".tsv" ? "\t" : ",";
  const writeStream = fs.createWriteStream(filePath, { encoding: "utf-8" });
  writeStream.write(exportData.headers.join(delimiter) + "\n");

  let count = 0;
  let aborted = false;
  let abortError = null;
  try {
    for (const rawRow of exportData.iterator) {
      const values = exportData.safeCols.map((sc) => {
        const val = rawRow[sc] ?? "";
        if (delimiter === "\t") {
          return val.includes("\t") || val.includes("\n") ? val.replace(/\t/g, " ").replace(/\n/g, " ") : val;
        }
        return val.includes(",") || val.includes('"') || val.includes("\n")
          ? `"${val.replace(/"/g, '""')}"`
          : val;
      });
      const ok = writeStream.write(values.join(delimiter) + "\n");
      if (!ok) await new Promise((r) => writeStream.once("drain", r));
      count += 1;
      if (count % 100000 === 0) safeSend?.("export-progress", { count });
    }
  } catch (e) {
    // Tab closed mid-export, DB read error, or disk error: the CSV is now truncated. Surface this
    // instead of silently returning the partial count as if the export completed — a manifest that
    // claims a complete forensic export over a truncated CSV is a chain-of-custody integrity loss.
    aborted = true;
    abortError = e.message;
    dbg("EXPORT", `delimited export interrupted after ${count} rows`, { error: e.message });
  }

  await new Promise((resolve, reject) => {
    writeStream.on("error", reject);
    writeStream.on("finish", resolve);
    writeStream.end();
  });
  return { count, aborted, error: abortError };
}

// ── HTML Report Builder ──────────────────────────────────────────
function buildReportHtml(data, fileName, tagColors = {}, vtEnrichment = null) {
  const esc = (s) => String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  // Tag colors are interpolated raw into style="" attributes below. tagColors arrives over
  // IPC and can be populated from a restored .tle session file (a semi-untrusted artifact a
  // colleague may share), so restrict each value to a strict hex color — the only form the
  // app's color pickers and theme constants ever produce — to prevent attribute breakout /
  // HTML injection (self-XSS) in the generated standalone report.
  const safeColor = (c) => (/^#[0-9a-fA-F]{3,8}$/.test(String(c || "")) ? String(c) : "#8b949e");
  const now = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  // Filter out columns that are entirely empty across bookmarked+tagged rows
  const allReportRows = [...data.bookmarkedRows];
  for (const rows of Object.values(data.taggedGroups)) {
    for (const r of rows) allReportRows.push(r);
  }
  const usedHeaders = data.headers.filter((h) =>
    allReportRows.some((r) => r[h] && String(r[h]).trim())
  );

  const renderTable = (rows, headers) => {
    if (rows.length === 0) return '<p style="color:#9a9590;font-style:italic;">No events</p>';
    let html = '<div class="table-wrap"><table><thead><tr>';
    for (const h of headers) html += `<th>${esc(h)}</th>`;
    html += "</tr></thead><tbody>";
    for (const row of rows) {
      html += "<tr>";
      for (const h of headers) html += `<td>${esc(row[h])}</td>`;
      html += "</tr>";
    }
    html += "</tbody></table></div>";
    return html;
  };

  let body = "";

  // Header
  body += `<div class="report-header">
    <h1>IRFlow Timeline Report</h1>
    <div class="meta">
      <span>Source: <strong>${esc(fileName)}</strong></span>
      <span>Generated: <strong>${now}</strong></span>
    </div>
  </div>`;

  // Summary cards
  body += `<div class="cards">
    <div class="card"><div class="card-val">${data.totalRows.toLocaleString()}</div><div class="card-label">Total Rows</div></div>
    <div class="card"><div class="card-val">${data.bookmarkCount.toLocaleString()}</div><div class="card-label">Bookmarked</div></div>
    <div class="card"><div class="card-val">${data.taggedRowCount.toLocaleString()}</div><div class="card-label">Tagged Rows</div></div>
    <div class="card"><div class="card-val">${data.tagCount}</div><div class="card-label">Unique Tags</div></div>
  </div>`;

  // Timestamp range
  if (data.tsRange) {
    body += `<div class="ts-range">
      <strong>Timeline Span (${esc(data.tsRange.column)}):</strong>
      ${esc(data.tsRange.earliest)} &mdash; ${esc(data.tsRange.latest)}
    </div>`;
  }

  // Tag breakdown chips
  if (data.tagSummary.length > 0) {
    body += '<div class="section"><h2>Tag Breakdown</h2><div class="tag-chips">';
    for (const { tag, cnt } of data.tagSummary) {
      const color = safeColor(tagColors[tag]);
      body += `<span class="tag-chip" style="border-color:${color};color:${color};background:${color}22">${esc(tag)} <strong>${cnt}</strong></span>`;
    }
    body += "</div></div>";
  }

  // VirusTotal IOC Enrichment summary
  if (vtEnrichment && vtEnrichment.perIocResults && vtEnrichment.results) {
    const vtr = vtEnrichment.results;
    const perIoc = vtEnrichment.perIocResults;
    const vtIocs = perIoc.filter((ioc) => vtr[ioc.raw]);
    // Split into timeline-matched vs feed-only IOCs
    const vtMatched = vtIocs.filter((ioc) => ioc.hits > 0);
    const vtFeedOnly = vtIocs.filter((ioc) => ioc.hits === 0);
    const malicious = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "malicious");
    const suspicious = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "suspicious");
    const clean = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "clean");
    const notFound = vtMatched.filter((ioc) => vtr[ioc.raw]?.verdict === "not_found" || vtr[ioc.raw]?.verdict === "private");
    const feedMal = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "malicious").length;
    const feedSus = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "suspicious").length;
    const feedClean = vtFeedOnly.filter((ioc) => vtr[ioc.raw]?.verdict === "clean").length;

    body += '<div class="section"><h2>VirusTotal IOC Enrichment</h2>';

    // Verdict summary cards (scoped to timeline-matched IOCs)
    body += '<div class="cards">';
    body += `<div class="card" style="border-color:#f85149"><div class="card-val" style="color:#f85149">${malicious.length}</div><div class="card-label">Malicious</div></div>`;
    body += `<div class="card" style="border-color:#d29922"><div class="card-val" style="color:#d29922">${suspicious.length}</div><div class="card-label">Suspicious</div></div>`;
    body += `<div class="card" style="border-color:#3fb950"><div class="card-val" style="color:#3fb950">${clean.length}</div><div class="card-label">Clean</div></div>`;
    body += `<div class="card"><div class="card-val">${notFound.length}</div><div class="card-label">Not Found</div></div>`;
    body += '</div>';
    if (feedMal + feedSus + feedClean > 0) {
      const parts = [];
      if (feedMal > 0) parts.push(`<span style="color:#f85149">${feedMal} malicious</span>`);
      if (feedSus > 0) parts.push(`<span style="color:#d29922">${feedSus} suspicious</span>`);
      if (feedClean > 0) parts.push(`<span style="color:#3fb950">${feedClean} clean</span>`);
      body += `<div style="text-align:center;font-size:11px;color:#8b949e;margin-top:4px">Feed only: ${parts.join(" · ")} <span style="opacity:0.7">(no timeline hits)</span></div>`;
    }

    // IOC details table (only VT-enriched IOCs)
    if (vtIocs.length > 0) {
      // Sort: malicious first, then suspicious, then clean, then not found
      const verdictOrder = { malicious: 0, suspicious: 1, clean: 2, not_found: 3, private: 3 };
      const sorted = [...vtIocs].sort((a, b) => (verdictOrder[vtr[a.raw]?.verdict] ?? 4) - (verdictOrder[vtr[b.raw]?.verdict] ?? 4));

      body += '<div class="table-wrap"><table><thead><tr>';
      body += '<th>IOC</th><th>Category</th><th>VT Score</th><th>Verdict</th><th>Threat</th><th>Queried At</th><th>Timeline Hits</th>';
      body += '</tr></thead><tbody>';
      for (const ioc of sorted) {
        const r = vtr[ioc.raw];
        const verdict = r?.verdict || "unknown";
        const verdictColor = verdict === "malicious" ? "#f85149" : verdict === "suspicious" ? "#d29922" : verdict === "clean" ? "#3fb950" : "#8b949e";
        body += '<tr>';
        body += `<td style="font-family:monospace;font-size:12px">${esc(ioc.raw)}</td>`;
        body += `<td>${esc(ioc.category.replace(/_/g, " "))}</td>`;
        body += `<td style="font-family:monospace"><span style="color:${verdictColor};font-weight:700">${esc(r?.score || "—")}</span></td>`;
        body += `<td><span style="background:${verdictColor}22;color:${verdictColor};border:1px solid ${verdictColor}66;padding:1px 8px;border-radius:3px;font-size:11px;font-weight:600">${esc(verdict)}</span></td>`;
        body += `<td style="font-size:11px;color:${verdictColor};font-style:italic">${r?.threatLabel ? esc(r.threatLabel) : "—"}</td>`;
        body += `<td style="font-size:11px;font-family:monospace;color:#8b949e;white-space:nowrap">${r?.queriedAt ? new Date(r.queriedAt).toISOString().replace("T", " ").slice(0, 19) + "Z" : "—"}</td>`;
        body += `<td style="text-align:right;font-family:monospace">${ioc.hits > 0 ? ioc.hits.toLocaleString() : "—"}</td>`;
        body += '</tr>';
      }
      body += '</tbody></table></div>';
    }
    body += '</div>';
  }

  // Detail tables are capped in getReportData to keep report generation within memory.
  const maxRows = data.maxReportRows || 0;
  const truncNote = (shown) =>
    maxRows > 0
      ? `<p style="color:#d29922;font-style:italic;margin:4px 0 10px;">Showing first ${shown.toLocaleString()} events (report detail capped at ${maxRows.toLocaleString()} rows).</p>`
      : "";

  // Bookmarked events table
  if (data.bookmarkedRows.length > 0) {
    body += `<div class="section"><h2>Bookmarked Events (${data.bookmarkCount})</h2>`;
    if (data.bookmarkedTruncated) body += truncNote(data.bookmarkedRows.length);
    body += renderTable(data.bookmarkedRows, usedHeaders);
    body += "</div>";
  }

  // Tagged event tables (one per tag)
  let taggedNoteShown = false;
  for (const { tag, cnt } of data.tagSummary) {
    const rows = data.taggedGroups[tag] || [];
    if (rows.length === 0) continue;
    const color = tagColors[tag] || "#8b949e";
    body += `<div class="section">
      <h2><span class="tag-badge" style="background:${color}33;color:${color};border:1px solid ${color}66">${esc(tag)}</span> (${cnt} events)</h2>`;
    // The tagged-row cap applies across all tags combined; note it once when hit.
    if (data.taggedTruncated && !taggedNoteShown) { body += truncNote(rows.length); taggedNoteShown = true; }
    body += renderTable(rows, usedHeaders);
    body += "</div>";
  }

  // Empty report fallback
  if (data.bookmarkedRows.length === 0 && data.tagSummary.length === 0) {
    body += '<div class="section"><p style="color:#9a9590;font-style:italic;text-align:center;padding:40px 0;">No bookmarked or tagged events to include in report.<br>Bookmark events with the star icon or tag them to include in the report.</p></div>';
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IRFlow Report — ${esc(fileName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f1114;color:#e0ddd8;font-family:-apple-system,'SF Pro Text','Segoe UI',sans-serif;font-size:13px;padding:30px;max-width:1400px;margin:0 auto}
.report-header{border-bottom:2px solid #E85D2A;padding-bottom:16px;margin-bottom:24px}
.report-header h1{font-size:22px;font-weight:700;color:#E85D2A}
.meta{display:flex;gap:24px;color:#9a9590;font-size:12px;margin-top:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#181b20;border:1px solid #2a2d33;border-radius:8px;padding:16px;text-align:center}
.card-val{font-size:24px;font-weight:700;color:#E85D2A}
.card-label{font-size:11px;color:#9a9590;text-transform:uppercase;letter-spacing:.06em;margin-top:4px}
.ts-range{background:#181b20;border:1px solid #2a2d33;border-radius:6px;padding:10px 16px;margin-bottom:24px;font-size:12px;color:#9a9590}
.section{margin-bottom:32px}
.section h2{font-size:16px;font-weight:600;margin-bottom:12px;color:#e0ddd8;display:flex;align-items:center;gap:8px}
.tag-chips{display:flex;flex-wrap:wrap;gap:8px}
.tag-chip{padding:4px 12px;border:1px solid;border-radius:20px;font-size:12px}
.tag-chip strong{margin-left:4px}
.tag-badge{padding:2px 10px;border-radius:4px;font-size:12px;font-weight:600}
.table-wrap{overflow-x:auto;border:1px solid #2a2d33;border-radius:8px}
table{width:100%;border-collapse:collapse;font-size:11px;font-family:'SF Mono','Fira Code',Menlo,monospace}
th{position:sticky;top:0;background:#181b20;color:#E85D2A;padding:8px 10px;text-align:left;border-bottom:2px solid #2a2d33;white-space:nowrap;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
td{padding:5px 10px;border-bottom:1px solid #1a1d22;color:#e0ddd8;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:nth-child(even){background:#141720}
tr:hover{background:rgba(232,93,42,.08)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid #2a2d33;color:#5c5752;font-size:10px;text-align:center}
@media print{body{background:#fff;color:#1c1917}th{background:#f7f5f3;color:#E85D2A}td{color:#1c1917;border-color:#e0dbd6}.card{border-color:#e0dbd6;background:#faf8f6}tr:nth-child(even){background:#faf8f6}.report-header{border-color:#E85D2A}.ts-range{background:#faf8f6;border-color:#e0dbd6}}
</style>
</head>
<body>
${body}
<footer>Generated by IRFlow Timeline &mdash; ${now}</footer>
</body>
</html>`;
}

module.exports = function registerExportHandlers(safeHandle, safeSend, { db, _activeWindow }) {
  safeHandle("export-filtered", async (event, { tabId, options }) => {
    const result = await dialog.showSaveDialog(_activeWindow(), {
      defaultPath: `filtered_export.csv`,
      filters: [
        { name: "CSV (Comma-separated)", extensions: ["csv"] },
        { name: "TSV (Tab-separated)", extensions: ["tsv"] },
        { name: "Excel Workbook (.xlsx)", extensions: ["xlsx"] },
      ],
    });
    if (result.canceled) return false;

    const exportData = db.exportQuery(tabId, options);
    if (!exportData) return false;

    const ext = path.extname(result.filePath).toLowerCase();

    // Excel export (XLSX)
    if (ext === ".xlsx") {
      const ExcelJS = require("exceljs");
      // Stream rows straight to disk via WorkbookWriter instead of building the whole
      // workbook in memory — a large filtered export (millions of rows) would otherwise
      // OOM the main process. Column widths come from header length up front, since
      // streaming can't revisit already-committed rows to auto-fit to the data.
      const workbook = new ExcelJS.stream.xlsx.WorkbookWriter({ filename: result.filePath, useStyles: true });
      const sheet = workbook.addWorksheet("Export");
      sheet.columns = exportData.headers.map((h) => ({
        width: Math.min(Math.max(String(h ?? "").length + 2, 12), 60),
      }));

      // Styled header row, committed before the data rows are streamed.
      const headerRow = sheet.addRow(exportData.headers);
      headerRow.font = { bold: true };
      headerRow.eachCell((cell) => {
        cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF161B22" } };
        cell.font = { bold: true, color: { argb: "FF58A6FF" } };
      });
      headerRow.commit();

      // Stream rows — commit each so it flushes to disk; guard against tab close.
      let count = 0;
      try {
        for (const rawRow of exportData.iterator) {
          const values = exportData.safeCols.map((sc) => rawRow[sc] ?? "");
          sheet.addRow(values).commit();
          count++;
          if (count % 100000 === 0) {
            safeSend("export-progress", { count });
          }
        }
      } catch (e) {
        // Tab closed or DB error during export — finalize what we have
        dbg("MAIN", `XLSX export interrupted after ${count} rows`, { error: e.message });
      }

      sheet.commit();
      await workbook.commit();
      return { count, filePath: result.filePath };
    }

    const { count, aborted } = await writeDelimitedExportToPath(exportData, result.filePath, safeSend);
    return { count, filePath: result.filePath, partial: aborted || undefined };
  });

  safeHandle("export-ai-history-package", async (event, { tabId, options, tabName, sourceFormat } = {}) => {
    const tabInfo = db.getTabInfo(tabId);
    if (!tabInfo) return { __ipcError: true, message: "No timeline data for this tab." };
    if (!sourceFormat || !String(sourceFormat).startsWith("ai-history-")) {
      return { __ipcError: true, message: "AI history package export is only available for AI Query History tabs." };
    }

    const sourcesOnly = !!options?.sourcesOnlyManifest;

    const pick = await dialog.showOpenDialog(_activeWindow(), openDialogOptions({
      title: sourcesOnly ? "Export Source Manifest (sources only)" : "Export AI History Package",
      message: sourcesOnly
        ? "Choose a folder. IRFlow will write sources_manifest.json (paths + SHA-256, no message bodies) and README_sources.txt."
        : "Choose a folder. IRFlow will write a filtered CSV, manifest.json (source paths + SHA-256), and README.txt.",
      defaultPath: path.join(os.homedir(), "Desktop"),
      properties: ["openDirectory", "createDirectory"],
      buttonLabel: "Export Here",
    }));
    if (pick.canceled || !pick.filePaths?.[0]) return { canceled: true };

    const outDir = pick.filePaths[0];
    const exportOpts = { ...(options || {}) };
    delete exportOpts.sourcesOnlyManifest;

    const sourceGroups = db.getGroupedColumnCounts(tabId, "SourceFile", exportOpts);
    const toolGroups = db.getGroupedColumnCounts(tabId, "Tool", exportOpts).groups;
    const { sources, hashedFileCount, hashTruncated } = await enrichSourceManifest(sourceGroups.groups);
    const toolBreakdown = toolGroups.map((g) => ({ tool: g.value, rowCount: g.count }));
    const filtersApplied = options?.filtersApplied !== false;

    if (sourcesOnly) {
      const manifestPath = path.join(outDir, "sources_manifest.json");
      const readmePath = path.join(outDir, "README_sources.txt");
      const manifest = buildSourcesOnlyManifest({
        tabName,
        sourceFormat,
        totalRows: sourceGroups.totalRows,
        filtersApplied,
        sources,
        hashedFileCount,
        hashTruncated,
        toolBreakdown,
      });

      await fsp.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf-8");
      await fsp.writeFile(readmePath, buildSourcesOnlyReadmeText({
        tabName,
        sourceFileCount: sources.length,
        hashTruncated,
        dirPath: outDir,
      }), "utf-8");

      dbg("EXPORT", "export-ai-history-sources-only", {
        outDir,
        sources: sources.length,
        hashTruncated,
      });

      return {
        canceled: false,
        sourcesOnly: true,
        dirPath: outDir,
        manifestPath,
        readmePath,
        rowCount: sourceGroups.totalRows,
        sourceFileCount: sources.length,
        hashTruncated,
      };
    }

    const base = sanitizeExportBaseName(tabName);
    const csvPath = path.join(outDir, `${base}_timeline.csv`);
    const manifestPath = path.join(outDir, "manifest.json");
    const readmePath = path.join(outDir, "README.txt");

    let visibleHeaders = exportOpts.visibleHeaders || tabInfo.headers || [];
    if (tabInfo.headers?.includes("FullText") && !visibleHeaders.includes("FullText")) {
      visibleHeaders = [...visibleHeaders, "FullText"];
    }
    const exportData = db.exportQuery(tabId, { ...exportOpts, visibleHeaders });
    if (!exportData) return { __ipcError: true, message: "Could not read timeline rows for export." };

    const { count: rowCount, aborted: exportAborted, error: exportError } =
      await writeDelimitedExportToPath(exportData, csvPath, safeSend);

    const manifest = buildPackageManifest({
      tabName,
      sourceFormat,
      totalRows: sourceGroups.totalRows,
      exportedRows: rowCount,
      filtersApplied,
      sources,
      hashedFileCount,
      hashTruncated,
      toolBreakdown,
    });
    // Record truncation in the manifest so the chain-of-custody artifact never asserts a complete
    // export over a CSV that aborted mid-stream.
    if (exportAborted) {
      manifest.exportComplete = false;
      manifest.exportError = exportError || "Export stream aborted before all rows were written.";
    }

    await fsp.writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf-8");
    await fsp.writeFile(readmePath, buildReadmeText({
      tabName,
      exportedRows: rowCount,
      sourceFileCount: sources.length,
      hashTruncated,
      dirPath: outDir,
    }), "utf-8");

    dbg("EXPORT", "export-ai-history-package", {
      outDir,
      rowCount,
      sources: sources.length,
      hashTruncated,
    });

    return {
      canceled: false,
      dirPath: outDir,
      csvPath,
      manifestPath,
      readmePath,
      rowCount,
      sourceFileCount: sources.length,
      hashTruncated,
      partial: exportAborted || undefined,
      exportError: exportAborted ? (exportError || "Export stream aborted before all rows were written.") : undefined,
    };
  });

  // Save text content to file with save dialog
  safeHandle("save-text-file", async (event, { content, defaultPath, filters }) => {
    const result = await dialog.showSaveDialog(_activeWindow(), { defaultPath, filters });
    if (result.canceled) return null;
    await fsp.writeFile(result.filePath, content, "utf-8");
    return { filePath: result.filePath };
  });

  // AI Secret Hunt exports have a separate main-process redaction boundary. Even if a future UI
  // regression accidentally serializes a revealed value, known secret formats are masked before
  // bytes reach disk.
  safeHandle("save-ai-secret-export", async (event, { content, defaultPath, filters }) => {
    const text = String(content ?? "");
    if (Buffer.byteLength(text, "utf8") > MAX_AI_SECRET_EXPORT_BYTES) {
      return { error: "AI Secret export exceeds the 128 MiB safety limit." };
    }
    const result = await dialog.showSaveDialog(_activeWindow(), { defaultPath, filters });
    if (result.canceled) return null;
    await fsp.writeFile(result.filePath, redactAiSecretExportText(text), "utf-8");
    return { filePath: result.filePath };
  });

  // Export ransomware report as PDF
  safeHandle("export-ransomware-pdf", async (event, { html, defaultName }) => {
    const result = await dialog.showSaveDialog(_activeWindow(), {
      defaultPath: defaultName || "ransomware_report.pdf",
      filters: [{ name: "PDF Document", extensions: ["pdf"] }],
    });
    if (result.canceled) return null;
    const win = new BrowserWindow({ show: false, width: 900, height: 1200, webPreferences: { offscreen: true, nodeIntegration: false, contextIsolation: true, sandbox: true } });
    try {
      await win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
      // Wait a moment for rendering
      await new Promise((r) => setTimeout(r, 500));
      const pdfBuf = await win.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
      await fsp.writeFile(result.filePath, pdfBuf);
      return { filePath: result.filePath };
    } finally {
      win.destroy();
    }
  });

  // Export AI Secret & Leak Scan exposure brief as PDF (redacted HTML → printToPDF)
  safeHandle("export-ai-secrets-pdf", async (event, { html, defaultName }) => {
    const result = await dialog.showSaveDialog(_activeWindow(), {
      defaultPath: defaultName || "ai-secret-exposure-brief.pdf",
      filters: [{ name: "PDF Document", extensions: ["pdf"] }],
    });
    if (result.canceled) return null;
    const document = buildAiSecretPrintDocument(html);
    if (Buffer.byteLength(document, "utf8") > MAX_AI_SECRET_EXPORT_BYTES) {
      return { error: "AI Secret report exceeds the 128 MiB safety limit." };
    }
    const url = "data:text/html;charset=utf-8," + encodeURIComponent(document);
    const win = new BrowserWindow({
      show: false,
      width: 900,
      height: 1200,
      webPreferences: {
        offscreen: true,
        nodeIntegration: false,
        contextIsolation: true,
        sandbox: true,
        javascript: false,
        webSecurity: true,
        partition: `ai-secret-pdf-${crypto.randomUUID()}`,
      },
    });
    hardenAiSecretPdfWindow(win, url);
    try {
      await win.loadURL(url);
      await new Promise((r) => setTimeout(r, 500));
      const pdfBuf = await win.webContents.printToPDF({ printBackground: true, preferCSSPageSize: true, margins: { top: 0, bottom: 0, left: 0, right: 0 } });
      await fsp.writeFile(result.filePath, pdfBuf);
      return { filePath: result.filePath };
    } finally {
      win.destroy();
    }
  });

  // Generate HTML report from bookmarked/tagged events
  safeHandle("generate-report", async (event, { tabId, fileName, tagColors, vtEnrichment }) => {
    const reportData = db.getReportData(tabId);
    if (!reportData) return { error: "No data available" };

    const result = await dialog.showSaveDialog(_activeWindow(), {
      defaultPath: `${fileName.replace(/\.[^.]+$/, "")}_report.html`,
      filters: [{ name: "HTML Report", extensions: ["html"] }],
    });
    if (result.canceled) return null;

    const html = buildReportHtml(reportData, fileName, tagColors, vtEnrichment);
    await fsp.writeFile(result.filePath, html, "utf-8");
    return { filePath: result.filePath };
  });
};

// Exposed for unit tests (HTML escaping / tag-color sanitization). The default export
// stays the IPC registration function; this is an additive property on it.
module.exports.buildReportHtml = buildReportHtml;
module.exports.redactAiSecretExportText = redactAiSecretExportText;
module.exports.buildAiSecretPrintDocument = buildAiSecretPrintDocument;
module.exports.hardenAiSecretPdfWindow = hardenAiSecretPdfWindow;
