import useUIStore from "../../store/useUIStore.js";
import useTheme from "../../hooks/useTheme.js";
import {
  HISTOGRAM_GRANULARITIES,
  MIN_SEARCH_LENGTH,
  SEARCH_BEHAVIORS,
  SEARCH_CONDITIONS,
  SEARCH_MATCH_MODES,
} from "../../constants/ui-controls.js";
import { Modal } from "../primitives/index.js";

export default function QuickHelpModal() {
  const modal = useUIStore((s) => s.modal);
  const setModal = useUIStore((s) => s.setModal);
  const { th } = useTheme();

  if (modal?.type !== "quickHelp") return null;

  const icon = (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={th.accent} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
  );

  const S = ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 700, color: th.accent, marginTop: 18, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.06em" }}>{children}</h3>;
  const P = ({ children }) => <p style={{ margin: "0 0 8px", color: th.text }}>{children}</p>;
  const Li = ({ children }) => <div style={{ display: "flex", gap: 8, marginBottom: 4 }}><span style={{ color: th.accent, flexShrink: 0 }}>-</span><span>{children}</span></div>;
  const K = ({ children }) => <span style={{ background: th.bgAlt, border: `1px solid ${th.border}`, borderRadius: 4, padding: "1px 5px", fontSize: 11, fontFamily: "monospace", color: th.textDim }}>{children}</span>;

  return (
    <Modal
      title="Quick Help"
      icon={icon}
      width={620}
      onClose={() => setModal(null)}
      bodyPadding="20px 24px"
    >
      <div style={{ fontSize: 13, color: th.text, lineHeight: 1.7 }}>
        <P>IRFlow Timeline can open CSV, TSV, TXT, LOG, XLSX, XLS, EVTX, Plaso, raw $MFT, and $J ($UsnJrnl) files and display them in a high-performance DuckDB-backed grid. Files stream into a temporary DuckDB database rather than loading fully into memory, so there is no row limit — tested with 30GB+ files and 150M+ rows.</P>

        <S>Supported Formats</S>
        <Li><b>CSV / TSV / TXT / LOG</b> — Auto-delimiter detection, streaming import. Handles multi-GB files.</Li>
        <Li><b>XLSX / XLS / XLSM</b> — Streaming reader for XLSX, SheetJS for legacy XLS. Multi-sheet support with sheet picker.</Li>
        <Li><b>EVTX</b> — Windows Event Log binary files. Parsed natively with full field extraction, provider resolution, and PayloadData mapping.</Li>
        <Li><b>$MFT</b> — Raw NTFS Master File Table. Full file path reconstruction from parent references, dual SI/FN timestamp extraction, and attribute flag parsing.</Li>
        <Li><b>$J / $UsnJrnl</b> — Raw NTFS USN Change Journal. Change reason mapping (rename, delete, data extend, security change, close), MFT parent correlation, and full path resolution.</Li>
        <Li><b>Plaso</b> — log2timeline/Plaso SQLite output files. All event sources and timestamps preserved.</Li>

        <S>Search Controls</S>
        {SEARCH_BEHAVIORS.map((behavior) => <Li key={behavior.value}><b>{behavior.label}</b> — {behavior.description}</Li>)}
        <P>Match modes:</P>
        {SEARCH_MATCH_MODES.map((mode) => <Li key={mode.value}><b>{mode.label}</b> — {mode.description}</Li>)}
        <P>Conditions:</P>
        {SEARCH_CONDITIONS.map((condition) => <Li key={condition.value}><b>{condition.label}</b> — {condition.description}</Li>)}
        <P>Search starts after at least <b>{MIN_SEARCH_LENGTH} characters</b>. The <b>Like</b> condition supports <K>%</K> (any characters) and <K>_</K> (one character).</P>
        <P>Prefix with <K>+AND</K> to require all terms, <K>-NOT</K> to exclude terms, or wrap in <K>"quotes"</K> for exact phrase matching.</P>

        <S>Column Filters</S>
        <P>Each column has a text filter input and a dropdown (▼) for value-based checkbox filtering. Filters can be combined across columns. Use the toggle button to temporarily disable individual filters without clearing them.</P>
        <Li><b>Filter in / Filter out</b> — Right-click any cell or <K>⌘</K>+Click to quickly filter. "Filter in" shows only rows matching that value; "Filter out" excludes rows with that value.</Li>
        <Li><b>Date range filter</b> — Click the ⏱ icon on timestamp columns to filter by date range.</Li>
        <Li><b>Advanced filter</b> — Use "Edit Filter" in the status bar for complex AND/OR filter logic.</Li>

        <S>Grouping</S>
        <P>Right-click any column header and select "Group by this column" to group rows. Multiple columns can be grouped hierarchically. Click the expand arrow (▶) to reveal rows within a group. Use the checkbox on group headers to select all rows in that group for copying.</P>

        <S>Tagging & Bookmarks</S>
        <Li><b>Tags</b> — Right-click any row to add colored tags via the Tags submenu. Select multiple rows (checkboxes) first to apply a tag to all selected rows at once. Tags are searchable, filterable, and visible in the Tags column.</Li>
        <Li><b>Bookmarks</b> — Click the bookmark icon (flag) on any row. Use <K>⌘B</K> to toggle "Flagged Only" view.</Li>
        <Li><b>Bulk tagging</b> — Use Bulk Actions to tag all filtered/visible rows at once, or tag by time ranges from the histogram.</Li>
        <Li><b>IOC tagging</b> — Load IOC files (CSV, XLSX, TSV) and auto-tag matching rows with per-IOC tags.</Li>

        <S>Timeline Histogram</S>
        <P>The histogram at the top shows event distribution over time. Click and drag to brush-select a time range — this filters the grid to only show events in that window. Available granularity: {HISTOGRAM_GRANULARITIES.map((item) => item.label).join(" / ")}. Use the histogram to identify activity bursts and gaps.</P>

        <S>DFIR Analysis Tools</S>
        <Li><b>Sigma Detection</b> — Dual-engine rule-based detection (Tools ▸ Sigma Scan): bundled Hayabusa over raw .evtx folders, or an in-app JS Sigma engine for imported timelines and EvtxECmd output. Scan presets, custom rules, noisy-rule suppression, and a MITRE ATT&CK-mapped triage dashboard with reopenable scan history.</Li>
        <Li><b>Process Inspector</b> — Parent-child process trees from Sysmon EID 1 and Security 4688, with 340+ MITRE ATT&CK chain rules (Office spawning PowerShell, LOLBins, etc.), integrity levels, and command lines. Analyst Profiles save suppressions/baselines to tame false positives.</Li>
        <Li><b>Lateral Movement Tracker</b> — Force-directed graph of logon events (4624/4625/4648) and RDP sessions, with seven sub-tabs: Accounts (per-identity scoring), Exec Sessions (WMI/PsExec/Impacket/RMM), Incidents, Campaign clustering, and Telemetry Coverage. Flags multi-hop chains, brute force, password spray, and credential compromise.</Li>
        <Li><b>Persistence Analyzer</b> — Scans EVTX for 30+ persistence techniques (scheduled tasks, services, WMI, registry autoruns, COM hijacking, DLL hijacking, drivers, and more), correlates account-persistence chains, reassembles PowerShell 4104 script blocks, and risk-scores 0-10.</Li>
        <Li><b>NTFS Analysis Tools</b> — Raw $MFT/$J suite: Ransomware Analytics, Timestomping (SI vs FN), File Activity Heatmap, ADS Analyzer, USN Journal Analysis with UsnJrnl Rewind path reconstruction, and Resident Data Extraction for recovering deleted artifacts.</Li>
        <Li><b>RDP Bitmap Cache</b> — Recovers visual remnants from Windows RDP cache (bcache*.bmc / cache????.bin) via bundled ANSSI-FR bmc-tools, with tile/collage previews and a hashed, exportable evidence package.</Li>
        <Li><b>IOC Matching & VirusTotal Enrichment</b> — Matches 17+ indicator types (IPs, domains, URLs, hashes, registry keys, named pipes, crypto wallets, JA3/JARM, and more), auto-defangs, and tags/highlights hits inline. Optional VirusTotal lookups add cached verdict badges, malware family labels, and relationship pivots, exportable to CSV/HTML reports.</Li>
        <Li><b>Gap Analysis</b> — Finds time gaps over a threshold to spot missing log coverage.</Li>
        <Li><b>Burst Detection</b> — Flags abnormal event-frequency spikes (brute-force / automated activity).</Li>
        <Li><b>Log Source Coverage</b> — Heatmap of which log sources have data over time to reveal collection gaps.</Li>
        <Li><b>Stacking</b> — Value frequency analysis on any column — "stack and count" for spotting outliers.</Li>

        <S>Export & Reporting</S>
        <Li><b>Export</b> — Export the current filtered view as CSV, TSV, XLSX, or XLS. Only visible/filtered rows are exported.</Li>
        <Li><b>HTML Report</b> — Generate a standalone HTML report with tagged/bookmarked rows, color-coded by tag. Includes VT enrichment summary (verdict cards, per-IOC scores, threat labels, timeline hit counts) when IOC matching with VirusTotal has been performed. Shareable without any tools needed.</Li>
        <Li><b>Sessions</b> — Save your entire workspace (tabs, filters, tags, bookmarks, color rules) as a .tle session file. Reload later to pick up exactly where you left off.</Li>

        <S>Tips</S>
        <Li>Drag column headers to reorder. Double-click a header divider to auto-fit column width.</Li>
        <Li>Right-click column headers for options: pin, hide, group, sort, stacking, stats. Right-click cells for copy, filter in/out, tags, and VT lookup.</Li>
        <Li><K>⌘</K>+Click any cell to quickly access Filter in, Filter out, and Hide column.</Li>
        <Li><K>⌘C</K> copies selected rows as tab-separated text (with headers). Works in both normal and grouped mode.</Li>
        <Li>Double-click any cell to see its full content in a popup.</Li>
        <Li>Drop files directly onto the window to import them.</Li>
        <Li><K>⌘K</K> opens the command palette so you can search available File, View, Actions, Tools, and Help commands.</Li>
        <Li>The status bar (bottom) shows active filters, row counts, and sort state. Click the file path to copy it.</Li>
        <Li>IRFlow Timeline checks for updates automatically; use <b>Help ▸ Check for Updates…</b> to check on demand and install with one click.</Li>
      </div>
    </Modal>
  );
}
