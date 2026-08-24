# IRFlow Timeline — Design System

The house UI language: **Apple "liquid glass" surfaces + a Unit 42 / threat-report palette + progressive disclosure.** Every new panel, modal, or analysis feature should follow this. The canonical, end-to-end reference implementation is **`src/components/modals/AiSecretsModal.jsx`** — when in doubt, copy its patterns.

> This is the design standard referenced from `CLAUDE.md`. Keep them in sync.

---

## 1. Principles

1. **Theme tokens only — never hardcode hex in a component.** Pull `const { th } = useTheme()` and derive every color from `th`. The app ships **Dark (default) + Light**; anything hardcoded breaks one of them. Tokens live in `src/constants/themes.js`.
2. **One brand orange.** `th.accent` (`#E85D2A`, a Palo Alto / Unit 42 orange) is the only accent — primary buttons, active/selected states, focus rings, links. Don't introduce other accent hues.
3. **Severity is its own scale.** Use `th.sev` for all risk/severity/threat UI. **Never** reuse `th.accent` for severity — they're deliberately distinct (a finding's severity must never look like a primary action).
4. **Verdict first.** The user should get the answer in one glance (a hero), then progressively drill in. Don't dump every stat, filter, and column on screen at once.
5. **Fewer clicks.** Auto-run the common path; put the 1–2 most-used controls in the toolbar and everything else behind a popover/disclosure/row-expansion.
6. **Redact sensitive data by default**, and **never write cleartext (secrets/PII) to disk** (exports/reports are redacted-only).

---

## 2. Palette (from `themes.js`)

| Purpose | Token | Dark | Light |
|---|---|---|---|
| Brand accent | `th.accent` / `th.accentHover` | `#E85D2A` / `#F47B50` | `#E85D2A` / `#C44D1E` |
| Severity: critical | `th.sev.critical` | `#f85149` | `#dc2626` |
| Severity: high | `th.sev.high` | `#f0883e` | `#cc4400` |
| Severity: medium | `th.sev.med` | `#d29922` | `#a16207` |
| Severity: low | `th.sev.low` | `#8b949e` | `#6b6560` |
| Severity: clean/ok | `th.sev.clean` | `#3fb950` | `#16a34a` |
| Severity: info | `th.sev.info` | `#58a6ff` | `#3b82f6` |
| Glass fill / border / hover | `th.glassBg` / `th.glassBorder` / `th.glassHover` | `rgba(255,255,255,.05)` / `.08` / `.10` | `rgba(0,0,0,.03)` / `.06` / `.08` |
| Surfaces | `th.bg` `th.bgAlt` `th.bgInput` `th.panelBg` `th.modalBg` | — | — |
| Text | `th.text` `th.textDim` `th.textMuted` | — | — |
| Status | `th.success` `th.warning` `th.danger` | — | — |

Severity helper (engine uses `medium`, theme key is `med`):

```js
const sev = th.sev;
const sevColor = (s) =>
  s === "critical" ? sev.critical : s === "high" ? sev.high :
  s === "medium" ? sev.med : s === "low" ? sev.low :
  s === "info" ? sev.info : sev.clean;
```

---

## 3. Liquid-glass style recipes

Floating surfaces (modals) already get `backdrop-filter: blur(40px) saturate(1.6)` from `DraggableResizableModal` / `components/primitives/Modal`. Inside, build panels/controls from these helpers (defined inline per component, derived from `th`):

```js
// translucent panel: hairline border + inner top-highlight
const glass = (extra = {}) => ({
  background: th.glassBg, border: `1px solid ${th.glassBorder}`,
  borderRadius: 14, boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)", ...extra,
});

// severity / status pill
const pill = (c, sm) => ({
  display: "inline-flex", alignItems: "center", gap: 5,
  padding: sm ? "2px 8px" : "3px 10px", borderRadius: 999,
  fontSize: sm ? 9.5 : 10.5, fontWeight: 700, letterSpacing: "0.03em",
  color: c, background: `${c}1f`, border: `1px solid ${c}44`,
  textTransform: "uppercase", whiteSpace: "nowrap",
});

// toolbar toggle (filled when active)
const softBtn = (active) => ({
  padding: "5px 11px", borderRadius: 9, fontSize: 11, fontWeight: 500, cursor: "pointer",
  color: active ? "#fff" : th.textDim,
  background: active ? th.accent : th.glassBg,
  border: `1px solid ${active ? th.accent : th.glassBorder}`,
});

// segmented control
const segWrap = { display: "inline-flex", padding: 3, gap: 2, ...glass({ borderRadius: 10 }) };
const segItem = (active) => ({
  padding: "5px 11px", borderRadius: 8, fontSize: 11, fontWeight: 600, cursor: "pointer",
  border: "1px solid transparent",
  color: active ? "#fff" : th.textMuted, background: active ? th.accent : "transparent",
});

// gradient primary button with accent glow
const primaryBtn = {
  padding: "9px 20px", borderRadius: 11, fontSize: 12.5, fontWeight: 600, cursor: "pointer", color: "#fff",
  background: `linear-gradient(180deg, ${th.accentHover || th.accent}, ${th.accent})`,
  border: `1px solid ${th.accent}`,
  boxShadow: `0 4px 16px ${th.accent}40, inset 0 1px 0 rgba(255,255,255,0.22)`,
};
const ghostBtn = { padding: "9px 16px", borderRadius: 11, fontSize: 12, fontWeight: 500, cursor: "pointer", color: th.textDim, background: "transparent", border: `1px solid ${th.glassBorder}` };
const tinyBtn  = { padding: "3px 9px", borderRadius: 7, fontSize: 10.5, fontWeight: 500, cursor: "pointer", color: th.textDim, background: th.glassBg, border: `1px solid ${th.glassBorder}` };
```

Conventions: radii 7 (tiny) → 14 (panels); hex-alpha suffixes `0f`/`14`/`1f` (tints), `44`/`55` (borders); animate with the existing `--ease-out` var and `tle-*` keyframes (`tle-pulse`, `tle-modal-in`, …).

**Monogram provenance badges** (fast scanning without trademarked logos): a rounded square, brand color at low alpha, 1–3 char monogram — see `PROVIDER_BRAND` / `TOOL_BRAND` / `ProviderBadge` in `AiSecretsModal.jsx`. Use recognizable brand *colors + initials*, never copyrighted logo SVGs.

---

## 4. Information architecture (progressive disclosure)

Standard layout for an analysis/results surface (see `AiSecretsModal.jsx`):

```
┌ HERO ───────────────────────────────────────────────┐  ← verdict at a glance
│  ◇ shield (tinted by worst severity)                 │     tinted gradient: `linear-gradient(135deg, ${sevColor}1a, transparent)`
│  "3 critical secrets exposed"   [Quick|Deep]  ✕      │     headline + 1-line stat strip
│  ▰▰▱▱ severity distribution bar                       │
├ TOOLBAR (one row) ───────────────────────────────────┤  ← 1–2 key controls only
│  All Crit High … | Group▾ |  🔍search  Filters▾  ⤓    │     advanced filters behind "Filters"
├ LIST (severity-sorted cards) ────────────────────────┤  ← scannable; ~2 lines each
│  ●CRIT  [AI] OpenAI Key   sk-…FJ   Claude ×3   ▸      │
│     └ expand → value+reveal, evidence, triage, actions│  ← detail only on demand
└ FOOTER ──────────────────────────────────────────────┘  ← status + New scan / Done
```

Rules:
- **Hero** answers "how bad?" before any scrolling; color it by the worst severity (`clean` green when nothing found).
- **Toolbar** holds only the most-used controls (severity filter, search, group-by). Everything else (per-field filters, column tools) goes behind a `Filters`/disclosure toggle.
- **List** rows are compact: a severity pill + provenance badge + title + redacted value + a count/where hint + a chevron. The whole row toggles expansion. Do **not** add a colored left accent stripe on cards, metric boxes, or list rows — severity lives in pills, not a vertical bar.
- **Expansion** is where heavy detail lives — evidence, notes/triage, secondary actions.
- **Group-by lenses** (Incident / Tool / Session, etc.) re-bucket the *same filtered set*; they're views, not new queries.
- **Reach for the shared shell**: `DraggableResizableModal` (draggable/resizable glass modal), `primitives/Modal`, or `Overlay`+`makeModalStyles` (`InlineModals.jsx`). Don't hand-roll overlays/backdrops.
- **Empty/clean and loading states** are first-class: a reassuring tinted glyph + one-line explanation + a single next-step CTA.

---

## 5. Reports / exports ("exposure brief")

Self-contained HTML, exported to real PDF via an offscreen `printToPDF` IPC (pattern: `export-ransomware-pdf` / `export-ai-secrets-pdf`) or saved as `.html`. Styling = threat-report brief:

- **Light page** (`#fff` / `#1c1917` text) for clean printing.
- **Dark header band** (`#0b0d10`, white text) with a **`#E85D2A` bottom border** + shield mark + title/subtitle.
- Stat boxes, a severity distribution bar, an "exposure by …" table, MITRE rollup, then the findings table.
- Section headers: `border-left: 3px solid #E85D2A`. Severity badges use the light-theme severity scale.
- **Redacted-only**: never interpolate cleartext secrets/PII or raw snippets into the export; HTML-escape every interpolated value.
- Footer line states the report is redacted and generated by IRFlow Timeline. Do **not** put any third-party (e.g. Unit 42) name/logo in the output — we evoke the *look*, not the brand.

Reference: `buildReportHtml()` in `AiSecretsModal.jsx`.

---

## 6. Do / Don't

- ✅ `color: th.sev.critical` ❌ `color: "#f85149"`
- ✅ severity via `th.sev`, primary action via `th.accent` ❌ severity rendered in the brand orange
- ✅ advanced filters behind a `Filters` toggle ❌ a 9-select grid always on screen
- ✅ auto-run the common path; one toggle for the variant ❌ a config screen before every action
- ✅ `glass()` panels + hairline borders ❌ opaque `bgAlt` boxes with heavy `border` lines for floating UI
- ✅ redacted value + per-row reveal ❌ cleartext secrets in the default view or any export
- ✅ reuse `DraggableResizableModal` / `Modal` / `Overlay` ❌ a bespoke fixed-position overlay
