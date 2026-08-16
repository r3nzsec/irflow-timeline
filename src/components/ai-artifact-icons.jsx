/**
 * Menu icons for AI artifact extractors. Each tool's glyph is tinted with its own brand color
 * (kept in sync with TOOL_BRAND in AiSecretsModal so the menu and the AI Secret Hunt result badges
 * match); group/chrome icons stay in the IRFlow / Unit 42 accent.
 */

const VIEW = "0 0 24 24";

// Brand tints used by the compact menu badges. Mirror TOOL_BRAND.
const BRAND = {
  claude: "#D97757",   // Anthropic Claude coral (the app-icon orange)
  openai: "#10A37F",   // OpenAI green (ChatGPT)
  codex: "#2F6FED",    // OpenAI Codex azure (the blue ">_" CLI mark)
  gemini: "#4285F4",   // Google blue
  cursor: "#7d8590",   // Cursor slate (monochrome brand)
  copilot: "#8b949e",  // GitHub grey (monochrome brand)
  windsurf: "#58a6ff", // Windsurf blue
  continue: "#3fb950", // Continue green
};

function MenuSvg({ children }) {
  return (
    <svg width="15" height="15" viewBox={VIEW} fill="none" aria-hidden="true" style={{ flexShrink: 0 }}>
      {children}
    </svg>
  );
}

function darken(hex, f = 0.72) {
  const m = /^#?([0-9a-fA-F]{6})$/.exec(hex);
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  const r = Math.round(((n >> 16) & 255) * f);
  const g = Math.round(((n >> 8) & 255) * f);
  const b = Math.round((n & 255) * f);
  return `#${((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1)}`;
}

/** Brand color → {glyph, chip, mid, deep} tones. */
function tones(c) {
  return { a: c, soft: `${c}1f`, mid: `${c}55`, deep: darken(c) };
}

function accentTones(th) {
  const a = th.accent;
  return { a, soft: th.accentSubtle || `${a}1f`, mid: `${a}55`, deep: th.accentHover || "#C44D1E" };
}

/** Claude — coral tile with a cream radial sunburst (Anthropic Claude app icon). */
export function ClaudeCodeMenuIcon() {
  const coral = BRAND.claude;
  const cream = "#F4EEE3";
  const rays = [[12, 5.8], [14.2, 8.2], [17.4, 8.9], [16.4, 12], [17.4, 15.1], [14.2, 15.8], [12, 18.2], [9.8, 15.8], [6.6, 15.1], [7.6, 12], [6.6, 8.9], [9.8, 8.2]];
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={coral} />
      <g stroke={cream} strokeWidth="1.5" strokeLinecap="round">
        {rays.map(([x, y], i) => <line key={i} x1="12" y1="12" x2={x} y2={y} />)}
      </g>
    </MenuSvg>
  );
}

/** OpenAI Codex — terminal prompt ">_" (the blue Codex CLI mark). */
export function OpenAiMenuIcon() {
  const { a, soft } = tones(BRAND.codex);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill="none" stroke={a} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" d="M8.4 8l3.3 4-3.3 4" />
      <path fill="none" stroke={a} strokeWidth="2" strokeLinecap="round" d="M12.9 16.1h3.6" />
    </MenuSvg>
  );
}

/**
 * ChatGPT Computer History (Skysight) — a display with an activity pulse: this artifact is recorded
 * screen/input activity, not a conversation transcript. It is a ChatGPT desktop feature, but the
 * summaries and feature state land under `~/.codex`, so Codex azure groups it with the other stores
 * an analyst opens that folder to find.
 */
export function ComputerHistoryMenuIcon() {
  const { a, soft } = tones(BRAND.codex);
  return (
    <MenuSvg>
      <rect x="2.5" y="4" width="19" height="13" rx="2" fill={soft} stroke={a} strokeWidth="1.15" />
      <path fill="none" stroke={a} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" d="M5.5 11.5h2.6l1.5-3 2 5.4 1.6-3.6 1.2 1.2h3.1" />
      <path stroke={a} strokeWidth="1.5" strokeLinecap="round" d="M9 20h6" />
    </MenuSvg>
  );
}

/** Grok Build — compact black-and-white Grok mark. */
export function GrokMenuIcon() {
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill="#050505" />
      <path
        fill="#fff"
        d="M17.55 5.72a8.18 8.18 0 0 0-10.7-.15 8.17 8.17 0 0 0-.94 11.56l1.66-1.55a5.92 5.92 0 0 1 .78-8.29 5.91 5.91 0 0 1 7.56-.12l1.64-1.45Z"
      />
      <path
        fill="#fff"
        d="m3.24 20.76 11.64-9.98c.46-.39 1.15-.24 1.4.31a5.92 5.92 0 0 1-8.75 7.35l-1.66 1.55a8.18 8.18 0 0 0 12.21-10.7L21.2 2.8 10.68 14.6l-7.44 6.16Z"
      />
    </MenuSvg>
  );
}

/** ChatGPT — chat bubble with knot (OpenAI green). */
export function ChatGptMenuIcon() {
  const { a, soft, mid } = tones(BRAND.openai);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill={a} d="M12 5.5c3.25 0 5.88 2.05 5.88 4.58 0 1.35-.72 2.58-1.85 3.35l.48 2.85-2.65-1.42a5.2 5.2 0 0 1-1.86.34c-3.25 0-5.88-2.05-5.88-4.58S8.75 5.5 12 5.5z" />
      <path fill={mid} d="M12 8.35c1.85 0 3.35 1.15 3.35 2.58S13.85 13.5 12 13.5s-3.35-1.15-3.35-2.58S10.15 8.35 12 8.35z" />
      <path fill="none" stroke={a} strokeWidth="1.4" strokeLinejoin="round" d="M9.2 11.1h5.6M10.1 12.65h3.8" />
    </MenuSvg>
  );
}

/** Gemini — four-point sparkle (Google Gemini mark). */
export function GeminiMenuIcon() {
  const { a, soft, mid } = tones(BRAND.gemini);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill={a} d="M12 4.25c.4 2.85 2.55 5 5.4 5.4.4-2.85 2.55-5 5.4-5.4-.4 2.85-2.55 5-5.4 5.4-.4-2.85-2.55-5-5.4-5.4z" />
      <path fill={mid} d="M12 9.35c1.45 0 2.62 1.17 2.62 2.62S13.45 14.6 12 14.6 9.38 13.43 9.38 11.97 10.55 9.35 12 9.35z" />
    </MenuSvg>
  );
}

/** Cursor — isometric 3D cursor prism (slate). */
export function CursorMenuIcon() {
  const { a, soft, mid, deep } = tones(BRAND.cursor);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill={mid} d="M7.25 15.75 12 18.75l4.75-3-4.75-3-4.75 3z" />
      <path fill={a} d="M7.25 15.75 12 12.75V6.25L7.25 9.25v6.5z" />
      <path fill={deep} d="M12 6.25l4.75 3v6.5L12 12.75V6.25z" />
      <path fill="none" stroke={a} strokeWidth="0.85" strokeLinejoin="round" d="M12 6.25 7.25 9.25 12 12.75l4.75-3L12 6.25z" />
    </MenuSvg>
  );
}

/** GitHub Copilot — visor "bot" head with antenna (distinct from the ChatGPT bubble; GitHub grey). */
export function CopilotMenuIcon() {
  const { a, soft } = tones(BRAND.copilot);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path stroke={a} strokeWidth="1.2" strokeLinecap="round" d="M12 8V6.3" />
      <circle cx="12" cy="5.6" r="0.95" fill={a} />
      <path fill={a} d="M6.2 12c0-2.2 2.6-3.6 5.8-3.6S17.8 9.8 17.8 12c0 2.7-2.3 4.6-5.8 4.6S6.2 14.7 6.2 12z" />
      <circle cx="9.8" cy="12.1" r="1.15" fill={soft} />
      <circle cx="14.2" cy="12.1" r="1.15" fill={soft} />
    </MenuSvg>
  );
}

/** Windsurf — sail on a mast above a wave (Windsurf blue). */
export function WindsurfMenuIcon() {
  const { a, soft, mid } = tones(BRAND.windsurf);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill={a} d="M12.4 4.6c2.9 1.3 4.5 4 4.7 9.1h-4.7V4.6z" />
      <path fill={mid} d="M11.6 6.6C9.5 8 8.4 10.4 8.3 13.7h3.3V6.6z" />
      <path stroke={a} strokeWidth="1.15" strokeLinecap="round" d="M12 4.3v9.6" />
      <path fill="none" stroke={a} strokeWidth="1.3" strokeLinecap="round" d="M6.6 16.8q1.5 1.4 3 0t3 0t3 0" />
    </MenuSvg>
  );
}

/** Continue — forward chevron (the "continue/next" carat, not a plus; Continue green). */
export function ContinueMenuIcon() {
  const { a, soft, mid } = tones(BRAND.continue);
  return (
    <MenuSvg>
      <circle cx="12" cy="12" r="10" fill={soft} />
      <path fill="none" stroke={mid} strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round" d="M7.5 8l4 4-4 4" />
      <path fill="none" stroke={a} strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" d="M12 8l4 4-4 4" />
    </MenuSvg>
  );
}

/** Collapsible subgroup — grid of app tiles (Tools → AI Artifacts → AI Apps). */
export function AiAppsGroupIcon({ th }) {
  const { a, soft } = accentTones(th);
  return (
    <MenuSvg>
      <rect x="3" y="3" width="8" height="8" rx="2" fill={soft} stroke={a} strokeWidth="1.05" />
      <rect x="13" y="3" width="8" height="8" rx="2" fill={soft} stroke={a} strokeWidth="1.05" />
      <rect x="3" y="13" width="8" height="8" rx="2" fill={soft} stroke={a} strokeWidth="1.05" />
      <rect x="13" y="13" width="8" height="8" rx="2" fill={soft} stroke={a} strokeWidth="1.05" />
    </MenuSvg>
  );
}

/** Group header — layered sparks for AI Artifacts. */
export function AiArtifactsGroupIcon({ th }) {
  const { a, soft, mid } = accentTones(th);
  return (
    <MenuSvg>
      <rect x="3" y="3" width="18" height="18" rx="4.5" fill={soft} stroke={a} strokeWidth="1.1" />
      <path fill={a} d="M8.4 9.6c.28 1.15 1.2 2 2.35 2.15-.58.1-1.1.42-1.52.82-.42-.4-.94-.72-1.52-.82 1.15-.15 2.07-1 2.35-2.15-.28-1.15-1.2-2-2.35-2.15.58-.1 1.1-.42 1.52-.82.42.4.94.72 1.52.82-1.15.15-2.07 1-2.35 2.15z" />
      <path fill={mid} d="M15 13.4c.22.9.92 1.55 1.82 1.68-.48.08-.92.3-1.28.58-.36-.28-.8-.5-1.28-.58.9-.13 1.6-.78 1.82-1.68-.22-.9-.92-1.55-1.82-1.68.48-.08.92-.3 1.28-.58.36.28.8.5 1.28.58-.9.13-1.6.78-1.82 1.68z" />
      <path fill="none" stroke={a} strokeWidth="1.15" strokeLinecap="round" d="M10.5 16h5" />
    </MenuSvg>
  );
}
