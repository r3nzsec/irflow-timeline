import useToastStore from "../../store/useToastStore.js";
import useTheme from "../../hooks/useTheme.js";

/**
 * Stacked toast notifications, bottom-right. Mount once at app root.
 *
 * Each toast has:
 *   - kind  ("info" | "success" | "warning" | "error")
 *   - message (string)
 *   - detail (optional secondary text)
 *   - ttl (auto-dismiss in ms; 0 = persist until dismissed)
 *
 * See useToastStore.js for the API.
 */
export default function ToastContainer() {
  const toasts = useToastStore((s) => s.toasts);
  const dismiss = useToastStore((s) => s.dismiss);
  const { th } = useTheme();

  if (toasts.length === 0) return null;

  const kindColor = (kind) => {
    switch (kind) {
      case "success": return th.sev.clean;
      case "warning": return th.warning;
      case "error":   return th.danger;
      case "info":
      default:        return th.sev.info;
    }
  };

  const kindIcon = (kind) => {
    const stroke = kindColor(kind);
    if (kind === "success") return <path d="M20 6L9 17l-5-5" />;
    if (kind === "warning") return <><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></>;
    if (kind === "error")   return <><circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" /></>;
    // info
    return <><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></>;
  };

  return (
    <div
      role="region"
      aria-label="Notifications"
      style={{
        position: "fixed", bottom: 18, right: 18, zIndex: 250,
        display: "flex", flexDirection: "column-reverse", gap: 10,
        pointerEvents: "none",
      }}
    >
      {toasts.map((t) => {
        const color = kindColor(t.kind);
        return (
          <div
            key={t.id}
            role={t.kind === "error" ? "alert" : "status"}
            aria-live={t.kind === "error" ? "assertive" : "polite"}
            style={{
              pointerEvents: "auto",
              minWidth: 280, maxWidth: 420,
              padding: "10px 12px 10px 14px",
              background: th.modalBg + "f2",
              border: `1px solid ${color}55`,
              borderRadius: 10,
              backdropFilter: "blur(40px) saturate(1.6)",
              WebkitBackdropFilter: "blur(40px) saturate(1.6)",
              boxShadow: "0 12px 40px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset",
              display: "flex", alignItems: "flex-start", gap: 10,
              fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
              animation: "tle-modal-in var(--m-modal) var(--ease-out)",
            }}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginTop: 1 }}>
              {kindIcon(t.kind)}
            </svg>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ color: th.text, fontSize: 12, fontWeight: 500, lineHeight: 1.4, wordBreak: "break-word" }}>
                {t.message}
              </div>
              {t.detail && (
                <div style={{ color: th.textDim, fontSize: 11, lineHeight: 1.4, marginTop: 4, wordBreak: "break-word", whiteSpace: "pre-wrap" }}>
                  {t.detail}
                </div>
              )}
              {t.actionLabel && t.onAction && (
                <button
                  onClick={() => { try { t.onAction(); } finally { dismiss(t.id); } }}
                  style={{
                    marginTop: 8, background: `${color}1f`, border: `1px solid ${color}66`,
                    color, cursor: "pointer", fontSize: 11, fontWeight: 600,
                    padding: "3px 10px", borderRadius: 5, fontFamily: "-apple-system, sans-serif",
                  }}
                >
                  {t.actionLabel}
                </button>
              )}
            </div>
            <button
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss"
              style={{
                background: "none", border: "none", color: th.textMuted,
                cursor: "pointer", fontSize: 14, padding: "0 2px", lineHeight: 1,
                flexShrink: 0, transition: "color var(--m-fast) var(--ease-out)",
              }}
              onMouseEnter={(e) => { e.currentTarget.style.color = th.text; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = th.textMuted; }}
            >
              ✕
            </button>
          </div>
        );
      })}
    </div>
  );
}
