import { useEffect, useId } from "react";
import useTheme from "../../hooks/useTheme.js";
import useFocusTrap from "../../hooks/useFocusTrap.js";
import Button from "./Button.jsx";

/**
 * Standard modal shell used across the app.
 *
 * Replaces ~30 lines of overlay/container/header/footer boilerplate per modal
 * and is the single place to evolve modal look-and-feel (dark mode, a11y,
 * keyboard handling, focus traps, etc.).
 *
 * Props:
 *   open       : if false, returns null (no portal flicker)
 *   onClose    : called by ✕, ESC, and overlay click (when closeOnOverlay)
 *   title      : header title text
 *   subtitle   : optional second line under the title
 *   icon       : optional JSX rendered to the left of the title (e.g. an svg)
 *   width      : pixel width of the dialog (default 520)
 *   maxHeight  : CSS max-height of the dialog (default "85vh")
 *   headerExtra: optional JSX rendered between title and close button
 *   footer     : optional JSX rendered in the footer; if omitted, footer is hidden.
 *                Pass `true` to render a default "Close" button.
 *   bodyPadding: padding for the body section (default "16px 20px")
 *   closeOnOverlay : default true
 *   closeOnEscape  : default true
 *   zIndex     : default 100
 *   bare       : if true, only renders the overlay (with ESC handling) and
 *                children — no centered container, no header, no footer.
 *                Use for resizable/draggable modals that fully control their
 *                own positioning.
 */
export default function Modal({
  open = true,
  onClose,
  title,
  subtitle,
  icon,
  width = 520,
  maxHeight = "85vh",
  headerExtra,
  footer,
  bodyPadding = "16px 20px",
  closeOnOverlay = true,
  closeOnEscape = true,
  zIndex = 100,
  bare = false,
  clickThrough = false,
  children,
}) {
  const { th } = useTheme();
  const titleId = useId();
  const dialogRef = useFocusTrap(open);

  useEffect(() => {
    if (!open || !closeOnEscape) return;
    const onKey = (e) => {
      if (e.key === "Escape") onClose?.();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, closeOnEscape, onClose]);

  if (!open) return null;

  const handleOverlayClick = (e) => {
    if (!closeOnOverlay) return;
    if (e.target === e.currentTarget) onClose?.();
  };

  if (bare) {
    return (
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Dialog"
        tabIndex={-1}
        onClick={handleOverlayClick}
        style={{
          position: "fixed",
          inset: 0,
          background: clickThrough ? "transparent" : th.overlay,
          zIndex,
          backdropFilter: clickThrough ? "none" : "blur(4px)",
          WebkitBackdropFilter: clickThrough ? "none" : "blur(4px)",
          WebkitAppRegion: clickThrough ? "no-drag" : "drag",
          pointerEvents: clickThrough ? "none" : undefined,
          animation: "tle-overlay-in var(--m-fast) var(--ease-out-soft)",
          outline: "none",
        }}
      >
        {children}
      </div>
    );
  }

  return (
    <div
      onClick={handleOverlayClick}
      style={{
        position: "fixed",
        inset: 0,
        background: th.overlay,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex,
        backdropFilter: "blur(4px)",
        WebkitBackdropFilter: "blur(4px)",
        WebkitAppRegion: "drag",
        animation: "tle-overlay-in var(--m-fast) var(--ease-out-soft)",
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? titleId : undefined}
        aria-label={title ? undefined : "Dialog"}
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={{
          background: th.modalBg + "f2",
          border: `1px solid ${th.glassBorder}`,
          borderRadius: 12,
          width,
          maxWidth: "94vw",
          maxHeight,
          display: "flex",
          flexDirection: "column",
          backdropFilter: "blur(40px) saturate(1.6)",
          WebkitBackdropFilter: "blur(40px) saturate(1.6)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset",
          WebkitAppRegion: "no-drag",
          overflow: "hidden",
          animation: "tle-modal-in var(--m-modal) var(--ease-out)",
          outline: "none",
        }}
      >
        {/* Header */}
        {(title || subtitle || icon || headerExtra || onClose) && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "14px 20px",
              borderBottom: `1px solid ${th.border}`,
              flexShrink: 0,
              gap: 12,
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
              {icon}
              <div style={{ minWidth: 0 }}>
                {title && (
                  <div
                    id={titleId}
                    style={{
                      fontSize: 15,
                      fontWeight: 600,
                      color: th.text,
                      fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                  >
                    {title}
                  </div>
                )}
                {subtitle && (
                  <div
                    style={{
                      fontSize: 11,
                      color: th.textDim,
                      marginTop: 2,
                      fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
                    }}
                  >
                    {subtitle}
                  </div>
                )}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {headerExtra}
              {onClose && (
                <button
                  onClick={onClose}
                  aria-label="Close"
                  style={{
                    background: "none",
                    border: "none",
                    color: th.textMuted,
                    cursor: "pointer",
                    fontSize: 18,
                    padding: "2px 6px",
                    lineHeight: 1,
                  }}
                >
                  ✕
                </button>
              )}
            </div>
          </div>
        )}

        {/* Body */}
        <div
          style={{
            padding: bodyPadding,
            overflow: "auto",
            flex: 1,
            color: th.text,
            fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
          }}
        >
          {children}
        </div>

        {/* Footer */}
        {footer && (
          <div
            style={{
              padding: "10px 20px",
              borderTop: `1px solid ${th.border}`,
              display: "flex",
              justifyContent: "flex-end",
              gap: 8,
              flexShrink: 0,
            }}
          >
            {footer === true ? (
              <Button variant="secondary" onClick={onClose}>
                Close
              </Button>
            ) : (
              footer
            )}
          </div>
        )}
      </div>
    </div>
  );
}
