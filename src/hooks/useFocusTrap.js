import { useEffect, useRef } from "react";

/**
 * Trap focus inside `containerRef` while `active`.
 *
 * On activation:
 *  - Captures `document.activeElement` so focus can return there on close.
 *  - Moves focus to the first focusable inside the container (or the container
 *    itself if it has tabIndex=-1).
 *
 * While active:
 *  - Tab/Shift+Tab cycles between the first and last focusable elements
 *    inside the container, so keyboard users cannot escape the modal.
 *
 * On deactivation:
 *  - Restores focus to the element that was active before the trap opened, after the
 *    closing event and only if focus is not elsewhere by then.
 *
 * Pair with role="dialog" + aria-modal="true" + aria-labelledby on the
 * container itself so screen readers announce the modal correctly.
 */
const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export default function useFocusTrap(active) {
  const containerRef = useRef(null);
  const previousActive = useRef(null);

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;

    // Remember where focus was before we opened
    previousActive.current = document.activeElement;

    // Move focus into the modal — prefer an element with autofocus, then the
    // first focusable, then the container itself (must have tabIndex=-1).
    const tryFocus = () => {
      const autofocus = container.querySelector("[autofocus]");
      if (autofocus instanceof HTMLElement) { autofocus.focus(); return; }
      const focusables = container.querySelectorAll(FOCUSABLE);
      if (focusables.length > 0 && focusables[0] instanceof HTMLElement) {
        focusables[0].focus();
        return;
      }
      container.focus();
    };
    // Defer one tick so any ref-attached elements are in the tree
    const handle = requestAnimationFrame(tryFocus);

    // Trap Tab inside the container
    const onKey = (e) => {
      if (e.key !== "Tab") return;
      const focusables = Array.from(container.querySelectorAll(FOCUSABLE)).filter(
        (el) => el instanceof HTMLElement && !el.hidden && el.offsetParent !== null
      );
      if (focusables.length === 0) {
        e.preventDefault();
        container.focus();
        return;
      }
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey, true);

    return () => {
      cancelAnimationFrame(handle);
      window.removeEventListener("keydown", onKey, true);
      // Restore focus to where it was before the modal opened, once the event that closed the
      // modal is over, and only if nothing else took focus meanwhile. Restoring it at once let
      // an Enter that closed a modal also press the button that opened it (Edit Filter in the
      // status bar), which opened the modal again.
      const prev = previousActive.current;
      setTimeout(() => {
        const now = document.activeElement;
        const focusLost = !now || now === document.body || now === document.documentElement;
        if (focusLost && prev instanceof HTMLElement && document.contains(prev)) prev.focus();
      }, 0);
    };
  }, [active]);

  return containerRef;
}
