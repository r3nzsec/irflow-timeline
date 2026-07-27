import { create } from "zustand";

/**
 * Global toast / notification queue. Replaces the OS-native alert() calls and
 * the inline `copiedMsg` flash state.
 *
 * Usage from anywhere:
 *
 *   import { toast } from "../store/useToastStore.js";
 *   toast.success("Copied to clipboard");
 *   toast.error("Import failed", { detail: error.message });
 *   toast.info("Loading...", { ttl: 0 });   // ttl=0 means no auto-dismiss
 *
 * The <ToastContainer /> primitive must be mounted once at the app root for
 * toasts to render — see App.jsx alongside the other portal-style components.
 *
 * Defaults:
 *   info / success  — auto-dismiss after 3500ms
 *   warning         — auto-dismiss after 6000ms
 *   error           — does NOT auto-dismiss (requires user action)
 */
let nextId = 1;
const ttlTimers = new Map();

const DEFAULT_TTL = { info: 3500, success: 3500, warning: 6000, error: 0 };

const useToastStore = create((set, get) => ({
  toasts: [],

  push: ({ kind = "info", message, detail, ttl, actionLabel, onAction, dedupeKey }) => {
    const effectiveTtl = ttl !== undefined ? ttl : DEFAULT_TTL[kind] ?? 3500;
    let id;
    set((s) => {
      const existing = dedupeKey ? s.toasts.find((item) => item.dedupeKey === dedupeKey) : null;
      id = existing?.id ?? nextId++;
      const item = { id, kind, message, detail, ttl: effectiveTtl, actionLabel, onAction, dedupeKey };
      return {
        toasts: existing
          ? s.toasts.map((toastItem) => toastItem.id === id ? item : toastItem)
          : [...s.toasts, item],
      };
    });

    const priorTimer = ttlTimers.get(id);
    if (priorTimer) clearTimeout(priorTimer);
    if (effectiveTtl > 0) {
      ttlTimers.set(id, setTimeout(() => get().dismiss(id), effectiveTtl));
    }
    return id;
  },

  dismiss: (id) => {
    const timer = ttlTimers.get(id);
    if (timer) clearTimeout(timer);
    ttlTimers.delete(id);
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },

  clear: () => {
    for (const timer of ttlTimers.values()) clearTimeout(timer);
    ttlTimers.clear();
    set({ toasts: [] });
  },
}));

export default useToastStore;

// Convenience API — drop-in replacements for alert() / inline message flashes.
export const toast = {
  info:    (message, opts = {}) => useToastStore.getState().push({ kind: "info",    message, ...opts }),
  success: (message, opts = {}) => useToastStore.getState().push({ kind: "success", message, ...opts }),
  warning: (message, opts = {}) => useToastStore.getState().push({ kind: "warning", message, ...opts }),
  error:   (message, opts = {}) => useToastStore.getState().push({ kind: "error",   message, ...opts }),
};
