import useUIStore from "../store/useUIStore.js";
import { isThemeName } from "../constants/themes.js";

/**
 * Apply a color scheme chosen inside the renderer (toolbar picker) and ask the main
 * process to remember it, so the native Color Scheme menu and the next launch agree.
 *
 * Changes that originate in the native menu arrive through `tle.onSetTheme` instead;
 * the main process has already persisted those.
 */
export function chooseTheme(name) {
  if (!isThemeName(name)) return false;
  useUIStore.getState().setThemeName(name);
  const tle = typeof window !== "undefined" ? window.tle : null;
  const pending = tle?.setThemePreference?.(name);
  if (pending && typeof pending.catch === "function") pending.catch(() => {});
  return true;
}
