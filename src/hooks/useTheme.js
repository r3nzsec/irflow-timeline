import { resolveTheme } from "../constants/themes.js";
import useUIStore from "../store/useUIStore.js";

/**
 * Returns the resolved theme object, the scheme name and whether it is a dark-based scheme.
 * Usage: const { th, themeName, isDark } = useTheme();
 */
export default function useTheme() {
  const themeName = useUIStore((s) => s.themeName);
  const th = resolveTheme(themeName);
  return { th, themeName, isDark: th.base === "dark" };
}
