import useTheme from "../../hooks/useTheme.js";
import { buttonStyles } from "./buttonStyles.js";

/**
 * Themed button with consistent variants across the app.
 *
 * Variants:
 *   - primary    : solid accent bg, contrasting theme text (default CTA)
 *   - secondary  : subtle btnBg, dim text (Close, Cancel)
 *   - ghost      : transparent, dim text (icon-only, ✕)
 *   - accentSoft : accent-tinted bg + accent border (e.g. "★ Bookmark All")
 *   - dangerSoft : danger-tinted bg + danger border
 *
 * Sizes: sm (4px 10px / 11px) | md (6px 14px / 12px, default) | lg (8px 18px / 13px)
 */
export default function Button({
  variant = "primary",
  size = "md",
  disabled = false,
  loading = false,
  fullWidth = false,
  style: extraStyle,
  children,
  ...rest
}) {
  const { th } = useTheme();
  const base = buttonStyles(th, { variant, size, disabled: disabled || loading });

  return (
    <button
      disabled={disabled || loading}
      style={{
        ...base,
        cursor: loading ? "wait" : disabled ? "not-allowed" : "pointer",
        width: fullWidth ? "100%" : undefined,
        ...extraStyle,
      }}
      {...rest}
    >
      {loading ? "..." : children}
    </button>
  );
}
