/**
 * Pure style object generator for themed buttons.
 *
 * Used internally by <Button>, but also exported so that legacy modal code that
 * builds raw `<button style={...}>` elements can opt into the same look without
 * a per-instance refactor:
 *
 *   const btn = useButtonStyles();
 *   const ms = { bp: btn.primary, bs: btn.secondary, bsm: btn.smallSecondary };
 *
 * Keeping this as a plain function (not a component) means it can be called
 * inside a modal's render pass without React rules.
 */
export function buttonStyles(th, { variant = "primary", size = "md", disabled = false } = {}) {
  const sizeMap = {
    sm: { padding: "4px 10px", fontSize: 11 },
    md: { padding: "6px 14px", fontSize: 12 },
    lg: { padding: "8px 18px", fontSize: 13 },
  };
  const sz = sizeMap[size] || sizeMap.md;

  let variantStyle;
  switch (variant) {
    case "secondary":
      variantStyle = {
        background: th.btnBg,
        color: disabled ? th.textMuted : th.textDim,
        border: `1px solid ${th.border}`,
      };
      break;
    case "ghost":
      variantStyle = {
        background: "none",
        color: disabled ? th.textMuted : th.textDim,
        border: "none",
      };
      break;
    case "accentSoft":
      variantStyle = {
        background: disabled ? th.btnBg : th.accent + "22",
        color: disabled ? th.textMuted : th.accent,
        border: `1px solid ${disabled ? th.border : th.accent + "44"}`,
        fontWeight: 500,
      };
      break;
    case "dangerSoft": {
      const dg = th.danger;
      variantStyle = {
        background: disabled ? th.btnBg : dg + "18",
        color: disabled ? th.textMuted : dg,
        border: `1px solid ${disabled ? th.border : dg + "44"}`,
        fontWeight: 500,
      };
      break;
    }
    case "primary":
    default:
      variantStyle = {
        background: disabled ? th.btnBg : th.fillAccent,
        color: disabled ? th.textMuted : th.onAccent,
        border: "none",
        fontWeight: 600,
      };
  }

  return {
    ...sz,
    ...variantStyle,
    borderRadius: 6,
    cursor: disabled ? "not-allowed" : "pointer",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
    whiteSpace: "nowrap",
    // No `outline: none` here — it would shadow the global :focus-visible keyboard ring.
    // :focus-visible keeps mouse clicks ring-free, so a focus indicator only shows for keyboard nav.
    transition: "background var(--m-base) var(--ease-out), color var(--m-base) var(--ease-out), border-color var(--m-base) var(--ease-out), transform var(--m-fast) var(--ease-out), box-shadow var(--m-base) var(--ease-out)",
  };
}

/**
 * Convenience preset that mirrors the legacy `ms.bp/bs/bsm` triplet used by
 * pre-primitive modals. Drop into existing code with:
 *
 *   const ms = { ...legacyMs(th), ip: ..., sl: ..., lb: ... };
 */
export function legacyMs(th) {
  return {
    bp: buttonStyles(th, { variant: "primary" }),
    bs: buttonStyles(th, { variant: "secondary" }),
    bsm: buttonStyles(th, { variant: "secondary", size: "sm" }),
  };
}
