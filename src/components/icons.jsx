import useTheme from "../hooks/useTheme.js";

export const BkmkIcon = ({ filled }) => {
  const { th } = useTheme();
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill={filled ? th.sev.med : "none"} stroke={filled ? th.sev.med : th.textMuted} strokeWidth="2">
      <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
    </svg>
  );
};

export const CheckboxIcon = ({ checked, indeterminate }) => {
  const { th } = useTheme();
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" style={{ verticalAlign: "middle" }}>
      <rect x="1" y="1" width="14" height="14" rx="2"
        fill={checked || indeterminate ? th.fillAccent : "none"}
        stroke={checked || indeterminate ? th.accent : th.textMuted} strokeWidth="1.5" />
      {checked && !indeterminate && (
        <polyline points="4,8 7,11 12,5" fill="none" stroke={th.onAccent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      )}
      {indeterminate && (
        <line x1="4" y1="8" x2="12" y2="8" stroke={th.onAccent} strokeWidth="2" strokeLinecap="round" />
      )}
    </svg>
  );
};
