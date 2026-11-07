import { useMemo } from "react";
import useTheme from "./useTheme.js";

/**
 * Returns the legacy `ms` style bundle that 13+ analysis modals share.
 *
 * Historically every modal redefined this same object inline. Centralizing it
 * means a single change propagates to every modal — and pairs naturally with
 * the <Modal> primitive shell.
 *
 * Tokens:
 *   mh   header h3
 *   fg   form group margin
 *   lb   small uppercase label
 *   sl   <select> styling
 *   ip   <input> styling
 *   bp   primary button
 *   bs   secondary button
 *   bsm  small secondary button
 */
export default function useModalChrome() {
  const { th } = useTheme();
  return useMemo(() => ({
    mh: { margin: "0 0 14px", fontSize: 16, fontWeight: 600, color: th.text, fontFamily: "-apple-system, sans-serif" },
    fg: { marginBottom: 10 },
    lb: { display: "block", fontSize: 10, color: th.textDim, marginBottom: 3, textTransform: "uppercase", letterSpacing: "0.06em", fontFamily: "-apple-system, sans-serif" },
    sl: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit" },
    ip: { width: "100%", padding: "6px 8px", background: th.bgInput, border: `1px solid ${th.btnBorder}`, borderRadius: 6, color: th.text, fontSize: 12, outline: "none", fontFamily: "inherit", boxSizing: "border-box" },
    bp: { padding: "6px 16px", background: th.primaryBtn, color: th.onPrimary, border: "none", borderRadius: 6, fontSize: 12, fontWeight: 500, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bs: { padding: "6px 16px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 6, fontSize: 12, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
    bsm: { padding: "3px 8px", background: th.btnBg, color: th.text, border: `1px solid ${th.btnBorder}`, borderRadius: 4, fontSize: 10, cursor: "pointer", fontFamily: "-apple-system,sans-serif" },
  }), [th]);
}
