export const ROW_HEIGHT = 26;
export const HEADER_HEIGHT = 34;
export const FILTER_HEIGHT = 28;
export const OVERSCAN = 20;
export const VIRTUAL_WINDOW = 10000;   // rows to fetch per SQL query window
export const VIRTUAL_AHEAD = 2000;     // trigger re-fetch when within this many rows of edge
// Chromium/Blink saturates layout positions near 2^24 (~16.7M) CSS pixels. Beyond that,
// scrolling becomes unreliable and rows past the ceiling are unreachable. We cap the
// physical scroll container at this height and map physical<->logical scroll positions.
// Below this threshold (~461k rows at 26px), scaling is a no-op and behavior is unchanged.
export const MAX_PHYSICAL_H = 12_000_000;
export const QUERY_DEBOUNCE = 500;
export const DETAIL_PANEL_HEIGHT_DEFAULT = 200;
export const DETAIL_PANEL_MIN_HEIGHT = 80;
export const DETAIL_PANEL_MAX_HEIGHT = 600;
export const TAG_COL_WIDTH_DEFAULT = 100;
export const TAG_COL_WIDTH_MIN = 60;
export const BKMK_COL_WIDTH = 34;
export const CHECKBOX_COL_WIDTH = 24;
export const VT_COL_WIDTH = 80;
export const EVIDENCE_COL_WIDTH = 220;
export const EVIDENCE_COL_MIN_WIDTH = 60;
export const VT_COMPATIBLE_RE = /^(SHA256|SHA1|MD5)_Hash$|^Domain_Name$|^IPv[46]_Address(:Port)?$|^URL$/;
// Delay before a gap in the row window is allowed to paint skeleton placeholders. Window
// fetches that resolve faster than this never flash grey bars on their way out.
export const SKELETON_ARM_DELAY = 120;
