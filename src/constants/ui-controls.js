import { MIN_SEARCH_LENGTH } from "../utils/search.js";

// Shared control definitions keep the toolbar, options bar, and help copy in sync.
export const SEARCH_BEHAVIORS = [
  { value: "filter", label: "Filter", description: "Hide rows that do not match." },
  { value: "highlight", label: "Highlight", description: "Keep every row visible and highlight matches." },
];

export const SEARCH_MATCH_MODES = [
  { value: "mixed", label: "Mixed", description: "Use the indexed search path when available, with a compatible fallback." },
  { value: "or", label: "OR", description: "Match rows containing any search term." },
  { value: "and", label: "AND", description: "Require every search term." },
  { value: "exact", label: "Exact", description: "Match the complete phrase." },
  { value: "regex", label: "Regex", description: "Evaluate the search as a regular expression." },
];

export const SEARCH_CONDITIONS = [
  { value: "contains", label: "Contains", description: "Match text containing the entered value." },
  { value: "fuzzy", label: "Fuzzy", description: "Find close spellings and likely typos." },
  { value: "startswith", label: "Starts with", description: "Match values beginning with the entered text." },
  { value: "endswith", label: "Ends with", description: "Match values ending with the entered text." },
  { value: "like", label: "Like", description: "Use SQL-style % and _ wildcards." },
  { value: "equals", label: "Equals", description: "Match the complete cell value." },
];

export const HISTOGRAM_GRANULARITIES = [
  { value: "day", label: "Day" },
  { value: "hour", label: "Hour" },
];

export { MIN_SEARCH_LENGTH };
