import { KAPE_PROFILES } from "../constants/kape-profiles.js";
import JUNTEI_TEMPLATES from "../../electron/juntei-templates.json" with { type: "json" };

/**
 * The format template that matches `headers`: all of its columns, and no other column except its
 * optionalColumns (any, with allowExtraColumns); with several, the one with the most columns.
 * Same rule as electron/format-templates.js, which sets the tab's timestamp columns from the
 * template, so the grid and the database agree on the format.
 */
export function detectFormatTemplate(headers) {
  const present = new Set(headers || []);
  let best = null;
  for (const t of JUNTEI_TEMPLATES.templates) {
    if (!t.columns.every((c) => present.has(c))) continue;
    if (!t.allowExtraColumns) {
      const known = new Set([...t.columns, ...(t.optionalColumns || [])]);
      if ([...present].some((h) => !known.has(h))) continue;
    }
    if (!best || t.columns.length > best.columns.length) best = t;
  }
  return best;
}

export function detectKapeProfile(headers) {
  const template = detectFormatTemplate(headers);
  // Juntei already writes its columns in order, so the file order is kept.
  if (template) return { name: template.name, detect: template.columns };
  const headerSet = new Set((headers || []).map((h) => String(h).toLowerCase()));
  for (const [name, profile] of Object.entries(KAPE_PROFILES)) {
    if (profile.detect.every((col) => headerSet.has(String(col).toLowerCase()))) return { name, ...profile };
  }
  return null;
}

export function isChainsawDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return has(/^system_time$/i) && has(/^id$/i)
    && (has(/^detection_rules$/i) || has(/^computer_name$/i) || has(/^workstation_name$/i));
}

export function isChainsawProcessDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return isChainsawDataset(headers)
    && (has(/^process_name$/i) || has(/^Event\.EventData\.Image$/i) || has(/^command_line$/i) || has(/^Event\.EventData\.CommandLine$/i));
}

export function isChainsawLogonDataset(headers) {
  const has = (re) => (headers || []).some((h) => re.test(h));
  return isChainsawDataset(headers)
    && has(/^target_username$/i)
    && has(/^logon_type$/i)
    && (has(/^source_ip$/i) || has(/^workstation_name$/i));
}
