// Hierarchical process graph layout for the Process Inspector.
//
// Pure layout: inputs are process nodes + detection map (+ optional focus keys).
// Output is positioned nodes/edges suitable for SVG rendering — no DOM.
//
// Design goals:
//   • Multi-root / multi-host campaigns readable as host swimlanes
//   • Cap node count so fleet timelines stay interactive
//   • Prefer suspicious + ancestry + direct children over "render everything"
//   • Respect consistentParentKey so PID-reuse mislinks don't pull wrong subtrees

import { consistentParentKey } from "./process-inspector-pipeline.js";

export const PROCESS_GRAPH_DEFAULTS = {
  maxNodes: 220,
  nodeWidth: 196,
  // Minimum card height; actual height grows to fit wrapped labels (no truncation).
  nodeHeight: 48,
  colGap: 48,
  rowGap: 16,
  hostGap: 36,
  padX: 40,
  padY: 32,
  // Typography used to estimate wrap so layout height matches the renderer.
  titleFontSize: 12,
  titleLineHeight: 16,
  subFontSize: 9,
  subLineHeight: 12,
  // Approx monospace advance (px) — SF Mono / Menlo at the sizes above.
  titleCharWidth: 7.2,
  subCharWidth: 5.5,
  // Inner horizontal padding: gutters + icon column.
  contentPadX: 36,
  contentPadY: 12,
  maxTitleLines: 6,
  maxSubLines: 4,
};

const _procBase = (p) => String(p?.processName || p?.image || "(unknown)").split(/[/\\]/).pop() || "(unknown)";

/** Soft-wrap a string into lines that fit `maxChars` (word-aware, then hard-break). */
export const wrapTextLines = (text, maxChars, maxLines = 20) => {
  const raw = String(text || "").trim();
  if (!raw) return [""];
  const limit = Math.max(4, Math.floor(maxChars));
  const lines = [];
  // Prefer splitting on path/backslash/space/dot boundaries so long names stay readable.
  const tokens = raw.split(/(\s+|\\+|\/+|[._-]+)/).filter((t) => t.length > 0);
  let cur = "";
  const push = (s) => {
    if (lines.length >= maxLines) return;
    lines.push(s);
  };
  const flush = () => {
    if (cur) { push(cur); cur = ""; }
  };
  for (const tok of tokens) {
    if (lines.length >= maxLines) break;
    if (!cur) {
      if (tok.length <= limit) { cur = tok; continue; }
      // Hard-break oversized token
      for (let i = 0; i < tok.length && lines.length < maxLines; i += limit) {
        const chunk = tok.slice(i, i + limit);
        if (i + limit < tok.length && lines.length === maxLines - 1) {
          push(chunk); // last line — full chunk, no ellipsis (height will grow instead)
        } else {
          push(chunk);
        }
      }
      cur = "";
      continue;
    }
    if (cur.length + tok.length <= limit) {
      cur += tok;
    } else {
      flush();
      if (tok.length <= limit) cur = tok;
      else {
        for (let i = 0; i < tok.length && lines.length < maxLines; i += limit) {
          push(tok.slice(i, i + limit));
        }
      }
    }
  }
  flush();
  return lines.length ? lines : [""];
};

/** Build the secondary meta line shown under the process name. */
export const buildNodeSubLine = (n) => {
  const parts = [];
  if (n?.pid) parts.push(`PID ${n.pid}`);
  if (n?.level > 0) {
    parts.push({ 3: "Critical", 2: "High", 1: "Medium" }[n.level] || "Detected");
  }
  if (n?.user) parts.push(n.user);
  return parts.join(" · ") || "—";
};

/**
 * Estimate card height so the full process name + meta fit without truncation.
 * Pure; kept in lockstep with ProcessGraphView typography.
 */
export const estimateNodeHeight = (processName, subLine, cfg = PROCESS_GRAPH_DEFAULTS) => {
  const contentW = Math.max(40, (cfg.nodeWidth || 196) - (cfg.contentPadX || 36));
  const titleChars = Math.max(4, Math.floor(contentW / (cfg.titleCharWidth || 7.2)));
  // Icon takes ~19px on the first title row; subsequent title wrap uses full width.
  // Use full width for estimate (slightly conservative height is fine).
  const titleLines = wrapTextLines(processName, titleChars, cfg.maxTitleLines || 6);
  const subChars = Math.max(4, Math.floor(contentW / (cfg.subCharWidth || 5.5)));
  const subLines = wrapTextLines(subLine, subChars, cfg.maxSubLines || 4);
  const titleH = titleLines.length * (cfg.titleLineHeight || 16);
  const subH = subLines.length * (cfg.subLineHeight || 12);
  const gap = 2;
  const padY = cfg.contentPadY || 12;
  const minH = cfg.nodeHeight || 48;
  return Math.max(minH, padY + titleH + gap + subH);
};

/**
 * Choose which process keys should seed the graph.
 *
 * Priority:
 *   1. Explicit focusKeys (story/cluster/selection context)
 *   2. Detected processes (level >= minLevel), highest triage score first
 *   3. Fallback: earliest processes (raw exploration)
 */
export const selectGraphSeedKeys = (processes, detMap, opts = {}) => {
  const {
    focusKeys = null,
    minLevel = 1,
    maxSeeds = 80,
  } = opts;
  if (!processes?.length) return [];

  if (focusKeys && focusKeys.size > 0) {
    const out = [];
    for (const k of focusKeys) {
      out.push(k);
      if (out.length >= maxSeeds) break;
    }
    return out;
  }

  const scored = [];
  for (const p of processes) {
    const det = detMap?.get?.(p.key) || { level: 0, triageScore: 0 };
    if ((det.level || 0) < minLevel) continue;
    scored.push({
      key: p.key,
      level: det.level || 0,
      triage: det.triageScore || 0,
      tsMs: Number.isFinite(p.tsMs) ? p.tsMs : Number.MAX_SAFE_INTEGER,
    });
  }
  scored.sort((a, b) =>
    b.level - a.level
    || b.triage - a.triage
    || a.tsMs - b.tsMs
  );

  if (scored.length > 0) {
    return scored.slice(0, maxSeeds).map((s) => s.key);
  }

  // No detections — show a small chronological sample so Graph mode still works.
  const sample = [...processes]
    .sort((a, b) => (Number.isFinite(a.tsMs) ? a.tsMs : 0) - (Number.isFinite(b.tsMs) ? b.tsMs : 0))
    .slice(0, Math.min(40, maxSeeds));
  return sample.map((p) => p.key);
};

/**
 * Expand seed keys to a connected subgraph: seeds + full ancestry + nearby
 * branch context + bounded descendants.
 * Caps at maxNodes; prefers keeping higher-severity nodes when truncating.
 */
export const buildGraphSubgraph = (processes, detMap, seedKeys, opts = {}) => {
  const maxNodes = opts.maxNodes ?? PROCESS_GRAPH_DEFAULTS.maxNodes;
  const includeChildren = opts.includeChildren !== false;
  const includeAncestors = opts.includeAncestors !== false;
  const includeBranchContext = opts.includeBranchContext !== false;
  const descendantDepth = Math.max(1, Number(opts.descendantDepth) || 2);
  if (!processes?.length || !seedKeys?.length) {
    return { keys: new Set(), truncated: false, seedCount: 0 };
  }

  const byKey = opts.byKey || new Map(processes.map((p) => [p.key, p]));
  const childMap = opts.childMap || (() => {
    const m = new Map();
    for (const p of processes) {
      if (!p.parentKey) continue;
      if (!m.has(p.parentKey)) m.set(p.parentKey, []);
      m.get(p.parentKey).push(p.key);
    }
    return m;
  })();

  const keep = new Set();
  const add = (key) => {
    if (!key || !byKey.has(key) || keep.has(key)) return false;
    if (keep.size >= maxNodes) return false;
    keep.add(key);
    return true;
  };

  // Seeds first
  for (const k of seedKeys) add(k);

  // Ancestors (via consistentParentKey)
  if (includeAncestors) {
    for (const seed of seedKeys) {
      let cur = byKey.get(seed);
      let hops = 0;
      while (cur && hops++ < 32) {
        const pk = consistentParentKey(cur, byKey);
        if (!pk || !byKey.has(pk)) break;
        if (!add(pk)) break;
        cur = byKey.get(pk);
      }
    }
  }

  const childRank = (key) => {
    const det = detMap?.get?.(key) || { level: 0, triageScore: 0 };
    const node = byKey.get(key);
    return {
      key,
      level: det.level || 0,
      triage: det.triageScore || 0,
      tsMs: Number.isFinite(node?.tsMs) ? node.tsMs : Number.MAX_SAFE_INTEGER,
    };
  };
  const rankedChildrenOf = (key) => (childMap.get(key) || [])
    .filter((ck) => {
      const child = byKey.get(ck);
      return child && consistentParentKey(child, byKey) === key;
    })
    .map(childRank)
    .sort((a, b) => b.level - a.level || b.triage - a.triage || a.tsMs - b.tsMs);

  // One-hop branch context from every included ancestor makes siblings visible
  // without recursively exploding the whole host process tree.
  if (includeChildren) {
    if (includeBranchContext) {
      const childCandidates = [];
      const contextRoots = [...keep];
      for (const k of contextRoots) {
        for (const child of rankedChildrenOf(k)) {
          if (!keep.has(child.key)) childCandidates.push(child);
        }
      }
      childCandidates.sort((a, b) =>
        b.level - a.level || b.triage - a.triage || a.tsMs - b.tsMs
      );
      for (const c of childCandidates) {
        if (keep.size >= maxNodes) break;
        add(c.key);
      }
    }

    // Follow the actual seed branches farther than one hop so child and
    // grandchild execution remain connected to the selected process.
    const queue = seedKeys.map((key) => ({ key, depth: 0 }));
    const expanded = new Set();
    let qi = 0;
    while (qi < queue.length && keep.size < maxNodes) {
      const { key, depth } = queue[qi++];
      if (expanded.has(key) || depth >= descendantDepth) continue;
      expanded.add(key);
      for (const child of rankedChildrenOf(key)) {
        if (keep.size >= maxNodes) break;
        add(child.key);
        queue.push({ key: child.key, depth: depth + 1 });
      }
    }
  }

  const truncated = seedKeys.some((k) => !keep.has(k)) || keep.size >= maxNodes;
  return { keys: keep, truncated, seedCount: seedKeys.length, byKey, childMap };
};

/**
 * Collect the selected process's evidence-backed lineage. The ancestry path is
 * root → selected; descendants are bounded so UI highlighting stays useful on
 * very large service trees. Any broken/mismatched parent reference is reported
 * rather than visually inventing an edge.
 */
export const collectGraphLineage = (selectedKey, byKey, childMap, opts = {}) => {
  const ancestorKeys = [];
  const descendantKeys = new Set();
  const ancestryEdgeIds = new Set();
  const descendantEdgeIds = new Set();
  const maxAncestorHops = Math.max(1, Number(opts.maxAncestorHops) || 32);
  const maxDescendantDepth = Math.max(0, Number(opts.maxDescendantDepth) || 2);
  let brokenParent = null;

  if (!selectedKey || !byKey?.has?.(selectedKey)) {
    return {
      pathKeys: [],
      ancestorKeys,
      descendantKeys,
      ancestryEdgeIds,
      descendantEdgeIds,
      relatedKeys: new Set(),
      brokenParent,
    };
  }

  const seenAncestors = new Set([selectedKey]);
  let cur = byKey.get(selectedKey);
  let hops = 0;
  while (cur && hops++ < maxAncestorHops) {
    const rawParentKey = cur.parentKey || "";
    if (!rawParentKey) break;
    const parentKey = consistentParentKey(cur, byKey);
    if (!parentKey || !byKey.has(parentKey)) {
      brokenParent = {
        childKey: cur.key,
        parentKey: rawParentKey,
        declaredName: cur.parentProcessName || "",
        reason: parentKey ? "parent event missing" : "parent identity mismatch",
      };
      break;
    }
    if (seenAncestors.has(parentKey)) {
      brokenParent = {
        childKey: cur.key,
        parentKey,
        declaredName: cur.parentProcessName || "",
        reason: "parent cycle",
      };
      break;
    }
    seenAncestors.add(parentKey);
    ancestorKeys.unshift(parentKey);
    ancestryEdgeIds.add(`${parentKey}->${cur.key}`);
    cur = byKey.get(parentKey);
  }

  if (maxDescendantDepth > 0) {
    const queue = [{ key: selectedKey, depth: 0 }];
    const expanded = new Set();
    let qi = 0;
    while (qi < queue.length) {
      const { key, depth } = queue[qi++];
      if (expanded.has(key) || depth >= maxDescendantDepth) continue;
      expanded.add(key);
      for (const childKey of (childMap?.get?.(key) || [])) {
        const child = byKey.get(childKey);
        if (!child || consistentParentKey(child, byKey) !== key) continue;
        descendantKeys.add(childKey);
        descendantEdgeIds.add(`${key}->${childKey}`);
        queue.push({ key: childKey, depth: depth + 1 });
      }
    }
  }

  const pathKeys = [...ancestorKeys, selectedKey];
  return {
    pathKeys,
    ancestorKeys,
    descendantKeys,
    ancestryEdgeIds,
    descendantEdgeIds,
    relatedKeys: new Set([...pathKeys, ...descendantKeys]),
    brokenParent,
  };
};

/**
 * Choose a compact, analyst-useful camera target from an already-laid-out
 * graph. The default anchor is the highest-priority seed; a selected process
 * takes precedence. Full ancestors and bounded descendants are kept so the
 * first view opens on a readable chain instead of shrinking every disconnected
 * root into one thumbnail.
 */
export const selectGraphViewportKeys = (layout, opts = {}) => {
  const nodes = layout?.nodes || [];
  const edges = layout?.edges || [];
  if (!nodes.length) return new Set();

  const nodeByKey = new Map(nodes.map((n) => [n.key, n]));
  const selected = opts.selectedKey && nodeByKey.has(opts.selectedKey)
    ? nodeByKey.get(opts.selectedKey)
    : null;
  const anchor = selected || [...nodes].sort((a, b) =>
    (b.level || 0) - (a.level || 0)
    || (b.triageScore || 0) - (a.triageScore || 0)
    || Number(!!b.isSeed) - Number(!!a.isSeed)
    || String(a.ts || "").localeCompare(String(b.ts || ""))
  )[0];
  if (!anchor) return new Set();

  const maxNodes = Math.max(1, Number(opts.maxNodes) || 24);
  const ancestorHops = Math.max(0, Number(opts.ancestorHops) || 12);
  const descendantHops = Math.max(0, Number(opts.descendantHops) || 2);
  const parentByTarget = new Map();
  const childrenBySource = new Map();
  for (const edge of edges) {
    if (!nodeByKey.has(edge.source) || !nodeByKey.has(edge.target)) continue;
    parentByTarget.set(edge.target, edge.source);
    if (!childrenBySource.has(edge.source)) childrenBySource.set(edge.source, []);
    childrenBySource.get(edge.source).push(edge.target);
  }

  const keep = new Set([anchor.key]);
  let cur = anchor.key;
  let hops = 0;
  while (hops++ < ancestorHops && keep.size < maxNodes) {
    const parent = parentByTarget.get(cur);
    if (!parent || keep.has(parent)) break;
    keep.add(parent);
    cur = parent;
  }

  const queue = [{ key: anchor.key, depth: 0 }];
  let qi = 0;
  while (qi < queue.length && keep.size < maxNodes) {
    const { key, depth } = queue[qi++];
    if (depth >= descendantHops) continue;
    const children = [...(childrenBySource.get(key) || [])].sort((a, b) => {
      const an = nodeByKey.get(a) || {};
      const bn = nodeByKey.get(b) || {};
      return (bn.level || 0) - (an.level || 0)
        || (bn.triageScore || 0) - (an.triageScore || 0);
    });
    for (const child of children) {
      if (keep.size >= maxNodes) break;
      keep.add(child);
      queue.push({ key: child, depth: depth + 1 });
    }
  }
  return keep;
};

/**
 * Calculate a centered SVG pan/zoom transform for either a focused node set or
 * the full graph. A focus view may crop distant roots intentionally; analysts
 * can still use "Fit all" for the complete overview.
 */
export const calculateGraphViewport = (layout, size, opts = {}) => {
  const allNodes = layout?.nodes || [];
  const width = Math.max(1, Number(size?.w) || 1);
  const height = Math.max(1, Number(size?.h) || 1);
  if (!allNodes.length) return { x: 0, y: 0, k: 1 };

  const focusKeys = opts.focusKeys;
  let nodes = focusKeys?.size
    ? allNodes.filter((n) => focusKeys.has(n.key))
    : allNodes;
  if (!nodes.length) nodes = allNodes;

  const minX = Math.min(...nodes.map((n) => n.x));
  const minY = Math.min(...nodes.map((n) => n.y));
  const maxX = Math.max(...nodes.map((n) => n.x + n.width));
  const maxY = Math.max(...nodes.map((n) => n.y + n.height));
  const contentW = Math.max(1, maxX - minX);
  const contentH = Math.max(1, maxY - minY);
  const padX = Math.max(16, Number(opts.padX) || 88);
  const padY = Math.max(16, Number(opts.padY) || 72);
  const availableW = Math.max(40, width - padX * 2);
  const availableH = Math.max(40, height - padY * 2);
  const minScale = Math.max(0.01, Number(opts.minScale) || 0.45);
  const maxScale = Math.max(minScale, Number(opts.maxScale) || 1.05);
  const fitScale = Math.min(availableW / contentW, availableH / contentH);
  const k = Math.max(minScale, Math.min(maxScale, fitScale));
  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  return {
    x: width / 2 - centerX * k,
    y: height / 2 - centerY * k,
    k,
  };
};

/**
 * Assign layered (depth) positions within host lanes.
 * Returns { nodes, edges, width, height, hosts, stats }.
 */
export const layoutProcessGraph = (processes, detMap, opts = {}) => {
  const cfg = { ...PROCESS_GRAPH_DEFAULTS, ...opts };
  const procs = processes || [];
  if (!procs.length) {
    return {
      nodes: [],
      edges: [],
      width: cfg.padX * 2,
      height: cfg.padY * 2,
      hosts: [],
      stats: { total: 0, rendered: 0, truncated: false, seeds: 0 },
    };
  }

  const byKey = opts.byKey || new Map(procs.map((p) => [p.key, p]));
  const childMap = opts.childMap || (() => {
    const m = new Map();
    for (const p of procs) {
      if (!p.parentKey) continue;
      if (!m.has(p.parentKey)) m.set(p.parentKey, []);
      m.get(p.parentKey).push(p.key);
    }
    return m;
  })();

  const minLevel = opts.minLevel ?? 1;
  const focusKeys = opts.focusKeys || null;
  const seedKeys = opts.seedKeys || selectGraphSeedKeys(procs, detMap, {
    focusKeys,
    minLevel,
    maxSeeds: opts.maxSeeds ?? 80,
  });

  const sub = buildGraphSubgraph(procs, detMap, seedKeys, {
    maxNodes: cfg.maxNodes,
    byKey,
    childMap,
    includeChildren: opts.includeChildren,
    includeAncestors: opts.includeAncestors,
    includeBranchContext: opts.includeBranchContext,
    descendantDepth: opts.descendantDepth,
  });

  // Depth relative to subgraph roots (not global tree depth)
  const depthMap = new Map();
  const subgraphParent = (node) => {
    const pk = consistentParentKey(node, byKey);
    if (!pk || !sub.keys.has(pk)) return null;
    return pk;
  };

  // Roots = nodes whose consistent parent is outside the subgraph
  const roots = [];
  for (const k of sub.keys) {
    const n = byKey.get(k);
    if (!n) continue;
    if (!subgraphParent(n)) roots.push(n);
  }

  // BFS depth
  const queue = [];
  for (const r of roots) {
    depthMap.set(r.key, 0);
    queue.push(r.key);
  }
  let qi = 0;
  while (qi < queue.length) {
    const k = queue[qi++];
    const d = depthMap.get(k) || 0;
    for (const ck of (childMap.get(k) || [])) {
      if (!sub.keys.has(ck) || depthMap.has(ck)) continue;
      // Only walk edges that match consistentParentKey
      const child = byKey.get(ck);
      if (!child || subgraphParent(child) !== k) continue;
      depthMap.set(ck, d + 1);
      queue.push(ck);
    }
  }
  // Orphans that weren't reached (cycles / broken links) — place as roots
  for (const k of sub.keys) {
    if (!depthMap.has(k)) {
      depthMap.set(k, 0);
      roots.push(byKey.get(k));
    }
  }

  // Group roots by host for swimlanes
  const hostOf = (n) => String(n?.normHost || n?.hostname || "").trim() || "(no host)";
  const hostOrder = [];
  const hostRoots = new Map();
  const seenHost = new Set();
  // Sort roots: host, then severity, then time
  const rootScore = (n) => {
    const det = detMap?.get?.(n.key) || { level: 0, triageScore: 0 };
    return { level: det.level || 0, triage: det.triageScore || 0, ts: Number.isFinite(n.tsMs) ? n.tsMs : 0 };
  };
  roots.sort((a, b) => {
    const ha = hostOf(a);
    const hb = hostOf(b);
    if (ha !== hb) return ha.localeCompare(hb);
    const sa = rootScore(a);
    const sb = rootScore(b);
    return sb.level - sa.level || sb.triage - sa.triage || sa.ts - sb.ts;
  });
  for (const r of roots) {
    const h = hostOf(r);
    if (!seenHost.has(h)) {
      seenHost.add(h);
      hostOrder.push(h);
      hostRoots.set(h, []);
    }
    hostRoots.get(h).push(r);
  }

  // Pixel-space placement: leaf-pack vertically with variable card heights so
  // wrapped process names / user strings never need truncation.
  const nodesOut = [];
  const pos = new Map(); // key -> { depth, y, height, host }
  const maxDepthSeen = { n: 0 };
  const { nodeWidth, colGap, rowGap, padX, padY, hostGap } = cfg;

  const measureKey = (key) => {
    const n = byKey.get(key);
    if (!n) return cfg.nodeHeight || 48;
    const det = detMap?.get?.(key) || { level: 0 };
    const processName = _procBase(n);
    const subLine = buildNodeSubLine({ pid: n.pid, user: n.user, level: det.level || 0 });
    return estimateNodeHeight(processName, subLine, cfg);
  };

  const placeTree = (key, depth, host, counter) => {
    if (!sub.keys.has(key) || pos.has(key)) return;
    const node = byKey.get(key);
    if (!node) return;
    const kids = (childMap.get(key) || [])
      .filter((ck) => sub.keys.has(ck) && !pos.has(ck))
      .filter((ck) => {
        const child = byKey.get(ck);
        return child && subgraphParent(child) === key;
      })
      .map((ck) => byKey.get(ck))
      .filter(Boolean)
      .sort((a, b) => {
        const sa = rootScore(a);
        const sb = rootScore(b);
        return sb.level - sa.level || sa.ts - sb.ts;
      });

    const height = measureKey(key);
    if (kids.length === 0) {
      const y = counter.y;
      counter.y += height + rowGap;
      pos.set(key, { depth, y, height, host });
      if (depth > maxDepthSeen.n) maxDepthSeen.n = depth;
      return;
    }
    for (const kid of kids) placeTree(kid.key, depth + 1, host, counter);
    // Center parent on the span of its children.
    const childPos = kids.map((k) => pos.get(k.key)).filter(Boolean);
    let y;
    if (childPos.length) {
      const top = Math.min(...childPos.map((p) => p.y));
      const bot = Math.max(...childPos.map((p) => p.y + p.height));
      y = (top + bot) / 2 - height / 2;
      // Don't climb above the first child (keeps host lanes tidy).
      if (y < top) y = top;
    } else {
      y = counter.y;
      counter.y += height + rowGap;
    }
    pos.set(key, { depth, y, height, host });
    if (depth > maxDepthSeen.n) maxDepthSeen.n = depth;
  };

  let hostLaneY = 0;
  for (const host of hostOrder) {
    const counter = { y: 0 };
    for (const r of hostRoots.get(host) || []) {
      placeTree(r.key, 0, host, counter);
    }
    const laneKeys = [...pos.entries()].filter(([, p]) => p.host === host);
    if (laneKeys.length === 0) continue;
    const minY = Math.min(...laneKeys.map(([, p]) => p.y));
    const maxY = Math.max(...laneKeys.map(([, p]) => p.y + p.height));
    const shift = hostLaneY - minY;
    for (const [k, p] of laneKeys) {
      pos.set(k, { ...p, y: p.y + shift });
    }
    hostLaneY = maxY + shift + (hostGap || 36);
  }

  let maxX = 0;
  let maxY = 0;
  for (const k of sub.keys) {
    const n = byKey.get(k);
    if (!n) continue;
    const det = detMap?.get?.(k) || { level: 0, reason: null, triageScore: 0 };
    const processName = _procBase(n);
    const height = measureKey(k);
    const p = pos.get(k) || { depth: 0, y: hostLaneY, height, host: hostOf(n) };
    const x = padX + p.depth * (nodeWidth + colGap);
    const y = padY + p.y;
    if (x + nodeWidth > maxX) maxX = x + nodeWidth;
    if (y + (p.height || height) > maxY) maxY = y + (p.height || height);
    nodesOut.push({
      key: k,
      x,
      y,
      width: nodeWidth,
      height: p.height || height,
      depth: p.depth,
      host: p.host,
      processName,
      pid: n.pid || "",
      user: n.user || "",
      ts: n.ts || "",
      image: n.image || "",
      cmdLine: n.cmdLine || "",
      level: det.level || 0,
      reason: det.reason || null,
      triageScore: det.triageScore || 0,
      isSeed: seedKeys.includes(k),
      childCount: n.childCount || 0,
      rowid: n.rowid,
    });
  }

  // Edges — only consistent parent links inside subgraph
  const edges = [];
  for (const n of nodesOut) {
    const src = byKey.get(n.key);
    if (!src) continue;
    const pk = subgraphParent(src);
    if (!pk) continue;
    const parentPos = nodesOut.find((x) => x.key === pk);
    if (!parentPos) continue;
    const link = src.link || null;
    edges.push({
      id: `${pk}->${n.key}`,
      source: pk,
      target: n.key,
      // source right-center → target left-center
      x1: parentPos.x + parentPos.width,
      y1: parentPos.y + parentPos.height / 2,
      x2: n.x,
      y2: n.y + n.height / 2,
      level: Math.max(parentPos.level, n.level),
      confidence: link?.confidence || src.linkConfidence || "",
      sourceKind: link?.source || src.linkSource || "",
    });
  }

  // Host labels (left of first root in each host)
  const hosts = hostOrder.map((host) => {
    const hostNodes = nodesOut.filter((n) => n.host === host);
    if (!hostNodes.length) return { host, y: 0, height: 0, count: 0 };
    const minY = Math.min(...hostNodes.map((n) => n.y));
    const maxY = Math.max(...hostNodes.map((n) => n.y + n.height));
    return { host, y: minY, height: maxY - minY, count: hostNodes.length };
  }).filter((h) => h.count > 0);

  return {
    nodes: nodesOut,
    edges,
    width: maxX + padX,
    height: maxY + padY,
    hosts,
    stats: {
      total: procs.length,
      rendered: nodesOut.length,
      truncated: sub.truncated || nodesOut.length >= cfg.maxNodes,
      seeds: seedKeys.length,
      hosts: hosts.length,
      maxDepth: maxDepthSeen.n,
    },
  };
};
