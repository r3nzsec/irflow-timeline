import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  buildNodeSubLine,
  calculateGraphViewport,
  collectGraphLineage,
  layoutProcessGraph,
  selectGraphSeedKeys,
  selectGraphViewportKeys,
} from "../../../utils/process-graph-layout.js";
import { PI_TYPOGRAPHY } from "../constants.js";

/**
 * SVG node-link process graph with pan/zoom.
 * Click a node to select; detail panel is owned by the parent modal.
 */
export default function ProcessGraphView({
  processes,
  detMap,
  byKeyMap,
  childMap,
  selectedKey,
  focusKeys = null,
  minLevel = 1,
  th,
  onSelect,
  ptIcon,
}) {
  const wrapRef = useRef(null);
  const [size, setSize] = useState({ w: 800, h: 500 });
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [showOverview, setShowOverview] = useState(false);
  const dragRef = useRef(null);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect;
      if (!cr) return;
      setSize({ w: Math.max(200, cr.width), h: Math.max(200, cr.height) });
    });
    ro.observe(el);
    setSize({ w: Math.max(200, el.clientWidth), h: Math.max(200, el.clientHeight) });
    return () => ro.disconnect();
  }, []);

  const effectiveFocusKeys = useMemo(() => {
    if (!selectedKey) return focusKeys;
    // Selected node is first so a large story/cluster focus cannot push it
    // beyond the graph seed cap.
    return new Set([selectedKey, ...(focusKeys || [])]);
  }, [focusKeys, selectedKey]);

  const compactFocusKeys = useMemo(() => {
    if (selectedKey) return new Set([selectedKey]);
    if (focusKeys?.size) {
      const ranked = [...focusKeys]
        .filter((key) => byKeyMap?.has?.(key))
        .sort((a, b) => {
          const ad = detMap?.get?.(a) || {};
          const bd = detMap?.get?.(b) || {};
          return (bd.level || 0) - (ad.level || 0)
            || (bd.triageScore || 0) - (ad.triageScore || 0);
        });
      if (ranked[0]) return new Set([ranked[0]]);
    }
    return new Set(selectGraphSeedKeys(processes, detMap, {
      minLevel,
      maxSeeds: 1,
    }));
  }, [selectedKey, focusKeys, byKeyMap, processes, detMap, minLevel]);

  const layout = useMemo(() => layoutProcessGraph(processes, detMap, {
    byKey: byKeyMap,
    childMap,
    focusKeys: showOverview ? effectiveFocusKeys : compactFocusKeys,
    minLevel,
    maxNodes: showOverview ? (selectedKey ? 160 : 180) : 24,
    maxSeeds: showOverview ? 80 : 1,
    descendantDepth: showOverview ? (selectedKey ? 3 : 2) : 3,
    includeBranchContext: showOverview,
  }), [processes, detMap, byKeyMap, childMap, effectiveFocusKeys, compactFocusKeys, minLevel, selectedKey, showOverview]);

  const lineage = useMemo(
    () => collectGraphLineage(selectedKey, byKeyMap, childMap, { maxDescendantDepth: 3 }),
    [selectedKey, byKeyMap, childMap],
  );
  const layoutNodeMap = useMemo(
    () => new Map(layout.nodes.map((n) => [n.key, n])),
    [layout.nodes],
  );
  const pathLabel = useMemo(() => {
    if (!lineage.pathKeys.length) return "";
    const names = lineage.pathKeys.map((key) => {
      const p = byKeyMap?.get?.(key);
      return String(p?.processName || p?.image || "(unknown)").split(/[/\\]/).pop();
    });
    const visible = names.length > 6 ? ["…", ...names.slice(-5)] : names;
    return visible.join(" › ");
  }, [lineage.pathKeys, byKeyMap]);
  const viewportFocusKeys = useMemo(
    () => selectGraphViewportKeys(layout, { selectedKey }),
    [layout, selectedKey],
  );

  useEffect(() => {
    if (selectedKey) setShowOverview(false);
  }, [selectedKey]);

  // Open on the highest-value local chain at a readable zoom. Fitting every
  // disconnected root made large investigations render as a tiny thumbnail.
  useEffect(() => {
    if (!layout.nodes.length || size.w < 40 || size.h < 40) return;
    setView(calculateGraphViewport(layout, size, showOverview ? {
      minScale: 0.01,
      maxScale: 1.05,
      padX: 48,
      padY: 48,
    } : {
      focusKeys: viewportFocusKeys,
      minScale: 0.45,
      maxScale: 1.05,
    }));
  }, [layout, size.w, size.h, viewportFocusKeys, showOverview]);

  // Pan selected node into view (soft)
  useEffect(() => {
    if (!selectedKey || !layout.nodes.length) return;
    const n = layout.nodes.find((x) => x.key === selectedKey);
    if (!n) return;
    const cx = n.x + n.width / 2;
    const cy = n.y + n.height / 2;
    setView((v) => {
      const sx = cx * v.k + v.x;
      const sy = cy * v.k + v.y;
      const margin = 80;
      let nx = v.x;
      let ny = v.y;
      if (sx < margin) nx += margin - sx;
      else if (sx > size.w - margin) nx -= sx - (size.w - margin);
      if (sy < margin) ny += margin - sy;
      else if (sy > size.h - margin) ny -= sy - (size.h - margin);
      if (nx === v.x && ny === v.y) return v;
      return { ...v, x: nx, y: ny };
    });
  }, [selectedKey, layout, size.w, size.h]);

  const onWheel = useCallback((e) => {
    e.preventDefault();
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) return;
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    setView((v) => {
      const k = Math.max(0.12, Math.min(2.5, v.k * factor));
      // Zoom toward cursor
      const x = mx - (mx - v.x) * (k / v.k);
      const y = my - (my - v.y) * (k / v.k);
      return { x, y, k };
    });
  }, []);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [onWheel]);

  const onPointerDown = (e) => {
    if (e.button !== 0) return;
    // Don't start pan when clicking a node (nodes stopPropagation)
    dragRef.current = { px: e.clientX, py: e.clientY, vx: view.x, vy: view.y, moved: false };
    e.currentTarget.setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e) => {
    const d = dragRef.current;
    if (!d) return;
    const dx = e.clientX - d.px;
    const dy = e.clientY - d.py;
    if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true;
    setView((v) => ({ ...v, x: d.vx + dx, y: d.vy + dy }));
  };
  const onPointerUp = () => { dragRef.current = null; };

  const focusView = () => {
    if (!layout.nodes.length) return;
    setShowOverview(false);
    if (showOverview) return;
    setView(calculateGraphViewport(layout, size, {
      focusKeys: viewportFocusKeys,
      minScale: 0.45,
      maxScale: 1.05,
    }));
  };

  const fitAllView = () => {
    if (!layout.nodes.length) return;
    setShowOverview(true);
    if (!showOverview) return;
    setView(calculateGraphViewport(layout, size, {
      minScale: 0.01,
      maxScale: 1.05,
      padX: 48,
      padY: 48,
    }));
  };

  const levelColor = (lv) => {
    if (lv >= 2) return th.accent;
    if (lv >= 1) return th.textDim;
    return th.border;
  };

  return (
    <div ref={wrapRef} style={{ flex: 1, minHeight: 0, minWidth: 0, position: "relative", overflow: "hidden", background: th.modalBg }}>
      {/* HUD */}
      <div style={{ position: "absolute", top: 8, left: 10, zIndex: 2, display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap", pointerEvents: "none" }}>
        <span style={{ fontSize: PI_TYPOGRAPHY.control, color: th.textMuted, fontFamily: "-apple-system, sans-serif", background: `${th.panelBg}cc`, border: `1px solid ${th.border}33`, borderRadius: 6, padding: "3px 8px", backdropFilter: "blur(8px)" }}>
          {showOverview ? "Overview" : "Focused chain"} · {layout.stats.rendered.toLocaleString()} of {layout.stats.total.toLocaleString()} processes
          {layout.stats.hosts > 1 ? ` · ${layout.stats.hosts} hosts` : ""}
          {layout.stats.truncated ? " · truncated" : ""}
        </span>
        <span style={{ fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif", pointerEvents: "auto" }}>
          Select a process to trace ancestors and descendants
        </span>
      </div>
      {selectedKey && pathLabel && (
        <div style={{
          position: "absolute",
          top: 34,
          left: 10,
          right: 118,
          zIndex: 2,
          display: "flex",
          gap: 6,
          alignItems: "center",
          minWidth: 0,
          pointerEvents: "none",
        }}>
          <span style={{
            flex: "0 0 auto",
            fontSize: PI_TYPOGRAPHY.meta,
            color: th.accent,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: "0.07em",
            fontFamily: "-apple-system, sans-serif",
          }}>
            Ancestry
          </span>
          <span title={pathLabel} style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontSize: PI_TYPOGRAPHY.meta,
            color: th.textDim,
            fontFamily: "'SF Mono', Menlo, monospace",
            background: `${th.panelBg}ee`,
            border: `1px solid ${th.border}55`,
            borderRadius: 4,
            padding: "3px 7px",
          }}>
            {pathLabel}
          </span>
          {lineage.descendantKeys.size > 0 && (
            <span style={{ flex: "0 0 auto", fontSize: PI_TYPOGRAPHY.meta, color: th.textMuted, fontFamily: "-apple-system, sans-serif" }}>
              + {lineage.descendantKeys.size} downstream
            </span>
          )}
          {lineage.brokenParent && (
            <span title={`${lineage.brokenParent.reason}: ${lineage.brokenParent.declaredName || lineage.brokenParent.parentKey}`} style={{ flex: "0 0 auto", fontSize: PI_TYPOGRAPHY.meta, color: th.accent, fontFamily: "-apple-system, sans-serif" }}>
              ancestry stops at unresolved parent
            </span>
          )}
        </div>
      )}
      <div style={{ position: "absolute", top: 8, right: 10, zIndex: 2, display: "flex", gap: 4 }}>
        <button type="button" onClick={focusView} title="Render and center the highest-priority local process chain" style={{ padding: "3px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: !showOverview ? `${th.accent}18` : th.btnBg, color: !showOverview ? th.accent : th.textDim, border: `1px solid ${!showOverview ? th.accent + "55" : th.border}`, fontFamily: "-apple-system, sans-serif" }}>Focus</button>
        <button type="button" onClick={fitAllView} title="Render the broader process overview and fit it into the viewport" style={{ padding: "3px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: showOverview ? `${th.accent}18` : th.btnBg, color: showOverview ? th.accent : th.textDim, border: `1px solid ${showOverview ? th.accent + "55" : th.border}`, fontFamily: "-apple-system, sans-serif" }}>Fit all</button>
        <button type="button" onClick={() => setView((v) => ({ ...v, k: Math.min(2.5, v.k * 1.15) }))} style={{ padding: "3px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}>+</button>
        <button type="button" onClick={() => setView((v) => ({ ...v, k: Math.max(0.12, v.k / 1.15) }))} style={{ padding: "3px 8px", fontSize: PI_TYPOGRAPHY.control, borderRadius: 4, cursor: "pointer", background: th.btnBg, color: th.textDim, border: `1px solid ${th.border}`, fontFamily: "-apple-system, sans-serif" }}>−</button>
      </div>

      {layout.nodes.length === 0 ? (
        <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: th.textMuted, fontSize: PI_TYPOGRAPHY.body, fontFamily: "-apple-system, sans-serif" }}>
          No processes to graph for the current filter. Try Hunt/Raw detections or clear severity filters.
        </div>
      ) : (
        <svg
          width="100%"
          height="100%"
          style={{ cursor: dragRef.current ? "grabbing" : "grab", touchAction: "none" }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={onPointerUp}
        >
          <defs>
            <marker id="pi-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={th.textMuted} />
            </marker>
            <marker id="pi-arrow-accent" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill={th.accent} />
            </marker>
          </defs>
          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {/* Host swimlane labels */}
            {layout.hosts.map((h) => {
              const hostLabel = String(h.host || "");
              const maxHostChars = 22;
              const hostText = hostLabel.length > maxHostChars
                ? `${hostLabel.slice(0, maxHostChars - 1)}…`
                : hostLabel;
              return (
                <g key={h.host}>
                  <text
                    x={12}
                    y={h.y - 8}
                    fill={th.textMuted}
                    fontSize={11}
                    fontFamily="'SF Mono', Menlo, monospace"
                    fontWeight={600}
                  >
                    {hostText}
                  </text>
                  <line
                    x1={8}
                    y1={h.y - 2}
                    x2={8}
                    y2={h.y + h.height + 4}
                    stroke={`${th.border}66`}
                    strokeWidth={2}
                    strokeLinecap="round"
                  />
                </g>
              );
            })}

            {/* Edges */}
            {layout.edges.map((e) => {
              const midX = (e.x1 + e.x2) / 2;
              const isAncestry = lineage.ancestryEdgeIds.has(e.id);
              const isDownstream = lineage.descendantEdgeIds.has(e.id);
              const isRelated = isAncestry || isDownstream;
              const color = isRelated ? th.accent : e.level > 0 ? levelColor(e.level) : th.textMuted;
              const conf = e.confidence === "high" ? 0.9 : e.confidence === "medium" ? 0.65 : 0.4;
              const sourceNode = layoutNodeMap.get(e.source);
              const targetNode = layoutNodeMap.get(e.target);
              const linkLabel = e.sourceKind === "guid" ? "Process GUID"
                : e.sourceKind === "pid-logon" ? "PID + logon"
                : e.sourceKind === "pid-session" ? "PID + session"
                : e.sourceKind === "pid-host" ? "PID + host"
                : e.sourceKind || "resolved parent";
              const shortLinkLabel = e.sourceKind === "guid" ? "GUID"
                : e.sourceKind === "pid-logon" ? "PID + logon"
                : e.sourceKind === "pid-session" ? "PID + session"
                : e.sourceKind === "pid-host" ? "PID + host"
                : "parent";
              return (
                <g key={e.id}>
                  <path
                    d={`M ${e.x1} ${e.y1} C ${midX} ${e.y1}, ${midX} ${e.y2}, ${e.x2} ${e.y2}`}
                    fill="none"
                    stroke={color}
                    strokeOpacity={selectedKey && !isRelated ? 0.18 : isRelated ? 0.95 : 0.35 + conf * 0.25}
                    strokeWidth={isAncestry ? 2.8 : isDownstream ? 2 : e.level >= 2 ? 1.8 : 1.2}
                    markerEnd={isRelated ? "url(#pi-arrow-accent)" : "url(#pi-arrow)"}
                  >
                    <title>{[
                      `${sourceNode?.processName || e.source} → ${targetNode?.processName || e.target}`,
                      `Link: ${linkLabel}`,
                      e.confidence ? `Confidence: ${e.confidence}` : null,
                    ].filter(Boolean).join("\n")}</title>
                  </path>
                  {isAncestry && (
                    <text
                      x={midX}
                      y={(e.y1 + e.y2) / 2 - 5}
                      textAnchor="middle"
                      fill={th.textMuted}
                      fontSize={8}
                      fontFamily="'SF Mono', Menlo, monospace"
                      pointerEvents="none"
                    >
                      {shortLinkLabel}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Nodes — full labels wrap onto new lines; card height grows to fit */}
            {layout.nodes.map((n, idx) => {
              const isSel = n.key === selectedKey;
              const isAncestry = lineage.ancestorKeys.includes(n.key);
              const isDownstream = lineage.descendantKeys.has(n.key);
              const isRelated = !selectedKey || lineage.relatedKeys.has(n.key);
              const col = n.level > 0 ? levelColor(n.level) : th.border;
              const fill = isSel ? `${th.accent}20`
                : isAncestry ? `${th.accent}0d`
                : isDownstream ? `${th.accent}08`
                : `${th.panelBg}ee`;
              const stroke = isSel || isAncestry || isDownstream ? th.accent : col;
              const padL = 8;
              const padR = n.isSeed && n.level > 0 ? 16 : 8;
              const contentX = padL;
              const contentW = Math.max(36, n.width - padL - padR);
              const titleColor = isSel ? th.accent : th.text;
              const subLine = buildNodeSubLine(n);
              const clipId = `pi-node-clip-${idx}`;
              return (
                <g
                  key={n.key}
                  transform={`translate(${n.x},${n.y})`}
                  opacity={isRelated ? 1 : 0.48}
                  style={{ cursor: "pointer" }}
                  onPointerDown={(ev) => ev.stopPropagation()}
                  onClick={(ev) => {
                    ev.stopPropagation();
                    onSelect?.(n.key);
                  }}
                >
                  <title>{[
                    n.processName,
                    isSel ? "Selected process" : isAncestry ? "Ancestor of selected process" : isDownstream ? "Descendant of selected process" : null,
                    n.pid ? `PID ${n.pid}` : null,
                    n.user || null,
                    n.reason || null,
                    n.image || null,
                    (n.ts || "").slice(0, 19) || null,
                  ].filter(Boolean).join("\n")}</title>
                  <defs>
                    <clipPath id={clipId}>
                      <rect x="0" y="0" width={n.width} height={n.height} rx="8" ry="8" />
                    </clipPath>
                  </defs>
                  <rect
                    width={n.width}
                    height={n.height}
                    rx={8}
                    ry={8}
                    fill={fill}
                    stroke={stroke}
                    strokeWidth={isSel ? 2.2 : 1.2}
                  />
                  <g clipPath={`url(#${clipId})`}>
                    <foreignObject
                      x={contentX}
                      y={0}
                      width={contentW}
                      height={n.height}
                      style={{ overflow: "hidden", pointerEvents: "none" }}
                    >
                      <div
                        xmlns="http://www.w3.org/1999/xhtml"
                        style={{
                          width: `${contentW}px`,
                          maxWidth: `${contentW}px`,
                          minHeight: `${n.height}px`,
                          display: "flex",
                          flexDirection: "column",
                          justifyContent: "center",
                          gap: 2,
                          boxSizing: "border-box",
                          padding: "6px 2px",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "flex-start",
                            gap: 5,
                            minWidth: 0,
                            maxWidth: "100%",
                          }}
                        >
                          {typeof ptIcon === "function" && (
                            <span style={{ flexShrink: 0, width: 14, height: 14, display: "flex", alignItems: "center", justifyContent: "center", marginTop: 1 }}>
                              {ptIcon(n.processName)}
                            </span>
                          )}
                          <span
                            style={{
                              flex: "1 1 auto",
                              minWidth: 0,
                              maxWidth: "100%",
                              fontFamily: "'SF Mono', Menlo, monospace",
                              fontSize: PI_TYPOGRAPHY.title,
                              fontWeight: 700,
                              color: titleColor,
                              lineHeight: "16px",
                              whiteSpace: "normal",
                              overflowWrap: "anywhere",
                              wordBreak: "break-word",
                            }}
                          >
                            {n.processName}
                          </span>
                        </div>
                        <div
                          style={{
                            maxWidth: "100%",
                            fontFamily: "'SF Mono', Menlo, monospace",
                            fontSize: PI_TYPOGRAPHY.meta,
                            color: th.textMuted,
                            lineHeight: "12px",
                            paddingLeft: typeof ptIcon === "function" ? 19 : 0,
                            whiteSpace: "normal",
                            overflowWrap: "anywhere",
                            wordBreak: "break-word",
                          }}
                        >
                          {subLine}
                        </div>
                      </div>
                    </foreignObject>
                    {n.isSeed && n.level > 0 && (
                      <circle cx={n.width - 10} cy={10} r={4} fill={col} stroke={th.modalBg} strokeWidth={1} />
                    )}
                  </g>
                </g>
              );
            })}
          </g>
        </svg>
      )}
    </div>
  );
}
