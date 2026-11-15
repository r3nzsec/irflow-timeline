/** The Tags cell offers tag choices directly, without the general event actions. */
export default function RowTagMenu({ th, palette = {}, currentTags = [], targetCount = 1, onToggle, onClear }) {
  const entries = [...Object.entries(palette),
    ...currentTags.filter((tag) => !Object.hasOwn(palette, tag)).map((tag) => [tag, th.textMuted])];
  const style = { display: "flex", alignItems: "center", gap: 8, width: "calc(100% - 8px)",
    padding: "6px 12px", margin: "0 4px", background: "none", border: "none", borderRadius: 6,
    color: th.text, fontSize: 12, textAlign: "left", cursor: "pointer",
    fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif" };
  const hover = {
    onMouseEnter: (e) => { e.currentTarget.style.background = `${th.accent}22`; },
    onMouseLeave: (e) => { e.currentTarget.style.background = "transparent"; },
  };
  const scope = targetCount > 1 ? `${targetCount.toLocaleString()} selected events` : "this event";
  return <div data-row-tag-menu="" style={{ width: 240, maxWidth: "calc(100vw - 24px)", maxHeight: "calc(100vh - 32px)", overflowY: "auto" }}>
    {entries.map(([tag, color]) => {
      const hasTag = currentTags.includes(tag);
      return <button key={tag} type="button" role="menuitemcheckbox" aria-checked={hasTag}
        {...hover} style={style} title={`${hasTag ? "Remove" : "Apply"} ${tag} on ${scope}`}
        onClick={() => onToggle(tag, !hasTag)}>
        <span aria-hidden="true" style={{ color }}>{hasTag ? "●" : "○"}</span>
        <span style={{ whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{tag}</span>
      </button>;
    })}
    <div role="separator" style={{ height: 1, background: th.border, margin: "4px 8px" }} />
    <button type="button" role="menuitem" {...hover}
      disabled={targetCount <= 1 && currentTags.length === 0}
      title={`Clear all tags from ${scope}`} onClick={onClear}
      style={{ ...style, opacity: targetCount <= 1 && currentTags.length === 0 ? 0.4 : 1 }}>Clear</button>
  </div>;
}
