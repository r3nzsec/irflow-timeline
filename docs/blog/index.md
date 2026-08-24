---
description: IRFlow Timeline release announcements, feature deep dives, and digital forensics workflow updates.
---

# IRFlow Timeline Blog

Release announcements and focused notes about new forensic workflows.

## Latest

### [IRFlow Timeline 1.0.12 — Diff Tabs, and a Triage Layer That Was Losing Work](/blog/v1.0.12-diff-tabs-and-triage)

**August 24, 2026**

Diff any two imported files into an Added / Removed / Changed timeline with field-level before/after. Plus two corrections: the tag and bookmark layer was silently discarding annotations in four separate ways — including every tag written during the post-import index build — and every DMG the project has published was an unsigned disk image that tripped Gatekeeper on download.

## Previous Releases

### [IRFlow Timeline 1.0.11 — Computer History, Verified Against the Artifact](/blog/v1.0.11-computer-history-verified)

**August 16, 2026**

Four claims IRFlow made about Computer History were wrong, and only fell over against a live capture: credential rows do not recover passwords, capture fidelity follows the UI toolkit rather than the app category, and a continuity check was clearing gaps it never assessed. Plus nine stores nobody was reading — the consolidated memory that outlives a cleared history, Claude Desktop deletion tombstones and staged uploads, and the Grok session index that survives deleting the session.

### [IRFlow Timeline 1.0.10 — ChatGPT Computer History](/blog/v1.0.10-computer-history)

**August 14, 2026**

ChatGPT Computer History becomes a new macOS artifact family: a timeline of what was typed, clicked, selected, and dragged, with credential-entry flagging, detection of cleared history, recovery of deleted activity summaries, and host attribution.

### [IRFlow Timeline 1.0.9 — Large EVTX Imports Fixed](/blog/v1.0.9-large-evtx-imports)

**July 27, 2026**

Bounded 64 KiB EVTX chunk parsing removes the Node 2 GiB failure, supports Windows Event Logs up to the format's approximately 4 GiB ceiling, and prevents duplicate pending imports and error notifications.

### [IRFlow Timeline 1.0.8 — AI Application Forensics Expanded](/blog/v1.0.8-ai-application-forensics)

**July 27, 2026**

Grok Build support, deeper Claude Desktop/Cowork and Codex recovery, exact AI tool-command evidence, collection-scale triage, and major Process Inspector improvements.
