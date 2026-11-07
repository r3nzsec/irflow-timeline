---
description: Complete list of auto-detected KAPE and EZ Tools profiles with column configurations and detection criteria.
---

# KAPE Profiles

Complete list of auto-detected KAPE / EZ Tool profiles with their column configurations.

## EZ Tools Profiles

### MFTECmd

**Detection:** Columns include `EntryNumber`, `ParentEntryNumber`, `InUse`

| Category | Columns |
|----------|---------|
| **Pinned** | FileName, ParentPath, Extension |
| **Prioritized** | FileSize, Created0x10, LastModified0x10, IsDirectory |
| **Hidden** | EntryNumber, SequenceNumber, ReferenceCount, ReparseTarget |
| **Auto-color** | Extension |

### EvtxECmd

**Detection:** Columns include `PayloadData1`, `Channel`, `Provider`

| Category | Columns |
|----------|---------|
| **Pinned** | TimeCreated, EventId, Channel |
| **Prioritized** | Computer, PayloadData1, PayloadData2, PayloadData3 |
| **Hidden** | ChunkNumber, Keywords, Opcode, RecordNumber |
| **Auto-color** | Channel |

### PECmd (Prefetch)

**Detection:** Columns include `ExecutableName`, `RunCount`, `SourceFilename`

| Category | Columns |
|----------|---------|
| **Pinned** | ExecutableName, RunCount |
| **Prioritized** | LastRun, PreviousRun0-6, SourceFilename, Volume |
| **Auto-color** | ExecutableName |

### LECmd (LNK Files)

**Detection:** Columns include `SourceFile`, `TargetPath`, `Arguments`

| Category | Columns |
|----------|---------|
| **Pinned** | SourceFile, TargetPath |
| **Prioritized** | Arguments, WorkingDirectory, CreatedOn, ModifiedOn |
| **Auto-color** | TargetPath |

### AmcacheParser (Files)

**Detection:** Columns include `ProgramId`, `SHA1`, `FullPath`

| Category | Columns |
|----------|---------|
| **Pinned** | FullPath, SHA1 |
| **Prioritized** | FileSize, CompileTime, BinaryType, Publisher |

### AmcacheParser (Programs)

**Detection:** Columns include `ProgramId`, `Name`, `Publisher`, `InstallDate`

| Category | Columns |
|----------|---------|
| **Pinned** | Name, Version |
| **Prioritized** | Publisher, InstallDate, UninstallString |

### RECmd (Registry)

**Detection:** Columns include `HivePath`, `Key`, `ValueName`, `ValueData`

| Category | Columns |
|----------|---------|
| **Pinned** | HivePath, Key, ValueName |
| **Prioritized** | ValueData, LastWriteTimestamp, ValueType |
| **Auto-color** | HivePath |

### SBECmd (ShellBags)

**Detection:** Columns include `AbsolutePath`, `ShellType`

| Category | Columns |
|----------|---------|
| **Pinned** | AbsolutePath, ShellType |
| **Prioritized** | LastWriteTime, MFTEntry, CreatedOn |

### SrumECmd (SRUM)

**Detection:** Columns include `ExeInfo`, `AppId`

| Category | Columns |
|----------|---------|
| **Pinned** | ExeInfo, AppId |
| **Prioritized** | Timestamp, NetworkUsage, ForegroundTime |

### AppCompatcache (Shimcache)

**Detection:** Columns include `ControlSet`, `CacheEntryPosition`, `Path`

| Category | Columns |
|----------|---------|
| **Pinned** | Path, LastModifiedTime |
| **Prioritized** | Executed, CacheEntryPosition |

### JLECmd (Jump Lists)

**Detection:** Columns include `SourceFile` and jump list-specific columns

| Category | Columns |
|----------|---------|
| **Pinned** | FileName, TargetPath |
| **Prioritized** | Arguments, CreatedOn, ModifiedOn |

## Timeline Format Profiles

### ForensicTimeline

**Detection:** Columns include `datetime`, `timestamp_desc`, `source`, `sourcetype`

| Category | Columns |
|----------|---------|
| **Pinned** | datetime, source, sourcetype |
| **Prioritized** | timestamp_desc, message, filename, display_name |
| **Auto-color** | source |

### Plaso SuperTimeline

**Detection:** Columns include `datetime`, `source`, `sourcetype`, `type`, `display_name`

| Category | Columns |
|----------|---------|
| **Pinned** | datetime, source, type |
| **Prioritized** | sourcetype, display_name, message, filename |
| **Auto-color** | source |

### MacTime (Bodyfile)

**Detection:** Columns include `Date`, `Size`, `Type`, `Mode`, `File Name`

| Category | Columns |
|----------|---------|
| **Pinned** | Date, File Name, Type |
| **Prioritized** | Size, Mode, UID, GID |

### KapeMiniTimeline

**Detection:** Columns include `Date`, `Time`, `Source`, `Short`, `Desc`

| Category | Columns |
|----------|---------|
| **Pinned** | Date, Time, Source |
| **Prioritized** | Type, Short, Desc |
| **Auto-color** | Source |

### PsortTimeline (Plaso)

**Detection:** Columns include `Timestamp`, `TimestampDescription`, `Source`, `SourceLong`

| Category | Columns |
|----------|---------|
| **Pinned** | Timestamp, Source |
| **Prioritized** | TimestampDescription, SourceLong |
| **Auto-color** | Source |

## Security Tool Profiles

Hayabusa's own profiles and outputs are recognized by their [Hayabusa Templates](/reference/hayabusa-templates). The two Hayabusa profiles below cover CSVs from custom Hayabusa profiles, and color rows by level the same way.

### Hayabusa (Standard)

**Detection:** Columns include `Timestamp`, `RuleTitle`, `Level`, `Computer`

| Category | Columns |
|----------|---------|
| **Pinned** | Timestamp, RuleTitle, Level |
| **Prioritized** | Computer, Channel, RuleFile |
| **Level colors** | Level, as in [Hayabusa Templates](/reference/hayabusa-templates#level-colors) |

### Hayabusa (Verbose)

**Detection:** Columns include `Timestamp`, `RuleTitle`, `Level`, `Details`, `ExtraFieldInfo`

| Category | Columns |
|----------|---------|
| **Pinned** | Timestamp, RuleTitle, Level |
| **Prioritized** | Details, ExtraFieldInfo, Computer |
| **Level colors** | Level, as in [Hayabusa Templates](/reference/hayabusa-templates#level-colors) |

### Chainsaw (Logons)

**Detection:** Columns include `system_time`, `id`, `workstation_name`, `target_username`, `source_ip`, `logon_type`

| Category | Columns |
|----------|---------|
| **Pinned** | system_time, target_username |
| **Prioritized** | source_ip, logon_type, workstation_name |
| **Auto-color** | logon_type |

### Chainsaw (Command Line Hunt)

**Detection:** Columns include `system_time`, `id`, `detection_rules`, `Event.EventData.CommandLine`, `process_name`

| Category | Columns |
|----------|---------|
| **Pinned** | system_time, detection_rules |
| **Prioritized** | Event.EventData.CommandLine, process_name, computer_name |
| **Auto-color** | detection_rules |

### Chainsaw (Process Creation Hunt)

**Detection:** Columns include `system_time`, `id`, `detection_rules`, `Event.EventData.Image`, `command_line`

| Category | Columns |
|----------|---------|
| **Pinned** | system_time, detection_rules |
| **Prioritized** | Event.EventData.Image, command_line, computer_name |
| **Auto-color** | detection_rules |

### Chainsaw (Registry Hunt)

**Detection:** Columns include `system_time`, `id`, `detection_rules`, `Event.EventData.Details`, `target_object`

| Category | Columns |
|----------|---------|
| **Pinned** | system_time, detection_rules |
| **Prioritized** | Event.EventData.Details, target_object, computer_name |
| **Auto-color** | detection_rules |

### Chainsaw (File Creation Hunt)

**Detection:** Columns include `system_time`, `id`, `detection_rules`, `Event.EventData.TargetFilename`, `image`

| Category | Columns |
|----------|---------|
| **Pinned** | system_time, detection_rules |
| **Prioritized** | Event.EventData.TargetFilename, image, computer_name |
| **Auto-color** | detection_rules |

### Chainsaw (Sigma)

**Detection:** Columns include `Timestamp`, `RuleTitle`, `Level`, `Channel`, `MitreTactics`

| Category | Columns |
|----------|---------|
| **Pinned** | Timestamp, RuleTitle, Level |
| **Prioritized** | Channel, MitreTactics |
| **Auto-color** | Level |

### BrowsingHistoryView

**Detection:** Columns include `URL`, `Title`, `Visit Time`, `Web Browser`

| Category | Columns |
|----------|---------|
| **Pinned** | Visit Time, URL, Title |
| **Prioritized** | Web Browser, Visit Count, Visit Type |
| **Auto-color** | Web Browser |

### KAPE Copy Log

**Detection:** Columns include `CopiedTimestamp`, `SourceFile`, `DestinationFile`, `SourceFileSha1`

| Category | Columns |
|----------|---------|
| **Pinned** | CopiedTimestamp, SourceFile |
| **Prioritized** | DestinationFile, SourceFileSha1 |
