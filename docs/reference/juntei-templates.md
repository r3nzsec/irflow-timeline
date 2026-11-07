---
description: The column templates IRFlow Timeline uses to recognize every CSV that Juntei writes, and each one's timestamp columns.
---

# Juntei Templates

IRFlow Timeline recognizes every CSV that [Juntei](https://github.com/Yamato-Security/juntei) 1.0.0 writes, from `juntei auto-parse` and from each `juntei parse-…` and `juntei persistence-hunter` command. Each output has a template listing its columns and, explicitly, which of them are timestamps.

When you open a Juntei CSV:

- The status bar shows the format, for example **Juntei MFT** or **Juntei Registry ShimCache**.
- **Only the template's timestamp columns are timestamps.** They get the ⏱ mark, your date format and time zone, chronological sorting, date-range filters, the histogram and the Timestamp Converter.
- **Every other column stays as written**, even when its name contains "Time" or "Date" or a value looks like a date. Without a template, IRFlow guesses timestamp columns from their names, and on Juntei's outputs that guess missed 56 timestamp columns (`MetadataChanged (SI)`, `LastRun`, `PreviousRun1`–`7`, `LastRunUTC`, `FirstConnectedUTC`, …) and took 33 other columns for timestamps (`UpdateSequenceNumber`, `StartType`, `FocusTimeMs`, `RedoTimes`, …).

## How a file is matched

A CSV is a template's output when its header row has every column of the template and no other column, in any order. Some outputs have optional columns:

- **Juntei MFT**: `-i` adds `ResidentDataBase64`, `ResidentDataHex` and `ResidentDataASCII`; `-x` adds `FromSlack`, `SlackRecord`, `SlackOffset` and `CopyOfEntryInUse`. None of them is a timestamp.
- **Juntei SRUM EnergyUsage**: some databases add `EventTimestamp` (a timestamp), `StateTransition`, `ChargeLevel`, `BatteryCount` and `BatteryChargeLimited`.
- **Juntei SRUM (other tables)**: for a SRUM table without a parser of its own, Juntei writes the common columns (`ID`, `Timestamp`, `EXE-Info`, …) followed by the table's columns as stored. Only `Timestamp` and `EXE-Timestamp` are timestamps.

A file with a column its template doesn't list (a CSV edited by hand, or from another Juntei version) is not matched, and IRFlow falls back to guessing from the column names. Juntei's JSON and JSONL outputs aren't covered: IRFlow opens the CSV outputs.

## Columns that are deliberately not timestamps

These columns hold dates or times but are not points in time IRFlow can convert, so they stay text:

| Columns | Format | Why |
|---|---|---|
| `FirstConnectedLocal`, `LastConnectedLocal` | Juntei Registry Networks | Local wall-clock times with no UTC offset. `FirstConnectedUTC` and `LastConnectedUTC` are the timestamps. |
| `ItemModifiedUTC`, `ItemCreatedUTC`, `ItemAccessedUTC` | Juntei Registry ShellBags, Juntei Registry OpenSaveMRU | FAT clocks from shell items, which carry no offset; Juntei's `-Z` leaves them unconverted too. |
| `RedoTimes`, `UndoTimes` | Juntei $LogFile | JSON holding several times. |
| `ValueData` | Juntei Registry Dump | Registry data as written; a few values happen to be dates. |
| `ForegroundCycleTime`, `BackgroundCycleTime`, `FaceTime`, `ConnectedTime`, `ActiveAcTime`, `ProcessorTime`, … | SRUM formats | Counters and durations. |
| `…Filetime`, `InstallDateRaw` | Registry formats | The raw value next to its decoded timestamp column. |

Some dates are written as the source stores them: `LinkDate` (like `03/15/2024 08:30:00`) and `InstallDate`, `FirstInstallDate` and `DriverVerDate` (like `03-15-2024`) in Amcache, and `InstallDate` (like `2024-03-15`) in Installed Programs. These are timestamps: IRFlow reads them month first, as UTC.

## Templates

### NTFS

| Format (status bar) | Written by | Timestamp columns |
|---|---|---|
| Juntei MFT | `auto-parse` → `FileSystem/MFT.csv`<br>`juntei parse-ntfs mft` | `DataModified (SI)`, `DataModified (FN)`, `Accessed (SI)`, `Accessed (FN)`, `MetadataChanged (SI)`, `MetadataChanged (FN)`, `Created (SI)`, `Created (FN)` |
| Juntei MFT (ys-ntfs-parser CSV) | `juntei parse-ntfs mft -t ys-ntfs-parser-csv` | `StandardInfoLastModified`, `StandardInfoLastAccess`, `StandardInfoCreated`, `FileNameLastModified`, `FileNameLastAccess`, `FileNameCreated`, `StandardInfoLastMFT-Modified`, `FileNameLastMFT-Modified` |
| Juntei USN Journal | `auto-parse` → `FileSystem/UsnJournal.csv`<br>`juntei parse-ntfs usn-journal` | `UpdateTimestamp` |
| Juntei $LogFile | `auto-parse` → `FileSystem/LogFile.csv`<br>`juntei parse-ntfs logfile` | `CreatedOn`, `ContentModifiedOn`, `RecordModifiedOn`, `LastAccessedOn` |
| Juntei $I30 | `auto-parse` → `FileSystem/I30.csv`<br>`juntei parse-ntfs i30` | `CreatedUTC`, `ModifiedUTC`, `MFT-ModifiedUTC`, `AccessedUTC` |
| Juntei $Boot | `auto-parse` → `FileSystem/Boot.csv`<br>`juntei parse-ntfs boot` | none |
| Juntei $Secure:$SDS | `auto-parse` → `FileSystem/SecureSDS.csv`<br>`juntei parse-ntfs secure-sds` | none |

### Files

| Format (status bar) | Written by | Timestamp columns |
|---|---|---|
| Juntei Prefetch | `auto-parse` → `ProcessExecution/Prefetch.csv`<br>`juntei parse-file prefetch` | `LastRun`, `PreviousRun1`, `PreviousRun2`, `PreviousRun3`, `PreviousRun4`, `PreviousRun5`, `PreviousRun6`, `PreviousRun7`, `VolumeCreated` |
| Juntei Prefetch Timeline | `auto-parse` → `ProcessExecution/PrefetchTimeline.csv`<br>`juntei parse-file prefetch -T` | `RunTime` |
| Juntei LNK | `auto-parse` → `FileAndFolderOpening/LNK.csv`<br>`juntei parse-file lnk` | `SourceCreated`, `SourceModified`, `SourceAccessed`, `TargetCreated`, `TargetModified`, `TargetAccessed`, `TrackerCreatedOn` |
| Juntei Jump Lists (Automatic) | `auto-parse` → `FileAndFolderOpening/JumpLists-AutomaticDestinations.csv`<br>`juntei parse-file jump-lists` → `AutomaticDestinations.csv` | `SourceCreated`, `SourceModified`, `SourceAccessed`, `CreationTime`, `LastModified`, `TargetCreated`, `TargetModified`, `TargetAccessed`, `TrackerCreatedOn` |
| Juntei Jump Lists (Custom) | `auto-parse` → `FileAndFolderOpening/JumpLists-CustomDestinations.csv`<br>`juntei parse-file jump-lists` → `CustomDestinations.csv` | `SourceCreated`, `SourceModified`, `SourceAccessed`, `TargetCreated`, `TargetModified`, `TargetAccessed`, `TrackerCreatedOn` |
| Juntei Defender Quarantine | `auto-parse` → `SecurityProducts/DefenderQuarantine.csv`<br>`juntei parse-file defender-quarantine` | `QuarantineTime`, `CreationTime`, `LastAccessTime`, `LastWriteTime` |

### SRUM

| Format (status bar) | Written by | Timestamp columns |
|---|---|---|
| Juntei SRUM AppResourceUseInfo | `auto-parse` → `ProcessExecution/SRUM-AppResourceUseInfo.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp` |
| Juntei SRUM AppTimelineProvider | `auto-parse` → `ProcessExecution/SRUM-AppTimelineProvider.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp`, `EndTime` |
| Juntei SRUM EnergyUsage | `auto-parse` → `SystemInformation/SRUM-EnergyUsage.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp`, `EventTimestamp` |
| Juntei SRUM IdentityMap | `auto-parse` → `SystemInformation/SRUM-IdentityMap.csv`<br>`juntei parse-ese srum` | none |
| Juntei SRUM NetworkConnections | `auto-parse` → `NetworkActivity/SRUM-NetworkConnections.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp`, `ConnectStartTime` |
| Juntei SRUM NetworkUsages | `auto-parse` → `NetworkActivity/SRUM-NetworkUsages.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp` |
| Juntei SRUM PushNotifications | `auto-parse` → `NetworkActivity/SRUM-PushNotifications.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp` |
| Juntei SRUM VfuProvider | `auto-parse` → `SystemInformation/SRUM-VfuProvider.csv`<br>`juntei parse-ese srum` | `Timestamp`, `EXE-Timestamp`, `StartTime`, `EndTime` |
| Juntei SRUM (other tables) | `auto-parse` → `<category>/SRUM-<table>.csv` for tables without a specific parser<br>`juntei parse-ese srum` → `SRUM-<table>.csv` for tables without a specific parser | `Timestamp`, `EXE-Timestamp` |

### Registry

| Format (status bar) | Written by | Timestamp columns |
|---|---|---|
| Juntei Registry Amcache Files | `auto-parse` → `FileExistence/Registry-Amcache-Files.csv`<br>`juntei parse-registry amcache` | `SourceVolumeKeyLastWrittenUTC`, `KeyLastWrittenUTC`, `LinkDate` |
| Juntei Registry Amcache Devices | `auto-parse` → `FileExistence/Registry-Amcache-Devices.csv`<br>`juntei parse-registry amcache` | `KeyLastWrittenUTC`, `DriverVerDate`, `FirstInstallDate`, `InstallDate` |
| Juntei Registry Amcache Findings | `auto-parse` → `FileExistence/Registry-Amcache-Findings.csv`<br>`juntei parse-registry amcache` | none |
| Juntei Registry Amcache Summary | `auto-parse` → `FileExistence/Registry-Amcache-Summary.csv`<br>`juntei parse-registry amcache` | none |
| Juntei Registry AppCompat | `auto-parse` → `ProcessExecution/Registry-AppCompat.csv`<br>`juntei parse-registry app-compat` | `LastSeenUTC`, `SdbInstalledUTC`, `KeyLastWrittenUTC` |
| Juntei Registry AppHistory | `auto-parse` → `Applications/Registry-AppHistory.csv`<br>`juntei parse-registry app-history` | `FirstUsedUTC`, `KeyLastWrittenUTC` |
| Juntei Registry Audit Policy | `auto-parse` → `SystemInformation/Registry-AuditPolicy.csv`<br>`juntei parse-registry auditpol` | `KeyLastWrittenUTC` |
| Juntei Registry BAM | `auto-parse` → `ProcessExecution/Registry-BAM.csv`<br>`juntei parse-registry bam` | `LastRunUTC`, `KeyLastWrittenUTC` |
| Juntei Registry BCD | `auto-parse` → `Persistence/Registry-BCD.csv`<br>`juntei parse-registry bcd` | `KeyLastWrittenUTC` |
| Juntei Registry FeatureUsage | `auto-parse` → `ProcessExecution/Registry-FeatureUsage.csv`<br>`juntei parse-registry feature-usage` | `LastAccessedUTC`, `KeyLastWrittenUTC` |
| Juntei Registry Installed Programs | `auto-parse` → `Applications/Registry-InstalledPrograms.csv`<br>`juntei parse-registry installed-programs` | `InstallDate`, `KeyLastWrittenUTC` |
| Juntei Registry LSA Secrets | `auto-parse` → `Accounts/Registry-LsaSecrets.csv`<br>`juntei parse-registry lsa-secrets` | `CurrentSetUTC`, `OldSetUTC`, `CurrentValueLastWrittenUTC`, `OldValueLastWrittenUTC`, `KeyLastWrittenUTC` |
| Juntei Registry MRU | `auto-parse` → `FileAndFolderOpening/Registry-MRU.csv`<br>`juntei parse-registry mru` | `TypedTimeUTC`, `LastUsedUTC`, `KeyLastWrittenUTC` |
| Juntei Registry MuiCache | `auto-parse` → `ProcessExecution/Registry-MuiCache.csv`<br>`juntei parse-registry muicache` | `KeyLastWrittenUTC` |
| Juntei Registry Networks | `auto-parse` → `NetworkActivity/Registry-Networks.csv`<br>`juntei parse-registry networks` | `FirstConnectedUTC`, `LastConnectedUTC`, `LeaseObtainedUTC`, `LeaseExpiresUTC`, `KeyLastWrittenUTC` |
| Juntei Registry Office | `auto-parse` → `FileAndFolderOpening/Registry-Office.csv`<br>`juntei parse-registry office` | `LastOpenedUTC`, `TrustedAtUTC`, `KeyLastWrittenUTC` |
| Juntei Registry OpenSaveMRU | `auto-parse` → `FileAndFolderOpening/Registry-OpenSaveMRU.csv`<br>`juntei parse-registry open-save-mru` | `LastUsedUTC`, `KeyLastWrittenUTC` |
| Juntei Registry Persistence | `auto-parse` → `Persistence/Registry-Persistence.csv`<br>`juntei parse-registry persistence` | `DisabledAtUTC`, `KeyLastWrittenUTC` |
| Juntei Registry RecentDocs | `auto-parse` → `FileAndFolderOpening/Registry-RecentDocs.csv`<br>`juntei parse-registry recent-docs` | `KeyLastWrittenUTC`, `LastOpenedUTC` |
| Juntei Registry Remote Access | `auto-parse` → `LateralMovement/Registry-RemoteAccess.csv`<br>`juntei parse-registry remote-access` | `KeyLastWrittenUTC` |
| Juntei Registry SAM | `auto-parse` → `Accounts/Registry-SAM.csv`<br>`juntei parse-registry sam` | `LastLogonUTC`, `LastLogonWholeSecondsUTC`, `PasswordLastSetUTC`, `AccountExpirationUTC`, `LastFailedLogonUTC`, `KeyLastWrittenUTC`, `NamesKeyLastWrittenUTC` |
| Juntei Registry Security Settings | `auto-parse` → `SecurityProducts/Registry-SecuritySettings.csv`<br>`juntei parse-registry security-settings` | `KeyLastWrittenUTC` |
| Juntei Registry Services | `auto-parse` → `Persistence/Registry-Services.csv`<br>`juntei parse-registry services` | `KeyLastWrittenUTC` |
| Juntei Registry ShellBags | `auto-parse` → `FileAndFolderOpening/Registry-ShellBags.csv`<br>`juntei parse-registry shell-bags` | `KeyLastWrittenUTC`, `ParentKeyLastWrittenUTC` |
| Juntei Registry ShimCache | `auto-parse` → `FileExistence/Registry-ShimCache.csv`<br>`juntei parse-registry shimcache` | `LastModifiedTimeUTC`, `CacheLastWrittenUTC`, `LastUpdateTimeUTC` |
| Juntei Registry System Info | `auto-parse` → `SystemInformation/Registry-SystemInfo.csv`<br>`juntei parse-registry system-info` | `InstallDateUTC`, `InstallTimeUTC`, `TimeZoneLastWrittenUTC`, `LastShutdownUTC`, `LogonUiLastWrittenUTC`, `CompNameLastWrittenUTC`, `PrimaryDomainLastWrittenUTC`, `VersionLastWrittenUTC` |
| Juntei Registry TaskCache | `auto-parse` → `Persistence/Registry-TaskCache.csv`<br>`juntei parse-registry taskcache` | `TreeKeyLastWrittenUTC`, `TaskKeyLastWrittenUTC`, `LastRegisteredUTC`, `LastRunUTC`, `LastSuccessfulRunUTC` |
| Juntei Registry USB | `auto-parse` → `ExternalDevices/Registry-USB.csv`<br>`juntei parse-registry usb` | `DeviceFirstInstallUTC`, `DriverLastInstalledUTC`, `LastArrivalUTC`, `LastRemovalUTC`, `KeyLastWrittenUTC` |
| Juntei Registry UserAssist | `auto-parse` → `ProcessExecution/Registry-UserAssist.csv`<br>`juntei parse-registry user-assist` | `LastRunUTC`, `KeyLastWrittenUTC` |
| Juntei Registry Dump | `auto-parse` → `Registry/Registry-Dump.csv`<br>`juntei parse-registry read` | `KeyLastWrittenUTC`, `ValueFiletimeUTC` |

### Persistence Hunter and auto-parse

| Format (status bar) | Written by | Timestamp columns |
|---|---|---|
| Juntei Persistence Hunter | `auto-parse` → `Persistence/PersistenceHunter.csv`<br>`juntei persistence-hunter` | `KeyLastWrite`, `LastChange` |
| Juntei Persistence Hunter Coverage | `juntei persistence-hunter --coverage` | none |
| Juntei auto-parse Manifest | `auto-parse` → `manifest.csv` | none |

The templates are in [`electron/juntei-templates.json`](https://github.com/r3nzsec/irflow-timeline/blob/main/electron/juntei-templates.json).
