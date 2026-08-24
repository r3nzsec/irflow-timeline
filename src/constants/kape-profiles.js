export const KAPE_PROFILES = {
  // ── EZ Tools ────────────────────────────────────────────────────
  "MFTECmd ($MFT)": {
    detect: ["EntryNumber", "SequenceNumber", "ParentPath", "FileName", "Created0x10"],
    hiddenColumns: ["UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "NameType", "LoggedUtilStream", "SequenceNumber", "InUse", "ParentSequenceNumber", "ParentEntryNumber", "IsAds", "SiFlags", "FnAttributeId", "OtherAttributeId", "ReferenceCount"],
    columnOrder: ["EntryNumber", "ParentPath", "FileName", "Extension", "IsDirectory", "HasAds", "FileSize", "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30", "LastRecordChange0x10", "LastAccess0x10", "ZoneIdContents", "Timestomped", "uSecZeros", "Copied"],
  },
  "EvtxECmd (EVTX)": {
    detect: ["RecordNumber", "TimeCreated", "EventId", "Provider", "Channel"],
    hiddenColumns: ["ChunkNumber", "ExtraDataOffset", "HiddenRecord", "ProcessId", "ThreadId"],
    columnOrder: ["RecordNumber", "EventRecordId", "TimeCreated", "EventId", "Level", "Provider", "Channel", "Computer", "UserId", "MapDescription", "UserName", "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo", "SourceFile", "Payload", "Keywords"],
  },
  "PECmd (Prefetch)": {
    detect: ["ExecutableName", "RunCount", "LastRun", "Volume0Name", "Hash"],
    hiddenColumns: ["FileSize", "ParsingError"],
    columnOrder: ["SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", "ExecutableName", "RunCount", "Hash", "Size", "Version", "LastRun", "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", "Volume0Name", "Volume0Serial", "Volume0Created", "Directories", "FilesLoaded"],
  },
  "LECmd (LNK)": {
    detect: ["SourceFile", "TargetIDAbsolutePath", "HeaderFlags", "DriveType"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "FileAttributes", "HeaderFlags", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "TargetMFTEntryNumber", "MachineID", "MachineMACAddress", "TrackerCreatedOn"],
  },
  "AmcacheParser (Files)": {
    detect: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1"],
    hiddenColumns: ["Language", "Usn", "LongPathHash", "BinaryType"],
    columnOrder: ["ApplicationName", "ProgramId", "FileKeyLastWriteTimestamp", "SHA1", "IsOsComponent", "FullPath", "Name", "FileExtension", "LinkDate", "ProductName", "Size", "Version", "ProductVersion", "IsPeFile", "BinFileVersion"],
  },
  "AmcacheParser (Programs)": {
    detect: ["ProgramId", "KeyLastWriteTimestamp", "Publisher", "InstallDate"],
    columnOrder: ["ProgramId", "KeyLastWriteTimestamp", "Name", "Version", "Publisher", "InstallDate", "OSVersionAtInstallTime", "BundleManifestPath", "HiddenArp", "InboxModernApp", "MsiPackageCode", "MsiProductCode", "PackageFullName", "RegistryKeyPath", "RootDirPath", "Type", "Source", "UninstallString"],
  },
  "RECmd (Registry)": {
    detect: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData"],
    columnOrder: ["HivePath", "KeyPath", "ValueName", "ValueType", "ValueData", "ValueData2", "ValueData3", "LastWriteTimestamp", "Description", "Category"],
  },
  "SBECmd (ShellBags)": {
    detect: ["AbsolutePath", "BagPath", "ShellType", "Value"],
    columnOrder: ["BagPath", "Slot", "NodeSlot", "MRUPosition", "AbsolutePath", "ShellType", "Value", "ChildBags", "CreatedOn", "ModifiedOn", "AccessedOn", "LastWriteTime", "FirstInteracted", "LastInteracted", "HasExplored"],
  },
  "SrumECmd (SRUM)": {
    detect: ["Timestamp", "ExeInfo", "SidType", "Sid"],
    columnOrder: ["Timestamp", "ExeInfo", "SidType", "Sid", "UserName"],
  },
  "AppCompatcache (Shimcache)": {
    detect: ["ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", "Executed"],
    hiddenColumns: ["FileSize"],
    columnOrder: ["ControlSet", "Duplicate", "CacheEntryPosition", "Executed", "LastModifiedTimeUTC", "Path", "SourceFile"],
  },
  "JLECmd (Auto Jump Lists)": {
    detect: ["AppId", "AppIdDescription", "EntryName", "TargetIDAbsolutePath"],
    columnOrder: ["SourceFile", "SourceCreated", "SourceModified", "SourceAccessed", "AppId", "AppIdDescription", "EntryName", "TargetCreated", "TargetModified", "TargetAccessed", "FileSize", "RelativePath", "WorkingDirectory", "LocalPath", "CommonPath", "Arguments", "TargetIDAbsolutePath", "MachineID", "MachineMACAddress", "TrackerCreatedOn", "InteractionCount"],
  },
  // ── Timeline Formats ────────────────────────────────────────────
  "ForensicTimeline": {
    detect: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description"],
    columnOrder: ["DateTime", "TimestampInfo", "ArtifactName", "Tool", "Description", "DataDetails", "DataPath", "FileExtension", "EvidencePath", "EventId", "User", "Computer", "FileSize", "IPAddress", "SourceAddress", "DestinationAddress", "SHA1", "Count", "RawData"],
    autoColorColumn: "ArtifactName",
  },
  "SuperTimeline (Plaso)": {
    detect: ["date", "time", "macb", "source", "sourcetype", "type"],
    columnOrder: ["date", "time", "macb", "source", "sourcetype", "type", "user", "host", "short", "desc", "filename", "inode", "notes", "format", "extra"],
    autoColorColumn: "source",
  },
  "MacTime": {
    detect: ["Timestamp", "Macb", "SourceName", "LongDescription", "FileName"],
    hiddenColumns: ["TimeZone", "Type", "Username", "HostName", "ShortDescription", "Version", "Notes", "Format", "Extra"],
    columnOrder: ["Timestamp", "SourceDescription", "SourceName", "Macb", "LongDescription", "Inode", "FileName"],
    autoColorColumn: "SourceName",
  },
  "KapeMiniTimeline": {
    detect: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    columnOrder: ["Timestamp", "DataType", "ComputerName", "UserSource", "Message"],
    autoColorColumn: "DataType",
  },
  "PsortTimeline (Plaso)": {
    detect: ["Timestamp", "TimestampDescription", "Source", "SourceLong"],
    columnOrder: ["Timestamp", "TimestampDescription", "Source", "SourceLong", "Message", "Parser", "DisplayName", "TagInfo"],
    autoColorColumn: "Source",
  },
  // ── Misc Tools ──────────────────────────────────────────────────
  "Hayabusa (Standard)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "EventId", "RecordId", "Details"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "RecordId", "Details", "ExtraFieldInfo"],
    autoColorColumn: "Level",
  },
  "Hayabusa (Verbose)": {
    detect: ["Timestamp", "RuleTitle", "Level", "MitreTactics", "MitreTags", "OtherTags"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "Chainsaw (Logons)": {
    detect: ["system_time", "id", "workstation_name", "target_username", "source_ip", "logon_type"],
    columnOrder: ["system_time", "id", "target_username", "source_ip", "workstation_name", "logon_type"],
    autoColorColumn: "logon_type",
  },
  "Chainsaw (Command Line Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.CommandLine", "process_name"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "process_name", "Event.EventData.CommandLine"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Process Creation Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Image", "command_line"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Image", "command_line"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Registry Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.Details", "target_object"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "target_object", "Event.EventData.Details"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (File Creation Hunt)": {
    detect: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.TargetFilename", "image"],
    columnOrder: ["system_time", "id", "detection_rules", "computer_name", "Event.EventData.TargetFilename", "image"],
    autoColorColumn: "detection_rules",
  },
  "Chainsaw (Sigma)": {
    detect: ["Timestamp", "RuleTitle", "Level", "Channel", "MitreTactics"],
    columnOrder: ["Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventId", "MitreTactics", "MitreTags", "OtherTags", "RecordId", "Details", "ExtraFieldInfo", "RuleFile", "EvtxFile"],
    autoColorColumn: "Level",
  },
  "BrowsingHistoryView": {
    detect: ["Url", "Title", "VisitTimeUtc", "WebBrowser", "UserProfile"],
    columnOrder: ["Url", "Title", "VisitTimeUtc", "VisitCount", "VisitedFrom", "VisitType", "WebBrowser", "UserProfile", "BrowserProfile", "UrlLength", "TypedCount", "HistoryFile"],
  },
  "KAPE Copy Log": {
    detect: ["CopiedTimestamp", "SourceFile", "DestinationFile", "SourceFileSha1"],
    columnOrder: ["CopiedTimestamp", "SourceFile", "DestinationFile", "FileSize", "SourceFileSha1", "DeferredCopy", "CreatedOnUtc", "ModifiedOnUtc", "LastAccessedOnUtc", "CopyDuration"],
  },
  "Tab Diff": {
    detect: ["_Diff", "_Baseline", "_Compare", "_ChangedFields"],
    hiddenColumns: ["_DiffDetail"],
    columnOrder: ["_Diff", "_ChangedFields", "_DiffSummary", "datetime", "_MatchKey", "_Baseline", "_Compare"],
    defaultSortCol: "datetime",
    defaultSortDir: "asc",
  },
  "AI Query History": {
    detect: ["Timestamp", "Role", "RecordType", "Summary", "SessionId", "Tool"],
    showAllColumns: true,
    columnOrder: [
      "Timestamp", "Role", "RecordType", "Summary", "FullText", "InvokedTool", "ToolCommand",
      "ToolDescription", "ToolInput", "SessionId",
      "MessageId", "ParentId", "Workspace", "IsSidechain", "GitBranch", "Tool", "Model",
      "InputTokens", "OutputTokens", "SourceFile", "LineNumber", "User", "Host", "Description", "RecordId",
    ],
    defaultSortCol: "Timestamp",
    defaultSortDir: "asc",
  },
};
