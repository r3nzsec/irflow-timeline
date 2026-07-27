const path = require("path");

function makeImportQueueKey(filePath, opts = {}) {
  return [
    path.resolve(filePath),
    opts.sheetName ?? "",
    opts.aiHistoryTool ?? "",
    opts.aiHistoryIncludeSubagents ? "subagents" : "main",
  ].join("\u0000");
}

function isDuplicatePendingImport(queue, activeKey, queueKey) {
  return activeKey === queueKey || queue.some((item) => item.queueKey === queueKey);
}

module.exports = { makeImportQueueKey, isDuplicatePendingImport };
