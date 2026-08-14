"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const Database = require("better-sqlite3");

const MAX_STORED_FINDINGS = 10_000;
const MAX_PAGE_SIZE = 1_000;
const MAX_AGGREGATE_KEYS = 100_000;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function safeJobId(jobId) {
  return String(jobId || "scan").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120);
}

function resultPathForJob(jobId) {
  return path.join(os.tmpdir(), `irflow-ai-secret-${safeJobId(jobId)}.sqlite`);
}

function removeStore(filePath) {
  if (!filePath) return;
  for (const suffix of ["", "-journal", "-wal", "-shm"]) {
    try { fs.unlinkSync(`${filePath}${suffix}`); } catch (err) {
      if (err?.code !== "ENOENT") throw err;
    }
  }
}

class AiSecretResultWriter {
  constructor(jobId, { maxStoredFindings = MAX_STORED_FINDINGS } = {}) {
    this.filePath = resultPathForJob(jobId);
    this.maxStoredFindings = Math.max(1, Math.min(MAX_STORED_FINDINGS, Number(maxStoredFindings) || MAX_STORED_FINDINGS));
    this.totalFindings = 0;
    this.storedFindings = 0;
    this.uniqueSecrets = 0;
    this.flaggedRows = 0;
    this.uniqueSecretsExact = true;
    this.flaggedRowsExact = true;
    this.closed = false;
    removeStore(this.filePath);
    this.db = new Database(this.filePath);
    this.db.pragma("journal_mode = DELETE");
    this.db.pragma("synchronous = OFF");
    this.db.exec(`
      CREATE TABLE findings (
        finding_id INTEGER PRIMARY KEY,
        severity_rank INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE TABLE unique_secrets (fingerprint TEXT PRIMARY KEY) WITHOUT ROWID;
      CREATE TABLE flagged_rows (row_key TEXT PRIMARY KEY) WITHOUT ROWID;
    `);
    this.insertFinding = this.db.prepare(
      "INSERT INTO findings (finding_id, severity_rank, timestamp, payload) VALUES (?, ?, ?, ?)",
    );
    this.insertFingerprint = this.db.prepare("INSERT OR IGNORE INTO unique_secrets (fingerprint) VALUES (?)");
    this.insertRow = this.db.prepare("INSERT OR IGNORE INTO flagged_rows (row_key) VALUES (?)");
    this.db.exec("BEGIN IMMEDIATE");
  }

  add(finding) {
    if (this.closed) throw new Error("AI Secret result store is closed");
    this.totalFindings++;
    if (finding?.fingerprint && this.uniqueSecrets < MAX_AGGREGATE_KEYS) {
      this.uniqueSecrets += this.insertFingerprint.run(String(finding.fingerprint)).changes;
      if (this.uniqueSecrets >= MAX_AGGREGATE_KEYS) this.uniqueSecretsExact = false;
    } else if (finding?.fingerprint) {
      this.uniqueSecretsExact = false;
    }
    const rowKey = finding?.rowId || finding?.recordId;
    if (rowKey != null && String(rowKey) !== "" && this.flaggedRows < MAX_AGGREGATE_KEYS) {
      this.flaggedRows += this.insertRow.run(String(rowKey)).changes;
      if (this.flaggedRows >= MAX_AGGREGATE_KEYS) this.flaggedRowsExact = false;
    } else if (rowKey != null && String(rowKey) !== "") {
      this.flaggedRowsExact = false;
    }
    if (this.storedFindings >= this.maxStoredFindings) return;
    const findingId = ++this.storedFindings;
    const payload = { ...(finding || {}), findingId: String(findingId) };
    // Defense in depth: no producer may accidentally reintroduce a cleartext result property.
    delete payload.match;
    delete payload.value;
    this.insertFinding.run(
      findingId,
      SEVERITY_RANK[payload.severity] || 0,
      String(payload.timestamp || ""),
      JSON.stringify(payload),
    );
  }

  finish() {
    if (this.closed) throw new Error("AI Secret result store is closed");
    this.db.exec("COMMIT");
    this.db.close();
    this.closed = true;
    return {
      resultStorePath: this.filePath,
      storedFindings: this.storedFindings,
      totalFindings: this.totalFindings,
      resultsTruncated: this.totalFindings > this.storedFindings,
      uniqueSecrets: this.uniqueSecrets,
      uniqueSecretsExact: this.uniqueSecretsExact,
      flaggedRows: this.flaggedRows,
      flaggedRowsExact: this.flaggedRowsExact,
    };
  }

  abort() {
    if (!this.closed) {
      try { this.db.exec("ROLLBACK"); } catch {}
      try { this.db.close(); } catch {}
      this.closed = true;
    }
    try { removeStore(this.filePath); } catch {}
  }
}

class AiSecretResultReader {
  constructor(filePath) {
    this.filePath = filePath;
  }

  page(offset = 0, limit = MAX_PAGE_SIZE) {
    const safeOffset = Math.max(0, Math.floor(Number(offset) || 0));
    const safeLimit = Math.max(1, Math.min(MAX_PAGE_SIZE, Math.floor(Number(limit) || MAX_PAGE_SIZE)));
    const db = new Database(this.filePath, { readonly: true, fileMustExist: true });
    try {
      const rows = db.prepare(`
        SELECT payload FROM findings
        ORDER BY severity_rank DESC, timestamp ASC, finding_id ASC
        LIMIT ? OFFSET ?
      `).all(safeLimit, safeOffset);
      const totalStored = db.prepare("SELECT COUNT(*) AS n FROM findings").get().n;
      const findings = rows.map((row) => JSON.parse(row.payload));
      return {
        findings,
        offset: safeOffset,
        limit: safeLimit,
        returned: findings.length,
        totalStored,
        hasMore: safeOffset + findings.length < totalStored,
      };
    } finally {
      db.close();
    }
  }

  get(findingId) {
    const id = Number(findingId);
    if (!Number.isInteger(id) || id < 1) return null;
    const db = new Database(this.filePath, { readonly: true, fileMustExist: true });
    try {
      const row = db.prepare("SELECT payload FROM findings WHERE finding_id = ?").get(id);
      return row ? JSON.parse(row.payload) : null;
    } finally {
      db.close();
    }
  }
}

module.exports = {
  AiSecretResultWriter,
  AiSecretResultReader,
  MAX_STORED_FINDINGS,
  MAX_PAGE_SIZE,
  MAX_AGGREGATE_KEYS,
  resultPathForJob,
  removeStore,
};
