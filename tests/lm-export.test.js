// Export-safety helpers for the Lateral Movement Tracker.
//
// The evidence-package export wrote complete raw source rows to disk. Lateral-movement
// evidence is precisely the material most likely to carry credentials, so "export the
// evidence" was a credential-exfiltration path by default. Separately, three different
// CSV escapers existed and none neutralised formula injection, while every exported
// Title/Description field derives from event data including command lines.

const test = require("node:test");
const assert = require("node:assert/strict");
const { pathToFileURL } = require("node:url");
const path = require("node:path");

// The helper is an ES module (renderer-side); load it dynamically.
let redactSecrets, redactRow, csvCell, toCSV, REDACTION_MASK;
test.before(async () => {
  const mod = await import(pathToFileURL(path.join(__dirname, "..", "src", "utils", "lm-export.js")).href);
  ({ redactSecrets, redactRow, csvCell, toCSV, REDACTION_MASK } = mod);
});

test("credential flags are preserved but their values are masked", () => {
  const cases = [
    ["psexec \\\\DC01 -u admin -p Pa$$w0rd cmd.exe", "Pa$$w0rd"],
    ["net use z: \\\\FS01\\C$ /user:CORP\\admin Hunter2", null], // value form varies; see below
    ["sqlcmd -S db01 -U sa -P S3cret!", "S3cret!"],
    ["connect --password=TopSecret1 --host db", "TopSecret1"],
    ["Invoke-Cmd -Token abc123def456 -Uri x", "abc123def456"],
  ];
  for (const [input, secret] of cases) {
    const out = redactSecrets(input);
    if (secret) {
      assert.ok(!out.includes(secret), `secret leaked from: ${input}\n  -> ${out}`);
      assert.ok(out.includes(REDACTION_MASK), `no mask applied to: ${input}\n  -> ${out}`);
    }
  }
});

test("the flag itself stays visible — that a credential was passed is evidence", () => {
  const out = redactSecrets("psexec -p Pa$$w0rd");
  assert.match(out, /-p/, "the -p flag should survive so the analyst still sees a password was supplied");
  assert.ok(!out.includes("Pa$$w0rd"));
});

test("NTLM hash pairs and encoded payloads are masked", () => {
  const hashes = redactSecrets("secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 corp/u@dc01");
  assert.ok(!hashes.includes("31d6cfe0d16ae931b73c59d7e0c089c0"), `hash leaked: ${hashes}`);

  const enc = redactSecrets("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA");
  assert.ok(!/SQBFAFgA[A-Za-z0-9+/=]{20,}/.test(enc), `encoded payload leaked: ${enc}`);
  assert.match(enc, /-enc/, "the -enc flag should survive");
});

test("ordinary command lines are left untouched", () => {
  const benign = "C:\\Windows\\System32\\cmd.exe /c whoami /all";
  assert.equal(redactSecrets(benign), benign);
  assert.equal(redactSecrets(""), "");
  assert.equal(redactSecrets(null), null);
});

test("redactRow masks string values and preserves everything else", () => {
  const row = {
    EventID: 4688,
    CommandLine: "psexec -p Hunter2 \\\\DC01",
    Computer: "WKS01",
    Flag: true,
    Nested: null,
  };
  const out = redactRow(row);
  assert.equal(out.EventID, 4688, "non-strings pass through unchanged");
  assert.equal(out.Flag, true);
  assert.equal(out.Nested, null);
  assert.equal(out.Computer, "WKS01", "benign strings are untouched");
  assert.ok(!out.CommandLine.includes("Hunter2"), `secret leaked: ${out.CommandLine}`);
  assert.equal(row.CommandLine, "psexec -p Hunter2 \\\\DC01", "the input row must not be mutated");
});

test("redactRow walks nested commandLines and executionDetails", () => {
  const item = {
    category: "Remote Service Execution",
    commandLines: ["sc \\\\host create x binPath= cmd.exe -p Pa$$w0rd"],
    executionDetails: [{ commandLine: "psexec -p Hunter2 \\\\DC01" }],
  };
  const out = redactRow(item);
  assert.ok(!out.commandLines[0].includes("Pa$$w0rd"), out.commandLines[0]);
  assert.ok(!out.executionDetails[0].commandLine.includes("Hunter2"), out.executionDetails[0].commandLine);
  assert.equal(item.commandLines[0].includes("Pa$$w0rd"), true, "input must not be mutated");
});

// ── CSV encoding ────────────────────────────────────────────────────────────────

test("csvCell neutralises formula injection", () => {
  // Excel/Sheets/Numbers treat these as formulas. Exported Title/Description fields are
  // derived from command lines, so an attacker controls this text.
  for (const payload of ["=cmd|'/c calc'!A1", "+1+1", "-2+3", "@SUM(1:2)", "\tlead", "\rlead"]) {
    const cell = csvCell(payload);
    assert.match(cell, /^"'/, `formula not neutralised: ${payload} -> ${cell}`);
  }
});

test("csvCell still quotes and escapes correctly", () => {
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell("line1\nline2"), '"line1\nline2"');
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(undefined), '""');
  assert.equal(csvCell(0), '"0"', "zero must not be treated as empty");
  assert.equal(csvCell("normal"), '"normal"');
});

test("toCSV renders rows of arrays", () => {
  const csv = toCSV([["Host", "Note"], ["DC01", "=danger"]]);
  assert.equal(csv, '"Host","Note"\n"DC01","\'=danger"');
});
