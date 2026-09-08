const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

function sha512Base64(filePath) {
  return crypto.createHash("sha512").update(fs.readFileSync(filePath)).digest("base64");
}

function verifyUpdateMetadata(ymlPath, artifactPaths) {
  const document = yaml.load(fs.readFileSync(ymlPath, "utf8"));
  const entries = Array.isArray(document?.files) ? document.files : [];
  const verified = [];

  for (const artifactPath of artifactPaths) {
    const name = path.basename(artifactPath);
    const entry = entries.find((candidate) => candidate?.url === name);
    if (!entry) throw new Error(`${name} is missing from ${path.basename(ymlPath)}`);

    const size = fs.statSync(artifactPath).size;
    const sha512 = sha512Base64(artifactPath);
    if (entry.size !== size || entry.sha512 !== sha512) {
      throw new Error(`${name} does not match ${path.basename(ymlPath)}`);
    }
    verified.push({ name, size, sha512 });
  }

  return verified;
}

if (require.main === module) {
  const [ymlPath, ...artifactPaths] = process.argv.slice(2);
  if (!ymlPath || artifactPaths.length === 0) {
    console.error("Usage: node scripts/verify-update-metadata.cjs <*-mac.yml> <artifact> [...]");
    process.exitCode = 2;
  } else {
    try {
      const verified = verifyUpdateMetadata(ymlPath, artifactPaths);
      console.log(`Verified updater metadata for ${verified.map((item) => item.name).join(", ")}`);
    } catch (error) {
      console.error(error && error.message ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}

module.exports = { sha512Base64, verifyUpdateMetadata };
