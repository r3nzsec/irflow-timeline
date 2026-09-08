#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const yaml = require("js-yaml");

const { verifyUpdateMetadata } = require("./verify-update-metadata.cjs");

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assetUrl(baseUrl, name) {
  const root = `${String(baseUrl || "").replace(/\/+$/, "")}/`;
  return new URL(name.split("/").map(encodeURIComponent).join("/"), root).toString();
}

async function fetchWithRetry(url, options, { fetchImpl, attempts, delayMs }) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchImpl(url, options);
      if (response.ok) return response;
      lastError = new Error(`${options.method || "GET"} ${url} returned HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < attempts) await sleep(delayMs * attempt);
  }
  throw lastError;
}

async function verifyPublishedUpdateFeed({
  baseUrl,
  metadataPath,
  artifactPaths,
  fetchImpl = globalThis.fetch,
  attempts = 6,
  delayMs = 1000,
}) {
  if (typeof fetchImpl !== "function") throw new Error("A Fetch-compatible implementation is required");
  if (!/^https:\/\//i.test(baseUrl) && !/^http:\/\/127\.0\.0\.1(?::\d+)?(?:\/|$)/i.test(baseUrl)) {
    throw new Error("Public updater base URL must use HTTPS");
  }

  const localMetadata = fs.readFileSync(metadataPath);
  const document = yaml.load(localMetadata.toString("utf8"));
  const entries = Array.isArray(document?.files) ? document.files : [];
  const downloadablePaths = artifactPaths.filter((file) => /\.(?:dmg|zip)$/i.test(file));
  verifyUpdateMetadata(metadataPath, downloadablePaths);

  const metadataUrl = new URL(assetUrl(baseUrl, path.basename(metadataPath)));
  metadataUrl.searchParams.set("irflow_verify", String(Date.now()));
  const metadataResponse = await fetchWithRetry(metadataUrl, {
    method: "GET",
    cache: "no-store",
    headers: { "cache-control": "no-cache" },
  }, { fetchImpl, attempts, delayMs });
  const publishedMetadata = Buffer.from(await metadataResponse.arrayBuffer());
  if (!publishedMetadata.equals(localMetadata)) {
    throw new Error(`${path.basename(metadataPath)} served by the public feed differs from the release artifact`);
  }

  const verified = [];
  for (const artifactPath of artifactPaths) {
    const name = path.basename(artifactPath);
    const size = fs.statSync(artifactPath).size;
    const entry = entries.find((candidate) => candidate?.url === name);
    if (/\.(?:dmg|zip)$/i.test(name) && (!entry || entry.size !== size)) {
      throw new Error(`${name} has no matching size in ${path.basename(metadataPath)}`);
    }

    const url = assetUrl(baseUrl, name);
    const head = await fetchWithRetry(url, {
      method: "HEAD",
      cache: "no-store",
      headers: { "cache-control": "no-cache" },
    }, { fetchImpl, attempts, delayMs });
    const publishedSize = Number(head.headers.get("content-length"));
    if (!Number.isSafeInteger(publishedSize) || publishedSize !== size) {
      throw new Error(`${name} public Content-Length ${publishedSize || "missing"} does not match ${size}`);
    }
    if (!/\bbytes\b/i.test(head.headers.get("accept-ranges") || "")) {
      throw new Error(`${name} does not advertise byte-range support`);
    }

    const range = await fetchWithRetry(url, {
      method: "GET",
      cache: "no-store",
      headers: { Range: "bytes=0-0", "cache-control": "no-cache" },
    }, { fetchImpl, attempts, delayMs });
    const contentRange = range.headers.get("content-range") || "";
    const body = Buffer.from(await range.arrayBuffer());
    if (range.status !== 206 || body.length !== 1 || contentRange !== `bytes 0-0/${size}`) {
      throw new Error(`${name} failed the single-byte range probe`);
    }
    verified.push({ name, size, url });
  }

  return {
    version: String(document?.version || ""),
    metadataUrl: metadataUrl.toString(),
    artifacts: verified,
  };
}

if (require.main === module) {
  const [baseUrl, metadataPath, ...artifactPaths] = process.argv.slice(2);
  if (!baseUrl || !metadataPath || artifactPaths.length === 0) {
    console.error("Usage: node scripts/verify-published-update-feed.cjs <base-url> <*-mac.yml> <artifact> [...]");
    process.exitCode = 2;
  } else {
    verifyPublishedUpdateFeed({ baseUrl, metadataPath, artifactPaths })
      .then((result) => {
        console.log(`Verified public updater ${result.version}: ${result.artifacts.map((item) => item.name).join(", ")}`);
      })
      .catch((error) => {
        console.error(error && error.message ? error.message : String(error));
        process.exitCode = 1;
      });
  }
}

module.exports = { assetUrl, fetchWithRetry, verifyPublishedUpdateFeed };
