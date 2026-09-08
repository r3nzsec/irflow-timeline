#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const yaml = require("js-yaml");

function normalizedBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function verifyAppUpdateConfig(configPath, expectedBaseUrl, expectedChannel = "latest") {
  const document = yaml.load(fs.readFileSync(configPath, "utf8"));
  const actualUrl = normalizedBaseUrl(document?.url);
  const wantedUrl = normalizedBaseUrl(expectedBaseUrl);

  if (document?.provider !== "generic") {
    throw new Error(`Packaged updater provider must be generic, got ${document?.provider || "missing"}`);
  }
  if (!wantedUrl || actualUrl !== wantedUrl) {
    throw new Error(`Packaged updater URL ${actualUrl || "missing"} does not match ${wantedUrl || "missing"}`);
  }
  if (!/^https:\/\//i.test(actualUrl)) {
    throw new Error("Packaged updater URL must use HTTPS");
  }
  if ((document?.channel || "latest") !== expectedChannel) {
    throw new Error(`Packaged updater channel must be ${expectedChannel}`);
  }
  if (document?.useMultipleRangeRequest !== false) {
    throw new Error("Packaged updater must use S3-compatible single-range downloads");
  }

  return {
    provider: document.provider,
    url: actualUrl,
    channel: document.channel || "latest",
    useMultipleRangeRequest: document.useMultipleRangeRequest,
  };
}

if (require.main === module) {
  const [configPath, expectedBaseUrl, expectedChannel = "latest"] = process.argv.slice(2);
  if (!configPath || !expectedBaseUrl) {
    console.error("Usage: node scripts/verify-app-update-config.cjs <app-update.yml> <base-url> [channel]");
    process.exitCode = 2;
  } else {
    try {
      const result = verifyAppUpdateConfig(configPath, expectedBaseUrl, expectedChannel);
      console.log(`Verified packaged updater: ${result.channel} -> ${result.url}`);
    } catch (error) {
      console.error(error && error.message ? error.message : String(error));
      process.exitCode = 1;
    }
  }
}

module.exports = { normalizedBaseUrl, verifyAppUpdateConfig };
