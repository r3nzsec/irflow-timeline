---
description: In-app macOS updates with electron-updater — automatic checks, manual Check for Updates, and one-click install on restart.
---

# Auto Update

IRFlow Timeline now supports in-app macOS updates with `electron-updater`.

## User flow

- First install still happens from the DMG
- Packaged builds check for updates automatically a few seconds after launch
- Users can also trigger **Help → Check for Updates…** from the in-app menu bar
- Downloaded updates install on restart

### Check for Updates

The manual check lives under **Help** in the menu bar:

![Help menu showing Check for Updates… alongside Quick Help, Keyboard Shortcuts, and About](/dfir-tips/Check-For-Updates-Button.png)

Selecting **Check for Updates…** opens an in-app status popup that reports whether you are up to date, shows download progress when an update is available, and prompts you to restart when the package is ready to install.

![Check for Updates result dialog showing update status after a manual check](/dfir-tips/Check-For-Updates.png)

## Generic HTTPS Feed

Builds now use `electron-builder.config.cjs`, which adds a generic publish provider only when an environment variable is present.

Required environment variables for a release build:

- `IRFLOW_UPDATE_BASE_URL=https://downloads.example.com/irflow-timeline`
- Optional: `IRFLOW_UPDATE_CHANNEL=latest`

Example:

```bash
export IRFLOW_UPDATE_BASE_URL="https://downloads.example.com/irflow-timeline"
export IRFLOW_UPDATE_CHANNEL="latest"
npm run dist:release
```

That build produces updater metadata inside the app bundle and release artifacts in `release/`.

## Build Modes

Use these two commands for different goals:

- `npm run dist:release`
  Real release build. This is the one you use for production DMGs and in-app updates.
  It should run in an environment where code signing and notarization are available.
- `npm run dist:smoke`
  Local packaging smoke test. This intentionally disables code signing discovery and skips notarization.
  Use it only to confirm the app packages and generates `.dmg`, `.zip`, and `latest-mac.yml`.

For a real local release build with the updater feed embedded:

```bash
export IRFLOW_UPDATE_BASE_URL="https://downloads.example.com/irflow-timeline"
export IRFLOW_UPDATE_CHANNEL="latest"
npm run dist:release
```

## What To Upload

For each macOS release, upload these files to the HTTPS/CDN path referenced by `IRFLOW_UPDATE_BASE_URL`:

- The `.zip` artifact
- The `.dmg` artifact
- The matching `.zip.blockmap` and `.dmg.blockmap` artifacts
- `latest-mac.yml` for the default channel, or `<channel>-mac.yml` for a custom channel

Requirements:

- The app must be signed and notarized
- The hosted files must be reachable over HTTPS
- The `.zip`, its exact `.zip.blockmap`, and `latest-mac.yml` must stay together at the same feed root for differential updates

## Release Automation

The repo now includes a tag-driven GitHub Actions workflow at `.github/workflows/release-macos.yml`.

After one-time setup, your normal release flow becomes:

1. Commit your code changes
2. Bump `package.json` to the new app version
3. Create a matching git tag such as `v1.2.3`
4. Push the branch and tag
5. GitHub Actions builds the signed/notarized macOS release, uploads the `.dmg`, `.zip`, and update metadata to both GitHub Releases and your generic HTTPS feed
6. Users receive the update in-app

Important:

- The git tag must match `package.json`, for example `package.json: 1.2.3` requires tag `v1.2.3`
- Uploading only a new DMG is not enough for in-app updates
- The workflow publishes the `.zip` and `latest-mac.yml` that `electron-updater` actually uses

### One-Time GitHub Setup

Repository variables:

- `IRFLOW_UPDATE_BASE_URL`
- `IRFLOW_UPDATE_BUCKET`
- `IRFLOW_UPDATE_PREFIX`
- `AWS_REGION`
- Optional: `IRFLOW_UPDATE_CHANNEL`
- Optional: `AWS_ENDPOINT_URL_S3`

Repository secrets:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `CSC_LINK`
- `CSC_KEY_PASSWORD`
- `APPLE_ID`
- `APPLE_APP_SPECIFIC_PASSWORD`
- `APPLE_TEAM_ID`

Notes:

- `CSC_LINK` should point to your macOS signing certificate in a format supported by `electron-builder`
- `AWS_ENDPOINT_URL_S3` allows the same workflow to target S3-compatible storage such as Cloudflare R2
- `IRFLOW_UPDATE_BASE_URL` must match the public HTTPS path that serves the files uploaded to `IRFLOW_UPDATE_BUCKET` and `IRFLOW_UPDATE_PREFIX`

### Example Release

```bash
# after committing changes
npm version patch
git push
git push --follow-tags
```

That tag push triggers the macOS release workflow automatically.

## Local Testing

To test updater behavior in development, create `dev-app-update.yml` in the project root:

```yaml
provider: generic
url: https://downloads.example.com/irflow-timeline
channel: latest
updaterCacheDirName: irflow-timeline-updater
```

Then run a packaged build against a real hosted feed and verify:

- Startup update detection
- Manual **Help → Check for Updates…** (see screenshots above)
- Popup progress during download and restart install prompt
