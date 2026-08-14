"use strict";

function shouldHideWindowOnClose({ platform = process.platform, isQuitting = false } = {}) {
  return platform === "darwin" && !isQuitting;
}

function restoreOrCreateWindow({ window, createWindow }) {
  if (!window || window.isDestroyed?.()) return createWindow();
  if (window.isMinimized?.()) window.restore();
  window.show?.();
  window.focus?.();
  return window;
}

module.exports = { shouldHideWindowOnClose, restoreOrCreateWindow };
