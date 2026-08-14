/** Release every transient resource owned by one AI Secret Hunt modal instance. */
export function cleanupAiSecretLifecycle(api, { jobId, scanId } = {}) {
  const actions = [];
  if (jobId) actions.push(Promise.resolve(api?.cancelJob?.(jobId)));
  if (scanId) actions.push(Promise.resolve(api?.releaseAiSecretScan?.(scanId)));
  return Promise.allSettled(actions);
}

