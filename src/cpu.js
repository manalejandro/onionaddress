/**
 * CPU worker source: wraps a Node worker thread (src/worker.js) behind the
 * source interface used by the search orchestrator.
 *
 * Source interface (shared with src/gpu.js):
 *   states  [{ kind, label, attempts, best, exited, error }]
 *   start(onEvent)                 begin searching
 *   stop()  -> Promise<void>       graceful stop with forced fallback
 * Events passed to onEvent:
 *   { type: 'stats' | 'match' | 'error' | 'exit', source: state, ... }
 */
import { Worker } from 'node:worker_threads';

const WORKER_URL = new URL('./worker.js', import.meta.url);
const STOP_GRACE_MS = 1000;

export function createCpuSource({ id, pattern, stopAfterFirst }) {
  const worker = new Worker(WORKER_URL);
  const state = {
    kind: 'cpu',
    label: `worker ${id}`,
    attempts: 0,
    best: 0,
    exited: false,
    error: null,
  };

  let onEvent = () => {};
  let resolveExit;
  const exitPromise = new Promise((resolve) => {
    resolveExit = resolve;
  });

  worker.on('message', (message) => {
    if (message.type === 'stats' || message.type === 'done') {
      state.attempts = Math.max(state.attempts, message.attempts);
      state.best = Math.max(state.best, message.best);
      onEvent({ type: 'stats', source: state });
    } else if (message.type === 'match') {
      state.attempts = Math.max(state.attempts, message.attempts);
      state.best = Math.max(state.best, message.best);
      onEvent({ type: 'match', source: state, match: message });
    } else if (message.type === 'error') {
      state.error = new Error(message.error?.message ?? 'worker error');
      onEvent({ type: 'error', source: state, error: state.error });
    }
  });

  worker.on('error', (error) => {
    state.error = error;
    onEvent({ type: 'error', source: state, error });
  });

  worker.on('exit', () => {
    state.exited = true;
    resolveExit();
    onEvent({ type: 'exit', source: state });
  });

  return {
    states: [state],

    start(handler) {
      onEvent = handler;
      worker.postMessage({ type: 'search', raw: pattern.raw, stopAfterFirst });
    },

    async stop() {
      try {
        worker.postMessage({ type: 'stop' });
      } catch {
        // already exited
      }
      const timer = setTimeout(() => {
        worker.terminate().catch(() => {});
      }, STOP_GRACE_MS);
      await exitPromise;
      clearTimeout(timer);
    },
  };
}
