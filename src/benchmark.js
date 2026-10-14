/**
 * Key generation micro-benchmark.
 *
 * Measures how many v3 address candidates this machine can produce per second
 * (Ed25519 keygen + base32). Feed the resulting rate into the estimator to
 * convert "attempts" into wall-clock time.
 */
import { Worker } from 'node:worker_threads';
import { defaultWorkerCount } from './search.js';

const WORKER_URL = new URL('./worker.js', import.meta.url);

export async function benchmark({ workers = defaultWorkerCount(), durationSeconds = 3 } = {}) {
  if (!Number.isInteger(workers) || workers < 1) {
    throw new TypeError('workers must be an integer >= 1');
  }
  if (!(durationSeconds > 0)) {
    throw new TypeError('durationSeconds must be > 0');
  }

  const results = [];
  const done = new Set();
  const workerList = [];

  await new Promise((resolve, reject) => {
    const markDone = (id) => {
      if (done.has(id)) return;
      done.add(id);
      if (done.size === workers) resolve();
    };

    for (let id = 0; id < workers; id += 1) {
      const worker = new Worker(WORKER_URL);
      workerList.push(worker);

      worker.on('message', (message) => {
        if (message.type === 'benchmark-result') {
          results.push({ id, attempts: message.attempts, activeMs: message.activeMs });
          markDone(id);
          worker.terminate().catch(() => {});
        }
      });
      worker.on('exit', () => markDone(id));
      worker.on('error', (error) => reject(error));

      worker.postMessage({ type: 'benchmark', durationMs: durationSeconds * 1000 });
    }
  });

  await Promise.allSettled(workerList.map((worker) => worker.terminate()));

  const attempts = results.reduce((sum, result) => sum + result.attempts, 0);
  const activeMs = Math.max(...results.map((result) => result.activeMs), 1);
  const rate = (attempts / activeMs) * 1000;

  return {
    workers,
    attempts,
    durationMs: activeMs,
    rate,
    ratePerWorker: rate / workers,
    results: results.sort((a, b) => a.id - b.id),
  };
}
