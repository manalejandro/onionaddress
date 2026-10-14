/**
 * Multi-source search orchestration.
 *
 * Runs one or more sources — Node worker threads on CPU (src/cpu.js),
 * native miner processes on GPU (src/gpu.js), or both — and funnels their
 * matches through a single save queue, so results are written in arrival
 * order and metadata stays consistent. GPU matches are re-derived and
 * verified with Node/OpenSSL before they get here.
 *
 * Events emitted through onEvent:
 *   progress  { attempts, rate, elapsedMs, expectedRemainingMs, probability, best }
 *   found     { match, found, count }
 *   warning   { message }
 *   stopping  { reason }
 *   stopped   { reason }
 *   error     { error, source? }
 */
import os from 'node:os';
import path from 'node:path';
import { createCpuSource } from './cpu.js';
import { successProbability } from './estimator.js';
import { createGpuSource, findMiner, listMinerDevices, verifyMinerMatch } from './gpu.js';
import { ensureOutputDir, reviseMetadata, saveResult } from './output.js';
import { parsePattern } from './pattern.js';
import { VERSION } from './version.js';

const PROGRESS_INTERVAL_MS = 500;
const RATE_WINDOW_MS = 6000;

export function defaultWorkerCount() {
  const available =
    typeof os.availableParallelism === 'function' ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, available - 1);
}

export async function search(options = {}) {
  const {
    pattern: patternInput,
    count = 1,
    workers = defaultWorkerCount(),
    devices = false,
    minerPath = null,
    timeoutSeconds = 0,
    outputDir = path.resolve(process.cwd(), 'output'),
    onEvent = () => {},
    signal,
  } = options;

  const pattern =
    patternInput && typeof patternInput === 'object' ? patternInput : parsePattern(patternInput);

  if (!Number.isInteger(count) || count < 0) {
    throw new TypeError('count must be an integer >= 0 (0 = unlimited)');
  }
  if (!Number.isInteger(workers) || workers < 0) {
    throw new TypeError('workers must be an integer >= 0');
  }
  if (typeof timeoutSeconds !== 'number' || timeoutSeconds < 0) {
    throw new TypeError('timeoutSeconds must be a number >= 0');
  }

  const wantsGpu = devices !== false && devices !== null && devices !== undefined;
  if (workers === 0 && !wantsGpu) {
    throw new TypeError('at least one CPU worker or GPU device is required');
  }

  // Resolve GPU devices up front so configuration errors surface early.
  let resolvedMiner = null;
  let gpuDevices = [];
  if (wantsGpu) {
    resolvedMiner = findMiner({ explicit: minerPath });
    if (!resolvedMiner) {
      throw new Error(
        'no miner binary found; build one with "make -C gpu cuda" (or "make -C gpu cpu") ' +
          'or set ONIONADDRESS_MINER',
      );
    }
    const available = await listMinerDevices(resolvedMiner);
    const wanted =
      devices === true ? available.map((device) => device.index) : Array.isArray(devices) ? devices : [devices];
    for (const index of wanted) {
      if (!available.some((device) => device.index === index)) {
        throw new Error(
          `device ${index} is not available (found: ${available.map((device) => device.index).join(', ')})`,
        );
      }
    }
    gpuDevices = wanted;
  }

  const startTime = Date.now();
  const startedAt = new Date(startTime);
  const found = [];
  const sources = [];
  const samples = [];

  let stopping = false;
  let stopReason = null;
  let timedOut = false;
  let aborted = false;
  let errored = false;
  let invalidResults = 0;
  let progressTimer = null;
  let timeoutTimer = null;
  let saveChain = Promise.resolve();
  let abortHandler = null;
  let resolveStopped;
  const stoppedPromise = new Promise((resolve) => {
    resolveStopped = resolve;
  });

  for (let id = 0; id < workers; id += 1) {
    sources.push(createCpuSource({ id, pattern, stopAfterFirst: count === 1 }));
  }
  if (wantsGpu) {
    sources.push(createGpuSource({ pattern, devices: gpuDevices, minerPath: resolvedMiner }));
  }
  const allStates = sources.flatMap((source) => source.states);

  const elapsedMs = () => Date.now() - startTime;
  const totalAttempts = () => {
    let total = 0;
    for (const state of allStates) total += state.attempts;
    return total;
  };
  const bestScore = () => {
    let best = 0;
    for (const state of allStates) best = Math.max(best, state.best);
    return best;
  };
  const currentRate = () => {
    if (samples.length < 2) return 0;
    const first = samples[0];
    const last = samples[samples.length - 1];
    const seconds = (last.t - first.t) / 1000;
    return seconds > 0 ? (last.attempts - first.attempts) / seconds : 0;
  };

  function summary() {
    const attempts = totalAttempts();
    const ms = elapsedMs();
    const seconds = ms / 1000;
    return {
      pattern,
      found,
      attempts,
      elapsedMs: ms,
      startedAt,
      requestedCount: count,
      completed: count > 0 && found.length >= count,
      timedOut,
      aborted,
      errored,
      invalidResults,
      reason: stopReason,
      rate: seconds > 0 ? attempts / seconds : 0,
      sources: allStates.map((state) => ({
        kind: state.kind,
        label: state.label,
        name: state.name ?? null,
        attempts: state.attempts,
        best: state.best,
      })),
      outputDir,
    };
  }

  async function stop(reason) {
    if (stopping) return;
    stopping = true;
    stopReason = reason;
    if (progressTimer) clearInterval(progressTimer);
    if (timeoutTimer) clearTimeout(timeoutTimer);
    onEvent({ type: 'stopping', reason });

    try {
      await Promise.all(sources.map((source) => source.stop()));
    } catch (error) {
      errored = true;
      onEvent({ type: 'error', error });
    } finally {
      if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
      onEvent({ type: 'stopped', reason: stopReason });
      resolveStopped();
    }
  }

  function handleSourceEvent(event) {
    switch (event.type) {
      case 'match':
        enqueueSave(event.match);
        break;
      case 'match-raw': {
        const verified = verifyMinerMatch(pattern, event.message);
        if (verified) {
          enqueueSave(verified);
        } else {
          invalidResults += 1;
          onEvent({
            type: 'warning',
            message: `discarded an unverifiable result from ${event.source.label} (hardware or driver fault)`,
          });
        }
        break;
      }
      case 'error':
        errored = true;
        onEvent({ type: 'error', source: event.source, error: event.error });
        break;
      case 'exit':
        if (!stopping && allStates.every((state) => state.exited)) {
          stop('sources-finished');
        }
        break;
      default:
        break; // 'stats' and 'ready' only update the source state
    }
  }

  function enqueueSave(message) {
    saveChain = saveChain
      .then(async () => {
        if (count > 0 && found.length >= count) return;
        const seed = Buffer.from(message.seedB64, 'base64');
        const publicKey = Buffer.from(message.publicKeyB64, 'base64');
        const foundAt = new Date();
        const attempts = totalAttempts();
        const { dir, hostname } = await saveResult({
          outputDir,
          address: message.address,
          seed,
          publicKey,
          pattern: { raw: pattern.raw, mode: pattern.mode, body: pattern.body },
          attempts,
          attemptsByFinder: message.attempts,
          startedAt,
          foundAt,
          version: VERSION,
        });
        const match = {
          address: message.address,
          hostname,
          dir,
          attempts,
          attemptsByFinder: message.attempts,
          foundAt,
          elapsedMs: Date.now() - startTime,
        };
        found.push(match);
        onEvent({ type: 'found', match, found: found.length, count });
        if (count > 0 && found.length >= count) stop('count');
      })
      .catch((error) => {
        errored = true;
        onEvent({ type: 'error', error });
        stop('write-error');
      });
  }

  if (signal) {
    if (signal.aborted) {
      aborted = true;
      stopReason = 'aborted';
      return summary();
    }
    abortHandler = () => {
      aborted = true;
      stop('aborted');
    };
    signal.addEventListener('abort', abortHandler, { once: true });
  }

  await ensureOutputDir(outputDir);

  for (const source of sources) source.start(handleSourceEvent);

  progressTimer = setInterval(() => {
    const attempts = totalAttempts();
    const now = Date.now();
    samples.push({ t: now, attempts });
    while (samples.length > 2 && now - samples[0].t > RATE_WINDOW_MS) samples.shift();
    const rate = currentRate();
    onEvent({
      type: 'progress',
      attempts,
      rate,
      elapsedMs: elapsedMs(),
      expectedRemainingMs: rate > 0 ? (pattern.space / rate) * 1000 : Infinity,
      probability: successProbability(attempts, pattern.space),
      best: bestScore(),
    });
  }, PROGRESS_INTERVAL_MS);

  if (timeoutSeconds > 0) {
    timeoutTimer = setTimeout(() => {
      timedOut = true;
      stop('timeout');
    }, timeoutSeconds * 1000);
  }

  await stoppedPromise;
  await saveChain;

  if (found.length > 0) {
    const finalAttempts = totalAttempts();
    for (const match of found) {
      try {
        await reviseMetadata(match.dir, { attempts: finalAttempts });
        match.attempts = finalAttempts;
      } catch (error) {
        errored = true;
        onEvent({ type: 'error', error });
      }
    }
  }

  return summary();
}
