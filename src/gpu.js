/**
 * GPU miner source: spawns one native miner process per CUDA device
 * (gpu/miner_cuda.cu, built with `make -C gpu cuda`) and talks the
 * JSON-lines protocol with it.
 *
 * Every match is re-derived and re-checked here with Node's own OpenSSL
 * bindings before it is handed to the orchestrator, so a driver bug, a bad
 * overclock or a buggy kernel can never produce a corrupt key file.
 *
 * Source interface: see src/cpu.js.
 */
import { spawn } from 'node:child_process';
import { constants as fsConstants, accessSync } from 'node:fs';
import crypto from 'node:crypto';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  addressBytesForPublicKey,
  base32Encode,
  privateKeyFromSeed,
  publicKeyBytes,
} from './onion.js';

const STOP_GRACE_MS = 2000;
const LIST_TIMEOUT_MS = 15000;

const CANDIDATE_URLS = [
  new URL('../bin/onionaddress-cuda', import.meta.url),
  new URL('../bin/onionaddress-cpu', import.meta.url),
];

/**
 * Locate a miner binary. An explicit path is authoritative (no fallback);
 * otherwise ONIONADDRESS_MINER wins, then the built binaries under bin/
 * (CUDA first, CPU reference second).
 */
export function findMiner({ explicit } = {}) {
  const isExecutable = (candidate) => {
    try {
      accessSync(candidate, fsConstants.X_OK);
      return true;
    } catch {
      return false;
    }
  };

  if (explicit) {
    return isExecutable(explicit) ? explicit : null;
  }
  const candidates = [process.env.ONIONADDRESS_MINER]
    .filter(Boolean)
    .concat(CANDIDATE_URLS.map((url) => fileURLToPath(url)));
  for (const candidate of candidates) {
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

/**
 * Ask a miner binary which devices it can drive. Returns
 * [{ backend, index, name, sm?, threads? }].
 */
export function listMinerDevices(minerPath) {
  return new Promise((resolve, reject) => {
    const child = spawn(minerPath, ['list-devices'], { stdio: ['ignore', 'pipe', 'pipe'] });
    const devices = [];
    let errorMessage = null;
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`miner list-devices timed out after ${LIST_TIMEOUT_MS}ms`));
    }, LIST_TIMEOUT_MS);
    const finish = (fn) => {
      clearTimeout(timer);
      fn();
    };

    createInterface({ input: child.stdout }).on('line', (line) => {
      try {
        const message = JSON.parse(line);
        if (message.type === 'device') devices.push(message);
        else if (message.type === 'error') errorMessage = message.message;
      } catch {
        // ignore non-JSON output
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (error) => finish(() => reject(error)));
    child.on('exit', (code) =>
      finish(() => {
        if (devices.length > 0) {
          resolve(devices);
        } else {
          reject(
            new Error(
              errorMessage ??
                `miner exited with code ${code}${stderr ? `: ${stderr.trim()}` : ''}`,
            ),
          );
        }
      }),
    );
  });
}

/**
 * Re-derive a miner result with Node/OpenSSL. Returns the normalized match
 * { address, seedB64, publicKeyB64, attempts } when the reported seed and
 * address are consistent and the pattern matches, or null otherwise.
 */
export function verifyMinerMatch(pattern, message) {
  if (typeof message.seed !== 'string' || message.seed.length !== 64) return null;
  const seed = Buffer.from(message.seed, 'hex');
  if (seed.length !== 32) return null;

  try {
    const publicKey = publicKeyBytes(crypto.createPublicKey(privateKeyFromSeed(seed)));
    const addressBytes = addressBytesForPublicKey(publicKey);
    if (base32Encode(addressBytes) !== message.address) return null;
    if (!pattern.match(addressBytes)) return null;
    return {
      address: message.address,
      seedB64: seed.toString('base64'),
      publicKeyB64: publicKey.toString('base64'),
      attempts: message.attempts,
    };
  } catch {
    return null;
  }
}

function spawnMinerDevice(minerPath, pattern, deviceIndex, emit) {
  const child = spawn(minerPath, ['mine', '--pattern', pattern.raw, '--device', String(deviceIndex)], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const state = {
    kind: 'cuda',
    label: `device ${deviceIndex}`,
    attempts: 0,
    best: 0,
    exited: false,
    error: null,
    name: null,
    threads: null,
  };

  let resolveExit;
  const exitPromise = new Promise((resolve) => {
    resolveExit = resolve;
  });
  let stderrTail = '';
  let stopping = false;
  let exited = false;
  let stdoutClosed = false;
  const maybeResolveExit = () => {
    if (exited && stdoutClosed) resolveExit();
  };

  child.stderr.on('data', (chunk) => {
    stderrTail = `${stderrTail}${chunk}`.slice(-2000);
  });
  child.stdout.on('close', () => {
    stdoutClosed = true;
    maybeResolveExit();
  });
  child.on('error', (error) => {
    state.error = error;
    state.exited = true;
    exited = true;
    maybeResolveExit();
    emit({ type: 'error', source: state, error });
  });
  child.on('exit', (code) => {
    state.exited = true;
    if (code !== 0 && !state.error && !stopping) {
      state.error = new Error(
        `miner exited with code ${code}${stderrTail ? `: ${stderrTail.trim()}` : ''}`,
      );
      emit({ type: 'error', source: state, error: state.error });
    }
    exited = true;
    maybeResolveExit();
    emit({ type: 'exit', source: state });
  });

  createInterface({ input: child.stdout }).on('line', (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (message.type === 'ready') {
      state.name = message.name;
      state.threads = message.threads;
      emit({ type: 'ready', source: state });
    } else if (message.type === 'progress') {
      state.attempts = Math.max(state.attempts, message.attempts);
      state.best = Math.max(state.best, message.best);
      emit({ type: 'stats', source: state });
    } else if (message.type === 'match') {
      emit({ type: 'match-raw', source: state, message });
    } else if (message.type === 'error') {
      state.error = new Error(message.message);
      emit({ type: 'error', source: state, error: state.error });
    }
  });

  return {
    state,
    child,
    exitPromise,
    sendStop() {
      stopping = true;
      try {
        child.stdin.write('{"type":"stop"}\n');
        child.stdin.end();
      } catch {
        // already gone
      }
    },
  };
}

/**
 * Source driving one miner process per device.
 */
export function createGpuSource({ pattern, devices, minerPath }) {
  let onEvent = () => {};
  const emit = (event) => onEvent(event);
  const processes = devices.map((deviceIndex) =>
    spawnMinerDevice(minerPath, pattern, deviceIndex, emit),
  );

  return {
    states: processes.map((p) => p.state),

    start(handler) {
      onEvent = handler;
      // miner processes were spawned eagerly and are already searching
    },

    async stop() {
      for (const p of processes) p.sendStop();
      await Promise.all(
        processes.map(async (p) => {
          const timer = setTimeout(() => {
            p.child.kill('SIGKILL');
          }, STOP_GRACE_MS);
          await p.exitPromise;
          clearTimeout(timer);
        }),
      );
    },
  };
}

/**
 * Measure the miners' candidate rate for a fixed duration. Returns
 * { attempts, elapsedMs, rate, devices }.
 */
export async function benchmarkMiner({ minerPath, devices = true, durationSeconds }) {
  const available = await listMinerDevices(minerPath);
  const wanted =
    devices === true
      ? available.map((device) => device.index)
      : Array.isArray(devices)
        ? devices
        : [devices];

  // A 32-character prefix never matches during a benchmark.
  const pattern = { raw: `^${'z'.repeat(32)}` };
  const source = createGpuSource({ pattern, devices: wanted, minerPath });
  source.start(() => {});

  const started = Date.now();
  await new Promise((resolve) => setTimeout(resolve, durationSeconds * 1000));
  const elapsedMs = Date.now() - started;
  const attempts = source.states.reduce((sum, state) => sum + state.attempts, 0);
  const results = source.states.map((state) => ({
    label: state.label,
    name: state.name,
    attempts: state.attempts,
  }));
  await source.stop();

  const elapsedSeconds = elapsedMs / 1000;
  return {
    attempts,
    elapsedMs,
    rate: elapsedSeconds > 0 ? attempts / elapsedSeconds : 0,
    devices: results,
  };
}
