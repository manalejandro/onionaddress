/**
 * Search worker. Each worker owns a thread and loops over the only known way
 * to mine a v3 address: generate a fresh Ed25519 key pair and compare the
 * address bytes (PUBKEY | CHECKSUM | VERSION) against the compiled pattern.
 *
 * Per-candidate pipeline (cost measured on Node 22, OpenSSL 3.5):
 *
 *   1. Ed25519 keygen ................ ~65 us   (irreducible, dominates)
 *   2. raw public key extraction ..... ~2 us    (via the JWK encoder;
 *                                                SPKI DER costs ~30x more)
 *   3. SHA3-256 checksum ............. ~1.5 us  (only when pattern.needsTail)
 *   4. bit-mask match + score ........ ~0.05 us (early-exit bit extraction)
 *
 * Prefixes of up to 51 characters live entirely inside the public key, so
 * for those the SHA3 checksum in step 3 is skipped altogether.
 *
 * The loop yields to the event loop every YIELD_EVERY attempts so the worker
 * can receive "stop" messages and report progress while it works.
 */
import crypto from 'node:crypto';
import { parentPort } from 'node:worker_threads';
import {
  ADDRESS_BYTES,
  CHECKSUM_PREFIX,
  addressBytesForPublicKey,
  base32Encode,
  generateKeyPair,
  seedFromPrivateKey,
  sha3_256,
} from './onion.js';
import { parsePattern } from './pattern.js';

const YIELD_EVERY = 512;
const HASH_INPUT_BYTES = CHECKSUM_PREFIX.length + 32 + 1; // 48
const VERSION = 0x03;

let running = false;

parentPort.on('message', (message) => {
  if (message.type === 'search') {
    runSearch(message).catch((error) => fail(error));
  } else if (message.type === 'benchmark') {
    runBenchmark(message).catch((error) => fail(error));
  } else if (message.type === 'stop') {
    running = false;
  }
});

function fail(error) {
  parentPort.postMessage({
    type: 'error',
    error: { message: error.message, stack: error.stack },
  });
  parentPort.close();
}

/**
 * One candidate: an Ed25519 key pair plus the raw 32-byte public key,
 * base64url-encoded by the JWK exporter. Key generation can fail in rare
 * OpenSSL corner cases; those candidates are simply skipped.
 */
function nextCandidate() {
  try {
    const { privateKey, publicKey } = generateKeyPair();
    return { privateKey, x: publicKey.export({ format: 'jwk' }).x };
  } catch {
    return null;
  }
}

const yieldToEventLoop = () => new Promise((resolve) => setImmediate(resolve));

async function runSearch({ raw, stopAfterFirst }) {
  running = true;
  const pattern = parsePattern(raw);
  const needsTail = pattern.needsTail;

  // Reusable scratch buffers: 35 address bytes plus one spare byte so the
  // two-byte 5-bit window lookups in pattern.score() stay in bounds, and the
  // pre-filled SHA3 input ".onion checksum" | PUBKEY | 0x03.
  const bytes = Buffer.allocUnsafe(ADDRESS_BYTES + 1);
  bytes[ADDRESS_BYTES] = 0;
  const hashInput = Buffer.allocUnsafe(HASH_INPUT_BYTES);
  CHECKSUM_PREFIX.copy(hashInput);
  hashInput[HASH_INPUT_BYTES - 1] = VERSION;

  let attempts = 0;
  let best = 0;
  let lastReport = Date.now();

  while (running) {
    for (let i = 0; i < YIELD_EVERY && running; i += 1) {
      const candidate = nextCandidate();
      if (!candidate) continue;
      attempts += 1;

      bytes.write(candidate.x, 0, 32, 'base64url');

      // Only pay for the checksum when the pattern actually reaches the tail.
      if (needsTail) {
        bytes.copy(hashInput, CHECKSUM_PREFIX.length, 0, 32);
        const digest = sha3_256(hashInput);
        bytes[32] = digest[0];
        bytes[33] = digest[1];
        bytes[34] = VERSION;
      }

      if (pattern.match(bytes)) {
        const publicKey = Buffer.from(bytes.subarray(0, 32));
        const address = base32Encode(addressBytesForPublicKey(publicKey));
        parentPort.postMessage({
          type: 'match',
          address,
          seedB64: seedFromPrivateKey(candidate.privateKey).toString('base64'),
          publicKeyB64: publicKey.toString('base64'),
          attempts,
        });
        best = 0;
        if (stopAfterFirst) {
          running = false;
          break;
        }
      } else {
        const score = pattern.score(bytes);
        if (score > best) best = score;
      }
    }

    const now = Date.now();
    if (now - lastReport >= 500) {
      parentPort.postMessage({ type: 'stats', attempts, best });
      lastReport = now;
    }
    if (running) await yieldToEventLoop();
  }

  parentPort.postMessage({ type: 'done', attempts, best });
  parentPort.close();
}

async function runBenchmark({ durationMs }) {
  running = true;
  const start = Date.now();
  const deadline = start + durationMs;
  let attempts = 0;

  while (running && Date.now() < deadline) {
    for (let i = 0; i < YIELD_EVERY && running; i += 1) {
      if (nextCandidate()) attempts += 1;
    }
    await yieldToEventLoop();
  }

  parentPort.postMessage({
    type: 'benchmark-result',
    attempts,
    activeMs: Date.now() - start,
  });
  parentPort.close();
}
