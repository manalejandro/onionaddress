import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { addressFromPrivateKey, privateKeyFromSeed } from '../src/onion.js';
import { listMinerDevices } from '../src/gpu.js';
import { search } from '../src/search.js';

const CPU_MINER = fileURLToPath(new URL('../bin/onionaddress-cpu', import.meta.url));
const CUDA_MINER = fileURLToPath(new URL('../bin/onionaddress-cuda', import.meta.url));

const hasCpuMiner = existsSync(CPU_MINER);
const hasCudaMiner =
  existsSync(CUDA_MINER) &&
  (() => {
    try {
      execFileSync(CUDA_MINER, ['list-devices'], { stdio: 'ignore', timeout: 60000 });
      return true;
    } catch {
      return false;
    }
  })();

const CPU_SKIP = hasCpuMiner ? false : 'bin/onionaddress-cpu not built (run: make -C gpu cpu)';
const CUDA_SKIP = hasCudaMiner ? false : 'bin/onionaddress-cuda not built or no CUDA device';

// Produced by an independent Python implementation (cryptography + hashlib).
const PYTHON_VECTOR = {
  seed: '42'.repeat(32),
  address: 'efjprum3peosirjsilqv6lvlns3476t3njpngaexsyhangeb3mjo7sad',
};

async function makeTempDir(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'onionaddress-gpu-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

function verifySeedLine(line) {
  const { seed, address } = JSON.parse(line);
  assert.equal(addressFromPrivateKey(privateKeyFromSeed(Buffer.from(seed, 'hex'))), address);
  return address;
}

test('cpu miner reproduces the fixed vector', { skip: CPU_SKIP }, () => {
  const out = execFileSync(CPU_MINER, ['selftest', '--seed', PYTHON_VECTOR.seed], { encoding: 'utf8' });
  assert.equal(JSON.parse(out.trim()).address, PYTHON_VECTOR.address);
});

test('cpu miner seeds agree with OpenSSL', { skip: CPU_SKIP, timeout: 120000 }, () => {
  const out = execFileSync(CPU_MINER, ['selftest', '--count', '150'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const lines = out.trim().split('\n');
  assert.equal(lines.length, 150);
  for (const line of lines) verifySeedLine(line);
});

test('cpu miner hashes agree with OpenSSL', { skip: CPU_SKIP, timeout: 60000 }, () => {
  const lengths = [0, 1, 3, 15, 31, 32, 47, 48, 55, 56, 63, 64, 111, 112, 127, 128, 135, 136, 137, 300];
  const inputs = lengths.map((n) => crypto.randomBytes(n).toString('hex'));
  const out = execFileSync(CPU_MINER, ['hash-selftest'], {
    input: `${inputs.join('\n')}\n`,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const lines = out.trim().split('\n');
  assert.equal(lines.length, lengths.length);
  for (const line of lines) {
    const { input, sha512, sha3 } = JSON.parse(line);
    const data = Buffer.from(input, 'hex');
    assert.equal(sha512, crypto.createHash('sha512').update(data).digest('hex'));
    assert.equal(sha3, crypto.createHash('sha3-256').update(data).digest('hex'));
  }
});

test('cpu miner reports itself as a device', { skip: CPU_SKIP }, async () => {
  const devices = await listMinerDevices(CPU_MINER);
  assert.equal(devices.length, 1);
  assert.equal(devices[0].backend, 'cpu');
});

test(
  'search() drives the miner protocol end to end (reference miner as device)',
  { skip: CPU_SKIP, timeout: 120000 },
  async (t) => {
    const outputDir = await makeTempDir(t);
    const result = await search({
      pattern: '^a',
      count: 1,
      workers: 0,
      devices: [0],
      minerPath: CPU_MINER,
      timeoutSeconds: 60,
      outputDir,
    });

    assert.equal(result.completed, true);
    assert.equal(result.found.length, 1);
    assert.ok(result.attempts > 0, 'attempts must be accounted for');

    const [match] = result.found;
    assert.match(match.address, /^a[a-z2-7]{55}$/);
    const secret = await readFile(
      path.join(outputDir, `${match.address}.onion`, 'hs_ed25519_secret_key'),
    );
    assert.equal(addressFromPrivateKey(privateKeyFromSeed(secret.subarray(32, 64))), match.address);

    const metadata = JSON.parse(
      await readFile(path.join(outputDir, `${match.address}.onion`, 'metadata.json'), 'utf8'),
    );
    assert.equal(metadata.address, `${match.address}.onion`);
    assert.ok(metadata.search.attemptsByFinder >= 1);
  },
);

test('cuda miner reproduces the fixed vector', { skip: CUDA_SKIP, timeout: 60000 }, () => {
  const out = execFileSync(CUDA_MINER, ['selftest', '--seed', PYTHON_VECTOR.seed], {
    encoding: 'utf8',
  });
  assert.equal(JSON.parse(out.trim()).address, PYTHON_VECTOR.address);
});

test('cuda miner seeds agree with OpenSSL', { skip: CUDA_SKIP, timeout: 180000 }, () => {
  const out = execFileSync(CUDA_MINER, ['selftest', '--count', '1000'], {
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
  });
  const lines = out.trim().split('\n');
  assert.equal(lines.length, 1000);
  for (const line of lines) verifySeedLine(line);
});

test('search() mines on the GPU and verifies every result', { skip: CUDA_SKIP, timeout: 180000 }, async (t) => {
  const outputDir = await makeTempDir(t);
  const result = await search({
    pattern: '^dead',
    count: 1,
    workers: 0,
    devices: true,
    timeoutSeconds: 120,
    outputDir,
  });

  assert.equal(result.completed, true);
  assert.equal(result.invalidResults, 0);
  assert.equal(result.found.length, 1);
  assert.ok(result.attempts > 0);

  const [match] = result.found;
  assert.match(match.address, /^dead[a-z2-7]{52}$/);
  const secret = await readFile(
    path.join(outputDir, `${match.address}.onion`, 'hs_ed25519_secret_key'),
  );
  assert.equal(addressFromPrivateKey(privateKeyFromSeed(secret.subarray(32, 64))), match.address);
});
