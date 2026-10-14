import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { addressFromPrivateKey, privateKeyFromSeed } from '../src/onion.js';
import { search } from '../src/search.js';

async function makeTempDir(t) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'onionaddress-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('finds a prefix and writes a usable hidden service directory', { timeout: 120000 }, async (t) => {
  const outputDir = await makeTempDir(t);
  const result = await search({ pattern: '^a', count: 1, workers: 2, timeoutSeconds: 60, outputDir });

  assert.equal(result.completed, true);
  assert.equal(result.found.length, 1);

  const [match] = result.found;
  assert.match(match.address, /^a[a-z2-7]{55}$/);
  assert.ok(match.address.endsWith('d'));

  const dir = path.join(outputDir, `${match.address}.onion`);

  const hostname = (await readFile(path.join(dir, 'hostname'), 'utf8')).trim();
  assert.equal(hostname, `${match.address}.onion`);

  const secretFile = await readFile(path.join(dir, 'hs_ed25519_secret_key'));
  assert.equal(secretFile.length, 96);
  assert.deepEqual(
    secretFile.subarray(0, 32),
    Buffer.concat([Buffer.from('== ed25519v1-secret: type0 =='), Buffer.alloc(3)]),
  );

  const publicFile = await readFile(path.join(dir, 'hs_ed25519_public_key'));
  assert.equal(publicFile.length, 64);
  assert.deepEqual(
    publicFile.subarray(0, 32),
    Buffer.concat([Buffer.from('== ed25519v1-public: type0 =='), Buffer.alloc(3)]),
  );

  // The saved seed must derive the saved public key and the exact address.
  const seed = secretFile.subarray(32, 64);
  assert.deepEqual(secretFile.subarray(64), publicFile.subarray(32));
  assert.equal(addressFromPrivateKey(privateKeyFromSeed(seed)), match.address);

  const metadata = JSON.parse(await readFile(path.join(dir, 'metadata.json'), 'utf8'));
  assert.equal(metadata.address, `${match.address}.onion`);
  assert.equal(metadata.pattern.raw, '^a');
  assert.equal(metadata.key.type, 'Ed25519');
  assert.equal(metadata.key.onionVersion, 3);
  assert.equal(metadata.search.attempts, result.attempts);
  assert.ok(metadata.search.attemptsByFinder >= 1);

  if (process.platform !== 'win32') {
    const credentials = await stat(path.join(dir, 'hs_ed25519_secret_key'));
    assert.equal(credentials.mode & 0o777, 0o600, 'secret key must be 0600');
  }

  const log = await readFile(path.join(outputDir, 'found.log'), 'utf8');
  assert.ok(log.includes(`${match.address}.onion`));
});

test('collects multiple suffix matches when count > 1', { timeout: 120000 }, async (t) => {
  const outputDir = await makeTempDir(t);
  const result = await search({ pattern: 'ayd$', count: 2, workers: 2, timeoutSeconds: 60, outputDir });

  assert.equal(result.completed, true);
  assert.equal(result.found.length, 2);
  assert.notEqual(result.found[0].address, result.found[1].address);
  for (const match of result.found) {
    assert.match(match.address, /ayd$/);
    const secretFile = await readFile(
      path.join(outputDir, `${match.address}.onion`, 'hs_ed25519_secret_key'),
    );
    assert.equal(addressFromPrivateKey(privateKeyFromSeed(secretFile.subarray(32, 64))), match.address);
  }
});

test('honors the timeout without finding an unlikely pattern', { timeout: 30000 }, async (t) => {
  const outputDir = await makeTempDir(t);
  const started = Date.now();
  const result = await search({ pattern: '^aaaaaa', count: 1, workers: 1, timeoutSeconds: 1, outputDir });
  const elapsed = Date.now() - started;

  assert.equal(result.timedOut, true);
  assert.equal(result.completed, false);
  assert.equal(result.found.length, 0);
  assert.ok(elapsed < 15000, `search stopped after ${elapsed}ms`);
});

test('can be aborted through an AbortSignal', { timeout: 30000 }, async (t) => {
  const outputDir = await makeTempDir(t);
  const controller = new AbortController();
  const promise = search({
    pattern: '^aaaaaa',
    count: 1,
    workers: 1,
    outputDir,
    signal: controller.signal,
  });
  setTimeout(() => controller.abort(), 500);

  const result = await promise;
  assert.equal(result.aborted, true);
  assert.equal(result.found.length, 0);
});

test('rejects invalid patterns before starting workers', async () => {
  await assert.rejects(search({ pattern: 'nope' }), /start it with "\^"/);
  await assert.rejects(search({ pattern: 'abcx$' }), /ends with "d"/);
});
