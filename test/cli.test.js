import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));

function runCli(...args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('--estimate prints the probability model', () => {
  const result = runCli('--estimate', '^abc');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /32,768/);
  assert.match(result.stdout, /median attempts/);
});

test('--estimate accounts for the fixed version bits of suffixes', () => {
  const result = runCli('--estimate', 'yd$');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /1 in 4\b/);
});

test('--help exits 0 and shows usage', () => {
  const result = runCli('--help');
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage/);
  assert.match(result.stdout, /Tor v3/);
});

test('--version prints the package version', () => {
  const result = runCli('--version');
  assert.equal(result.status, 0);
  assert.match(result.stdout.trim(), /^\d+\.\d+\.\d+$/);
});

test('invalid patterns exit with code 2', () => {
  const result = runCli('nope');
  assert.equal(result.status, 2);
  assert.match(result.stderr, /\^/);
});

test('impossible suffixes exit with code 2', () => {
  const wrongLast = runCli('abcz$');
  assert.equal(wrongLast.status, 2);
  assert.match(wrongLast.stderr, /ends with "d"/);

  const wrongPenultimate = runCli('azd$');
  assert.equal(wrongPenultimate.status, 2);
  assert.match(wrongPenultimate.stderr, /second-to-last/);
});

test('refuses astronomically unlikely patterns unless forced', () => {
  const result = runCli(`^${'a'.repeat(10)}`);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--force/);
});

test('missing pattern exits with code 1', () => {
  const result = runCli();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /missing search pattern/);
});

test('unknown options exit with code 1', () => {
  const result = runCli('--nope', '^abc');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unknown option/);
});

test('devices command without a miner binary fails cleanly', () => {
  const result = spawnSync(process.execPath, [CLI, 'devices', '--miner', '/nonexistent/onion-miner'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no miner binary found/);
});

test('--gpu with a missing miner binary fails cleanly', () => {
  const result = runCli('--gpu', '--miner', '/nonexistent/onion-miner', '^abc');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no miner binary found/);
});
