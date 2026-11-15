import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { ensureMiner, findMiner, minerKind } from '../src/gpu.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

/**
 * The native miners are built on install (postinstall) or lazily on first use.
 * Both paths only work if the sources and the build script are actually
 * published, so the packaging allowlist is asserted here.
 */
test('package ships everything the on-demand build needs', () => {
  assert.ok(pkg.files.includes('src'), 'files must include src');
  assert.ok(pkg.files.includes('gpu'), 'files must include gpu (miner sources)');
  assert.ok(pkg.files.includes('scripts'), 'files must include scripts (build script)');

  assert.match(pkg.scripts.postinstall, /build-miners\.js/);
  assert.ok(existsSync(path.join(ROOT, 'scripts', 'build-miners.js')));

  for (const file of ['gpu/core.h', 'gpu/tables.h', 'gpu/miner_cpu.cpp', 'gpu/miner_cuda.cu', 'gpu/Makefile']) {
    assert.ok(existsSync(path.join(ROOT, file)), `${file} must exist`);
  }
});

test('miner binaries are gitignored build artifacts', () => {
  const ignore = readFileSync(path.join(ROOT, '.gitignore'), 'utf8');
  assert.match(ignore, /^bin\/$/m);
});

test('minerKind classifies binaries by name', () => {
  assert.equal(minerKind('/x/bin/onionaddress-cuda'), 'cuda');
  assert.equal(minerKind('/x/bin/onionaddress-cpu'), 'cpu');
  assert.equal(minerKind('/x/bin/something-else'), 'unknown');
});

test('an explicit miner path is authoritative and never rebuilt', () => {
  assert.equal(ensureMiner({ explicit: '/nonexistent/onion-miner' }), null);
  assert.equal(findMiner({ explicit: '/nonexistent/onion-miner' }), null);
});

test('the miner resolution honours ONIONADDRESS_MINER', (t) => {
  const target = path.join(ROOT, 'bin', 'onionaddress-cpu');
  if (!existsSync(target)) {
    t.skip('bin/onionaddress-cpu not built (run: npm run build:cpu)');
    return;
  }
  const previous = process.env.ONIONADDRESS_MINER;
  process.env.ONIONADDRESS_MINER = target;
  try {
    assert.equal(findMiner(), target);
  } finally {
    if (previous === undefined) delete process.env.ONIONADDRESS_MINER;
    else process.env.ONIONADDRESS_MINER = previous;
  }
});
