#!/usr/bin/env node
/**
 * Best-effort native miner build, wired to the `postinstall` hook so the
 * package is functional right after `npm install` / `npx github:...`.
 *
 * It never fails the install: the pure-Node CPU search always works, and the
 * native miners are an optional accelerator. Every failure is reported as a
 * hint instead of a non-zero exit code, because a broken compiler or a missing
 * CUDA toolkit must not make the package uninstallable.
 *
 * Build order:
 *   1. bin/onionaddress-cpu   — g++ (or any CXX), always attempted
 *   2. bin/onionaddress-cuda  — nvcc, only when the CUDA toolkit is present
 *
 * Environment overrides:
 *   ONION_SKIP_NATIVE_BUILD=1   do nothing
 *   ONION_CUDA_ARCH=sm_90       force the nvcc architecture (default: native
 *                               when a GPU is visible, otherwise PTX for
 *                               compute_75 so the driver can JIT it)
 *   CXX / NVCC                  toolchain overrides (same as the Makefile)
 */
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const GPU_DIR = path.join(ROOT, 'gpu');
const BIN_DIR = path.join(ROOT, 'bin');
const IS_WINDOWS = process.platform === 'win32';

const CPU_BIN = path.join(BIN_DIR, IS_WINDOWS ? 'onionaddress-cpu.exe' : 'onionaddress-cpu');
const CUDA_BIN = path.join(BIN_DIR, IS_WINDOWS ? 'onionaddress-cuda.exe' : 'onionaddress-cuda');

const notes = [];

function canRun(command, args = ['--version']) {
  if (!command) return false;
  try {
    const result = spawnSync(command, args, { stdio: 'ignore' });
    return !result.error;
  } catch {
    return false;
  }
}

function run(command, args, label) {
  const result = spawnSync(command, args, { cwd: ROOT, stdio: 'inherit' });
  if (result.error) {
    notes.push(`${label}: ${result.error.message}`);
    return false;
  }
  if (result.status !== 0) {
    notes.push(`${label}: exited with code ${result.status}`);
    return false;
  }
  return true;
}

function findNvcc() {
  const candidates = [
    process.env.NVCC,
    process.env.CUDA_PATH && path.join(process.env.CUDA_PATH, 'bin', 'nvcc'),
    '/usr/local/cuda/bin/nvcc',
    '/opt/cuda/bin/nvcc',
    'nvcc',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (candidate.includes('/') || candidate.includes('\\')) {
      if (existsSync(candidate)) return candidate;
    } else if (canRun(candidate)) {
      return candidate;
    }
  }
  return null;
}

function gpuVisible() {
  return canRun('nvidia-smi', ['-L']);
}

function buildCpu() {
  const cxx = process.env.CXX || (canRun('g++') ? 'g++' : canRun('c++') ? 'c++' : canRun('clang++') ? 'clang++' : null);
  if (!cxx) {
    notes.push('cpu miner skipped: no C++ compiler found (set CXX to build it manually)');
    return false;
  }
  const args = ['-O2', '-std=c++17', '-o', CPU_BIN, path.join(GPU_DIR, 'miner_cpu.cpp')];
  if (process.env.EXTRA_FLAGS) args.splice(1, 0, ...process.env.EXTRA_FLAGS.split(' '));
  const ok = run(cxx, args, 'cpu miner build');
  if (ok && !IS_WINDOWS) {
    try {
      chmodSync(CPU_BIN, 0o755);
    } catch {
      // non-fatal
    }
  }
  return ok && existsSync(CPU_BIN);
}

function buildCuda() {
  const nvcc = findNvcc();
  if (!nvcc) {
    notes.push('cuda miner skipped: nvcc not found (install the CUDA toolkit, then run `npm run build:cuda`)');
    return false;
  }
  const arch = process.env.ONION_CUDA_ARCH || (gpuVisible() ? 'native' : null);
  const args = ['-O3', '-std=c++17'];
  if (arch) {
    args.push(`-arch=${arch}`);
  } else {
    // No GPU visible at build time: emit PTX so any driver >= Turing can JIT it.
    args.push('-gencode', 'arch=compute_75,code=compute_75');
  }
  if (process.env.EXTRA_FLAGS) args.push(...process.env.EXTRA_FLAGS.split(' '));
  args.push('-o', CUDA_BIN, path.join(GPU_DIR, 'miner_cuda.cu'));

  const ok = run(nvcc, args, 'cuda miner build');
  if (ok && !IS_WINDOWS) {
    try {
      chmodSync(CUDA_BIN, 0o755);
    } catch {
      // non-fatal
    }
  }
  return ok && existsSync(CUDA_BIN);
}

function main() {
  if (process.env.ONION_SKIP_NATIVE_BUILD === '1') return 0;
  if (!existsSync(path.join(GPU_DIR, 'core.h'))) {
    // Sources are not shipped in this install; nothing to build.
    return 0;
  }

  mkdirSync(BIN_DIR, { recursive: true });
  process.stdout.write('onionaddress: building native miners (optional, best effort)\n');

  const cpu = buildCpu();
  const cuda = buildCuda();

  process.stdout.write(
    `  ${cpu ? '✓' : '·'} cpu  ${path.relative(ROOT, CPU_BIN)}\n` +
      `  ${cuda ? '✓' : '·'} cuda ${path.relative(ROOT, CUDA_BIN)}\n`,
  );
  for (const note of notes) process.stdout.write(`  · ${note}\n`);
  if (!cpu && !cuda) {
    process.stdout.write(
      '  The pure-Node CPU search still works; GPU mining needs the CUDA miner.\n',
    );
  }
  return 0;
}

try {
  process.exitCode = main();
} catch (error) {
  // Never break the install because of the optional native build.
  process.stdout.write(`onionaddress: native build skipped (${error.message})\n`);
  process.exitCode = 0;
}
