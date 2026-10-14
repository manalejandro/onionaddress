#!/usr/bin/env node
import path from 'node:path';
import process from 'node:process';
import { benchmark } from './benchmark.js';
import {
  difficulty,
  formatCount,
  formatDuration,
  formatInteger,
  formatProbability,
  successProbability,
} from './estimator.js';
import { PatternError, parsePattern } from './pattern.js';
import { benchmarkMiner, findMiner, listMinerDevices } from './gpu.js';
import { defaultWorkerCount, search } from './search.js';
import { VERSION } from './version.js';

/** Patterns that need more expected attempts than this are refused unless --force. */
const FORCE_ATTEMPTS_THRESHOLD = 2 ** 39; // ~5.5e11 attempts
/** Patterns above this expected effort produce a warning. */
const WARN_ATTEMPTS_THRESHOLD = 1e9;

const useColor = Boolean(process.stderr.isTTY) && !process.env.NO_COLOR;
const style = {
  bold: (text) => (useColor ? `\x1b[1m${text}\x1b[0m` : text),
  dim: (text) => (useColor ? `\x1b[2m${text}\x1b[0m` : text),
  green: (text) => (useColor ? `\x1b[32m${text}\x1b[0m` : text),
  yellow: (text) => (useColor ? `\x1b[33m${text}\x1b[0m` : text),
  red: (text) => (useColor ? `\x1b[31m${text}\x1b[0m` : text),
  cyan: (text) => (useColor ? `\x1b[36m${text}\x1b[0m` : text),
};

class UsageError extends Error {}

const HELP = `onionaddress ${VERSION} · Tor v3 onion service vanity address generator

Usage
  onionaddress [options] <pattern>
  onionaddress benchmark [options] [--gpu [devices]]
  onionaddress devices

Pattern
  ^string    address must start with string (prefix)
  string$    address must end with string (suffix)
  ^string$   exact address match (requires a full 56-character address)
  The search string uses the v3 base32 alphabet (a-z, 2-7) and is case-insensitive.
  Every v3 address ends with "d" and the character before it is one of a/i/q/y.

Options
  -c, --count <n>      number of matches to find before stopping (default: 1, 0 = unlimited)
  -w, --workers <n>    CPU worker threads (default: CPU count - 1; with --gpu: 0 unless set)
  -t, --timeout <s>    stop after <s> seconds (0 = run until matched)
  -o, --output <dir>   directory for matches (default: ./output)
      --gpu [devices]  mine on CUDA devices instead of CPU (e.g. --gpu, --gpu 1, --gpu 0,1)
      --miner <path>   path to the miner binary (default: bin/onionaddress-cuda, then -cpu)
      --estimate       print the probability model for the pattern and exit
      --force          allow patterns that need more than 2^39 expected attempts
      --no-progress    disable the live progress line
  -q, --quiet          only print results and errors
  -h, --help           show this help
  -v, --version        show the version

Benchmark options
      --seconds <s>    benchmark duration (default: 3)

Examples
  onionaddress ^abc
  onionaddress dead$
  onionaddress -c 5 -w 8 ^a
  onionaddress --gpu ^dead              # CUDA, all devices
  onionaddress --gpu 0 -w 4 ^dead       # CUDA device 0 plus 4 CPU workers
  onionaddress --estimate "^duck"
  onionaddress benchmark --gpu --seconds 5
  onionaddress devices

Exit codes
  0 match(es) found · 1 error · 2 invalid or refused pattern · 3 stopped (timeout or SIGINT)
`;

async function main() {
  const argv = process.argv.slice(2);
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    if (error instanceof UsageError) {
      process.stderr.write(`${style.red('error:')} ${error.message}\n\n${HELP}`);
      return 1;
    }
    throw error;
  }

  if (options.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (options.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (options.command === 'benchmark') {
    return runBenchmarkCommand(options);
  }
  if (options.command === 'devices') {
    return runDevicesCommand(options);
  }
  if (!options.pattern) {
    process.stderr.write(`${style.red('error:')} missing search pattern\n\n${HELP}`);
    return 1;
  }
  return runSearchCommand(options);
}

function parseArgs(argv) {
  const args = [];
  for (const arg of argv) {
    if (arg.startsWith('--') && arg.includes('=')) {
      const index = arg.indexOf('=');
      args.push(arg.slice(0, index), arg.slice(index + 1));
    } else {
      args.push(arg);
    }
  }

  const options = {
    command: 'search',
    pattern: null,
    count: 1,
    workers: defaultWorkerCount(),
    workersExplicit: false,
    gpu: false,
    miner: null,
    timeout: 0,
    output: 'output',
    estimate: false,
    force: false,
    progress: true,
    quiet: false,
    help: false,
    version: false,
    seconds: 3,
  };

  const positional = [];
  const next = (name) => {
    if (args.length === 0) throw new UsageError(`option ${name} requires a value`);
    return args.shift();
  };

  while (args.length > 0) {
    const arg = args.shift();
    switch (arg) {
      case '-h':
      case '--help':
        options.help = true;
        break;
      case '-v':
      case '--version':
        options.version = true;
        break;
      case '-q':
      case '--quiet':
        options.quiet = true;
        break;
      case '--no-progress':
        options.progress = false;
        break;
      case '--estimate':
        options.estimate = true;
        break;
      case '--force':
        options.force = true;
        break;
      case '-c':
      case '--count':
        options.count = parseInteger(next(arg), arg, { min: 0 });
        break;
      case '-w':
      case '--workers':
        options.workers = parseInteger(next(arg), arg, { min: 1 });
        options.workersExplicit = true;
        break;
      case '--gpu': {
        const peek = args[0];
        if (peek !== undefined && /^[0-9]+(,[0-9]+)*$/.test(peek)) {
          args.shift();
          options.gpu = peek.split(',').map((value) => Number(value));
        } else {
          options.gpu = true;
        }
        break;
      }
      case '--miner':
        options.miner = next(arg);
        break;
      case '-t':
      case '--timeout':
        options.timeout = parseNumber(next(arg), arg, { min: 0 });
        break;
      case '-o':
      case '--output':
        options.output = next(arg);
        break;
      case '--seconds':
        options.seconds = parseNumber(next(arg), arg, { min: 0, exclusive: true });
        break;
      default:
        if (arg.startsWith('-') && arg !== '-') {
          throw new UsageError(`unknown option "${arg}"`);
        }
        positional.push(arg);
        break;
    }
  }

  if (positional.length > 0) {
    if (positional[0] === 'benchmark') {
      options.command = 'benchmark';
    } else if (positional[0] === 'devices') {
      options.command = 'devices';
    } else if (positional[0] === 'help') {
      options.help = true;
    } else if (positional[0] === 'version') {
      options.version = true;
    } else {
      options.pattern = positional[0];
    }
    if (
      positional.length > 1 &&
      !options.help &&
      !options.version &&
      options.command === 'search'
    ) {
      throw new UsageError(`unexpected extra argument "${positional[1]}"`);
    }
  }

  return options;
}

function parseInteger(value, name, { min = 0 } = {}) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min) {
    throw new UsageError(`${name} expects an integer >= ${min}, got "${value}"`);
  }
  return parsed;
}

function parseNumber(value, name, { min = 0, exclusive = false } = {}) {
  const parsed = Number(value);
  const invalid = !Number.isFinite(parsed) || (exclusive ? parsed <= min : parsed < min);
  if (invalid) {
    throw new UsageError(`${name} expects a number ${exclusive ? '>' : '>='} ${min}, got "${value}"`);
  }
  return parsed;
}

async function runSearchCommand(options) {
  let pattern;
  try {
    pattern = parsePattern(options.pattern);
  } catch (error) {
    if (error instanceof PatternError) {
      process.stderr.write(`${style.red('error:')} ${error.message}\n`);
      return 2;
    }
    throw error;
  }

  const stats = difficulty(pattern.space);

  if (options.estimate) {
    printEstimate(pattern, stats);
    return 0;
  }

  if (stats.expectedAttempts > FORCE_ATTEMPTS_THRESHOLD && !options.force) {
    process.stderr.write(
      `${style.red('error:')} pattern ${style.bold(pattern.toString())} needs about ` +
        `${formatInteger(stats.expectedAttempts)} attempts on average, which is not realistic ` +
        'for a single run\n' +
        '       use --force to start it anyway, --estimate to study the odds first, ' +
        'or pick a shorter pattern\n',
    );
    return 2;
  }

  if (!options.quiet) printBanner(pattern, stats, options);

  if (stats.expectedAttempts > WARN_ATTEMPTS_THRESHOLD) {
    process.stderr.write(
      `  ${style.yellow('warning')} high expected effort: about ` +
        `${formatInteger(stats.expectedAttempts)} attempts ` +
        `${style.dim('(run `onionaddress benchmark` to translate this into time)')}\n\n`,
    );
  }

  const controller = new AbortController();
  let sigints = 0;
  const onSigint = () => {
    sigints += 1;
    if (sigints > 1) process.exit(130);
    process.stderr.write('\n  interrupting, shutting down miners ...\n');
    controller.abort();
  };
  process.on('SIGINT', onSigint);

  const useGpu = options.gpu !== false;
  const workers = useGpu && !options.workersExplicit ? 0 : options.workers;

  const renderer = new ProgressRenderer(pattern, options);
  let result;
  try {
    result = await search({
      pattern,
      count: options.count,
      workers,
      devices: useGpu ? options.gpu : false,
      minerPath: options.miner,
      timeoutSeconds: options.timeout,
      outputDir: path.resolve(process.cwd(), options.output),
      signal: controller.signal,
      onEvent: (event) => renderer.handle(event),
    });
  } catch (error) {
    process.removeListener('SIGINT', onSigint);
    renderer.finish();
    process.stderr.write(`${style.red('error:')} ${error.message}\n`);
    return 1;
  }

  process.removeListener('SIGINT', onSigint);
  renderer.finish();
  printSummary(result, pattern);

  if (result.completed) return 0;
  if (result.errored) return 1;
  return 3;
}

async function runBenchmarkCommand(options) {
  if (options.gpu !== false) {
    return runGpuBenchmarkCommand(options);
  }

  process.stderr.write(
    `${style.bold('onionaddress')} ${VERSION} ${style.dim('· keygen benchmark (cpu)')}\n\n` +
      `  measuring ${options.workers} worker${options.workers === 1 ? '' : 's'} for ${options.seconds}s ...\n`,
  );

  const result = await benchmark({ workers: options.workers, durationSeconds: options.seconds });

  process.stderr.write(
    `\n  total attempts   ${formatInteger(result.attempts)}\n` +
      `  throughput       ${formatCount(result.rate)} keys/s ` +
      `${style.dim(`(${formatCount(result.ratePerWorker)} per worker)`)}\n\n`,
  );
  printRoughExpectations(result.rate);
  return 0;
}

async function runGpuBenchmarkCommand(options) {
  const minerPath = findMiner({ explicit: options.miner });
  if (!minerPath) {
    printMissingMinerError();
    return 1;
  }

  process.stderr.write(
    `${style.bold('onionaddress')} ${VERSION} ${style.dim('· CUDA miner benchmark')}\n\n` +
      `  measuring for ${options.seconds}s ...\n`,
  );

  let result;
  try {
    result = await benchmarkMiner({
      minerPath,
      devices: options.gpu,
      durationSeconds: options.seconds,
    });
  } catch (error) {
    process.stderr.write(`${style.red('error:')} ${error.message}\n`);
    return 1;
  }

  process.stderr.write(
    `\n  miner            ${style.dim(minerPath)}\n` +
      `  total attempts   ${formatInteger(result.attempts)}\n` +
      `  throughput       ${formatCount(result.rate)} keys/s\n`,
  );
  for (const device of result.devices) {
    process.stderr.write(
      `    ${device.label}${device.name ? ` · ${device.name}` : ''} · ${formatInteger(device.attempts)} attempts\n`,
    );
  }
  process.stderr.write('\n');
  printRoughExpectations(result.rate);
  return 0;
}

function printRoughExpectations(rate) {
  process.stderr.write('  rough expectations with this machine:\n');
  for (const length of [3, 4, 5, 6, 7]) {
    const space = 32 ** length;
    const expected = space / rate;
    const median = (space * Math.LN2) / rate;
    process.stderr.write(
      `    ^${'a'.repeat(length).padEnd(7)} ${formatInteger(space).padStart(12)} attempts` +
        `  expected ${formatDuration(expected).padStart(7)}  median ${formatDuration(median)}\n`,
    );
  }
}

function printMissingMinerError() {
  process.stderr.write(
    `${style.red('error:')} no miner binary found\n` +
      `  build one with ${style.bold('make -C gpu cuda')} (NVIDIA GPU + CUDA toolkit)\n` +
      `  or ${style.bold('make -C gpu cpu')} for the reference miner, then run again\n` +
      `  (or point --miner / $ONIONADDRESS_MINER at a miner binary)\n`,
  );
}

async function runDevicesCommand(options) {
  const minerPath = findMiner({ explicit: options.miner });
  if (!minerPath) {
    printMissingMinerError();
    return 1;
  }

  let devices;
  try {
    devices = await listMinerDevices(minerPath);
  } catch (error) {
    process.stderr.write(`${style.red('error:')} ${error.message}\n`);
    return 1;
  }

  process.stderr.write(
    `${style.bold('onionaddress')} ${VERSION} ${style.dim('· miner devices')}\n\n` +
      `  miner ${style.dim(minerPath)}\n\n`,
  );
  for (const device of devices) {
    const details = [];
    if (device.sm) details.push(`${device.sm} SMs`);
    if (device.threads) details.push(`${device.threads} threads`);
    process.stderr.write(
      `  [${device.index}] ${device.backend} · ${device.name}${details.length ? ` · ${details.join(' · ')}` : ''}\n`,
    );
  }
  return 0;
}

function printBanner(pattern, stats, options) {
  const useGpu = options.gpu !== false;
  const workers = useGpu && !options.workersExplicit ? 0 : options.workers;
  let sources;
  if (!useGpu) {
    sources = `cpu · ${workers} worker${workers === 1 ? '' : 's'}`;
  } else {
    const deviceSpec =
      options.gpu === true
        ? 'all devices'
        : `device${options.gpu.length === 1 ? '' : 's'} ${options.gpu.join(',')}`;
    sources =
      `cuda · ${deviceSpec}` + (workers > 0 ? ` + cpu · ${workers} worker${workers === 1 ? '' : 's'}` : '');
  }

  process.stderr.write(
    `${style.bold('onionaddress')} ${VERSION} ` +
      `${style.dim('· Tor v3 onion service vanity address generator')}\n\n` +
      `  ${style.dim('pattern  ')} ${style.cyan(pattern.toString())} ` +
      `${style.dim(`(${pattern.mode}, ${pattern.length} char${pattern.length === 1 ? '' : 's'})`)}\n` +
      `  ${style.dim('odds     ')} 1 in ${formatInteger(pattern.space)} addresses ` +
      `${style.dim(`· expected ${formatInteger(stats.expectedAttempts)} attempts`)}\n` +
      `  ${style.dim('sources  ')} ${sources}\n\n`,
  );
}

function printEstimate(pattern, stats) {
  const rows = [
    ['pattern', `${pattern.toString()} (${pattern.mode})`],
    [
      'matching addresses',
      `1 in ${formatInteger(pattern.space)}` +
        (pattern.mode === 'suffix' ? style.dim(' (fixed version bits excluded)') : ''),
    ],
    ['expected attempts', formatInteger(stats.expectedAttempts)],
    ['median attempts', `${formatInteger(stats.medianAttempts)} ${style.dim('(50% chance)')}`],
    ['p90 attempts', `${formatInteger(stats.p90Attempts)} ${style.dim('(90% chance)')}`],
    ['p99 attempts', `${formatInteger(stats.p99Attempts)} ${style.dim('(99% chance)')}`],
  ];
  const width = Math.max(...rows.map(([label]) => label.length)) + 2;
  let output = '';
  for (const [label, value] of rows) output += `${label.padEnd(width)}${value}\n`;
  output += `\ntip: run ${style.bold('onionaddress benchmark')} to measure this machine and translate attempts into time\n`;
  process.stdout.write(output);
}

function printSummary(result, pattern) {
  const seconds = result.elapsedMs / 1000;
  const avgRate = seconds > 0 ? result.attempts / seconds : 0;

  if (result.found.length > 0) {
    process.stderr.write(
      `\n  ${style.green('done')} ${result.found.length} match${result.found.length === 1 ? '' : 'es'} ` +
        `in ${formatDuration(seconds)} ` +
        `${style.dim(`(${formatInteger(result.attempts)} attempts · ${formatCount(avgRate)} keys/s)`)}\n`,
    );
    for (const match of result.found) {
      process.stderr.write(`    ${match.hostname}  ${style.dim(match.dir)}\n`);
    }
    if (!result.completed) {
      process.stderr.write(
        `  ${style.yellow('stopped')} before reaching the requested ${result.requestedCount} matches\n`,
      );
    }
  } else {
    const reason = result.timedOut ? 'timed out' : result.aborted ? 'interrupted' : 'stopped';
    const probability = successProbability(result.attempts, pattern.space);
    process.stderr.write(
      `\n  ${style.yellow(reason)} after ${formatDuration(seconds)} and ` +
        `${formatInteger(result.attempts)} attempts ` +
        `${style.dim(`(success probability so far: ${formatProbability(probability)})`)}: ` +
        `no match for ${pattern.toString()} yet\n`,
    );
    process.stderr.write(
      `  ${style.dim('tips: try --gpu on a CUDA machine, more workers (-w), a shorter pattern, or --estimate to plan the odds first')}\n`,
    );
  }
}

class ProgressRenderer {
  constructor(pattern, options) {
    this.pattern = pattern;
    this.enabled = options.progress && !options.quiet && Boolean(process.stderr.isTTY);
  }

  handle(event) {
    if (event.type === 'progress') this.renderProgress(event);
    else if (event.type === 'found') this.renderFound(event);
    else if (event.type === 'error') this.renderError(event);
  }

  clearLine() {
    if (this.enabled) process.stderr.write('\r\x1b[2K');
  }

  renderProgress(event) {
    if (!this.enabled) return;
    const parts = [`${formatCount(event.attempts)} attempts`];
    if (event.rate > 0) {
      parts.push(`${formatCount(event.rate)} keys/s`);
      parts.push(`${formatDuration(event.elapsedMs / 1000)} elapsed`);
      parts.push(`~${formatDuration(event.expectedRemainingMs / 1000)} remaining`);
    } else {
      parts.push(`${formatDuration(event.elapsedMs / 1000)} elapsed`);
    }
    parts.push(`p=${formatProbability(event.probability)}`);
    if (event.best > 0) parts.push(`closest ${formatClosest(this.pattern, event.best)}`);
    process.stderr.write(`\r\x1b[2K  ${style.dim('searching')} ${parts.join(style.dim(' · '))}`);
  }

  renderFound(event) {
    this.clearLine();
    const { match } = event;
    const counter = event.count === 0 ? `${event.found}/∞` : `${event.found}/${event.count}`;
    process.stderr.write(
      `  ${style.green('✔ found')} ${style.bold(match.hostname)} ${style.dim(`(${counter})`)}\n` +
        `    ${style.dim('saved to')} ${match.dir}\n`,
    );
  }

  renderError(event) {
    this.clearLine();
    process.stderr.write(`  ${style.red('error:')} ${event.error?.message ?? event.error}\n`);
  }

  finish() {
    if (this.enabled) process.stderr.write('\r\x1b[2K');
  }
}

function formatClosest(pattern, best) {
  const hidden = '·'.repeat(pattern.length - best);
  if (pattern.mode === 'suffix') {
    return `${hidden}${pattern.body.slice(pattern.length - best)}$ (${best}/${pattern.length})`;
  }
  if (pattern.mode === 'exact') {
    return `^${pattern.body.slice(0, best)}${hidden}$ (${best}/${pattern.length})`;
  }
  return `^${pattern.body.slice(0, best)}${hidden} (${best}/${pattern.length})`;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`${style.red('error:')} ${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
