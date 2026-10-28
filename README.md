# onionaddress

[![CI](https://github.com/manalejandro/onionaddress/actions/workflows/ci.yml/badge.svg)](https://github.com/manalejandro/onionaddress/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node.js >= 20](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org)

Vanity address generator for **Tor v3 onion services**, written in plain
Node.js with **zero runtime dependencies**.

`onionaddress` reads a search string (`^string` for a prefix, `string$` for a
suffix, `^string$` for an exact match), validates that the string can actually
appear in a v3 onion address, estimates how hard it will be to find, and then
searches in parallel across your CPU cores — or on your NVIDIA GPU via the
bundled CUDA miner — until it finds matching Ed25519 keys. Every match is
saved as a ready-to-use hidden service directory under `output/`.

> [!NOTE]
> V3 onion services are the current Tor standard (supported since Tor 0.3.3),
> so the generated keys work with today's Tor. Keep in mind that a distinctive
> address is recognizable and therefore linkable — use a vanity address only
> where that is acceptable.

---

## Features

- **Pattern search** — prefix (`^abc`), suffix (`abc$`) and exact (56 chars) matching.
- **Validation first** — wrong alphabet, wrong length or impossible tails are
  rejected before any work starts. Every v3 address ends in `d`, and the
  character before it is always one of `a/i/q/y`; suffixes that contradict
  this can never match and are refused up front.
- **Probability model** — `--estimate` prints expected, median, p90 and p99
  attempts. Suffix patterns are modelled correctly: the fixed version byte
  makes them ~256× easier than the raw character count suggests.
- **Fast search** — Ed25519 key generation on worker threads, one per CPU
  core. Prefixes of up to 51 characters skip the SHA3 checksum entirely
  because they live completely inside the public key, and the mining loop
  reuses scratch buffers and extracts raw keys through the cheapest Node API
  (~160K candidates/s on a 6-core desktop).
- **Optional CUDA backend** — a self-contained CUDA miner (`gpu/`, built with
  `make -C gpu cuda`) mines on NVIDIA GPUs at ~8.3M candidates/s on a
  GTX 1650 SUPER (~50× the Node CPU path), sharing the same verified crypto
  core. Every GPU result is re-derived and re-checked with Node/OpenSSL
  before anything is written to disk.
- **Fast matching** — patterns are compiled to bit masks over the 35 address
  bytes, so only the bytes the pattern touches are compared, and the
  "closest match" tracker reads 5-bit groups straight from those bytes
  instead of encoding whole addresses.
- **Live progress** — attempts, keys/s, elapsed time, ETA, cumulative success
  probability and the *closest* partial match seen so far.
- **First match or many** — stop at the first result or keep going
  (`--count N`, `0` = unlimited) with an optional `--timeout`.
- **Tor-native output** — each match is stored in `output/<address>.onion/`
  with `hostname`, `hs_ed25519_secret_key`, `hs_ed25519_public_key` and
  `metadata.json`, using exactly the formats Tor expects.
- **Zero dependencies** — only Node.js built-ins (`node:crypto`,
  `node:worker_threads`, `node:test`).

## Requirements

- Node.js **>= 20**
- No runtime dependencies
- Optional, for `--gpu`: an NVIDIA GPU and a CUDA toolkit (>= 11) to build the
  miner with `make -C gpu cuda`

## Installation

```bash
# install the CLI straight from GitHub
npm install -g github:manalejandro/onionaddress

# or clone and link it locally
git clone https://github.com/manalejandro/onionaddress.git
cd onionaddress
npm link

# or run it without installing anything
npx github:manalejandro/onionaddress --help
```

## Usage

```
onionaddress [options] <pattern>
onionaddress benchmark [options]
onionaddress devices
```

### Pattern syntax

| Pattern            | Mode    | Matches addresses that…                    |
| ------------------ | ------- | ------------------------------------------ |
| `^abc`             | prefix  | start with `abc`                           |
| `abc$`             | suffix  | end with `abc`                             |
| `^<56 chars>$`     | exact   | are exactly that address                   |

- The search string uses the v3 base32 alphabet: `a-z` and `2-7`. Uppercase
  input is normalized to lowercase; `0`, `1`, `8`, `9` can never appear in a
  v3 address and are rejected.
- The sequence must be 1–56 characters long (v3 addresses are 56 characters,
  plus `.onion`).
- **Tail rules:** every v3 address ends with `d` (the fixed version byte
  `0x03`) and the character before it is always one of `a`, `i`, `q`, `y`.
  A suffix (or exact pattern) that violates these rules can never match and is
  rejected with an explanation.
- Patterns whose expected effort exceeds 2^39 attempts (~72 days even on the
  fast machine below) are refused unless you pass `--force`.

### Options

| Option               | Description                                                              |
| -------------------- | ------------------------------------------------------------------------ |
| `-c, --count <n>`    | matches to find before stopping (default `1`, `0` = unlimited)            |
| `-w, --workers <n>`  | CPU worker threads (default: CPU count − 1; with `--gpu`: 0 unless set)  |
| `--gpu [devices]`    | mine on CUDA devices instead of CPU (`--gpu`, `--gpu 1`, `--gpu 0,1`)     |
| `--miner <path>`     | miner binary to use (default: `bin/onionaddress-cuda`, then `-cpu`)       |
| `-t, --timeout <s>`  | stop after `<s>` seconds (`0` = run until matched)                        |
| `-o, --output <dir>` | directory for matches (default `./output`)                                |
| `--estimate`         | print the probability model for the pattern and exit                      |
| `--force`            | allow patterns that need more than 2^39 expected attempts                 |
| `--no-progress`      | disable the live progress line                                            |
| `-q, --quiet`        | only print results and errors                                             |
| `-h, --help`         | show help                                                                 |
| `-v, --version`      | show the version                                                          |
| `--seconds <s>`      | benchmark duration in seconds (benchmark command only, default `3`)       |

### Examples

```bash
# addresses that start with "duck"
onionaddress ^duck

# addresses that end with "dead"
onionaddress dead$

# estimate the odds for a pattern without searching
onionaddress --estimate ^abc

# collect five addresses that start with "a" and keep going
onionaddress -c 5 -w 8 ^a

# limit a hard search to 30 seconds
onionaddress -t 30 ^abcde

# mine on all CUDA devices
onionaddress --gpu ^dead

# CUDA device 0 plus 4 CPU workers
onionaddress --gpu 0 -w 4 ^dead

# list the devices a built miner can drive
onionaddress devices

# measure this machine first
onionaddress benchmark --seconds 5
onionaddress benchmark --gpu --seconds 5
```

A successful run looks like this:

```console
$ onionaddress -w 11 ^dead

onionaddress 1.0.0 · Tor v3 onion service vanity address generator

  pattern   ^dead (prefix, 4 chars)
  odds      1 in 1,048,576 addresses · expected 1,048,576 attempts
  workers   11

  ✔ found deadzadfhpffinglkq7yx76scttfn234t7cvsuukghwm6b2bayhhqcqd.onion (1/1)
    saved to /home/you/onionaddress/output/deadzadfhpffinglkq7yx76scttfn234t7cvsuukghwm6b2bayhhqcqd.onion

  done 1 match in 9.7s (1,532,828 attempts · 158K keys/s)
    deadzadfhpffinglkq7yx76scttfn234t7cvsuukghwm6b2bayhhqcqd.onion  /home/you/onionaddress/output/deadzadfhpffinglkq7yx76scttfn234t7cvsuukghwm6b2bayhhqcqd.onion
```

While searching, the progress line shows throughput, how close the search has
come to the requested string, and the cumulative probability of having found
it by now:

```
  searching 320K attempts · 160K keys/s · 2.5s elapsed · ~3.5m remaining · p=0.95% · closest ^abc·· (3/5)
```

## Difficulty and time

A v3 address is `base32(PUBKEY | CHECKSUM | VERSION)`: 280 bits total, with
the last 8 bits fixed by the version byte. The bits a pattern pins down are
uniform, so the attempts until a match follow a geometric distribution:

- **Prefix** of *n* characters: space `32^n` (5 uniform bits per character).
- **Suffix** of *n* characters: space `2^(5n−8)` for *n* ≥ 2 — the fixed
  version byte removes 8 bits of work. `d$` always matches (space 1) and
  `yd$` has space 4. In other words, suffix search is ~256× cheaper than prefix
  search for the same character count.
- Median attempts: `ln(2) · space` (50% chance by then) · p90: `ln(10) · space`
  · p99: `ln(100) · space`.

Multiply by your measured key rate (`onionaddress benchmark`) to get wall-clock
time. Both tables use **162K keys/s**, the rate measured on the development
machine (Intel i5-10400F, 6 cores / 12 threads, Node 22, 11 workers):

| Prefix chars | Matching addresses (of 2^280) | Expected time @ 162K keys/s | Median time |
| :----------: | ----------------------------: | :-------------------------: | :---------: |
| 1            |                            32 |           1 ms              |   1 ms      |
| 2            |                         1,024 |           6 ms              |   4 ms      |
| 3            |                        32,768 |           202 ms            |   140 ms    |
| 4            |                     1,048,576 |           6.5 s             |   4.5 s     |
| 5            |                    33,554,432 |           3.5 min           |   2.4 min   |
| 6            |                 1,073,741,824 |           1.8 h             |   1.3 h     |
| 7            |                34,359,738,368 |           2.5 days          |   1.7 days  |
| 8            |             1,099,511,627,776 |           78.6 days         |   54.4 days |

| Suffix chars | Matching addresses | Expected time @ 162K keys/s | Median time |
| :----------: | -----------------: | :-------------------------: | :---------: |
| 1 (`d$`)     | always matches     |           1 ms              |   1 ms      |
| 2            |                  4 |           1 ms              |   1 ms      |
| 3            |                128 |           1 ms              |   1 ms      |
| 4            |              4,096 |           25 ms             |   18 ms     |
| 5            |            131,072 |           809 ms            |   561 ms    |
| 6            |          4,194,304 |           26 s              |   18 s      |
| 7            |        134,217,728 |           13.8 min          |   9.6 min   |
| 8            |      4,294,967,296 |           7.4 h             |   5.1 h     |
| 9            |    137,438,953,472 |           9.8 days          |   6.8 days  |

With the CUDA miner (~8.3M keys/s on the test GTX 1650 SUPER — see the GPU
section below) divide those times by ~50: a 5-character prefix comes out in
~4 seconds, 6 characters in ~2.2 minutes, 7 characters in ~1.2 hours.

Use `--estimate` for exact numbers on any pattern:

```console
$ onionaddress --estimate abid$
pattern             abid$ (suffix)
matching addresses  1 in 4,096 (fixed version bits excluded)
expected attempts   4,096
median attempts     2,839 (50% chance)
p90 attempts        9,431 (90% chance)
p99 attempts        18,863 (99% chance)
```

## How it works

### Address derivation

Tor derives a v3 onion address as:

```
onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
```

1. Generate a fresh **Ed25519** key pair (`node:crypto`, OpenSSL).
2. Take the raw **32-byte public key** — unlike v2 there is no hashing step:
   the public key *is* the beginning of the address.
3. Append the **2-byte checksum**: the first two bytes of
   `SHA3-256(".onion checksum" | PUBKEY | VERSION)`.
4. Append the **version byte** `0x03`.
5. Encode the 35 bytes with the RFC 4648 base32 alphabet in lowercase, no
   padding → exactly 56 characters `a`-`z`, `2`-`7`.

Because the version byte is constant, every v3 address ends with `d`, and its
bits share the preceding character (`a`, `i`, `q` or `y` only). The derivation
is verified in CI against two independent implementations: Python
(`cryptography` + `hashlib` + `base64.b32encode`, used for the fixed test
vector) and OpenSSL (`pkey -pubout` + `dgst -sha3-256`).

### The search algorithm

1. **Compile the pattern to a bit mask.** The requested characters are
   projected onto the 280-bit address space (5 bits per character, MSB first).
   Prefixes touch the leading address bytes, suffixes the trailing ones, and
   matching only compares the bytes the pattern actually covers. Prefixes of
   up to 51 characters live entirely inside the public key, so the search
   skips computing the SHA3 checksum for them.
2. **Generate candidates in parallel.** Each worker thread loops:
   Ed25519 keygen → raw public key extraction → (checksum when needed) →
   bit-mask check. The per-candidate cost on the development machine is:

   | Step                                    | Cost     |
   | --------------------------------------- | -------- |
   | Ed25519 key generation                  | ~65 µs   |
   | raw public key extraction (JWK encoder) | ~2 µs    |
   | SHA3-256 checksum (only when needed)    | ~1.5 µs  |
   | bit-mask match + closeness tracking     | ~0.05 µs |

   Two details matter for throughput: the raw key is pulled out through the
   JWK encoder because exporting the same key as SPKI DER costs ~30× more
   inside Node, and workers reuse scratch buffers (address bytes and SHA3
   input) so a candidate allocates almost nothing beyond the key pair itself.
   Key generation dominates, so throughput scales almost linearly with CPU
   cores: ~14.8K candidates/s per worker, ~162K/s on this 6-core machine.
3. **Track closeness.** For every non-matching candidate, workers also count
   how many characters match the pattern from the relevant side. The 5-bit
   groups are extracted straight from the address bytes and the loop stops at
   the first mismatch (~20 ns on random candidates, versus ~2 µs for encoding
   the whole address); the longest run seen so far is reported as `closest`,
   a live sense of how near the search is.
4. **Estimate the odds.** The progress line reports cumulative probability
   `p = 1 − e^(−attempts / space)` and an ETA derived from `space / rate`.
   The geometric distribution is memoryless, so the expected *remaining*
   effort stays at `space` attempts no matter how long you have searched —
   what improves over time is the probability that you would already have
   found it.

In other words: the probability model *approximates the requested string
against the address space before you burn CPU*, so you can pick a target that
is actually reachable instead of discovering after a week that the pattern
needed months. The expected work of a given pattern itself is a property of
the address format, not of this implementation — but the format is kind to
miners: suffixes cost a fraction of prefixes, and 4–6 character patterns are
minutes away on a desktop CPU.

```console
$ onionaddress benchmark --seconds 5
onionaddress 1.0.0 · keygen benchmark

  measuring 11 workers for 5s ...

  total attempts   816,128
  throughput       162K keys/s (14.8K per worker)

  rough expectations with this machine:
    ^aaa           32,768 attempts  expected   202ms  median 140ms
    ^aaaa       1,048,576 attempts  expected    6.5s  median 4.5s
    ^aaaaa     33,554,432 attempts  expected    3.4m  median 2.4m
    ^aaaaaa  1,073,741,824 attempts  expected    1.8h  median 1.3h
    ^aaaaaaa 34,359,738,368 attempts  expected    2.4d  median 1.7d
```

## GPU mining (CUDA)

`onionaddress` ships a self-contained CUDA miner that reuses the same
verifiable crypto core as the CPU path and typically runs ~30× faster.

### Build

```bash
make -C gpu cuda     # NVIDIA GPU + CUDA toolkit -> bin/onionaddress-cuda
make -C gpu cpu      # g++ reference miner (used by the test suite) -> bin/onionaddress-cpu
```

The Makefile finds `nvcc` in `PATH` or `/usr/local/cuda/bin` and targets your
GPU by default (`-arch=native`); use `make -C gpu cuda CUDA_ARCH=sm_75` for
cross-compiling.

### Usage

```bash
onionaddress devices                 # what can the miner drive?
onionaddress --gpu ^dead             # mine on all CUDA devices
onionaddress --gpu 0 -w 4 ^dead      # device 0 plus 4 CPU workers (hybrid)
onionaddress benchmark --gpu         # measure GPU throughput
```

```console
$ onionaddress --gpu ^onion

onionaddress 1.0.0 · Tor v3 onion service vanity address generator

  pattern   ^onion (prefix, 5 chars)
  odds      1 in 33,554,432 addresses · expected 33,554,432 attempts
  sources   cuda · all devices

  ✔ found onion5szwnndtlgox2pwkwev6l64d5wsh6rlnou6hslpxiesnlzqenad.onion (1/1)
    saved to /home/you/onionaddress/output/onion5szwnndtlgox2pwkwev6l64d5wsh6rlnou6hslpxiesnlzqenad.onion

  done 1 match in 3.0s (24,002,560 attempts · 8.03M keys/s)
```

### Measured throughput

| Machine                    | Rate         |
| -------------------------- | ------------ |
| GTX 1650 SUPER (1 device)  | ~8.3M keys/s |
| i5-10400F, 11 Node workers | ~162K keys/s |

That is ~50× over the pure-Node path on this machine, which moves feasible
targets by roughly 2.5 characters: 6-character prefixes go from hours to
minutes, 7-character prefixes from days to about an hour.

### How it works

- **Shared, verified core.** `gpu/core.h` implements SHA-512, SHA3-256,
  GF(2^255−19) arithmetic, Ed25519 fixed-base comb multiplication (built from
  runtime-derived constants) and the pattern matcher once; it compiles both as
  host C++ and as CUDA device code. The CPU reference miner exercises the same
  code, and the test suite cross-checks thousands of random seeds against
  Node/OpenSSL — the CUDA kernel only adds the parallel scaffolding.
- **Wave-based execution.** The host launches the kernel in ~0.25s waves,
  reads back counters and matches between waves, and polls stdin for stop
  commands, so progress reporting, timeouts and Ctrl+C behave exactly like the
  CPU path.
- **Trust, but verify.** Every match reported by the GPU is re-derived with
  Node's own OpenSSL bindings and matched against the pattern before it is
  saved; a flaky driver, a bad overclock or a kernel bug can never write a
  corrupt key, and discarded results are counted (`invalidResults`).
- **Key generation stays random.** Candidate seeds come from a splitmix64
  stream whose salt is read from `/dev/urandom` on the host and never stored;
  the private keys cannot be reconstructed from the public search parameters.

### What was measured (and what did not work)

Every change below was profiled on the device rather than guessed. Per-stage
costs measured with a dedicated microbenchmark (cycles per operation per lane):
`fe_add` ~395, `fe_mul` ~3200 (~400 SASS instructions), `ge_madd` ~26K,
`fe_invert` ~738K, `sha512` ~22K, `sha3` ~34K.

Kept, because they measured faster:

- **8-bit comb windows** (31 mixed additions instead of 63 with 4-bit): the
  single biggest win.
- **Branch-free field arithmetic and pattern matching** — data-dependent
  branches make all 32 lanes of a warp execute both paths serially.
- **Warp batch inversion** (Montgomery + `__shfl`): 32 candidates share one
  inversion chain, so `fe_invert` effectively disappears from the hot path.
- **Tail-free prefix mining**: prefixes up to 51 characters never compute the
  SHA3-256 checksum.
- **Structure-of-arrays comb table**: a warp reads 32 adjacent `u32` per
  coordinate instead of 32 scattered cache lines.

Measured and rejected:

| Experiment | Result | Verdict |
| --- | --- | --- |
| 4-bit windows (128 KB table, L1-resident, 63 madds) | 6.3M keys/s | worse than 8-bit |
| **8-bit windows (1 MB table, L2-resident, 31 madds)** | **8.3M keys/s** | **best** |
| 16-bit windows (128 MB table, DRAM-resident, 15 madds) | 3.3M keys/s | 2.6× worse: every lookup misses L2 and the madd chain is serial |
| Split the comb into 2 / 4 independent chains (more ILP) | 5.0M / 4.8M keys/s | worse: each extra chain needs a live point accumulator (~32 registers) and the kernel already uses ~116, so it spills |
| Radix 2^26 (10-limb) field arithmetic, ref10-style | 3117 vs 3222 cycles per `fe_mul` | only 3% faster — not worth the rewrite risk |
| `-maxrregcount` 96 / 128 / 168 | 7.1M / 7.2M / 8.2M keys/s | the compiler's default (~116) wins |

The remaining ceiling is memory latency on the comb table plus the serial
dependency chain of mixed additions; that is why the L2-resident 1 MB table
beats both a smaller table (more arithmetic) and a much larger one (DRAM
latency). `ONION_COMB_BITS` and `ONION_COMB_CHAINS` are compile-time knobs
(`make -C gpu cuda EXTRA_FLAGS=-DONION_COMB_BITS=4`) so other GPUs can be
tuned without touching the code.

## Output

Each match produces a self-contained, Tor-ready hidden service directory:

```
output/
├── found.log                             # append-only log of every match
└── dea2rybj25nxx3z2k2vckt2uxbolg23b5hgsd3fautxvti3mbic6i2id.onion/
    ├── hostname                          # "dea2….onion\n"
    ├── hs_ed25519_secret_key             # seed || public key, 96 bytes (0600)
    ├── hs_ed25519_public_key             # public key, 64 bytes
    └── metadata.json                     # pattern, attempts, timings, key info
```

`metadata.json` records the total candidates generated by the whole run
(`search.attempts`), the exact candidate index of the worker that produced the
match (`search.attemptsByFinder`), and the public key — never secret material.

To verify at any time that a saved key really produces its address:

```js
import { readFileSync } from 'node:fs';
import { addressFromPrivateKey, privateKeyFromSeed } from 'onionaddress';

const file = readFileSync('output/dea2….onion/hs_ed25519_secret_key');
console.log(addressFromPrivateKey(privateKeyFromSeed(file.subarray(32, 64))));
```

A `torrc` entry for the generated service (works with any Tor that supports
v3, i.e. 0.3.3+, which is every current release):

```text
HiddenServiceDir /full/path/to/output/dea2….onion
HiddenServicePort 80 127.0.0.1:8080
```

## Library API

Everything the CLI does is available programmatically:

```js
import { parsePattern, search, difficulty, addressFromPrivateKey } from 'onionaddress';

const pattern = parsePattern('^abc');
console.log(difficulty(pattern.space)); // expected/median/p90/p99 attempts

const result = await search({
  pattern,          // or the raw string "^abc"
  count: 1,         // 0 = unlimited
  workers: 4,
  timeoutSeconds: 0,
  outputDir: './output',
  onEvent: (event) => {
    if (event.type === 'progress') console.log(event.attempts, event.rate);
    if (event.type === 'found') console.log('match:', event.match.hostname);
  },
});

console.log(result.found, result.attempts, result.completed);
```

Useful exports: `parsePattern`, `search`, `benchmark`, `generateKeyPair`,
`addressFromPublicKey`, `addressFromPrivateKey`, `addressBytesForPublicKey`,
`checksumForPublicKey`, `base32Encode`, `privateKeyFromSeed`,
`publicKeyFileBytes`, `secretKeyFileBytes`, `difficulty`,
`successProbability`, `saveResult`, `VERSION`.

## Exit codes

| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | the requested number of matches was found                 |
| `1`  | usage or runtime error                                    |
| `2`  | invalid or refused pattern                                |
| `3`  | stopped by timeout or SIGINT before completing the search |

## Development

```bash
npm test             # unit + integration tests (node:test, no dependencies)
make -C gpu cpu      # build the reference miner used by the miner tests
```

The test suite includes:

- RFC 4648 base32 vectors and address derivation tests, plus a fixed vector
  produced by an independent Python implementation (`cryptography` +
  `hashlib.sha3_256` + `base64.b32encode`),
- property tests that the compiled bit masks and the closeness scoring agree
  with a plain base32-string reference implementation,
- a regression test that the mining hot loop's reusable SHA3 input produces
  the same checksum bytes as the canonical derivation (guarding hex-vs-bytes
  and buffer-layout mistakes),
- a cross-check of the whole derivation against OpenSSL (SPKI extraction and
  `dgst -sha3-256`),
- end-to-end searches that verify the generated hidden service directories
  (Tor `ed25519v1` headers, seed/public-key round-trip, 0600 permissions,
  metadata) and the timeout/abort paths,
- miner tests: the C/CUDA core is validated against the independent Python
  vector and OpenSSL (fixed vectors, thousands of random seeds, hash vectors
  for both primitives), the JSON protocol is exercised end to end, and on a
  CUDA machine the GPU kernel itself is cross-checked the same way,
- CLI integration tests (help, estimate, impossible-suffix rejection, exit
  codes, missing-miner errors).

CI runs the suite on Node 20, 22 and 24 (`.github/workflows/ci.yml`).

## Security notes

- `hs_ed25519_secret_key` **is** the service identity: keep it private, back
  it up, and never commit it.
- A distinctive address is recognizable across contexts, which can link
  service activity together. Vanity addresses are best suited to
  public-facing services where that trade-off is acceptable.
- Generated keys never leave your machine; this tool only uses Node's local
  OpenSSL bindings.

## License

[MIT](LICENSE) © manalejandro

This project is intended for legitimate use with your own onion services and
for research/education. The authors accept no responsibility for how the
generated keys are used.
