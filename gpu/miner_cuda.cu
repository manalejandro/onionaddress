/*
 * CUDA miner for onionaddress.
 *
 * Shares gpu/core.h with the CPU reference miner, so every cryptographic
 * primitive is already cross-checked against OpenSSL by test/miner.test.js.
 *
 * Execution model: the host launches short "waves" of work (a few hundred
 * milliseconds each). Each wave is a single kernel launch over a persistent
 * grid; per-thread PRNG state and attempt counters live in device memory and
 * survive across waves. Between waves the host reads counters/results back,
 * prints protocol lines and polls stdin for stop commands.
 *
 * Matches carry the seed and are verified again by the Node orchestrator
 * before anything is written to disk, so a flaky driver or bad overclock can
 * never produce a corrupt key file.
 *
 * Security note: candidate seeds come from a splitmix64 stream seeded by a
 * 64-bit value read from /dev/urandom on the host. The salt is never stored,
 * so the generated private keys cannot be reproduced from the public search
 * parameters.
 *
 * Modes:
 *   selftest [--count N] [--seed <32-byte hex>]   (runs on the GPU)
 *   mine --pattern <^str|str$> [--device N]
 *   list-devices
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cuda_runtime.h>

#include <string>

#include "core.h"

/* ------------------------------------------------------------------ */
/* device-side constant tables                                         */
/* ------------------------------------------------------------------ */

__device__ const u64 D_SHA512_K[80] = ONION_SHA512_K;
__device__ const u64 D_SHA512_INIT[8] = ONION_SHA512_INIT;
__device__ const u64 D_KECCAK_RC[24] = ONION_KECCAK_RC;
__device__ const u8 D_KECCAK_RHO[25] = ONION_KECCAK_RHO;

#define MAX_MATCHES 512

typedef struct {
  u64 attempts;      /* attempts by the finding thread */
  u8 seed[32];
  u8 addr[35];
} match_slot;

typedef struct {
  u64 attempts;      /* atomic total for the wave */
  u32 best;          /* atomic max score */
  u32 count;         /* atomic match count  */
  u32 overflow;      /* matches beyond MAX_MATCHES */
} wave_counters;

/* ------------------------------------------------------------------ */
/* device helpers                                                      */
/* ------------------------------------------------------------------ */

__global__ void comb_init_kernel(comb_table *table) {
  const u32 w = threadIdx.x;
  if (w >= COMB_WINDOWS) return;
  fe d2;
  ge B;
  if (onion_curve_init(d2, &B) != 0) return;
  if (w == 0) {
    for (u32 i = 0; i < 8; i++) table->d2[i] = d2[i];
  }
  onion_comb_init_window(table, w, d2, &B);
}

__global__ void mine_kernel(u64 iterations, u64 salt, u64 *prng_states,
                            u64 *thread_attempts, const comb_table *table,
                            onion_pattern pattern, match_slot *slots,
                            wave_counters *counters) {
  const onion_tables T = {D_SHA512_K, D_SHA512_INIT, D_KECCAK_RC, D_KECCAK_RHO};
  const u32 tid = blockIdx.x * blockDim.x + threadIdx.x;

  u64 state = prng_states[tid];
  const u64 attempts_before = thread_attempts[tid];
  u64 attempts = attempts_before;
  u32 best = 0;
  (void)salt;

  /* addr[35] is the spare byte the score's two-byte window reads; bytes
   * 32..34 stay zero while the pattern never touches the tail. */
  u8 addr[36];
  addr[32] = 0;
  addr[33] = 0;
  addr[34] = 0;
  addr[35] = 0;

  for (u64 it = 0; it < iterations; it++) {
    u8 seed[32];
    splitmix64_fill(&state, seed);

    ge point;
    onion_point_from_seed(&T, table, seed, &point);

    fe zinv;
    fe_invert_warp(zinv, point.Z);

    if (pattern.needs_tail) {
      u8 pub[32];
      ge_compress_inv(&point, zinv, pub);
      onion_memcpy(addr, pub, 32);
      onion_append_checksum(&T, pub, addr);
    } else {
      /* prefixes up to 51 characters: no SHA3-256 at all */
      ge_compress_inv(&point, zinv, addr);
    }
    attempts++;

    if (onion_pattern_match(&pattern, addr)) {
      const u32 pos = atomicAdd(&counters->count, 1u);
      if (pos < MAX_MATCHES) {
        if (!pattern.needs_tail) onion_append_checksum(&T, addr, addr);
        for (u32 i = 0; i < 32; i++) slots[pos].seed[i] = seed[i];
        for (u32 i = 0; i < 35; i++) slots[pos].addr[i] = addr[i];
        slots[pos].attempts = attempts;
      } else {
        atomicAdd(&counters->overflow, 1u);
      }
      if (!pattern.needs_tail) {
        addr[32] = 0;
        addr[33] = 0;
        addr[34] = 0;
      }
    } else {
      const u32 score = onion_pattern_score(&pattern, addr);
      if (score > best) best = score;
    }
  }

  prng_states[tid] = state;
  thread_attempts[tid] = attempts;
  atomicAdd((unsigned long long *)&counters->attempts, (unsigned long long)(attempts - attempts_before));
  atomicMax(&counters->best, best);
}

__global__ void selftest_kernel(u64 salt, u64 *prng_states, comb_table *table,
                                match_slot *out) {
  const onion_tables T = {D_SHA512_K, D_SHA512_INIT, D_KECCAK_RC, D_KECCAK_RHO};
  const u32 tid = blockIdx.x * blockDim.x + threadIdx.x;
  u64 state = prng_states[tid];
  u8 seed[32];
  u8 addr[35];
  splitmix64_fill(&state, seed);
  onion_address_from_seed(&T, table, seed, addr);
  for (u32 i = 0; i < 32; i++) out[tid].seed[i] = seed[i];
  for (u32 i = 0; i < 35; i++) out[tid].addr[i] = addr[i];
  out[tid].attempts = 0;
  (void)salt;
}

__global__ void selftest_seed_kernel(comb_table *table, const u8 *seeds,
                                     match_slot *out) {
  const onion_tables T = {D_SHA512_K, D_SHA512_INIT, D_KECCAK_RC, D_KECCAK_RHO};
  const u32 tid = blockIdx.x * blockDim.x + threadIdx.x;
  u8 addr[35];
  onion_address_from_seed(&T, table, seeds + 32 * tid, addr);
  for (u32 i = 0; i < 32; i++) out[tid].seed[i] = seeds[32 * tid + i];
  for (u32 i = 0; i < 35; i++) out[tid].addr[i] = addr[i];
  out[tid].attempts = 0;
}

/* ------------------------------------------------------------------ */
/* host helpers                                                        */
/* ------------------------------------------------------------------ */

#define CUDA_CHECK(call, what)                                              \
  do {                                                                      \
    const cudaError_t err_ = (call);                                        \
    if (err_ != cudaSuccess) {                                              \
      fprintf(stderr, "%s: %s\n", (what), cudaGetErrorString(err_));        \
      printf("{\"type\":\"error\",\"message\":\"%s: %s\"}\n", (what),       \
             cudaGetErrorString(err_));                                     \
      fflush(stdout);                                                       \
      exit(1);                                                              \
    }                                                                       \
  } while (0)

static const char *ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

static std::string to_hex(const u8 *bytes, size_t n) {
  static const char *digits = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (size_t i = 0; i < n; i++) {
    out.push_back(digits[bytes[i] >> 4]);
    out.push_back(digits[bytes[i] & 15]);
  }
  return out;
}

static bool from_hex(const std::string &hex, u8 *out, size_t n) {
  if (hex.size() != n * 2) return false;
  for (size_t i = 0; i < n; i++) {
    const auto digit = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    const int hi = digit(hex[2 * i]);
    const int lo = digit(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = (u8)((hi << 4) | lo);
  }
  return true;
}

static double now_seconds() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static u64 random_salt() {
  u64 salt = 0;
  FILE *f = fopen("/dev/urandom", "rb");
  if (f == NULL || fread(&salt, 1, sizeof(salt), f) != sizeof(salt)) {
    salt = (u64)time(NULL) ^ ((u64)getpid() << 32);
  }
  if (f != NULL) fclose(f);
  return salt;
}

static bool compile_pattern(const std::string &raw, onion_pattern *out) {
  std::string input = raw;
  std::string body = input;
  int mode = 0;
  if (!input.empty() && input[0] == '^') {
    body = input.substr(1);
    mode = 1;
  }
  if (!body.empty() && body[body.size() - 1] == '$') {
    body = body.substr(0, body.size() - 1);
    mode = mode == 1 ? 3 : 2;
  }
  if (mode == 0 || body.empty()) return false;
  if (mode == 3) mode = 1;
  for (size_t i = 0; i < body.size(); i++) {
    if (body[i] >= 'A' && body[i] <= 'Z') body[i] = (char)(body[i] - 'A' + 'a');
    if (strchr(ALPHABET, body[i]) == NULL) return false;
  }
  if (body.size() > 56) return false;

  out->ncmp = 0;
  out->mode = (u32)mode;
  out->needs_tail = 0;
  out->nchars = (u32)body.size();
  for (u32 i = 0; i < out->nchars; i++) {
    out->vals[i] = (u8)(strchr(ALPHABET, body[i]) - ALPHABET);
  }

  u8 masks[35] = {0};
  u8 values[35] = {0};
  u32 bit = mode == 2 ? 280 - 5 * out->nchars : 0;
  for (size_t i = 0; i < body.size(); i++) {
    const u32 value = (u32)(strchr(ALPHABET, body[i]) - ALPHABET);
    for (int shift = 4; shift >= 0; shift--) {
      const u32 byte = bit >> 3;
      const u32 offset = 7 - (bit & 7);
      masks[byte] |= (u8)(1u << offset);
      if ((value >> shift) & 1) values[byte] |= (u8)(1u << offset);
      bit++;
    }
  }
  for (u32 byte = 0; byte < 35; byte++) {
    if (masks[byte] != 0) {
      out->cbyte[out->ncmp] = (u8)byte;
      out->cmask[out->ncmp] = masks[byte];
      out->cval[out->ncmp] = values[byte];
      if (byte >= 32) out->needs_tail = 1;
      out->ncmp++;
    }
  }
  return true;
}

static u32 device_thread_count(int device, cudaDeviceProp *prop) {
  CUDA_CHECK(cudaGetDeviceProperties(prop, device), "cudaGetDeviceProperties");
  int blocks_per_sm = 0;
  CUDA_CHECK(cudaOccupancyMaxActiveBlocksPerMultiprocessor(&blocks_per_sm, mine_kernel, 256, 0),
             "occupancy");
  if (blocks_per_sm < 1) blocks_per_sm = 1;
  u64 threads = (u64)prop->multiProcessorCount * (u64)blocks_per_sm * 256ull;
  return (u32)threads;
}

/* ------------------------------------------------------------------ */
/* modes                                                               */
/* ------------------------------------------------------------------ */

static int cmd_list_devices() {
  int count = 0;
  const cudaError_t err = cudaGetDeviceCount(&count);
  if (err != cudaSuccess || count == 0) {
    printf("{\"type\":\"error\",\"message\":\"no CUDA devices: %s\"}\n",
           cudaGetErrorString(err));
    fflush(stdout);
    return 1;
  }
  for (int i = 0; i < count; i++) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, i) != cudaSuccess) continue;
    u32 threads = 0;
    if (cudaSetDevice(i) == cudaSuccess) {
      cudaDeviceProp full;
      threads = device_thread_count(i, &full);
    }
    printf("{\"type\":\"device\",\"backend\":\"cuda\",\"index\":%d,\"name\":\"%s\","
           "\"sm\":%d,\"threads\":%u}\n",
           i, prop.name, prop.multiProcessorCount, threads);
  }
  fflush(stdout);
  return 0;
}

static int cmd_selftest(int device, int count, const char *seed_hex) {
  CUDA_CHECK(cudaSetDevice(device), "cudaSetDevice");

  comb_table *d_table = NULL;
  CUDA_CHECK(cudaMalloc(&d_table, sizeof(comb_table)), "cudaMalloc(comb)");
  comb_init_kernel<<<1, COMB_WINDOWS>>>(d_table);
  CUDA_CHECK(cudaDeviceSynchronize(), "comb_init_kernel");

  if (seed_hex != NULL) {
    u8 seed[32];
    if (!from_hex(seed_hex, seed, 32)) {
      printf("{\"type\":\"error\",\"message\":\"bad --seed\"}\n");
      return 1;
    }
    u8 *d_seeds = NULL;
    match_slot *d_out = NULL;
    CUDA_CHECK(cudaMalloc(&d_seeds, 32), "cudaMalloc(seeds)");
    CUDA_CHECK(cudaMalloc(&d_out, sizeof(match_slot)), "cudaMalloc(out)");
    CUDA_CHECK(cudaMemcpy(d_seeds, seed, 32, cudaMemcpyHostToDevice), "memcpy(seed)");
    selftest_seed_kernel<<<1, 1>>>(d_table, d_seeds, d_out);
    CUDA_CHECK(cudaDeviceSynchronize(), "selftest_seed_kernel");
    match_slot slot;
    CUDA_CHECK(cudaMemcpy(&slot, d_out, sizeof(slot), cudaMemcpyDeviceToHost), "memcpy(out)");
    char address[57];
    onion_base32_56(slot.addr, address);
    printf("{\"type\":\"selftest\",\"seed\":\"%s\",\"address\":\"%s\"}\n",
           to_hex(slot.seed, 32).c_str(), address);
    fflush(stdout);
    cudaFree(d_seeds);
    cudaFree(d_out);
    cudaFree(d_table);
    return 0;
  }

  u64 *d_states = NULL;
  match_slot *d_out = NULL;
  CUDA_CHECK(cudaMalloc(&d_states, sizeof(u64) * count), "cudaMalloc(states)");
  CUDA_CHECK(cudaMalloc(&d_out, sizeof(match_slot) * count), "cudaMalloc(out)");

  u64 *states = (u64 *)malloc(sizeof(u64) * count);
  u64 salt = random_salt() | 1;
  for (int i = 0; i < count; i++) {
    states[i] = salt + (u64)i * 0x9E3779B97F4A7C15ull;
  }
  CUDA_CHECK(cudaMemcpy(d_states, states, sizeof(u64) * count, cudaMemcpyHostToDevice),
             "memcpy(states)");

  const int block = 256;
  const int grid = (count + block - 1) / block;
  selftest_kernel<<<grid, block>>>(salt, d_states, d_table, d_out);
  CUDA_CHECK(cudaDeviceSynchronize(), "selftest_kernel");

  match_slot *slots = (match_slot *)malloc(sizeof(match_slot) * count);
  CUDA_CHECK(cudaMemcpy(slots, d_out, sizeof(match_slot) * count, cudaMemcpyDeviceToHost),
             "memcpy(out)");

  for (int i = 0; i < count; i++) {
    char address[57];
    onion_base32_56(slots[i].addr, address);
    printf("{\"type\":\"selftest\",\"seed\":\"%s\",\"address\":\"%s\"}\n",
           to_hex(slots[i].seed, 32).c_str(), address);
  }
  fflush(stdout);

  free(states);
  free(slots);
  cudaFree(d_states);
  cudaFree(d_out);
  cudaFree(d_table);
  return 0;
}

static int cmd_mine(int device, const std::string &pattern_raw) {
  onion_pattern pattern;
  if (!compile_pattern(pattern_raw, &pattern)) {
    printf("{\"type\":\"error\",\"message\":\"bad pattern\"}\n");
    return 1;
  }

  CUDA_CHECK(cudaSetDevice(device), "cudaSetDevice");
  cudaDeviceProp prop;
  const u32 threads = device_thread_count(device, &prop);

  comb_table *d_table = NULL;
  u64 *d_states = NULL;
  u64 *d_attempts = NULL;
  match_slot *d_slots = NULL;
  wave_counters *d_counters = NULL;
  CUDA_CHECK(cudaMalloc(&d_table, sizeof(comb_table)), "cudaMalloc(comb)");
  CUDA_CHECK(cudaMalloc(&d_states, sizeof(u64) * threads), "cudaMalloc(states)");
  CUDA_CHECK(cudaMalloc(&d_attempts, sizeof(u64) * threads), "cudaMalloc(attempts)");
  CUDA_CHECK(cudaMalloc(&d_slots, sizeof(match_slot) * MAX_MATCHES), "cudaMalloc(slots)");
  CUDA_CHECK(cudaMalloc(&d_counters, sizeof(wave_counters)), "cudaMalloc(counters)");

  comb_init_kernel<<<1, COMB_WINDOWS>>>(d_table);
  CUDA_CHECK(cudaDeviceSynchronize(), "comb_init_kernel");

  u64 *states = (u64 *)malloc(sizeof(u64) * threads);
  u64 *attempts = (u64 *)calloc(threads, sizeof(u64));
  u64 salt = random_salt() | 1;
  for (u32 i = 0; i < threads; i++) {
    u64 s = salt ^ ((u64)i * 0x9E3779B97F4A7C15ull);
    s ^= s >> 29;
    states[i] = s | 1;
  }
  CUDA_CHECK(cudaMemcpy(d_states, states, sizeof(u64) * threads, cudaMemcpyHostToDevice), "memcpy");
  CUDA_CHECK(cudaMemcpy(d_attempts, attempts, sizeof(u64) * threads, cudaMemcpyHostToDevice), "memcpy");

  printf("{\"type\":\"ready\",\"backend\":\"cuda\",\"device\":%d,\"name\":\"%s\","
         "\"threads\":%u}\n",
         device, prop.name, threads);
  fflush(stdout);

  fcntl(0, F_SETFL, fcntl(0, F_GETFL, 0) | O_NONBLOCK);

  const u32 block = 256;
  const u32 grid = threads / block;
  u64 iterations = 64;             /* adaptive; retuned after each wave */
  u64 total_attempts = 0;
  u32 best = 0;
  double last_report = now_seconds();

  for (;;) {
    CUDA_CHECK(cudaMemset(d_counters, 0, sizeof(wave_counters)), "memset(counters)");

    const double wave_start = now_seconds();
    mine_kernel<<<grid, block>>>(iterations, salt, d_states, d_attempts, d_table, pattern,
                                 d_slots, d_counters);
    CUDA_CHECK(cudaDeviceSynchronize(), "mine_kernel");
    const double wave_time = now_seconds() - wave_start;

    wave_counters counters;
    CUDA_CHECK(cudaMemcpy(&counters, d_counters, sizeof(counters), cudaMemcpyDeviceToHost),
               "memcpy(counters)");

    total_attempts += counters.attempts;
    if (counters.best > best) best = counters.best;

    if (counters.count > 0) {
      u32 take = counters.count;
      if (take > MAX_MATCHES) take = MAX_MATCHES;
      match_slot *slots = (match_slot *)malloc(sizeof(match_slot) * take);
      CUDA_CHECK(cudaMemcpy(slots, d_slots, sizeof(match_slot) * take, cudaMemcpyDeviceToHost),
                 "memcpy(slots)");
      for (u32 i = 0; i < take; i++) {
        char address[57];
        onion_base32_56(slots[i].addr, address);
        printf("{\"type\":\"match\",\"address\":\"%s\",\"seed\":\"%s\",\"attempts\":%llu,"
               "\"device\":%d}\n",
               address, to_hex(slots[i].seed, 32).c_str(),
               (unsigned long long)slots[i].attempts, device);
      }
      fflush(stdout);
      free(slots);
    }

    const double now = now_seconds();
    if (now - last_report >= 0.5) {
      printf("{\"type\":\"progress\",\"attempts\":%llu,\"best\":%u,\"device\":%d}\n",
             (unsigned long long)total_attempts, best, device);
      fflush(stdout);
      last_report = now;
    }

    /* adapt the wave size towards ~0.25 s of work */
    if (wave_time > 0.01) {
      const double rate = (double)(counters.attempts ? counters.attempts : iterations * threads);
      iterations = (u64)(rate * 0.25 / (double)threads);
      if (iterations < 16) iterations = 16;
      if (iterations > 100000000ull) iterations = 100000000ull;
    }

    char buf[256];
    const ssize_t got = read(0, buf, sizeof(buf) - 1);
    if (got > 0) {
      buf[got] = 0;
      if (strstr(buf, "stop") != NULL) break;
    }
  }

  /* final progress line so the orchestrator has exact totals */
  printf("{\"type\":\"progress\",\"attempts\":%llu,\"best\":%u,\"device\":%d}\n",
         (unsigned long long)total_attempts, best, device);
  fflush(stdout);

  free(states);
  free(attempts);
  cudaFree(d_table);
  cudaFree(d_states);
  cudaFree(d_attempts);
  cudaFree(d_slots);
  cudaFree(d_counters);
  return 0;
}

/* ------------------------------------------------------------------ */

static void usage() {
  fprintf(stderr,
          "usage: onionaddress-cuda <selftest|mine|list-devices> [--device N] "
          "[--pattern P] [--count N]\n");
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string mode = argv[1];
  int device = 0;
  int count = 1;
  const char *seed = NULL;
  std::string pattern;

  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--device") == 0 && i + 1 < argc) device = atoi(argv[++i]);
    else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
    else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) seed = argv[++i];
    else if (strcmp(argv[i], "--pattern") == 0 && i + 1 < argc) pattern = argv[++i];
  }

  if (mode == "list-devices") return cmd_list_devices();
  if (mode == "selftest") return cmd_selftest(device, count, seed);
  if (mode == "mine") {
    if (pattern.empty()) {
      printf("{\"type\":\"error\",\"message\":\"missing --pattern\"}\n");
      return 1;
    }
    return cmd_mine(device, pattern);
  }
  usage();
  return 2;
}
