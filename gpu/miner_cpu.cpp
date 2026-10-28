/*
 * CPU reference miner for onionaddress.
 *
 * Two purposes:
 *   - it is the test vehicle for gpu/core.h: test/miner.test.js cross-checks
 *     its results against Node/OpenSSL (fixed vectors + thousands of random
 *     seeds), so every line of shared math is verified before the CUDA kernel
 *     reuses it;
 *   - it speaks the same JSON-lines protocol as the CUDA miner, so the Node
 *     orchestration can be tested end-to-end without a GPU.
 *
 * Modes:
 *   selftest [--count N] [--seed <32-byte hex>]
 *   hash-selftest              (reads hex lines on stdin)
 *   mine --pattern <^str|str$>
 *   list-devices
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "core.h"

/* ------------------------------------------------------------------ */
/* constant tables and shared state                                    */
/* ------------------------------------------------------------------ */

static const u64 H_SHA512_K[80] = ONION_SHA512_K;
static const u64 H_SHA512_INIT[8] = ONION_SHA512_INIT;
static const u64 H_KECCAK_RC[24] = ONION_KECCAK_RC;
static const u8 H_KECCAK_RHO[25] = ONION_KECCAK_RHO;

static onion_tables g_tables = {H_SHA512_K, H_SHA512_INIT, H_KECCAK_RC, H_KECCAK_RHO};
static comb_table g_comb;

/* ------------------------------------------------------------------ */
/* small utilities                                                     */
/* ------------------------------------------------------------------ */

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
    int hi = hex[2 * i] < '0' ? -1 : hex[2 * i] <= '9' ? hex[2 * i] - '0'
                            : hex[2 * i] >= 'a' && hex[2 * i] <= 'f' ? hex[2 * i] - 'a' + 10
                            : hex[2 * i] >= 'A' && hex[2 * i] <= 'F' ? hex[2 * i] - 'A' + 10
                                                                     : -1;
    int lo = hex[2 * i + 1] < '0' ? -1 : hex[2 * i + 1] <= '9' ? hex[2 * i + 1] - '0'
                              : hex[2 * i + 1] >= 'a' && hex[2 * i + 1] <= 'f' ? hex[2 * i + 1] - 'a' + 10
                              : hex[2 * i + 1] >= 'A' && hex[2 * i + 1] <= 'F' ? hex[2 * i + 1] - 'A' + 10
                                                                               : -1;
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

static void emit_error(const char *message) {
  printf("{\"type\":\"error\",\"message\":\"%s\"}\n", message);
  fflush(stdout);
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

/* ------------------------------------------------------------------ */
/* pattern compilation (same semantics as src/pattern.js)              */
/* ------------------------------------------------------------------ */

static bool compile_pattern(const std::string &raw, onion_pattern *out) {
  /* strip and normalize */
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
  if (mode == 3) mode = 1; /* exact is handled as a 56-char prefix */
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

/* ------------------------------------------------------------------ */
/* modes                                                               */
/* ------------------------------------------------------------------ */

static int cmd_selftest(int count, const char *seed_hex) {
  if (onion_comb_init(&g_comb) != 0) {
    emit_error("curve initialization failed");
    return 1;
  }

  if (seed_hex != NULL) {
    u8 seed[32];
    if (!from_hex(seed_hex, seed, 32)) {
      emit_error("bad --seed");
      return 1;
    }
    u8 addr[35];
    char address[57];
    onion_address_from_seed(&g_tables, &g_comb, seed, addr);
    onion_base32_56(addr, address);
    printf("{\"type\":\"selftest\",\"seed\":\"%s\",\"address\":\"%s\"}\n",
           to_hex(seed, 32).c_str(), address);
    fflush(stdout);
    return 0;
  }

  u64 state = random_salt() | 1;
  for (int i = 0; i < count; i++) {
    u8 seed[32];
    u8 addr[35];
    char address[57];
    splitmix64_fill(&state, seed);
    onion_address_from_seed(&g_tables, &g_comb, seed, addr);
    onion_base32_56(addr, address);
    printf("{\"type\":\"selftest\",\"seed\":\"%s\",\"address\":\"%s\"}\n",
           to_hex(seed, 32).c_str(), address);
  }
  fflush(stdout);
  return 0;
}

static int cmd_hash_selftest() {
  char line[4096];
  while (fgets(line, sizeof(line), stdin) != NULL) {
    std::string hex(line);
    while (!hex.empty() && (hex[hex.size() - 1] == '\n' || hex[hex.size() - 1] == '\r')) {
      hex.pop_back();
    }
    /* an empty line is the empty message, not a blank to skip */

    std::vector<u8> data(hex.size() / 2);
    if (!from_hex(hex, data.data(), data.size())) {
      emit_error("bad hex line");
      return 1;
    }

    u8 sha512_out[64];
    u8 sha3_out[32];
    onion_sha512(&g_tables, data.data(), (u32)data.size(), sha512_out);
    onion_sha3_256(&g_tables, data.data(), (u32)data.size(), sha3_out);
    printf("{\"type\":\"hash\",\"input\":\"%s\",\"sha512\":\"%s\",\"sha3\":\"%s\"}\n",
           hex.c_str(), to_hex(sha512_out, 64).c_str(), to_hex(sha3_out, 32).c_str());
  }
  fflush(stdout);
  return 0;
}

static int cmd_list_devices() {
  printf("{\"type\":\"device\",\"backend\":\"cpu\",\"index\":0,\"name\":\"CPU reference miner\",\"threads\":1}\n");
  fflush(stdout);
  return 0;
}

static int cmd_mine(const std::string &pattern_raw) {
  onion_pattern pattern;
  if (!compile_pattern(pattern_raw, &pattern)) {
    emit_error("bad pattern");
    return 1;
  }
  if (onion_comb_init(&g_comb) != 0) {
    emit_error("curve initialization failed");
    return 1;
  }

  /* stop commands arrive on stdin; poll without blocking */
  fcntl(0, F_SETFL, fcntl(0, F_GETFL, 0) | O_NONBLOCK);

  printf("{\"type\":\"ready\",\"backend\":\"cpu\",\"device\":0,"
         "\"name\":\"CPU reference miner\",\"threads\":1}\n");
  fflush(stdout);

  u64 state = random_salt() | 1;
  u64 attempts = 0;
  u32 best = 0;
  double last_report = now_seconds();

  u8 addr[36];
  addr[35] = 0; /* spare byte for the score's two-byte window */
  if (!pattern.needs_tail) onion_memset(addr + 32, 0, 3);

  for (;;) {
    for (u32 i = 0; i < 256; i++) {
      u8 seed[32];
      ge point;
      splitmix64_fill(&state, seed);
      onion_point_from_seed(&g_tables, &g_comb, seed, &point);

      if (pattern.needs_tail) {
        u8 pub[32];
        ge_compress(&point, pub);
        onion_memcpy(addr, pub, 32);
        onion_append_checksum(&g_tables, pub, addr);
      } else {
        /* prefixes up to 51 chars live inside the public key: no SHA3 at all */
        ge_compress(&point, addr);
      }
      attempts++;

      if (onion_pattern_match(&pattern, addr)) {
        char address[57];
        if (!pattern.needs_tail) onion_append_checksum(&g_tables, addr, addr);
        onion_base32_56(addr, address);
        printf("{\"type\":\"match\",\"address\":\"%s\",\"seed\":\"%s\",\"attempts\":%llu,"
               "\"device\":0}\n",
               address, to_hex(seed, 32).c_str(), (unsigned long long)attempts);
        fflush(stdout);
        continue;
      }
      const u32 score = onion_pattern_score(&pattern, addr);
      if (score > best) best = score;
    }

    const double now = now_seconds();
    if (now - last_report >= 0.5) {
      printf("{\"type\":\"progress\",\"attempts\":%llu,\"best\":%u,\"device\":0}\n",
             (unsigned long long)attempts, best);
      fflush(stdout);
      last_report = now;
    }

    char buf[256];
    const ssize_t got = read(0, buf, sizeof(buf) - 1);
    if (got > 0) {
      buf[got] = 0;
      if (strstr(buf, "stop") != NULL) break;
    }
  }

  /* final progress line so the orchestrator has exact totals */
  printf("{\"type\":\"progress\",\"attempts\":%llu,\"best\":%u,\"device\":0}\n",
         (unsigned long long)attempts, best);
  fflush(stdout);
  return 0;
}

/* ------------------------------------------------------------------ */

static void usage() {
  fprintf(stderr,
          "usage: onionaddress-cpu <selftest|hash-selftest|mine|list-devices> [options]\n");
}

int main(int argc, char **argv) {
  if (argc < 2) {
    usage();
    return 2;
  }
  const std::string mode = argv[1];

  if (mode == "selftest") {
    int count = 1;
    const char *seed = NULL;
    for (int i = 2; i < argc; i++) {
      if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) count = atoi(argv[++i]);
      else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) seed = argv[++i];
    }
    return cmd_selftest(count, seed);
  }
  if (mode == "hash-selftest") return cmd_hash_selftest();
  if (mode == "list-devices") return cmd_list_devices();
  if (mode == "mine") {
    std::string pattern;
    for (int i = 2; i < argc; i++) {
      if (strcmp(argv[i], "--pattern") == 0 && i + 1 < argc) pattern = argv[++i];
    }
    if (pattern.empty()) {
      emit_error("missing --pattern");
      return 1;
    }
    return cmd_mine(pattern);
  }

  usage();
  return 2;
}
