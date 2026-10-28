/*
 * Shared mining core for onionaddress.
 *
 * Compiled both by g++ (CPU reference miner, used for tests) and by nvcc
 * (CUDA miner). Everything here is host/device portable.
 *
 * The Ed25519 pipeline:
 *
 *   seed --SHA-512--> clamp --> scalar a --comb(a)--> A = a*B --compress--> PUBKEY
 *   address = base32(PUBKEY | SHA3-256(".onion checksum" | PUBKEY | 0x03)[:2] | 0x03)
 *
 * Field elements are eight 32-bit limbs, little-endian, fully reduced mod
 * p = 2^255 - 19 after every operation. The fixed-base comb uses a table of
 * 64 windows x 16 points generated at startup by the same arithmetic, so no
 * magic constants are transcribed: d = -121665/121666 and the base point are
 * derived at runtime.
 *
 * test/miner.test.js cross-checks thousands of random seeds and fixed vectors
 * against Node/OpenSSL, for both the CPU and the CUDA binaries.
 */
#ifndef ONIONADDRESS_CORE_H
#define ONIONADDRESS_CORE_H

#include <stdint.h>

#ifdef __CUDACC__
#define ONION_HD __host__ __device__
#else
#define ONION_HD
#endif

#include "tables.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef struct {
  const u64 *sha512_k;     /* 80 constants */
  const u64 *sha512_init;  /* 8 constants  */
  const u64 *keccak_rc;    /* 24 constants */
  const u8 *keccak_rho;    /* 25 offsets   */
} onion_tables;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

ONION_HD static inline void onion_memcpy(u8 *dst, const u8 *src, u32 n) {
  for (u32 i = 0; i < n; i++) dst[i] = src[i];
}

ONION_HD static void onion_memset(u8 *dst, u8 value, u32 n) {
  for (u32 i = 0; i < n; i++) dst[i] = value;
}

/* ------------------------------------------------------------------ */
/* SHA-512 (FIPS 180-4)                                                */
/* ------------------------------------------------------------------ */

ONION_HD static inline u64 rotr64(u64 x, u32 n) {
  return (x >> n) | (x << (64 - n));
}

ONION_HD static void sha512_block(const u64 *K, u64 h[8], const u8 block[128]) {
  u64 w[80];

  for (u32 i = 0; i < 16; i++) {
    w[i] = ((u64)block[8 * i] << 56) | ((u64)block[8 * i + 1] << 48) |
           ((u64)block[8 * i + 2] << 40) | ((u64)block[8 * i + 3] << 32) |
           ((u64)block[8 * i + 4] << 24) | ((u64)block[8 * i + 5] << 16) |
           ((u64)block[8 * i + 6] << 8) | (u64)block[8 * i + 7];
  }
  for (u32 t = 16; t < 80; t++) {
    const u64 s0 = rotr64(w[t - 15], 1) ^ rotr64(w[t - 15], 8) ^ (w[t - 15] >> 7);
    const u64 s1 = rotr64(w[t - 2], 19) ^ rotr64(w[t - 2], 61) ^ (w[t - 2] >> 6);
    w[t] = w[t - 16] + s0 + w[t - 7] + s1;
  }

  u64 a = h[0], b = h[1], c = h[2], d = h[3];
  u64 e = h[4], f = h[5], g = h[6], hh = h[7];

  for (u32 t = 0; t < 80; t++) {
    const u64 S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
    const u64 ch = (e & f) ^ (~e & g);
    const u64 T1 = hh + S1 + ch + K[t] + w[t];
    const u64 S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
    const u64 maj = (a & b) ^ (a & c) ^ (b & c);
    const u64 T2 = S0 + maj;
    hh = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

ONION_HD static void onion_sha512(const onion_tables *T, const u8 *data, u32 len,
                                  u8 out[64]) {
  u64 h[8];
  for (u32 i = 0; i < 8; i++) h[i] = T->sha512_init[i];

  u32 offset = 0;
  while (len - offset >= 128) {
    sha512_block(T->sha512_k, h, data + offset);
    offset += 128;
  }

  u8 tail[256];
  const u32 rem = len - offset;
  onion_memset(tail, 0, 256);
  onion_memcpy(tail, data + offset, rem);
  tail[rem] = 0x80;

  const u64 totalBits = (u64)len * 8;
  const u32 tailLen = rem < 112 ? 128 : 256;
  for (u32 i = 0; i < 8; i++) {
    tail[tailLen - 8 + i] = (u8)(totalBits >> (56 - 8 * i));
  }
  for (u32 i = 0; i < tailLen; i += 128) sha512_block(T->sha512_k, h, tail + i);

  for (u32 i = 0; i < 8; i++) {
    for (u32 j = 0; j < 8; j++) out[8 * i + j] = (u8)(h[i] >> (56 - 8 * j));
  }
}

/* ------------------------------------------------------------------ */
/* Keccak-f[1600] / SHA3-256 (FIPS 202)                                */
/* ------------------------------------------------------------------ */

ONION_HD static inline u64 rotl64(u64 x, u32 n) {
  return n == 0 ? x : (x << n) | (x >> (64 - n));
}

ONION_HD static void keccak_f(const u64 *rc, const u8 *rho, u64 st[25]) {
  for (u32 round = 0; round < 24; round++) {
    u64 c[5], dd[5];
    for (u32 x = 0; x < 5; x++) {
      c[x] = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
    }
    for (u32 x = 0; x < 5; x++) {
      dd[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (u32 y = 0; y < 5; y++) {
      for (u32 x = 0; x < 5; x++) st[x + 5 * y] ^= dd[x];
    }

    u64 b[25];
    for (u32 y = 0; y < 5; y++) {
      for (u32 x = 0; x < 5; x++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(st[x + 5 * y], rho[x + 5 * y]);
      }
    }
    for (u32 y = 0; y < 5; y++) {
      for (u32 x = 0; x < 5; x++) {
        st[x + 5 * y] =
            b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
      }
    }
    st[0] ^= rc[round];
  }
}

ONION_HD static void onion_sha3_256(const onion_tables *T, const u8 *data,
                                    u32 len, u8 out[32]) {
  const u32 RATE = 136;
  u64 st[25];
  onion_memset((u8 *)st, 0, 200);

  u32 offset = 0;
  while (len - offset >= RATE) {
    for (u32 i = 0; i < RATE; i++) {
      st[i >> 3] ^= (u64)data[offset + i] << (8 * (i & 7));
    }
    keccak_f(T->keccak_rc, T->keccak_rho, st);
    offset += RATE;
  }

  u8 block[136];
  onion_memset(block, 0, RATE);
  const u32 rem = len - offset;
  onion_memcpy(block, data + offset, rem);
  block[rem] ^= 0x06;
  block[RATE - 1] ^= 0x80;
  for (u32 i = 0; i < RATE; i++) {
    st[i >> 3] ^= (u64)block[i] << (8 * (i & 7));
  }
  keccak_f(T->keccak_rc, T->keccak_rho, st);

  for (u32 i = 0; i < 32; i++) {
    out[i] = (u8)(st[i >> 3] >> (8 * (i & 7)));
  }
}

/* ------------------------------------------------------------------ */
/* GF(2^255 - 19): eight 32-bit limbs, little-endian, fully reduced    */
/*                                                                     */
/* Every operation below is branch-free with a fixed instruction count: */
/* conditional reductions are done with masked selects instead of       */
/* comparisons, and carry propagation uses fixed-length loops. On a GPU  */
/* this matters enormously — data-dependent branches make all 32 lanes   */
/* of a warp execute both paths serially.                              */
/* ------------------------------------------------------------------ */

typedef u32 fe[8];

#define FE_P_LIMB(i) ((i) == 0 ? 0xffffffedu : ((i) == 7 ? 0x7fffffffu : 0xffffffffu))

ONION_HD static void fe_zero(fe h) {
  for (u32 i = 0; i < 8; i++) h[i] = 0;
}

ONION_HD static void fe_one(fe h) {
  fe_zero(h);
  h[0] = 1;
}

/* p = 2^255 - 19 */
ONION_HD static void fe_p(fe h) {
  for (u32 i = 0; i < 8; i++) h[i] = FE_P_LIMB(i);
}

ONION_HD static int fe_is_zero(const fe a) {
  u32 acc = 0;
  for (u32 i = 0; i < 8; i++) acc |= a[i];
  return acc == 0;
}

/* -1, 0 or 1 comparing as integers (setup-time only) */
ONION_HD static int fe_cmp(const fe a, const fe b) {
  for (int i = 7; i >= 0; i--) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

/* h = a - b assuming a >= b (setup-time helper) */
ONION_HD static void fe_sub_raw(fe h, const fe a, const fe b) {
  u64 borrow = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 t = (u64)a[i] - (u64)b[i] - borrow;
    h[i] = (u32)t;
    borrow = (t >> 32) & 1;
  }
}

/* h = -a (mod p) (setup-time helper) */
ONION_HD static void fe_neg(fe h, const fe a) {
  if (fe_is_zero(a)) {
    fe_zero(h);
    return;
  }
  fe p;
  fe_p(p);
  fe_sub_raw(h, p, a);
}

/* two masked conditional subtractions of p: enough because h < 2^256 = 2p+38 */
ONION_HD static void fe_reduce2(fe h) {
  for (u32 pass = 0; pass < 2; pass++) {
    u32 r[8];
    u64 borrow = 0;
    for (u32 i = 0; i < 8; i++) {
      const u64 d = (u64)h[i] - (u64)FE_P_LIMB(i) - borrow;
      r[i] = (u32)d;
      borrow = (d >> 32) & 1;
    }
    const u32 mask = (u32)borrow - 1u; /* borrow=1 -> keep h, borrow=0 -> take r */
    for (u32 i = 0; i < 8; i++) h[i] = (h[i] & ~mask) | (r[i] & mask);
  }
}

/* h = a + b (mod p), a, b < p; branch-free (a+b < 2p < 2^256) */
ONION_HD static void fe_add(fe h, const fe a, const fe b) {
  u32 t[8];
  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 s = (u64)a[i] + (u64)b[i] + carry;
    t[i] = (u32)s;
    carry = s >> 32;
  }

  u32 r[8];
  u64 borrow = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 d = (u64)t[i] - (u64)FE_P_LIMB(i) - borrow;
    r[i] = (u32)d;
    borrow = (d >> 32) & 1;
  }
  const u32 mask = (u32)borrow - 1u;
  for (u32 i = 0; i < 8; i++) h[i] = (t[i] & ~mask) | (r[i] & mask);
}

/* h = a - b (mod p), a, b < p; branch-free (adds p back when a < b) */
ONION_HD static void fe_sub(fe h, const fe a, const fe b) {
  u32 t[8];
  u64 borrow = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 d = (u64)a[i] - (u64)b[i] - borrow;
    t[i] = (u32)d;
    borrow = (d >> 32) & 1;
  }

  const u32 mask = (u32)(0 - borrow); /* borrow=1 -> add p */
  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 s = (u64)t[i] + ((u32)FE_P_LIMB(i) & mask) + carry;
    h[i] = (u32)s;
    carry = s >> 32;
  }
}

/* h = a * b (mod p): schoolbook product, then fold 2^256 -> 38, then reduce */
ONION_HD static void fe_mul(fe h, const fe a, const fe b) {
  u32 t[16];
  for (u32 i = 0; i < 16; i++) t[i] = 0;

  for (u32 i = 0; i < 8; i++) {
    u64 carry = 0;
    for (u32 j = 0; j < 8; j++) {
      const u64 s = (u64)t[i + j] + (u64)a[i] * (u64)b[j] + carry;
      t[i + j] = (u32)s;
      carry = s >> 32;
    }
    for (u32 k = i + 8; k < 16; k++) {
      const u64 s = (u64)t[k] + carry;
      t[k] = (u32)s;
      carry = s >> 32;
    }
  }

  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 v = (u64)t[i] + (u64)t[i + 8] * 38 + carry;
    h[i] = (u32)v;
    carry = v >> 32;
  }

  /* fold the leftover carry (bounded by ~39) three times; each pass shrinks it */
  for (u32 pass = 0; pass < 3; pass++) {
    u64 c = carry * 38;
    carry = 0;
    for (u32 i = 0; i < 8; i++) {
      const u64 s = (u64)h[i] + c;
      h[i] = (u32)s;
      c = s >> 32;
    }
    carry = c;
  }

  fe_reduce2(h);
}

/* h = a * small (mod p), small < 2^32 */
ONION_HD static void fe_mul_small(fe h, const fe a, u32 small) {
  u32 t[8];
  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    const u64 v = (u64)a[i] * small + carry;
    t[i] = (u32)v;
    carry = v >> 32;
  }
  for (u32 pass = 0; pass < 3; pass++) {
    u64 c = carry * 38;
    carry = 0;
    for (u32 i = 0; i < 8; i++) {
      const u64 s = (u64)t[i] + c;
      t[i] = (u32)s;
      c = s >> 32;
    }
    carry = c;
  }
  for (u32 i = 0; i < 8; i++) h[i] = t[i];
  fe_reduce2(h);
}

ONION_HD static void fe_sq(fe h, const fe a) {
  fe_mul(h, a, a);
}

/* h = a squared `repeats` times */
ONION_HD static void fe_sq_repeat(fe h, const fe a, u32 repeats) {
  fe t;
  for (u32 i = 0; i < 8; i++) t[i] = a[i];
  for (u32 i = 0; i < repeats; i++) fe_sq(t, t);
  for (u32 i = 0; i < 8; i++) h[i] = t[i];
}

/*
 * h = a^(p-2) = a^-1 (mod p). Exponent 2^255 - 21.
 *
 * Chain built from b_{2m} = b_m^(2^m) * b_m with b_k = a^(2^k - 1), then
 * (2^250 - 1) * 2^5 + 11 = 2^255 - 21: 254 squarings, 11 multiplications.
 */
ONION_HD static void fe_invert(fe h, const fe a) {
  fe z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1;

  fe_sq(z2, a);                                                /* 2 */
  fe_sq(t1, z2); fe_sq(t1, t1);                                /* 8 */
  fe_mul(z9, t1, a);                                           /* 9 */
  fe_mul(z11, z9, z2);                                         /* 11 */
  fe_sq(t1, z11);                                              /* 22 */
  fe_mul(z2_5_0, t1, z9);                                      /* 2^5-1 */

  fe_sq_repeat(t0, z2_5_0, 5); fe_mul(z2_10_0, t0, z2_5_0);    /* 2^10-1 */
  fe_sq_repeat(t0, z2_10_0, 10); fe_mul(z2_20_0, t0, z2_10_0); /* 2^20-1 */
  fe_sq_repeat(t0, z2_20_0, 20); fe_mul(t1, t0, z2_20_0);      /* 2^40-1 */
  fe_sq_repeat(t0, t1, 10); fe_mul(z2_50_0, t0, z2_10_0);      /* 2^50-1 */
  fe_sq_repeat(t0, z2_50_0, 50); fe_mul(z2_100_0, t0, z2_50_0);/* 2^100-1 */
  fe_sq_repeat(t0, z2_100_0, 100); fe_mul(t1, t0, z2_100_0);   /* 2^200-1 */
  fe_sq_repeat(t0, t1, 50); fe_mul(t1, t0, z2_50_0);           /* 2^250-1 */
  fe_sq_repeat(t0, t1, 5);                                     /* 2^255-2^5 */
  fe_mul(h, t0, z11);                                          /* 2^255-21 */
}

/*
 * Batch inversion (Montgomery's trick): n inversions for the price of one
 * fe_invert plus 3n multiplications. Used to build the comb table.
 * `in` and `out` must not alias.
 */
ONION_HD static void fe_batch_invert(fe *out, const fe *in, u32 n) {
  if (n == 0) return;
  for (u32 i = 0; i < 8; i++) out[0][i] = in[0][i];
  for (u32 i = 1; i < n; i++) fe_mul(out[i], out[i - 1], in[i]);

  fe u;
  fe_invert(u, out[n - 1]);

  for (u32 i = n; i-- > 1;) {
    fe inv_i;
    fe_mul(inv_i, u, out[i - 1]); /* 1/z_i = u * P_{i-1} */
    fe_mul(u, u, in[i]);          /* u <- 1/P_{i-1}       */
    for (u32 k = 0; k < 8; k++) out[i][k] = inv_i[k];
  }
  for (u32 k = 0; k < 8; k++) out[0][k] = u[k];
}

/* h = a^e for an arbitrary exponent (8 little-endian limbs).
 * Square-and-multiply; used only for one-time setup. */
ONION_HD static void fe_exp_simple(fe h, const fe a, const u32 e[8]) {
  fe acc;
  fe_one(acc);
  for (int i = 255; i >= 0; i--) {
    fe_sq(acc, acc);
    if ((e[i >> 5] >> (i & 31)) & 1) fe_mul(acc, acc, a);
  }
  for (u32 i = 0; i < 8; i++) h[i] = acc[i];
}

/* ------------------------------------------------------------------ */
/* Edwards curve points (extended coordinates) and the fixed-base comb */
/* ------------------------------------------------------------------ */

typedef struct {
  fe X, Y, Z, T;
} ge;

/*
 * Comb geometry. ONION_COMB_BITS is the window width in bits: the scalar's 256
 * bits are split into COMB_WINDOWS windows of COMB_BITS bits, each selecting
 * one of COMB_ENTRIES precomputed points. Wider windows mean fewer mixed
 * additions (the dominant cost) at the price of a bigger table:
 *
 *    8 bits -> 32 windows x 256 entries   =   1 MB, 31 madds
 *   16 bits -> 16 windows x 65536 entries = 128 MB, 15 madds
 */
#ifndef ONION_COMB_BITS
#define ONION_COMB_BITS 8
#endif

#define COMB_WINDOWS (256 / ONION_COMB_BITS)
#define COMB_ENTRIES (1u << ONION_COMB_BITS)

/*
 * Fixed-base comb table: window w holds the points n * 16^w * B (n = 0..15) in
 * affine form (Z = 1), plus T = X*Y and T2 = 2d*X*Y for the madd formula.
 *
 * Layout is structure-of-arrays on purpose: for a fixed window/coordinate/limb
 * the entries are contiguous, so the 32 lanes of a warp read 32 adjacent u32
 * values (one or two 32-byte sectors) instead of 32 scattered 128-byte cache
 * lines. With the naive array-of-structs layout the kernel is memory bound and
 * the arithmetic is nearly free; SoA removes ~32x of the memory transactions.
 */
typedef struct {
  u32 X[COMB_WINDOWS][8][COMB_ENTRIES];
  u32 Y[COMB_WINDOWS][8][COMB_ENTRIES];
  u32 T[COMB_WINDOWS][8][COMB_ENTRIES];
  u32 T2[COMB_WINDOWS][8][COMB_ENTRIES];
  u32 d2[8]; /* 2d, needed to combine the independent comb chains */
} comb_table;

/*
 * Unified extended-coordinates addition for a = -1 (add-2008-hwcd-3),
 * valid for arbitrary pairs including doubling. `d2` is 2*d (mod p).
 */
ONION_HD static void ge_add(ge *r, const ge *p, const ge *q, const fe d2) {
  fe a, b, c, d, e, f, g, h, t;

  fe_sub(a, p->Y, p->X);
  fe_sub(t, q->Y, q->X);
  fe_mul(a, a, t);              /* A = (Y1-X1)(Y2-X2) */

  fe_add(b, p->Y, p->X);
  fe_add(t, q->Y, q->X);
  fe_mul(b, b, t);              /* B = (Y1+X1)(Y2+X2) */

  fe_mul(t, q->T, d2);          /* 2d*T2 */
  fe_mul(c, p->T, t);           /* C = T1*2d*T2 */

  fe_mul(d, p->Z, q->Z);
  fe_add(d, d, d);              /* D = 2*Z1*Z2 */

  fe_sub(e, b, a);
  fe_sub(f, d, c);
  fe_add(g, d, c);
  fe_add(h, b, a);

  fe_mul(r->X, e, f);
  fe_mul(r->Y, g, h);
  fe_mul(r->T, e, h);
  fe_mul(r->Z, f, g);
}

/* mixed addition: q affine (Z = 1) with precomputed qT2 = 2d*Xq*Yq */
ONION_HD static void ge_madd_aff(ge *r, const ge *p, const fe qX, const fe qY, const fe qT2) {
  fe a, b, c, d, e, f, g, h, t;

  fe_sub(a, p->Y, p->X);
  fe_sub(t, qY, qX);
  fe_mul(a, a, t);

  fe_add(b, p->Y, p->X);
  fe_add(t, qY, qX);
  fe_mul(b, b, t);

  fe_mul(c, p->T, qT2);

  fe_add(d, p->Z, p->Z);

  fe_sub(e, b, a);
  fe_sub(f, d, c);
  fe_add(g, d, c);
  fe_add(h, b, a);

  fe_mul(r->X, e, f);
  fe_mul(r->Y, g, h);
  fe_mul(r->T, e, h);
  fe_mul(r->Z, f, g);
}

/* madd against a comb table entry (loads the entry with coalesced accesses) */
ONION_HD static void ge_madd_tab(ge *r, const ge *p, const comb_table *table, u32 w, u32 n) {
  fe qX, qY, qT2;
  for (u32 i = 0; i < 8; i++) {
    qX[i] = table->X[w][i][n];
    qY[i] = table->Y[w][i][n];
    qT2[i] = table->T2[w][i][n];
  }
  ge_madd_aff(r, p, qX, qY, qT2);
}

/*
 * Derive the curve constants d = -121665/121666, d2 = 2d and the base point
 * B = (4/5, sqrt((y^2-1)/(d*y^2+1))) with even x. Returns 0 on success.
 *
 * Only the curve parameters 121665/121666 and 4/5 are written down; every
 * other value is computed with the field arithmetic above.
 */
ONION_HD static int onion_curve_init(fe d2, ge *B) {
  fe one, five, d, y, num, den, t0, t1, iota;
  /* (p+3)/8 = 2^252 - 2, for the square-root exponent */
  u32 e_sqrt[8] = {0xfffffffeu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                   0xffffffffu, 0xffffffffu, 0xffffffffu, 0x0fffffffu};
  /* (p-1)/4 = 2^253 - 5, for sqrt(-1) = 2^((p-1)/4) */
  u32 e_iota[8] = {0xfffffffbu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
                   0xffffffffu, 0xffffffffu, 0xffffffffu, 0x1fffffffu};

  fe_one(one);
  fe_mul_small(five, one, 5);

  /* d = -(121665 * inv(121666)) */
  fe_mul_small(t0, one, 121666);
  fe_invert(t0, t0);
  fe_mul_small(t0, t0, 121665);
  fe_neg(d, t0);
  fe_add(d2, d, d);

  /* y = 4/5 */
  fe_invert(t1, five);
  fe_mul_small(y, t1, 4);

  /* x = sqrt((y^2 - 1) / (d*y^2 + 1)) with even x */
  fe_sq(t0, y);
  fe_sub(num, t0, one);          /* y^2 - 1 */
  fe_mul(den, d, t0);
  fe_add(den, den, one);         /* d*y^2 + 1 */
  fe_invert(den, den);
  fe_mul(num, num, den);         /* target = x^2 */

  fe_exp_simple(B->X, num, e_sqrt);
  fe_sq(t0, B->X);
  if (fe_cmp(t0, num) != 0) {
    /* sqrt(-1) = 2^((p-1)/4) */
    fe two;
    fe_one(two);
    fe_add(two, two, two);
    fe_exp_simple(iota, two, e_iota);
    fe_mul(B->X, B->X, iota);
    fe_sq(t0, B->X);
    if (fe_cmp(t0, num) != 0) return -1;
  }
  if (B->X[0] & 1) fe_neg(B->X, B->X);   /* B has sign bit 0 (even x) */

  for (u32 i = 0; i < 8; i++) B->Y[i] = y[i];
  fe_one(B->Z);
  fe_mul(B->T, B->X, B->Y);
  return 0;
}

/*
 * Fill one comb window: entry [w][n] = n * 256^w * B in affine form, plus
 * T = X*Y and T2 = 2d*X*Y for the mixed addition. Entry [w][0] is the neutral
 * element (0 : 1).
 *
 * The 255 points are chained with mixed additions and converted to affine in
 * chunks, so each chunk pays one fe_invert (via fe_batch_invert) instead of
 * one per entry.
 */
#define COMB_INIT_CHUNK 32

ONION_HD static void onion_comb_init_window(comb_table *table, u32 w,
                                            const fe d2, const ge *B) {
  /* entry 0 is the neutral element (0 : 1 : 1 : 0) */
  for (u32 i = 0; i < 8; i++) {
    table->X[w][i][0] = 0;
    table->Y[w][i][0] = (i == 0) ? 1u : 0u;
    table->T[w][i][0] = 0;
    table->T2[w][i][0] = 0;
  }

  /* G_w = (2^COMB_BITS)^w * B: COMB_BITS doublings per window */
  ge G;
  for (u32 i = 0; i < 8; i++) {
    G.X[i] = B->X[i];
    G.Y[i] = B->Y[i];
    G.Z[i] = B->Z[i];
    G.T[i] = B->T[i];
  }
  for (u32 i = 0; i < w; i++) {
    for (u32 k = 0; k < ONION_COMB_BITS; k++) ge_add(&G, &G, &G, d2);
  }

  /* affine G, so the chain below can use mixed additions */
  fe ginv, gx, gy, gt, gt2;
  fe_invert(ginv, G.Z);
  fe_mul(gx, G.X, ginv);
  fe_mul(gy, G.Y, ginv);
  fe_mul(gt, gx, gy);
  fe_mul(gt2, gt, d2);

  fe cx[COMB_INIT_CHUNK], cy[COMB_INIT_CHUNK], cz[COMB_INIT_CHUNK], cinv[COMB_INIT_CHUNK];
  ge P = G;
  u32 c = 0;

  for (u32 n = 1; n < COMB_ENTRIES; n++) {
    for (u32 i = 0; i < 8; i++) {
      cx[c][i] = P.X[i];
      cy[c][i] = P.Y[i];
      cz[c][i] = P.Z[i];
    }
    c++;

    if (c == COMB_INIT_CHUNK || n == COMB_ENTRIES - 1) {
      fe_batch_invert(cinv, cz, c);
      const u32 first = n - c + 1;
      for (u32 k = 0; k < c; k++) {
        fe x, y, t, t2;
        fe_mul(x, cx[k], cinv[k]);
        fe_mul(y, cy[k], cinv[k]);
        fe_mul(t, x, y);
        fe_mul(t2, t, d2);
        const u32 idx = first + k;
        for (u32 i = 0; i < 8; i++) {
          table->X[w][i][idx] = x[i];
          table->Y[w][i][idx] = y[i];
          table->T[w][i][idx] = t[i];
          table->T2[w][i][idx] = t2[i];
        }
      }
      c = 0;
    }

    if (n + 1 < COMB_ENTRIES) ge_madd_aff(&P, &P, gx, gy, gt2);
  }
}

ONION_HD static int onion_comb_init(comb_table *table) {
  fe d2;
  ge B;
  if (onion_curve_init(d2, &B) != 0) return -1;
  for (u32 i = 0; i < 8; i++) table->d2[i] = d2[i];
  for (u32 w = 0; w < COMB_WINDOWS; w++) onion_comb_init_window(table, w, d2, &B);
  return 0;
}

/*
 * r = scalar * B using the comb table; scalar is 32 little-endian bytes.
 * One 8-bit window per byte: 31 mixed additions instead of 63 with 4-bit
 * windows.
 *
 * The additions form a serial dependency chain. Splitting the windows into
 * ONION_COMB_CHAINS independent partial sums would raise ILP, but each extra
 * chain needs another live point accumulator (~32 registers) and the kernel
 * already runs at ~116 registers/thread: measured on a GTX 1650 SUPER, 2 and 4
 * chains are 35% and 39% SLOWER than 1 because of spilling. So the default is
 * a single chain; the knob stays available for GPUs with more registers.
 */
#ifndef ONION_COMB_CHAINS
#define ONION_COMB_CHAINS 1
#endif

/* extract the COMB_BITS-bit digit of window w from the little-endian scalar */
ONION_HD static u32 comb_digit(const u8 scalar[32], u32 w) {
  const u32 bit = w * ONION_COMB_BITS;
  u32 digit = 0;
  for (u32 k = 0; k < ONION_COMB_BITS; k++) {
    digit |= (u32)((scalar[(bit + k) >> 3] >> ((bit + k) & 7)) & 1) << k;
  }
  return digit;
}

ONION_HD static void comb_mult(ge *r, const u8 scalar[32], const comb_table *table) {
  ge acc[ONION_COMB_CHAINS];

  for (u32 c = 0; c < ONION_COMB_CHAINS; c++) {
    const u32 digit = comb_digit(scalar, c);
    for (u32 i = 0; i < 8; i++) {
      acc[c].X[i] = table->X[c][i][digit];
      acc[c].Y[i] = table->Y[c][i][digit];
      acc[c].T[i] = table->T[c][i][digit];
    }
    fe_one(acc[c].Z);
  }

  for (u32 w = ONION_COMB_CHAINS; w < COMB_WINDOWS; w++) {
    ge_madd_tab(&acc[w % ONION_COMB_CHAINS], &acc[w % ONION_COMB_CHAINS], table, w,
                comb_digit(scalar, w));
  }

  fe d2;
  for (u32 i = 0; i < 8; i++) d2[i] = table->d2[i];

  *r = acc[0];
  for (u32 c = 1; c < ONION_COMB_CHAINS; c++) {
    ge_add(r, r, &acc[c], d2);
  }
}

/* compress r to the 32-byte Ed25519 public key encoding */
ONION_HD static void ge_compress_inv(const ge *p, const fe zinv, u8 out[32]) {
  fe x, y;
  fe_mul(x, p->X, zinv);
  fe_mul(y, p->Y, zinv);

  for (u32 i = 0; i < 32; i++) {
    out[i] = (u8)(y[i >> 2] >> (8 * (i & 3)));
  }
  out[31] = (u8)(out[31] | ((x[0] & 1) << 7));
}

ONION_HD static void ge_compress(const ge *p, u8 out[32]) {
  fe zinv;
  fe_invert(zinv, p->Z);
  ge_compress_inv(p, zinv, out);
}

/* ------------------------------------------------------------------ */
/* warp-cooperative batch inversion (CUDA only)                        */
/* ------------------------------------------------------------------ */

#ifdef __CUDACC__

__device__ static inline void fe_shfl_sync(fe out, const fe in, int srcLane) {
  for (int i = 0; i < 8; i++) out[i] = __shfl_sync(0xffffffffu, in[i], srcLane);
}

__device__ static inline void fe_shfl_up_sync(fe out, const fe in, unsigned delta) {
  for (int i = 0; i < 8; i++) out[i] = __shfl_up_sync(0xffffffffu, in[i], delta);
}

__device__ static inline void fe_shfl_down_sync(fe out, const fe in, unsigned delta) {
  for (int i = 0; i < 8; i++) out[i] = __shfl_down_sync(0xffffffffu, in[i], delta);
}

/*
 * Batch inversion across the 32 lanes of a warp (Montgomery's trick).
 *
 * The 254-squaring inversion chain runs once per warp on a broadcast value,
 * so 32 candidates pay for a single inversion instead of 32. All 32 lanes must
 * reach this call (no divergence around it). A zero z would only occur if a
 * candidate scalar were a multiple of the group order (~2^-252), and such a
 * result is discarded by the host-side verification anyway.
 */
__device__ static void fe_invert_warp(fe out, const fe z) {
  const unsigned lane = threadIdx.x & 31u;

  /* inclusive prefix products: P_i = z_0 * ... * z_i */
  fe P;
  for (int i = 0; i < 8; i++) P[i] = z[i];
  for (unsigned off = 1; off < 32; off <<= 1) {
    fe q;
    fe_shfl_up_sync(q, P, off);
    if (lane >= off) fe_mul(P, P, q);
  }

  /* inclusive suffix products: S_i = z_i * ... * z_31 */
  fe S;
  for (int i = 0; i < 8; i++) S[i] = z[i];
  for (unsigned off = 1; off < 32; off <<= 1) {
    fe q;
    fe_shfl_down_sync(q, S, off);
    if (lane + off < 32) fe_mul(S, S, q);
  }

  /* one inversion for the whole warp on the total product */
  fe total, u;
  fe_shfl_sync(total, P, 31);
  fe_invert(u, total);

  /* exclusive prefix E_i = prod_{j<i} z_j, exclusive suffix N_i = prod_{j>i} z_j */
  fe E, N;
  fe_shfl_up_sync(E, P, 1);
  if (lane == 0) fe_one(E);
  fe_shfl_down_sync(N, S, 1);
  if (lane == 31) fe_one(N);

  /* out_i = u * E_i * N_i = 1 / z_i */
  fe_mul(out, u, E);
  fe_mul(out, out, N);
}

#endif /* __CUDACC__ */

/* ------------------------------------------------------------------ */
/* address derivation and pattern matching                             */
/* ------------------------------------------------------------------ */

/* A = clamp(SHA-512(seed)) * B, left in projective coordinates */
ONION_HD static void onion_point_from_seed(const onion_tables *T,
                                           const comb_table *table,
                                           const u8 seed[32], ge *r) {
  u8 h[64];
  onion_sha512(T, seed, 32, h);

  /* clamp */
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;

  comb_mult(r, h, table);
}

/* out[32..35] = SHA3-256(".onion checksum" | pub | 0x03)[:2] | 0x03 */
ONION_HD static void onion_append_checksum(const onion_tables *T, const u8 pub[32],
                                           u8 out[35]) {
  u8 input[48];
  const u8 prefix[15] = {'.', 'o', 'n', 'i', 'o', 'n', ' ', 'c',
                         'h', 'e', 'c', 'k', 's', 'u', 'm'};
  onion_memcpy(input, prefix, 15);
  onion_memcpy(input + 15, pub, 32);
  input[47] = 0x03;

  u8 digest[32];
  onion_sha3_256(T, input, 48, digest);
  out[32] = digest[0];
  out[33] = digest[1];
  out[34] = 0x03;
}

/* 35 address bytes = PUBKEY(32) | SHA3-256 checksum(2) | 0x03 */
ONION_HD static void onion_address_from_seed(const onion_tables *T,
                                             const comb_table *table,
                                             const u8 seed[32], u8 out[35]) {
  ge r;
  onion_point_from_seed(T, table, seed, &r);
  ge_compress(&r, out);
  onion_append_checksum(T, out, out);
}

/* pattern compiled like the Node side: masks over the 35 address bytes */
#define ONION_PATTERN_MAXCMP 35

typedef struct {
  u32 ncmp;
  u8 cbyte[ONION_PATTERN_MAXCMP];
  u8 cmask[ONION_PATTERN_MAXCMP];
  u8 cval[ONION_PATTERN_MAXCMP];
  u32 mode;        /* 1 = prefix, 2 = suffix */
  u32 nchars;
  u8 vals[56];
  u32 needs_tail;  /* 1 when the pattern touches the checksum/version bytes */
} onion_pattern;

/* branch-free: no early exit, so a warp never diverges inside the loop */
ONION_HD static int onion_pattern_match(const onion_pattern *p, const u8 addr[35]) {
  u32 ok = 1;
  for (u32 i = 0; i < p->ncmp; i++) {
    ok &= (u32)((addr[p->cbyte[i]] & p->cmask[i]) == p->cval[i]);
  }
  return (int)ok;
}

/* value of the 5-bit base32 group starting at bit (MSB-first) */
ONION_HD static u32 onion_value_at(const u8 *bytes, u32 bit) {
  const u32 byte = bit >> 3;
  const u32 pair = ((u32)bytes[byte] << 8) | (u32)bytes[byte + 1];
  return (pair >> (11 - (bit & 7))) & 31;
}

/* matching characters from the pattern side; needs a 36-byte buffer with a
 * zero spare byte at index 35. Branch-free with a warp-uniform trip count. */
ONION_HD static u32 onion_pattern_score(const onion_pattern *p, const u8 *addr36) {
  u32 best = 0;
  u32 alive = 1;
  for (u32 i = 0; i < p->nchars; i++) {
    const u32 bit = (p->mode == 1) ? i * 5 : 280 - 5 * (i + 1);
    const u32 want = (p->mode == 1) ? p->vals[i] : p->vals[p->nchars - 1 - i];
    const u32 ok = (u32)(onion_value_at(addr36, bit) == want) & alive;
    best += ok;
    alive &= ok;
  }
  return best;
}

/* RFC 4648 base32, lowercase, no padding */
ONION_HD static void onion_base32_56(const u8 bytes[35], char out[57]) {
  const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
  u32 bit = 0;
  for (u32 c = 0; c < 56; c++) {
    u32 v = 0;
    for (u32 k = 0; k < 5; k++) {
      const u32 idx = bit + k;
      const u32 byte = idx >> 3;
      const u32 b = byte < 35 ? ((u32)bytes[byte] >> (7 - (idx & 7))) & 1 : 0;
      v = (v << 1) | b;
    }
    out[c] = alphabet[v];
    bit += 5;
  }
  out[56] = 0;
}

/* splitmix64 */
ONION_HD static inline u64 splitmix64_next(u64 *state) {
  *state += 0x9E3779B97F4A7C15ull;
  u64 z = *state;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}

ONION_HD static void splitmix64_fill(u64 *state, u8 seed[32]) {
  for (u32 i = 0; i < 4; i++) {
    const u64 v = splitmix64_next(state);
    for (u32 j = 0; j < 8; j++) seed[8 * i + j] = (u8)(v >> (8 * j));
  }
}

#endif /* ONIONADDRESS_CORE_H */
