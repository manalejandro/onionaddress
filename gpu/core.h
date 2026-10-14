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
/* ------------------------------------------------------------------ */

typedef u32 fe[8];

ONION_HD static void fe_zero(fe h) {
  for (u32 i = 0; i < 8; i++) h[i] = 0;
}

ONION_HD static void fe_one(fe h) {
  fe_zero(h);
  h[0] = 1;
}

/* p = 2^255 - 19 */
ONION_HD static void fe_p(fe h) {
  h[0] = 0xffffffed; h[1] = 0xffffffff; h[2] = 0xffffffff; h[3] = 0xffffffff;
  h[4] = 0xffffffff; h[5] = 0xffffffff; h[6] = 0xffffffff; h[7] = 0x7fffffff;
}

ONION_HD static int fe_is_zero(const fe a) {
  u32 acc = 0;
  for (u32 i = 0; i < 8; i++) acc |= a[i];
  return acc == 0;
}

/* -1, 0 or 1 comparing as integers */
ONION_HD static int fe_cmp(const fe a, const fe b) {
  for (int i = 7; i >= 0; i--) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

/* h = a - b assuming a >= b */
ONION_HD static void fe_sub_raw(fe h, const fe a, const fe b) {
  u64 borrow = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 t = (u64)a[i] - (u64)b[i] - borrow;
    h[i] = (u32)t;
    borrow = (t >> 32) & 1;
  }
}

/* fold an overflow carry of 2^256 into the limbs: 2^256 = 38 (mod p) */
ONION_HD static void fe_fold_carry(fe h, u64 carry) {
  while (carry != 0) {
    u64 v = (u64)h[0] + carry * 38;
    h[0] = (u32)v;
    carry = v >> 32;
    for (u32 i = 1; i < 8 && carry != 0; i++) {
      u64 w = (u64)h[i] + carry;
      h[i] = (u32)w;
      carry = w >> 32;
    }
  }
}

/* reduce to [0, p) */
ONION_HD static void fe_reduce(fe h) {
  fe p;
  fe_p(p);
  while (fe_cmp(h, p) >= 0) fe_sub_raw(h, h, p);
}

/* h = a + b (mod p), a, b < p */
ONION_HD static void fe_add(fe h, const fe a, const fe b) {
  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 t = (u64)a[i] + (u64)b[i] + carry;
    h[i] = (u32)t;
    carry = t >> 32;
  }
  fe_reduce(h);
}

/* h = -a (mod p) */
ONION_HD static void fe_neg(fe h, const fe a) {
  if (fe_is_zero(a)) {
    fe_zero(h);
    return;
  }
  fe p;
  fe_p(p);
  fe_sub_raw(h, p, a);
}

/* h = a - b (mod p), a, b < p */
ONION_HD static void fe_sub(fe h, const fe a, const fe b) {
  fe nb;
  fe_neg(nb, b);
  fe_add(h, a, nb);
}

ONION_HD static void fe_mul_wide(const fe a, const fe b, u32 t[16]) {
  for (u32 i = 0; i < 16; i++) t[i] = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 carry = 0;
    for (u32 j = 0; j < 8; j++) {
      u64 sum = (u64)t[i + j] + (u64)a[i] * (u64)b[j] + carry;
      t[i + j] = (u32)sum;
      carry = sum >> 32;
    }
    u32 k = i + 8;
    while (carry != 0 && k < 16) {
      u64 sum = (u64)t[k] + carry;
      t[k] = (u32)sum;
      carry = sum >> 32;
      k++;
    }
  }
}

/* h = a * b (mod p) */
ONION_HD static void fe_mul(fe h, const fe a, const fe b) {
  u32 t[16];
  fe_mul_wide(a, b, t);

  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 v = (u64)t[i] + (u64)t[i + 8] * 38 + carry;
    h[i] = (u32)v;
    carry = v >> 32;
  }
  fe_fold_carry(h, carry);
  fe_reduce(h);
}

/* h = a * small (mod p), small < 2^32 */
ONION_HD static void fe_mul_small(fe h, const fe a, u32 small) {
  u64 carry = 0;
  for (u32 i = 0; i < 8; i++) {
    u64 v = (u64)a[i] * small + carry;
    h[i] = (u32)v;
    carry = v >> 32;
  }
  fe_fold_carry(h, carry);
  fe_reduce(h);
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

typedef struct {
  fe X, Y;  /* affine coordinates (Z = 1) */
  fe T;     /* X * Y */
  fe T2;    /* 2*d*X*Y, precomputed for madd */
} ge_aff;

#define COMB_WINDOWS 64
#define COMB_ENTRIES 16

typedef struct {
  ge_aff e[COMB_WINDOWS * COMB_ENTRIES];
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

/* madd: q is affine with precomputed q->T2 = 2*d*q->X*q->Y */
ONION_HD static void ge_madd(ge *r, const ge *p, const ge_aff *q) {
  fe a, b, c, d, e, f, g, h, t;

  fe_sub(a, p->Y, p->X);
  fe_sub(t, q->Y, q->X);
  fe_mul(a, a, t);

  fe_add(b, p->Y, p->X);
  fe_add(t, q->Y, q->X);
  fe_mul(b, b, t);

  fe_mul(c, p->T, q->T2);

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
 * Fill one comb window: entry [w][n] = n * 16^w * B as affine coordinates
 * plus T2 = 2d*X*Y. Entry [w][0] is the neutral element (0, 1).
 */
ONION_HD static void onion_comb_init_window(comb_table *table, u32 w,
                                            const fe d2, const ge *B) {
  ge_aff *base = &table->e[w * COMB_ENTRIES];

  fe_zero(base->X);
  fe_one(base->Y);
  fe_zero(base->T);
  fe_zero(base->T2);

  /* G_w = 16^w * B (four doublings per window) */
  ge G;
  for (u32 i = 0; i < 8; i++) {
    G.X[i] = B->X[i];
    G.Y[i] = B->Y[i];
    G.Z[i] = B->Z[i];
    G.T[i] = B->T[i];
  }
  for (u32 i = 0; i < w; i++) {
    ge_add(&G, &G, &G, d2);
    ge_add(&G, &G, &G, d2);
    ge_add(&G, &G, &G, d2);
    ge_add(&G, &G, &G, d2);
  }

  /* P_n = n * G_w for n = 1..15 */
  ge P = G;
  for (u32 n = 1; n < COMB_ENTRIES; n++) {
    ge_aff *entry = &base[n];
    fe zin;
    fe_invert(zin, P.Z);
    fe_mul(entry->X, P.X, zin);
    fe_mul(entry->Y, P.Y, zin);
    fe_mul(entry->T, entry->X, entry->Y);
    fe_mul(entry->T2, entry->T, d2);
    if (n + 1 < COMB_ENTRIES) ge_add(&P, &P, &G, d2);
  }
}

ONION_HD static int onion_comb_init(comb_table *table) {
  fe d2;
  ge B;
  if (onion_curve_init(d2, &B) != 0) return -1;
  for (u32 w = 0; w < COMB_WINDOWS; w++) onion_comb_init_window(table, w, d2, &B);
  return 0;
}

/* r = scalar * B using the comb table; scalar is 32 little-endian bytes */
ONION_HD static void comb_mult(ge *r, const u8 scalar[32], const comb_table *table) {
  const ge_aff *first = &table->e[scalar[0] & 15];
  for (u32 i = 0; i < 8; i++) {
    r->X[i] = first->X[i];
    r->Y[i] = first->Y[i];
    r->T[i] = first->T[i];
  }
  fe_one(r->Z);

  for (u32 w = 1; w < COMB_WINDOWS; w++) {
    const u32 nibble = (scalar[w >> 1] >> (4 * (w & 1))) & 15;
    ge_madd(r, r, &table->e[w * COMB_ENTRIES + nibble]);
  }
}

/* compress r to the 32-byte Ed25519 public key encoding */
ONION_HD static void ge_compress(const ge *p, u8 out[32]) {
  fe zin, x, y;
  fe_invert(zin, p->Z);
  fe_mul(x, p->X, zin);
  fe_mul(y, p->Y, zin);

  for (u32 i = 0; i < 32; i++) {
    out[i] = (u8)(y[i >> 2] >> (8 * (i & 3)));
  }
  out[31] = (u8)(out[31] | ((x[0] & 1) << 7));
}

/* ------------------------------------------------------------------ */
/* address derivation and pattern matching                             */
/* ------------------------------------------------------------------ */

/* 35 address bytes = PUBKEY(32) | SHA3-256 checksum(2) | 0x03 */
ONION_HD static void onion_address_from_seed(const onion_tables *T,
                                             const comb_table *table,
                                             const u8 seed[32], u8 out[35]) {
  u8 h[64];
  onion_sha512(T, seed, 32, h);

  /* clamp */
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;

  ge r;
  comb_mult(&r, h, table);
  ge_compress(&r, out);

  u8 input[48];
  const u8 prefix[15] = {'.', 'o', 'n', 'i', 'o', 'n', ' ', 'c',
                         'h', 'e', 'c', 'k', 's', 'u', 'm'};
  onion_memcpy(input, prefix, 15);
  onion_memcpy(input + 15, out, 32);
  input[47] = 0x03;

  u8 digest[32];
  onion_sha3_256(T, input, 48, digest);
  out[32] = digest[0];
  out[33] = digest[1];
  out[34] = 0x03;
}

/* pattern compiled like the Node side: masks over the 35 address bytes */
#define ONION_PATTERN_MAXCMP 35

typedef struct {
  u32 ncmp;
  u8 cbyte[ONION_PATTERN_MAXCMP];
  u8 cmask[ONION_PATTERN_MAXCMP];
  u8 cval[ONION_PATTERN_MAXCMP];
  u32 mode;      /* 1 = prefix, 2 = suffix */
  u32 nchars;
  u8 vals[56];
} onion_pattern;

ONION_HD static int onion_pattern_match(const onion_pattern *p, const u8 addr[35]) {
  for (u32 i = 0; i < p->ncmp; i++) {
    if ((addr[p->cbyte[i]] & p->cmask[i]) != p->cval[i]) return 0;
  }
  return 1;
}

/* value of the 5-bit base32 group starting at bit (MSB-first) */
ONION_HD static u32 onion_value_at(const u8 *bytes, u32 bit) {
  const u32 byte = bit >> 3;
  const u32 pair = ((u32)bytes[byte] << 8) | (u32)bytes[byte + 1];
  return (pair >> (11 - (bit & 7))) & 31;
}

/* matching characters from the pattern side; needs a 36-byte buffer with a
 * zero spare byte at index 35 */
ONION_HD static u32 onion_pattern_score(const onion_pattern *p, const u8 *addr36) {
  u32 best = 0;
  if (p->mode == 1) {
    while (best < p->nchars && onion_value_at(addr36, best * 5) == p->vals[best]) {
      best++;
    }
  } else {
    while (best < p->nchars &&
           onion_value_at(addr36, 280 - 5 * (best + 1)) ==
               p->vals[p->nchars - 1 - best]) {
      best++;
    }
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
