// Gram (Telegram Money) wallet vanity search kernel.
//
// Per candidate: random 128-bit entropy -> BIP39 12 words -> PBKDF2-HMAC-SHA512 (2048) seed
// -> SLIP-10 ed25519 m/44'/607'/0' -> public key -> WalletTg trampoline StateInit hash
// -> non-bounceable base64url address -> case-insensitive suffix check.
//
// The same file compiles as Metal (macOS), OpenCL C (Windows/Linux GPUs) and plain C++ (tests).
// Every GPU hit is re-derived on the CPU by gram-verify.mjs before anything is printed.

#ifdef __METAL_VERSION__
#include <metal_stdlib>
using namespace metal;
typedef ulong u64; typedef uint u32; typedef uchar u8; typedef long i64; typedef int i32;
#define T thread
#define W device
#define GC constant
#elif defined(__OPENCL_VERSION__)
typedef ulong u64; typedef uint u32; typedef uchar u8; typedef long i64; typedef int i32;
#define T
#define W __global
#define GC __constant
#define inline
#else
#include <stdint.h>
typedef uint64_t u64; typedef uint32_t u32; typedef uint8_t u8; typedef int64_t i64; typedef int32_t i32;
#define T
#define W
#define GC static const
#endif

GC u64 K512[80] = {0x428a2f98d728ae22UL,0x7137449123ef65cdUL,0xb5c0fbcfec4d3b2fUL,0xe9b5dba58189dbbcUL,0x3956c25bf348b538UL,0x59f111f1b605d019UL,0x923f82a4af194f9bUL,0xab1c5ed5da6d8118UL,0xd807aa98a3030242UL,0x12835b0145706fbeUL,0x243185be4ee4b28cUL,0x550c7dc3d5ffb4e2UL,0x72be5d74f27b896fUL,0x80deb1fe3b1696b1UL,0x9bdc06a725c71235UL,0xc19bf174cf692694UL,0xe49b69c19ef14ad2UL,0xefbe4786384f25e3UL,0x0fc19dc68b8cd5b5UL,0x240ca1cc77ac9c65UL,0x2de92c6f592b0275UL,0x4a7484aa6ea6e483UL,0x5cb0a9dcbd41fbd4UL,0x76f988da831153b5UL,0x983e5152ee66dfabUL,0xa831c66d2db43210UL,0xb00327c898fb213fUL,0xbf597fc7beef0ee4UL,0xc6e00bf33da88fc2UL,0xd5a79147930aa725UL,0x06ca6351e003826fUL,0x142929670a0e6e70UL,0x27b70a8546d22ffcUL,0x2e1b21385c26c926UL,0x4d2c6dfc5ac42aedUL,0x53380d139d95b3dfUL,0x650a73548baf63deUL,0x766a0abb3c77b2a8UL,0x81c2c92e47edaee6UL,0x92722c851482353bUL,0xa2bfe8a14cf10364UL,0xa81a664bbc423001UL,0xc24b8b70d0f89791UL,0xc76c51a30654be30UL,0xd192e819d6ef5218UL,0xd69906245565a910UL,0xf40e35855771202aUL,0x106aa07032bbd1b8UL,0x19a4c116b8d2d0c8UL,0x1e376c085141ab53UL,0x2748774cdf8eeb99UL,0x34b0bcb5e19b48a8UL,0x391c0cb3c5c95a63UL,0x4ed8aa4ae3418acbUL,0x5b9cca4f7763e373UL,0x682e6ff3d6b2b8a3UL,0x748f82ee5defb2fcUL,0x78a5636f43172f60UL,0x84c87814a1f0ab72UL,0x8cc702081a6439ecUL,0x90befffa23631e28UL,0xa4506cebde82bde9UL,0xbef9a3f7b2c67915UL,0xc67178f2e372532bUL,0xca273eceea26619cUL,0xd186b8c721c0c207UL,0xeada7dd6cde0eb1eUL,0xf57d4f7fee6ed178UL,0x06f067aa72176fbaUL,0x0a637dc5a2c898a6UL,0x113f9804bef90daeUL,0x1b710b35131c471bUL,0x28db77f523047d84UL,0x32caab7b40c72493UL,0x3c9ebe0a15c9bebcUL,0x431d67c49c100d4cUL,0x4cc5d4becb3e42b6UL,0x597f299cfc657e2aUL,0x5fcb6fab3ad6faecUL,0x6c44198c4a475817UL};
GC u64 IV512[8] = {0x6a09e667f3bcc908UL,0xbb67ae8584caa73bUL,0x3c6ef372fe94f82bUL,0xa54ff53a5f1d36f1UL,0x510e527fade682d1UL,0x9b05688c2b3e6c1fUL,0x1f83d9abfb41bd6bUL,0x5be0cd19137e2179UL};
GC u32 K256[64] = {0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
GC u32 IV256[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};

// sha256 of the WalletTg trampoline code cell (contracts/WalletTrampoline.boc)
GC u8 CODE_HASH[32] = {
  0x91,0x49,0xae,0x51,0xc1,0xe4,0x68,0x97,0x10,0xce,0xbf,0x78,0x30,0x29,0x7b,0x16,
  0xac,0xfb,0xad,0xb3,0x63,0xa9,0x20,0xa5,0x37,0x89,0x3e,0x7f,0xfe,0xec,0xa7,0x68};

// ---------------------------------------------------------------- SHA-512

inline u64 ror64(u64 x, u32 n) { return (x >> n) | (x << (64 - n)); }

void sha512_compress(T u64 *st, T const u64 *blk) {
  u64 w[16];
  for (int i = 0; i < 16; i++) w[i] = blk[i];
  u64 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
  for (int i = 0; i < 80; i++) {
    u64 wi;
    if (i < 16) {
      wi = w[i];
    } else {
      u64 w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
      u64 s0 = ror64(w15, 1) ^ ror64(w15, 8) ^ (w15 >> 7);
      u64 s1 = ror64(w2, 19) ^ ror64(w2, 61) ^ (w2 >> 6);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
    }
    u64 t1 = h + (ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41)) + ((e & f) ^ (~e & g)) + K512[i] + wi;
    u64 t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

void sha512_init(T u64 *st) { for (int i = 0; i < 8; i++) st[i] = IV512[i]; }

// Final block: `len` (<= 111) message bytes after `prefix` bytes already compressed.
void sha512_tail(T u64 *st, T const u8 *msg, u32 len, u32 prefix) {
  u64 blk[16];
  for (int i = 0; i < 16; i++) blk[i] = 0;
  for (u32 i = 0; i < len; i++) blk[i >> 3] |= (u64)msg[i] << (56 - 8 * (i & 7));
  blk[len >> 3] |= (u64)0x80 << (56 - 8 * (len & 7));
  blk[15] = (u64)(prefix + len) * 8;
  sha512_compress(st, blk);
}

void words_to_bytes64(T const u64 *st, T u8 *out, int n) {
  for (int i = 0; i < n; i++) out[i] = (u8)(st[i >> 3] >> (56 - 8 * (i & 7)));
}

// HMAC-SHA512 pads: key (<= 128 bytes) xor ipad/opad, one compression each.
void hmac512_init(T const u8 *key, u32 klen, T u64 *ist, T u64 *ost) {
  u64 bi[16], bo[16];
  for (int i = 0; i < 16; i++) { bi[i] = 0; bo[i] = 0; }
  for (u32 i = 0; i < 128; i++) {
    u8 k = i < klen ? key[i] : 0;
    bi[i >> 3] |= (u64)(u8)(k ^ 0x36) << (56 - 8 * (i & 7));
    bo[i >> 3] |= (u64)(u8)(k ^ 0x5c) << (56 - 8 * (i & 7));
  }
  sha512_init(ist); sha512_compress(ist, bi);
  sha512_init(ost); sha512_compress(ost, bo);
}

// out = HMAC-SHA512(key, msg) as 64 bytes; msg <= 111 bytes.
void hmac512(T const u8 *key, u32 klen, T const u8 *msg, u32 mlen, T u8 *out) {
  u64 ist[8], ost[8];
  hmac512_init(key, klen, ist, ost);
  sha512_tail(ist, msg, mlen, 128);
  u8 inner[64];
  words_to_bytes64(ist, inner, 64);
  sha512_tail(ost, inner, 64, 128);
  words_to_bytes64(ost, out, 64);
}

// BIP39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64).
void bip39_seed(T const u8 *mn, u32 mnlen, T u8 *seed) {
  u64 ist[8], ost[8];
  hmac512_init(mn, mnlen, ist, ost);
  u8 salt[12] = {'m','n','e','m','o','n','i','c',0,0,0,1};
  u64 s[8], u[8], acc[8], blk[16];
  for (int i = 0; i < 8; i++) s[i] = ist[i];
  sha512_tail(s, salt, 12, 128);
  for (int i = 0; i < 8; i++) { blk[i] = s[i]; u[i] = ost[i]; }
  blk[8] = (u64)0x80 << 56;
  for (int i = 9; i < 15; i++) blk[i] = 0;
  blk[15] = (128 + 64) * 8;
  sha512_compress(u, blk);
  for (int i = 0; i < 8; i++) acc[i] = u[i];
  for (int it = 1; it < 2048; it++) {
    for (int i = 0; i < 8; i++) { blk[i] = u[i]; s[i] = ist[i]; }
    sha512_compress(s, blk);
    for (int i = 0; i < 8; i++) { blk[i] = s[i]; u[i] = ost[i]; }
    sha512_compress(u, blk);
    for (int i = 0; i < 8; i++) acc[i] ^= u[i];
  }
  words_to_bytes64(acc, seed, 64);
}

// SLIP-10 ed25519, path m/44'/607'/0' -> 32-byte private seed.
void slip10_ton(T const u8 *seed, T u8 *priv) {
  u8 key[12] = {'e','d','2','5','5','1','9',' ','s','e','e','d'};
  u8 I[64], msg[37], chain[32];
  hmac512(key, 12, seed, 64, I);
  u32 path[3] = {44u, 607u, 0u};
  for (int d = 0; d < 3; d++) {
    for (int i = 0; i < 32; i++) chain[i] = I[32 + i];
    msg[0] = 0;
    for (int i = 0; i < 32; i++) msg[1 + i] = I[i];
    u32 idx = path[d] | 0x80000000u;
    msg[33] = (u8)(idx >> 24); msg[34] = (u8)(idx >> 16); msg[35] = (u8)(idx >> 8); msg[36] = (u8)idx;
    hmac512(chain, 32, msg, 37, I);
  }
  for (int i = 0; i < 32; i++) priv[i] = I[i];
}

// ---------------------------------------------------------------- SHA-256

inline u32 ror32(u32 x, u32 n) { return (x >> n) | (x << (32 - n)); }

void sha256_compress(T u32 *st, T const u32 *blk) {
  u32 w[16];
  for (int i = 0; i < 16; i++) w[i] = blk[i];
  u32 a = st[0], b = st[1], c = st[2], d = st[3], e = st[4], f = st[5], g = st[6], h = st[7];
  for (int i = 0; i < 64; i++) {
    u32 wi;
    if (i < 16) {
      wi = w[i];
    } else {
      u32 w15 = w[(i - 15) & 15], w2 = w[(i - 2) & 15];
      u32 s0 = ror32(w15, 7) ^ ror32(w15, 18) ^ (w15 >> 3);
      u32 s1 = ror32(w2, 17) ^ ror32(w2, 19) ^ (w2 >> 10);
      wi = w[i & 15] = w[i & 15] + s0 + w[(i - 7) & 15] + s1;
    }
    u32 t1 = h + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + wi;
    u32 t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
    h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e; st[5] += f; st[6] += g; st[7] += h;
}

// sha256 of a short message (len <= 119, at most two blocks).
void sha256_short(T const u8 *msg, u32 len, T u8 *out) {
  u32 st[8], blk[16];
  for (int i = 0; i < 8; i++) st[i] = IV256[i];
  u32 nblocks = len + 9 <= 64 ? 1 : 2;
  for (u32 b = 0; b < nblocks; b++) {
    for (int i = 0; i < 16; i++) blk[i] = 0;
    for (u32 i = 0; i < 64; i++) {
      u32 pos = b * 64 + i;
      u8 v = pos < len ? msg[pos] : (pos == len ? 0x80 : 0);
      blk[i >> 2] |= (u32)v << (24 - 8 * (i & 3));
    }
    if (b == nblocks - 1) blk[15] = len * 8;
    sha256_compress(st, blk);
  }
  for (int i = 0; i < 32; i++) out[i] = (u8)(st[i >> 2] >> (24 - 8 * (i & 3)));
}

// ---------------------------------------------------------------- ed25519 (ref10-style arithmetic)
// Field elements: 10 signed limbs in radix 2^25.5 (26, 25, 26, 25, ... bits), so every product is 32x32->64.
// The public key is a fixed-base multiplication: 32 table lookups (one per scalar byte), no doublings.
// Table (built by the host): entry [i][d] = d * 256^i * B as (y+x, y-x, 2dxy), 30 limbs each.

void fe_add(T i32 *o, T const i32 *a, T const i32 *b) { for (int i = 0; i < 10; i++) o[i] = a[i] + b[i]; }
void fe_sub(T i32 *o, T const i32 *a, T const i32 *b) { for (int i = 0; i < 10; i++) o[i] = a[i] - b[i]; }

void fe_mul(T i32 *o, T const i32 *f, T const i32 *g) {
  i32 f2[10], g19[10];
  for (int i = 0; i < 10; i++) { f2[i] = f[i] * (1 + (i & 1)); g19[i] = 19 * g[i]; }
  i64 t[10];
  for (int i = 0; i < 10; i++) t[i] = 0;
  for (int i = 0; i < 10; i++)
    for (int j = 0; j < 10; j++) {
      i32 a = (j & 1) ? f2[i] : f[i];            // odd*odd limbs carry an extra factor 2
      if (i + j < 10) t[i + j] += (i64)a * g[j];
      else t[i + j - 10] += (i64)a * g19[j];     // 2^255 = 19
    }
  for (int i = 0; i < 10; i++) {
    int bits = 26 - (i & 1);
    i64 c = (t[i] + ((i64)1 << (bits - 1))) >> bits;
    t[i] -= c * ((i64)1 << bits);
    if (i < 9) t[i + 1] += c; else t[0] += 19 * c;
  }
  i64 c = (t[0] + ((i64)1 << 25)) >> 26;
  t[0] -= c * ((i64)1 << 26); t[1] += c;
  for (int i = 0; i < 10; i++) o[i] = (i32)t[i];
}

// o = in^(2^n)
void fe_pow2k(T i32 *o, T const i32 *in, int n) {
  fe_mul(o, in, in);
  for (int i = 1; i < n; i++) fe_mul(o, o, o);
}

// o = z^(p-2) = z^(2^255 - 21)
void fe_inv(T i32 *o, T const i32 *z) {
  i32 t0[10], t1[10], t2[10], t3[10];
  fe_pow2k(t0, z, 1);                                // 2
  fe_pow2k(t1, t0, 2);                               // 8
  fe_mul(t1, z, t1);                                 // 9
  fe_mul(t0, t0, t1);                                // 11
  fe_pow2k(t2, t0, 1);                               // 22
  fe_mul(t1, t1, t2);                                // 2^5 - 1
  fe_pow2k(t2, t1, 5);   fe_mul(t1, t2, t1);         // 2^10 - 1
  fe_pow2k(t2, t1, 10);  fe_mul(t2, t2, t1);         // 2^20 - 1
  fe_pow2k(t3, t2, 20);  fe_mul(t2, t3, t2);         // 2^40 - 1
  fe_pow2k(t2, t2, 10);  fe_mul(t1, t2, t1);         // 2^50 - 1
  fe_pow2k(t2, t1, 50);  fe_mul(t2, t2, t1);         // 2^100 - 1
  fe_pow2k(t3, t2, 100); fe_mul(t2, t3, t2);         // 2^200 - 1
  fe_pow2k(t2, t2, 50);  fe_mul(t1, t2, t1);         // 2^250 - 1
  fe_pow2k(t1, t1, 5);   fe_mul(o, t1, t0);          // 2^255 - 21
}

// Canonical 32-byte little-endian encoding.
void fe_tobytes(T u8 *s, T const i32 *f) {
  i32 h[10];
  for (int i = 0; i < 10; i++) h[i] = f[i];
  i32 q = (19 * h[9] + (1 << 24)) >> 25;
  for (int i = 0; i < 10; i++) q = (h[i] + q) >> (26 - (i & 1));
  h[0] += 19 * q;
  for (int i = 0; i < 10; i++) {
    int bits = 26 - (i & 1);
    i32 c = h[i] >> bits;
    h[i] -= c * (1 << bits);
    if (i < 9) h[i + 1] += c;
  }
  u64 acc = 0;
  int nb = 0, k = 0;
  for (int i = 0; i < 10; i++) {
    acc |= (u64)(u32)h[i] << nb;
    nb += 26 - (i & 1);
    while (nb >= 8) { s[k++] = (u8)acc; acc >>= 8; nb -= 8; }
  }
  s[31] = (u8)acc;
}

// Public key for a 32-byte ed25519 private seed (not constant-time: runs on our own machine).
void ed25519_pubkey(W const i32 *edtab, T const u8 *priv, T u8 *pub) {
  u64 st[8];
  sha512_init(st);
  sha512_tail(st, priv, 32, 0);
  u8 h[64];
  words_to_bytes64(st, h, 64);
  h[0] &= 248; h[31] &= 127; h[31] |= 64;

  i32 px[10], py[10], pz[10], pt[10];           // extended coordinates, starts as neutral (0, 1, 1, 0)
  for (int i = 0; i < 10; i++) { px[i] = 0; py[i] = 0; pz[i] = 0; pt[i] = 0; }
  py[0] = 1; pz[0] = 1;
  for (int i = 0; i < 32; i++) {
    W const i32 *src = edtab + (i * 256 + h[i]) * 30;
    i32 q[30], a[10], b[10], c[10], d[10], e[10], f[10], g[10], hh[10];
    for (int k = 0; k < 30; k++) q[k] = src[k];
    fe_add(a, py, px); fe_mul(a, a, q);
    fe_sub(b, py, px); fe_mul(b, b, q + 10);
    fe_mul(c, pt, q + 20);
    fe_add(d, pz, pz);
    fe_sub(e, a, b); fe_sub(f, d, c); fe_add(g, d, c); fe_add(hh, a, b);
    fe_mul(px, e, f); fe_mul(py, hh, g); fe_mul(pz, g, f); fe_mul(pt, e, hh);
  }
  i32 zi[10], tx[10], ty[10];
  fe_inv(zi, pz);
  fe_mul(tx, px, zi);
  fe_mul(ty, py, zi);
  fe_tobytes(pub, ty);
  u8 xb[32];
  fe_tobytes(xb, tx);
  pub[31] ^= (u8)((xb[0] & 1) << 7);
}

// ---------------------------------------------------------------- BIP39 + address

// 12-word mnemonic for 16 bytes of entropy; returns its byte length.
u32 bip39_mnemonic(W const u8 *words, W const u8 *wlens, T const u8 *entropy, T u8 *mn) {
  u8 h[32];
  sha256_short(entropy, 16, h);
  u32 len = 0;
  for (int w = 0; w < 12; w++) {
    u32 idx = 0;
    for (int b = 0; b < 11; b++) {
      u32 pos = w * 11 + b;
      u32 bit = pos < 128 ? (entropy[pos >> 3] >> (7 - (pos & 7))) & 1 : (h[0] >> (7 - (pos - 128))) & 1;
      idx = (idx << 1) | bit;
    }
    if (w) mn[len++] = ' ';
    for (u32 i = 0; i < wlens[idx]; i++) mn[len++] = words[idx * 8 + i];
  }
  return len;
}

// Raw 36-byte user-friendly address: 0x51 (non-bounceable) | wc 0 | hash | crc16.
void gram_address(T const u8 *pub, T u8 *addr) {
  u8 data[43], init[71], dh[32];
  data[0] = 0x00; data[1] = 0x52;                // refs 0; 41 data bytes
  data[2] = 0x00;                                // Storage prefix 0x00 (revision 0)
  data[3] = 0; data[4] = 0; data[5] = 0; data[6] = 0;              // seqno 0
  data[7] = 0x7f; data[8] = 0xff; data[9] = 0x7f; data[10] = 0x11; // mainnet subwallet id
  for (int i = 0; i < 32; i++) data[11 + i] = pub[i];
  sha256_short(data, 43, dh);
  init[0] = 0x02; init[1] = 0x01; init[2] = 0x34; // 2 refs; 5 bits 00110 (code, data, no lib)
  init[3] = 0; init[4] = 0; init[5] = 0; init[6] = 0; // ref depths
  for (int i = 0; i < 32; i++) { init[7 + i] = CODE_HASH[i]; init[39 + i] = dh[i]; }
  addr[0] = 0x51; addr[1] = 0x00;
  sha256_short(init, 71, addr + 2);
  u32 crc = 0;
  for (int i = 0; i < 34; i++) {
    crc ^= (u32)addr[i] << 8;
    for (int b = 0; b < 8; b++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  addr[34] = (u8)(crc >> 8); addr[35] = (u8)crc;
}

inline u8 b64url(u32 v) {
  return v < 26 ? (u8)('A' + v) : v < 52 ? (u8)('a' + v - 26) : v < 62 ? (u8)('0' + v - 52) : (v == 62 ? '-' : '_');
}

// 48-char base64url of the 36-byte address.
void address_text(T const u8 *addr, T u8 *out) {
  for (int g = 0; g < 12; g++) {
    u32 v = ((u32)addr[3 * g] << 16) | ((u32)addr[3 * g + 1] << 8) | addr[3 * g + 2];
    for (int k = 0; k < 4; k++) out[4 * g + k] = b64url((v >> (18 - 6 * k)) & 63);
  }
}

// Full pipeline for one entropy; writes the address text (48 chars).
void derive_candidate(W const u8 *words, W const u8 *wlens, W const i32 *edtab, T const u8 *entropy, T u8 *pub, T u8 *text) {
  u8 mn[108], seed[64], priv[32], addr[36];
  u32 mnlen = bip39_mnemonic(words, wlens, entropy, mn);
  bip39_seed(mn, mnlen, seed);
  slip10_ton(seed, priv);
  ed25519_pubkey(edtab, priv, pub);
  gram_address(pub, addr);
  address_text(addr, text);
}

#ifdef __METAL_VERSION__

struct Params {
  uint base[4];      // random 128-bit entropy base (little-endian u32 limbs), fresh every batch
  uchar suffix[8];   // suffix (lowercase unless exact), right-aligned compare
  uint suffixLen;    // 0 = benchmark (never matches)
  uint exact;        // 1 = case-sensitive
};

kernel void search(device const uchar *words [[buffer(0)]],
                   device const uchar *wlens [[buffer(1)]],
                   constant Params &prm [[buffer(2)]],
                   device atomic_uint *found [[buffer(3)]],
                   device const int *edtab [[buffer(4)]],   // ed25519 fixed-base table, 32*256*30 limbs
                   uint gid [[thread_position_in_grid]]) {
  // entropy = base + gid (128-bit add), serialized big-endian like the host does
  uint limb[4];
  ulong carry = gid;
  for (int i = 0; i < 4; i++) { ulong s = (ulong)prm.base[i] + carry; limb[i] = (uint)s; carry = s >> 32; }
  uchar entropy[16];
  for (int i = 0; i < 4; i++)
    for (int k = 0; k < 4; k++) entropy[15 - (4 * i + k)] = (uchar)(limb[i] >> (8 * k));

  uchar pub[32], text[48];
  derive_candidate(words, wlens, edtab, entropy, pub, text);

  uint n = prm.suffixLen;
  if (n == 0) return;
  for (uint i = 0; i < n; i++) {
    uchar c = text[48 - n + i];
    if (!prm.exact && c >= 'A' && c <= 'Z') c += 32;
    if (c != prm.suffix[8 - n + i]) return;
  }
  if (atomic_fetch_add_explicit(&found[0], 1u, memory_order_relaxed) == 0)
    atomic_store_explicit(&found[1], gid, memory_order_relaxed);
}

#elif defined(__OPENCL_VERSION__)

// Same Params layout as the Metal kernel, passed as a 32-byte constant buffer.
typedef struct {
  uint base[4];
  uchar suffix[8];
  uint suffixLen;
  uint exact;
} Params;

__kernel void search(__global const uchar *words, __global const uchar *wlens,
                     __constant const Params *prm, __global volatile uint *found,
                     __global const int *edtab) {
  uint gid = (uint)get_global_id(0);
  uint limb[4];
  ulong carry = gid;
  for (int i = 0; i < 4; i++) { ulong s = (ulong)prm->base[i] + carry; limb[i] = (uint)s; carry = s >> 32; }
  uchar entropy[16];
  for (int i = 0; i < 4; i++)
    for (int k = 0; k < 4; k++) entropy[15 - (4 * i + k)] = (uchar)(limb[i] >> (8 * k));

  uchar pub[32], text[48];
  derive_candidate(words, wlens, edtab, entropy, pub, text);

  uint n = prm->suffixLen;
  if (n == 0) return;
  for (uint i = 0; i < n; i++) {
    uchar c = text[48 - n + i];
    if (!prm->exact && c >= 'A' && c <= 'Z') c += 32;
    if (c != prm->suffix[8 - n + i]) return;
  }
  if (atomic_inc(&found[0]) == 0) found[1] = gid;
}

#endif
