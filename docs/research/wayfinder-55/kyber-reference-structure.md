# Research: pq-crystals/kyber Reference Implementation Structure for ML-KEM-512

Ticket: [15.2 — pq-crystals/kyber reference implementation structure for Kotlin port](https://github.com/trancee/MeshLink-crypto/issues/55)
Source: pq-crystals/kyber `ref/` directory (branch `main`), read via GitHub raw URLs

## Summary

The pq-crystals/kyber reference implementation for ML-KEM-512 uses `KYBER_K=2` (set via compile-time macro). It consists of 9 source files in `ref/` plus the hash layer in `fips202.c`/`symmetric-shake.c`. The ML-KEM NTT operates over a **different field** (q=3329) from the already-implemented ML-DSA-44 NTT (q=8380417) — they **cannot share NTT code**.

## 1. Source File Layout (C reference, `ref/`)

| File | Purpose |
|---|---|
| `params.h` | Compile-time constants: KYBER_K=2, KYBER_N=256, KYBER_Q=3329, KYBER_SYMBYTES=32, KYBER_ETA1=3, KYBER_ETA2=2, byte sizes |
| `api.h` | Public API byte sizes + function declarations (keypair, enc, dec) |
| `kem.h` / `kem.c` | CCA-secure KEM wrapper: `keypair`, `keypair_derand`, `enc`, `enc_derand`, `dec` — calls indcpa + hash_h + hash_g + rkprf + verify + cmov |
| `indcpa.h` / `indcpa.c` | CPA-PKE: `indcpa_keypair_derand`, `indcpa_enc`, `indcpa_dec` + pack/unpack helpers + `gen_matrix` (matrix A from seed) + `rej_uniform` |
| `poly.h` / `poly.c` | Single polynomial: NTT, invNTT, compress, decompress, tobytes, frombytes, frommsg, tomsg, getnoise_eta1/eta2, basemul_montgomery, tomont, reduce, add, sub |
| `polyvec.h` / `polyvec.c` | Vector of K polynomials: ntt, invntt_tomont, basemul_acc_montgomery, compress, decompress, tobytes, frombytes, add, reduce |
| `ntt.h` / `ntt.c` | NTT + inverse NTT + basemul + zetas[128] table (Montgomery form, 2^16 base) |
| `reduce.h` / `reduce.c` | `montgomery_reduce` (QINV=-3327, MONT=-1044) + `barrett_reduce` |
| `cbd.h` / `cbd.c` | `poly_cbd_eta1` + `poly_cbd_eta2` (Coin-based sampling from SHAKE256/XOF output) |
| `verify.h` / `verify.c` | `verify` (ct comparison) + `cmov` + `cmov_int16` (constant-time) |
| `symmetric.h` / `symmetric-shake.c` | Hash wrappers: `hash_h`=SHA3-256, `hash_g`=SHA3-512, `xof`=SHAKE128, `prf`=SHAKE256, `rkprf`=SHAKE256 |
| `fips202.h` / `fips202.c` | Keccak-f[1600] + SHA3-256/512 + SHAKE128/256 primitives |

## 2. ML-KEM-512 Parameters (KYBER_K=2)

From `params.h` and `api.h` (verified against source):

| Parameter | Value |
|---|---|
| KYBER_K | 2 |
| KYBER_N | 256 |
| KYBER_Q | 3329 |
| KYBER_SYMBYTES | 32 |
| KYBER_SSBYTES | 32 |
| KYBER_ETA1 | 3 |
| KYBER_ETA2 | 2 |
| KYBER_POLYBYTES | 384 (256 × int16, NTT-domain serialization) |
| KYBER_POLYVECBYTES | 768 (K × 384) |
| KYBER_POLYCOMPRESSEDBYTES | 128 |
| KYBER_POLYVECCOMPRESSEDBYTES | 640 (K × 320) |
| KYBER_INDCPA_MSGBYTES | 32 |
| KYBER_INDCPA_PUBLICKEYBYTES | 800 (768 + 32) |
| KYBER_INDCPA_SECRETKEYBYTES | 768 |
| KYBER_INDCPA_BYTES | 768 (640 + 128) |
| KYBER_PUBLICKEYBYTES | 800 |
| KYBER_SECRETKEYBYTES | 1632 (768 + 800 + 2×32) |
| KYBER_CIPHERTEXTBYTES | 768 |
| KYBER_ENCCOINBYTES | 32 |
| KYBER_KEYPAIRCOINBYTES | 64 |

**Note**: The learned memory mentioned sk=2400 bytes, but the C reference defines `pqcrystals_kyber512_SECRETKEYBYTES = 1632`. The 2400 value is for ML-KEM-768. The Kotlin port must use 1632.

## 3. Secret Key Layout (1632 bytes)

From `kem.c crypto_kem_keypair_derand`:

```text
sk = [ indcpa_sk (768 bytes) ] [ pk (800 bytes) ] [ H(pk) (32 bytes) ] [ z (32 bytes) ]
       0..767                   768..1567           1568..1599          1600..1631
```

- `indcpa_sk`: CPA secret key (polyvec, 768 bytes)
- `pk`: full public key (800 bytes, for decapsulation)
- `H(pk)`: SHA3-256 hash of pk (32 bytes, multitarget countermeasure)
- `z`: additional randomness (32 bytes, for implicit rejection / pseudo-random k on failure)

## 4. Hash Function Injection Points (from `symmetric.h`)

| Macro | Implementation | Used where |
|---|---|---|
| `hash_h(OUT, IN, INBYTES)` | `sha3_256` | `kem.c`: H(pk) in keypair; H(pk) countermeasure in enc |
| `hash_g(OUT, IN, INBYTES)` | `sha3_512` | `kem.c`: G(buf) in enc; `indcpa.c`: hash_g in keypair (split coins into pk_seed+nonce_seed) |
| `xof_absorb/absorb` / `xof_squeezeblocks` | `shake128_absorb` + `shake128_squeezeblocks` | `indcpa.c gen_matrix`: matrix A sampling via rejection from SHAKE128, seeded with (pk_seed, i, j) |
| `prf(OUT, OUTBYTES, KEY, NONCE)` | `kyber_shake256_prf` | `poly.c poly_getnoise_eta1/eta2`: noise generation from noiseseed + nonce |
| `rkprf(OUT, KEY, INPUT)` | `kyber_shake256_rkprf` | `kem.c dec`: implicit rejection key generation (z concatenated with ct gives ss-prime) |

### Hash input/output details

**hash_g in keypair** (`indcpa.c`):

- Input: `buf[33 bytes]` = coins[0..31] + KYBER_K (byte 32)
- Output: 64 bytes — first 32 bytes = publicseed, next 32 bytes = noiseseed

**hash_g in enc** (`kem.c`):

- Input: 64-byte buffer = coins bytes 0-31 concatenated with H(pk) bytes 0-31
- Output: 64 bytes — first 32 = ss (shared secret), next 32 = coins for indcpa_enc

**hash_h in keypair** (`kem.c`):

- Input: pk (800 bytes)
- Output: 32 bytes stored at sk[1568..1599]

**hash_h in enc** (`kem.c`):

- Input: pk (800 bytes)
- Output: 32 bytes appended to coins, forming buf[32..64]

**rkprf in dec** (`kem.c`):

- Input: key=z (32 bytes), input=ct (768 bytes)
- Output: 32 bytes = pseudo-random ss on failure

## 5. CCA Transform Structure (FIPS 203 FO)

### Encaps (kem.c, `crypto_kem_enc_derand`)

1. `buf = coins || hash_h(pk)` — 64 bytes
2. `hash_g(kr, buf, 64)` — 64 bytes (first 32 = ss, next 32 = coins-prime)
3. `indcpa_enc(ct, buf[0:32], pk, kr[32:64])` — encrypt the message (coins[0:32] is the "message" m)
4. Return `ss = kr[0:32]`

### Decaps (kem.c, `crypto_kem_dec`)

1. `indcpa_dec(buf, ct, sk)` — decrypted m (32 bytes)
2. `buf[32:64] = H(pk)` — from sk
3. `hash_g(kr, buf, 64)` — 64 bytes (first 32 = ss-prime, next 32 = coins-prime)
4. `indcpa_enc(cmp, buf[0:32], pk, kr[32:64])` — re-encrypt
5. `fail = verify(ct, cmp, 768)` — constant-time ct comparison
6. `rkprf(ss, z, ct)` — pseudo-random key from z and ct
7. `cmov(ss, kr, 32, !fail)` — if verification failed, use rkprf result; else use kr

## 6. File-to-Kotlin Mapping

| C file | Kotlin file | Existing ML-DSA analog |
|---|---|---|
| `params.h` | Constants in `MLKEM512.kt` or `MLKEMParams.kt` | params inside `MLDSA44.kt` — **new** |
| `api.h` + `kem.h` + `kem.c` | `MLKEM512.kt` (PureK object) | `MLDSA44.kt` |
| `indcpa.c` | `IndCpa.kt` | no direct analog — ML-DSA does not have separate IndCPA |
| `poly.h` + `poly.c` | `MLKEMPoly.kt` | `MLDSAPoly.kt` — **separate file, different q** |
| `polyvec.h` + `polyvec.c` | `MLKEMPolyVec.kt` | `MLDSAPolyVec.kt` — **separate file, different q** |
| `ntt.h` + `ntt.c` | `MLKEMNtt.kt` | `MLDSANtt.kt` — **new, q=3329 not 8380417** |
| `reduce.h` + `reduce.c` | `MLKEMReduce.kt` | `MLDSANtt.kt` (reduce inside) — **new, QINV=-3327** |
| `cbd.c` | `MLKEMCbd.kt` | `MLDSASampling.kt` — **new, different structure** |
| `verify.c` | Reuse `verify`/`cmov` from ML-DSA or `MLKEMVerify.kt` | `MLDSANtt.kt` (verify/cmov) |
| `symmetric.h` + `symmetric-shake.c` | Reuse existing `SHAKE128.kt`, `SHAKE256.kt`, `SHA3_256.kt`, `SHA3_512.kt` | same files — **shared** |

## 7. Key Finding: NTT Cannot Be Shared

**ML-DSA-44 NTT** (`MLDSANtt.kt`):

- Q = 8380417 (25-bit prime)
- QINV = 58728449 (Q-inverse mod 2^32)
- MONT = -4186625 (2^32 mod Q)
- zetas: 256 entries, zeta times 2^32 mod Q
- 64-bit Montgomery reduce, 32-bit Barrett reduce

**ML-KEM-512 NTT** (from `ntt.c`, `reduce.c`):

- Q = 3329 (14-bit prime)
- QINV = -3327 (Q-inverse mod 2^16)
- MONT = -1044 (2^16 mod Q)
- zetas: 128 entries from `ntt.c`
- 32-bit Montgomery reduce, 16-bit Barrett reduce

The zetas table, reduction constants, and Montgomery domain base are completely different. **ML-KEM-512 needs its own `MLKEMNtt.kt` and `MLKEMReduce.kt` files.** This is the same conclusion as the learned memory (issue #50 survey).

## 8. Poly Message Encoding

From `poly.h`:

- `poly_frommsg`: message to polynomial (bit decomposition, 1 bit per coeff, coefficients 0 or (Q+1)/2 = 1665)
- `poly_tomsg`: polynomial to message (threshold comparison: 0 if coeff < Q/2, 1 otherwise)

## 9. CCA Security and Implicit Rejection

FIPS 203 requires CCA security via the Fujisaki-Okamoto transform. The key security properties:

- **`z` (rejection key)**: stored in sk[1600..1631], used only when decapsulation fails (ct does not re-encrypt to match)
- **Implicit rejection**: on failure, `rkprf(z, ct)` generates a pseudo-random ss — this prevents attackers from distinguishing valid vs invalid ciphertexts
- **`cmov`**: branch-free conditional move — `cmov(ss, kr, 32, !fail)` selects kr if not-failed else ss (which was set to rkprf output)
- **`verify`**: constant-time byte-by-byte XOR accumulator

## Reference

Source: pq-crystals/kyber, branch `main`, `ref/` directory.

- `params.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/params.h>
- `api.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/api.h>
- `kem.c`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/kem.c>
- `indcpa.c`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/indcpa.c>
- `poly.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/poly.h>
- `polyvec.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/polyvec.h>
- `ntt.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/ntt.h>
- `reduce.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/reduce.h>
- `cbd.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/cbd.h>
- `verify.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/verify.h>
- `symmetric.h`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/symmetric.h>
- `symmetric-shake.c`: <https://raw.githubusercontent.com/pq-crystals/kyber/main/ref/symmetric-shake.c>

[1] The zetas table is in `ntt.c`, not `ntt.h`. It contains 128 int16 values in Montgomery form (zeta times 2^16 mod 3329).
