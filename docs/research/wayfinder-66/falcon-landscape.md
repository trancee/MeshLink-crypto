# Falcon-FN-DSA Landscape Research

## Metadata

- **Investigators**: FalconResearch subagent (task), 2026-09-05
- **Primary sources**: falcon-sign.info (spec + reference impl), PQClean, NIST, BouncyCastle, FQ 206 slide deck (Ray Perlner)
- **Status**: Completed. Key facts below directly inform the wayfinder map's decision tickets.

---

## 1. Falcon v1.2 Specification

**Source**: <https://falcon-sign.info/falcon.pdf> (Falcon specification v1.2, 2020-01-10, ~1921 pages)

### Parameter sets

| Parameter | Falcon-512 | Falcon-1024 |
|-----------|-----------|-------------|
| n (degree) | 512 | 1024 |
| logn | 9 | 10 |
| pk (public key) | 666 bytes (trimmed) / 897 bytes (raw) | 1281 / 1793 |
| sk (secret key) | ~1281 bytes (expanded: 5044/10126) | ~2565 bytes (expanded: 10084/20290) |
| sig (signature, compressed) | 666 bytes (min) / 690 (padded) / 1162 (raw) | 1310 (min) / 1336 (padded) / 2318 (raw) |

### Algorithm overview

- **KeyGen** (Algorithms 1–2 in spec): Generate NTRU keypair over Z[x]/(x^n + 1). Uses SHAKE-256 for seed expansion. Produces (pk, sk) with expanded secret key containing FFT basis and LDL tree.
- **Sign** (Algorithm 3): Hash-and-sign using Fast Fourier Sampling (FFS) over Gaussian integers. Requires:

  - FFT over Z[i] (complex field) — uses 64-bit FP
  - Gaussian sampler — uses 64-bit FP for the inverse CDF
  - Rejection sampling loop (may iterate multiple times)

- **Verify** (Algorithm 4): Recomputes the hash, checks signature norm bound. **NO floating-point required** — purely integer operations over Z_q.
- **hash_to_curve**: Maps a message digest to a polynomial in Z_q[x]/(x^n+1); uses SHAKE-256.

### Floating-point usage

Falcon uses double-precision (64-bit IEEE 754) floating-point for:

1. **FFT** (fft.h / fft.c): Complex FFT over Gaussian integers Z[i]. Operations: +, -, *, and the twiddle factors are FP values.
2. **Gaussian sampler** (sample.h / sample.c): Inverse CDF sampling using the Fast Fourier Sampling technique. Uses FP for the sampler table lookup and rejection bounds.
3. **GG18 bounds computation**: Floating-point comparison for norm checks during signing.

**Key asymmetry**: Only **signing** requires FP. **Verification** is entirely integer-based (operations in Z_q, norm check on integer coefficients).

### Constant-time variant

The spec includes a `ct_` prefixed constant-time reference implementation (Section 7.3). This variant:

- Uses bitwise operations instead of branches where possible
- Still uses FP for the FFT and sampler
- Guards against timing and cache attacks via careful ordering

---

## 2. Test Vector Sources

### PQClean

- **Location**: `crypto_sign/falcon-512/` and `crypto_sign/falcon-1024/`
- **Status**: PQClean was **archived Aug 4, 2026** (read-only, but still accessible)
- **Clean variant files** (falcon-512): `api.h`, `fpr.h`, `inner.h`, `sign.c`, `verify.c`, `codec_i8.c`, `codec_i16.c`, `keygen.c`, `fft.c`, `fft64.c`, `small.c`, `shake.c`, `utils.c`, etc.
- CRITICAL: The `fpr.h` header implements a **custom integer-arithmetic IEEE 754 binary64 emulator** (`FALCON_FPEMU`) rather than using C `double`.

### Official NIST KAT files

- **Source**: <https://falcon-sign.info/falcon-round3.zip> → `KAT/` directory
- **Files**:

  - `falcon512-KAT.rsp` (1.25 MB) — 100 test vectors
  - `falcon1024-KAT.rsp` (1.76 MB) — 100 test vectors
  - Corresponding `.req` files

- **Format**: NIST KAT `.rsp` format — `count`, `seed`, `pk`, `sk`, `smlen`, `sm`, `mlen`, `msg` fields
- **Deterministic signing**: Tests use a fixed RNG seed (via the PRNG), so signatures are deterministic and byte-for-byte reproducible.

### C2SP/Wycheproof

- **Result**: **No Falcon test vectors exist in Wycheproof** (confirmed by grepping `files.md` and the testvectors directory).
- Wycheproof does NOT have a `falcon` or `fn-dsa` test directory.
- The repo should use NIST KAT files (from falcon-round3.zip) as the primary correctness oracle, not Wycheproof.

### NIST CAVP

- NIST CAVP does not list Falcon in its published algorithm list as of 2026-09-05. The official NIST KAT files from the Falcon project site are the authoritative source.

### Recommendation

Use the **NIST KAT files** (`falcon512-KAT.rsp`, `falcon1024-KAT.rsp`) from <https://falcon-sign.info/falcon-round3.zip> as the test vector corpus. These provide deterministic signing verification (seed-based keygen → signature byte-for-byte match), following the same pattern as the existing `mldsa_44_sign_seed_test.json` Wycheproof tests.

---

## 3. Reference Implementation Structure

### pq-crystals/falcon repo

- **GitHub**: Repo **removed** from GitHub (HTTP 404 as of 2026-09-05); canonical source: <https://falcon-sign.info/>
- **Status**: Original repo archived Aug 4, 2026, later **removed**; reference code mirrored in PQClean (`crypto_sign/falcon-512/clean/`)
- **Contents**: `Extra/c/` directory contained the canonical C reference implementation

### PQClean Falcon (clean variant)

The PQClean `crypto_sign/falcon-512/clean/` directory mirrors the upstream structure:

| File | Purpose |
|------|---------|
| `api.h` | Size constants (FALCON_KEYGEN_SEEDBYTES=40, FALCON_SIG_COMPRESSED, FALCON_SIG_PADDED, FALCON_SIG_CT, etc.) |
| `fpr.h` | **FP abstraction layer** — implements IEEE 754 binary64 using integer arithmetic (FALCON_FPEMU mode) OR native double (FALCON_FPNATIVE mode). No C `double` in the integer-only mode. |
| `inner.h` | Internal constants, type definitions, macro-based field arithmetic in Z_q |
| `fft.h` / `fft.c` | FFT over Z[i] (Gaussian integers) using the `fpr` abstraction |
| `fft64.h` / `fft64.c` | 64-element FFT specialization |
| `small.h` / `small.c` | Small field operations (modulo small primes for the small-coefficient representation) |
| `shake.h` / `shake.c` | SHAKE-256 interface (NIST encoding of the sponge) |
| `sample.h` / `sample.c` | Gaussian sampling (Fast Fourier Sampling, samplerZ) |
| `sign.h` / `sign.c` | Signature generation (Algorithm 3), rejection loop, domain separation |
| `verify.h` / `verify.c` | Signature verification (Algorithm 4) — **integer-only, no FP** |
| `keygen.h` / `keygen.c` | Key generation (Algorithm 1), expanded key creation |
| `codec_i8.h` / `codec_i8.c` | Encoding: small polynomials to/from bytes |
| `codec_i16.h` / `codec_i16.c` | Encoding: field elements to/from bytes |

### Two FP modes

The reference implementation's `config.h` documents two compile-time modes:

- **`FALCON_FPNATIVE`**: Uses native C `double` — faster but not constant-time on all platforms
- **`FALCON_FPEMU`**: Implements IEEE 754 binary64 arithmetic using pure integer operations — slower but portable and constant-time-friendly

The `fpr.h` header implements the `FALCON_FPEMU` mode by emulating IEEE 754 binary64 operations (add, subtract, multiply, divide, sqrt, FMA, comparison) using integer arithmetic. This is the approach that makes a pure-Kotlin port possible while preserving ADR-0001 (integer-only).

### PRNG fix

The `falcon-round3.zip` contains the **pre-2021-11-01** PRNG fix version. The fixed version (with the PRNG initialization correction) is available separately. PQClean's archived version includes the fix.

---

## 4. Floating-Point in Kotlin Multiplatform

### Kotlin Double on each target

- **JVM**: `Double` compiles to JVM `double` bytecode. IEEE 754 64-bit operations are handled by the JVM's FPU. Constant-time depends on the JVM implementation and CPU. The JVM does NOT guarantee constant-time FP operations.
- **Android**: Same as JVM (ART runtime). `Double` → `double`.
- **iOS (Kotlin/Native)**: `Double` compiles to C `double` via LLVM. Kotlin/Native does **not** enable `-ffast-math` by default (strict FP semantics are preserved). However, constant-time is not guaranteed — FP operations can still leak timing through denormals, NaN handling, and FPU pipeline behavior.

### IEEE 754 compliance

- Kotlin's `Double` type maps to IEEE 754 binary64 on all targets.
- Kotlin/Native does NOT apply `-ffast-math` or `-ffinite-math` flags by default, so FP semantics are strict (matching the spec's "no FMA" requirement).
- The Kotlin/JVM backend with `-Xfp-on-strict` or `strict` math mode preserves IEEE 754 semantics.

### Constant-time analysis

- **Kotlin Double is NOT guaranteed constant-time** — operations have data-dependent timing (denormal handling, NaN propagation, rounding, pipeline stalls).
- The repo's detekt `ConstantTimeRule` (in `crypto-detekt-rules/src/main/kotlin/.../ConstantTimeRule.kt`) currently checks for:

  - `if`/`when` branches that reference `@Secret`-annotated parameter names
  - Array indexing by `@Secret`-annotated parameter names
  - It does **NOT** currently check for floating-point variable-time operations

- This means FP operations in signing would NOT be flagged by the existing detekt rule, but they would NOT be constant-time either.

### Key comparison: PQClean's approach

PQClean's Falcon `fpr.h` implements **integer-only IEEE 754 binary64 emulation** (`FALCON_FPEMU`). This approach:

- Uses only integer arithmetic (add, sub, mul, shifts)
- Is amenable to constant-time implementation (all operations are integer-based)
- Would comply with ADR-0001 (no BigInteger, integer-only)
- Matches the spec's numerical behavior exactly (since it emulates IEEE 754)

This is the **recommended approach** for the Kotlin port: port PQClean's `fpr.h` integer-only FP emulation to Kotlin, enabling constant-time Falcon signing without native floating-point.

---

## 5. FN-DSA / FIPS 206 Status

### Current NIST status (as of 2026-09-05)

- **FIPS 203** (ML-KEM): Finalized Aug 13, 2024 ✓
- **FIPS 204** (ML-DSA): Finalized Aug 13, 2024 ✓
- **FIPS 205** (SLH-DSA): Finalized Aug 13, 2024 ✓
- **FIPS 206** (FN-DSA): **Still "in development"** — IPD (Initial Proposed Draft) awaiting approval as of the 2025 status presentation
- **ISO/IEC 18033-7:2024**: Published (includes FN-DSA)

### FIPS 206 slide deck (Ray Perlner, 2025)

Key takeaways from <https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf>:

| Aspect | Falcon v1.2 | FIPS 206 (proposed) |
|--------|-------------|---------------------|
| Core algorithm | Same | Same (FN-DSA based on Falcon) |
| KeyGen FP | Native or emulated | Native or emulated OR **fixed-point allowed** (KAT match NOT required) |
| Sign FP | Native or emulated | Native or emulated (KAT match required, **no FMA**) |
| Verify FP | None (integer-only) | None (integer-only) |
| GS-norm check | Standard | New max value: 0.9999 × 1.17√q |
| LDL leaf check | Standard | Must be in [σ_min, σ_max] range |
| Seeds | 40 bytes for keygen | 40 bytes (32 for keygen) — **pseudorandom seeds** |
| Randomness | Per-coefficient | 79 bits per coefficient (BaseSampler) |
| Key export | Exportable | **Discourages** export of FFT basis/LDL tree (would encode FP values) |
| Modes | Pure / pre-hash | Separate pure / prehash, separate internal / external |
| Future | — | **BUFF transform** planned (will change signature format) |

### Implications

1. **Implement against Falcon v1.2** — stable, well-vetted, all KATs available. Label as "Falcon", not "FN-DSA" (per falcon-fn-dsa skill guidance).
2. The FIPS 206 GS-norm change and LDL leaf check are minor numerical adjustments to verification — can be handled as a compatibility flag.
3. The BUFF transform is a **breaking change** planned for FIPS 206 — signature format will change. Implementers must be prepared for a future migration.
4. KeyGen fixed-point allowance means the integer-only FP emulation is acceptable for keygen under FIPS 206.

---

## 6. Existing Kotlin/JVM Falcon Implementations

### BouncyCastle (bcgit/bc-java)

- **Location**: `core/src/main/java/org/bouncycastle/pq/crypto/falcon/`
- **FP approach**: Uses native Java `double` for all FP operations. Has `FPREngine.java` (111 lines) with custom FP math methods (`FPREMULTIPLY`, `FP_EXPAND`, `FPREDUCE`, `FPMUL`, `FPADD`, `FPSUB`, `FPSQRT`, `FPDIV`).
- **Constant-time**: BouncyCastle's implementation is NOT constant-time (uses data-dependent branches and native double). It's used for functional verification, not cryptographic security.
- **Kotlin accessibility**: BouncyCastle is a Java library — accessible from Kotlin but not pure-Kotlin.

### Tink

- Tink does not have a standalone Falcon implementation. It would use BouncyCastle as a backend.

### Conscrypt

- No Falcon support.

### PQClean (Kotlin/JVM)

- PQClean's Falcon uses the **integer-only FP emulation** (`fpr.h` with `FALCON_FPEMU`) when compiled without native double support. This is the reference for a pure-integer port.

---

## 7. Key Decision Support

### FP approach decision (for wayfinder ticket G1)

| Option | Kotlin Double (FP-native) | Integer-only FP emulation (PQClean fpr.h port) |
|--------|--------------------------|-----------------------------------------------|
| Spec compliance | Exact (native double matches spec) | Exact (IEEE 754 binary64 emulated with integers) |
| ADR-0001 compliance | Breaks (uses Double, not integer-only) | Passes (integer arithmetic only) |
| Constant-time | No guarantee (FP is data-dependent) | Possible (all operations are integer-based) |
| Complexity | Low (Kotlin Double is built-in) | High (must port fpr.h, ~300 lines of integer FP emulation) |
| Performance | Fast (native FP) | Slower (integer emulation) |
| detekt ConstantTimeRule | Not flagged (rule doesn't check FP) | Not flagged (integer ops) |
| Risk | Timing leaks in signing | Porting bugs, numerical mismatch |
| Recommendation | Use only if constant-time FP is proven | **Recommended** for pure-K constant-time compliance |

### Test vector decision (for wayfinder ticket R1/T1)

- Use **NIST KAT files** from falcon-round3.zip (100 vectors for Falcon-512)
- No Wycheproof corpus exists for Falcon
- Format: NIST `.rsp` (count, seed, pk, sk, sm, msg, smlen, mlen fields)
- Will need a parser (similar to existing WycheproofJson.kt but for KAT format)

### Spec decision (for wayfinder ticket G3/scope)

- Target **Falcon v1.2** specification
- FIPS 206 still in development (IPD awaiting approval as of 2026-09-05)
- Label as "Falcon" (not "FN-DSA") per falcon-fn-dsa skill guidance

## Sources

1. Falcon specification v1.2: <https://falcon-sign.info/falcon.pdf>
2. Falcon project: <https://falcon-sign.info/>
3. PQClean Falcon (archived): <https://github.com/PQClean/PQClean/tree/master/crypto_sign/falcon-512>
4. Official KATs: <https://falcon-sign.info/falcon-round3.zip>
5. NIST PQC status: <https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization>
6. FIPS 206 slide deck: <https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf>
7. BouncyCastle Falcon: <https://github.com/bcgit/bc-java/tree/main/core/src/main/java/org/bouncycastle/pqc/crypto/falcon>
8. Google Wycheproof: <https://github.com/google/wycheproof> (no Falcon vectors)
