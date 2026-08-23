# Research: Keccak/SHAKE256 reference-port survey

Survey for the SHAKE256 pure-Kotlin port (MeshLink-crypto, ADR-0001/0002/0003/0005).
Primary sources read in full: PQClean `common/fips202.c`, BouncyCastle
`KeccakDigest.java`/`SHAKEDigest.java`, kotlincrypto `sponges/keccak`
(`F1600.kt`, `KeccakP.kt`, `State.kt`) + `hash/sha3`
(`KeccakDigest.kt`, `SHAKEDigest.kt`, `SHAKE256.kt`), and
KeccakKotlin (`KeccakMath.kt`, `AbstractKeccakFunction.kt`,
`KeccakParameter.kt`, `api/SHAKE256.kt`).

## Shared algorithm facts (verified across all four)

- State: `uint64_t[25]` / `long[25]` / `LongArray(25)` — 25 lanes of 64 bits =
  1600-bit Keccak-f[1600]. Lane index is `x + 5*y` (x,y in 0..4), little-endian
  byte-to-lane. **Kotlin `Long` is the natural type; no `BigInteger` needed
  (ADR-0001 allows 64-bit word arithmetic).**
- SHAKE256 rate `r = 136` bytes (1088 bit), capacity `c = 512`. SHAKE128 rate
  `r = 168`, capacity `c = 256`. Round constants `RC[24]` identical in all
  sources (the FIPS 202 / Keccak team values).
- Domain-separation suffix absorbed as a partial byte before the pad10\*1:
  SHAKE uses the 4-bit suffix `1111` → byte `0x1F`; SHA3 uses `01` → `0x06`;
  cSHAKE/KMAC use `00` → `0x04`.
- Padding pad10\*1: set the first free bit (at the absorb position), then set
  bit 63 of lane `(r-1)/8` (the last rate lane). Equivalent to the
  `0x80`-in-last-byte form used by kotlincrypto/BC.
- Permutation: 24 fixed rounds, branch-free (theta → rho/pi → chi → iota),
  with a scalar-register unrolling (a00..a24). **No data-dependent branching
  and no secret-dependent indexing in any implementation.** The absorb/squeeze
  index positions are functions of the public message length and the public
  rate — never of secret data.

## 1. PQClean C reference — `common/fips202.c` (canonical spec implementation)

- **License:** Public domain. Header: "Based on the public domain
  implementation … Keccak/TweetFips202 by Gilles Van Assche, D. J. Bernstein,
  P. Schwabe." Per-implementation LICENSE files in PQClean read "Public
  Domain".
- **Structure:** The authoritative reference. Exposes a non-incremental API
  (`shake256(u8 *out, size_t outlen, const u8 *in, size_t inlen)`) and an
  incremental API (`keccak_inc_init / keccak_inc_absorb / keccak_inc_finalize /
  keccak_inc_squeeze`). State is `uint64_t[26]`: 25 lanes + a 26th word that
  tracks the partial-byte count (`s_inc[25]`) across absorb/squeeze.
  `KeccakF1600_StatePermute` is the 24-round permutation; `KeccakF_RoundConstants[24]`.
  `keccak_inc_finalize(s, r, 0x1F)` absorbs the `0x1F` SHAKE domain byte and
  the trailing pad10\*1 high bit; `keccak_inc_squeeze` permutes, extracts `r`
  bytes little-endian, and resumes on the next block.
- **Performance:** C, native, with SIMD variants (`keccak4x/KeccakP-1600-times4`)
  in sibling dirs. The `inc` API is byte-granular and tight. This is the speed
  ceiling; PQClean ports from here.
- **Constant-time:** Permutation is branch-free and index-independent.
  Byte-level absorb/squeeze indices derive from public length. Suitable as the
  spec/structure reference, though C's compiler side-channels are out of scope
  for the pure-K lint gate.
- **Portability to MeshLink patterns:** The *algorithm structure and the
  sponge absorb/pad/squeeze logic* are the direct template — port
  `keccak_inc_absorb` → `SHAKE256Hasher.update`, `keccak_inc_finalize` → the
  `digest`/`squeeze` padding step (domain byte `0x1F` + pad10\*1), and
  `keccak_inc_squeeze` → incremental `squeeze(out, len)`. The exact C byte
  shuffling (`s_inc[off >> 3] ^= m[i] << (8 * (off & 7)`) is replaceable by a
  straight lane-XOR loop over whole rate blocks plus a tail, which is simpler
  and matches the kotlincrypto/BC style. **Primary reference for the sponge
  control flow and the pad/finalize step.**

## 2. BouncyCastle — `KeccakDigest.java` / `SHAKEDigest.java`

- **License:** MIT (`https://www.bouncycastle.org/licence.html`; "Copyright (c) 2000-2026
  The Legion of the Bouncy Castle Inc.").
- **Structure:** `KeccakDigest` holds `long[] state = new long[25]`, `byte[]
  dataQueue` (192 bytes — sized for the largest rate), `rate`, `bitsInQueue`,
  `fixedOutputLength`, `squeezing`, and a `queuePacked` lazy-pack counter.
  `KeccakPermutation()` is the clean scalar-register 24-round permutation
  (`a00 ^ = …`, identical layout to PQClean and kotlincrypto).
  `absorb(byte[])` XORs whole rate-blocks into state and permutes; one-byte
  `absorb(byte)` and `absorbBits(int, int)` handle partial bytes.
  `padAndSwitchToSqueezingPhase()` sets the pad10\*1 high bit on the last rate
  lane. `squeeze()` permutes via `KeccakExtract()` then lazily materialises
  lanes with `ensureQueuePacked()` (only packs the lanes actually consumed —
  a real optimization for small/fixed outputs). `SHAKEDigest extends
  KeccakDigest` adds `doOutput`: calls `absorbBits(0x0F, 4)` (the SHAKE suffix)
  then `squeeze` — i.e. SHAKE is a fixed suffix on the generic Keccak sponge.
- **Performance:** Mature Java; the scalar permutation avoids per-round array
  indexing. Lazy lane packing saves work on short squeezes (relevant for fixed
  ML-DSA nonce derivation, but not for ML-KEM's bulk SHAKE).
- **Constant-time:** `KeccakPermutation` is branch-free and index-free (scalar
  registers). The absorb/squeeze indices are public (length/rate). Note BC also
  flags which CRYSTALS ops are variable-time in `MLDSAEngine.java` (rejection
  sampling, Fiat-Shamir loop) — a useful commenting pattern to replicate, not a
  Keccak issue. Clean for the `ConstantTimeRule`.
- **Portability to MeshLink patterns:** `KeccakPermutation()` is the **most
  readable pure-scalar permutation** to lift verbatim (rename to Kotlin
  `Long`/`ushr`/`rotateLeft`). `long[25]` → `LongArray(25)`; `byte[]` →
  `ByteArray`. The lazy `queuePacked` optimization is optional. The
  `SHAKEDigest.doOutput` (absorbBits `0x0F` + squeeze) mirrors exactly the
  pad/finalize the MeshLink hasher needs. **Best structural cross-check for the
  permutation; strong candidate as the literal port source for the core.**

## 3. kotlincrypto — `sponges/keccak` + `hash/sha3` (pure Kotlin, KMP)

- **License:** Apache 2.0.
- **Structure:** Two modules. `org.kotlincrypto.sponges.keccak`
  (`library/keccak/...`): `F1600.kt` is `LongArray(25)` state with `addData(i,
  v) { state[i] = state[i] xor v }` and a `get(i)` accessor; `State.kt` is the
  sealed `Collection<Long>` base. `KeccakP.kt` holds the public extension
  `F1600.keccakP(rounds=24): Unit` — the **scalar-register 24-round
  permutation (a00..a24) with the `RC[24]` array**, written in plain Kotlin
  (`rotateLeft`, `xor`, `inv`, `<<<`-style shifts). No dependencies in the
  permutation itself. `org.kotlincrypto.hash.sha3`
  (`library/sha3/...`): `KeccakDigest` (sealed) wraps the `F1600` state,
  with `compressProtected(input, offset)` absorbing `blockSize()` bytes as lanes
  via `input.leLongAt(...)` then calling `state.keccakP()`; `finalizeAndExtractTo`
  does `buf[bufPos] = dsByte; buf[lastIndex] ^= 0x80; compressProtected(buf, 0)`
  (the pad10\*1 via the dsByte + high bit), then `extract(...)` squeezes lane by
  lane. `SHAKEDigest` extends `KeccakDigest`; constants
  `PAD_SHAKE = 0x1f`, `BLOCK_SIZE_BIT_256 = 136`, `BLOCK_SIZE_BIT_128 = 168`.
  `SHAKE256` is `SHAKEDigest(..., blockSize = 136, ...)`. The hash module
  additionally depends on `kotlincrypto.core` (Digest/Xof base), `kotlincrypto.bitops`
  (endian helpers), and `kotlincrypto.sponges.keccak` — so as a *dependency* it
  pulls the core/bitops modules.
- **Performance:** Pure Kotlin KMP, scalar Long arithmetic — the fastest
  portable pure-Kotlin permutation here. The `RC` array carries commented hex
  values with signed-decimal `Long` literals (`-9223372036854742902L` etc.) so
  the high bit survives two's complement. A clean-room `keccakP` is small
  (≈60 LOC) and dependency-free.
- **Constant-time:** `keccakP` is branch-free and uses fixed scalar registers
  — no secret-dependent index, no `if` on data. `compressProtected` absorbs a
  fixed `blockSize()`; `extract` indexes lanes by public position. Fully
  compatible with `@Secret` annotation on the message path (the
  `ConstantTimeRule` will not flag it; there is no secret branching to trip).
- **Portability to MeshLink patterns:** **This is the top-ranked permutation
  port target.** `F1600.keccakP` maps 1:1 to `KeccakF1600PureK` over
  `LongArray(25)` — no BigInteger, 64-bit word arithmetic (ADR-0001 ✓), KMP
  (commonMain), constant-time (ADR-0003 ✓). The absorb/pad/squeeze in
  `KeccakDigest` mirrors the SHA256Hasher `update`/`digest` pattern already in
  the repo. Caveat: only the permutation module is needed; do **not** depend on
  `kotlincrypto.hash` as a library (it pulls core/bitops and an opinionated
  Digest/Xof API) — vendor just the `keccakP` + a thin sponge hasher, exactly
  as MeshLink vendors its own `SHA256Hasher` rather than importing a digest
  library.

## 4. KeccakKotlin (ronhombre/KeccakKotlin, v2.0.x)

- **License:** Apache 2.0 (`LICENSE.txt`).
- **Structure:** A broader "everything SHA-3" KMP library. Core permutation in
  `internal/KeccakMath.kt`. The **master branch** is optimized and "relatively
  unreadable" (per its own comment — a more readable `standard` branch
  exists). It represents state as `Array<LongArray>(5) { LongArray(5) }` — a
  5×5 `[x][y]` matrix rather than the flat `LongArray(25)` used by PQClean/BC/
  kotlincrypto; `directPermute` then does theta/rho-pi/chi/iota with fixed
  `state[x][y]` indices and `KeccakConstants.ROUND[i]` (the same 24 round
  constants). Parameters live in `KeccakParameter` enum: SHAKE_256 has
  `BITRATE=1088` → `BYTERATE=136`, domain suffix `FlexiByte(0b1111, 3)`;
  SHA3 uses `0b10`; cSHAKE/KMAC `0b00`. `AbstractKeccakFunction` wraps
  streaming absorb in a `UniversalDigestor`; the suffix domain byte is applied
  by `addLast()` (overridden per variant). Uses `@JvmSynthetic` (JVM-only
  annotation; ignored on iOS/Android Native but signals JVM-first intent) and
  little-endian `Long`-to-bytes packing helpers. SHAKE256 KAT test
  `46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f` for
  empty input (NIST/FIPS-202 known-answer vector).
- **Performance:** Claims a 275 GB → 54 GB memory-reduction during 1 M
  ML-KEM operations (per the project's own README). But the matrix state
  (`Array<LongArray>`) allocates 6 objects per state vs. one `LongArray`, and
  the master branch is hard to audit — a tradeoff for a constant-time
  security library.
- **Constant-time:** The permutation is branch-free with fixed indices, so it
  respects the discipline. `pad10n1Direct` and `getLongAt` index by public
  position, not by secret. However the 5×5 matrix form makes the
  `ConstantTimeRule`/review story weaker than the flat scalar form, and
  `@JvmSynthetic` is dead weight for non-JVM targets.
- **Portability to MeshLink patterns:** **Usable only as a secondary reference.**
  The `KeccakParameter` enum and the cSHAKE/KMAC pre-padding code
  (`leftEncode`/`rightEncode`/`encodeToBytes` via CLZ) are handy templates for
  future cSHAKE/KMAC extensions of MeshLink — but for a first SHAKE256 port the
  permutation structure diverges from the flat-`LongArray` form used by PQClean
  and BC, so it is a worse lift than kotlincrypto.

## 5. Other Kotlin/Java Keccak implementations (notable mentions)

- **JDK JCA (native, not pure-K):** SHA-3 (`MessageDigest` `SHA3-*`) ships in
  the SUN provider since JDK 9. SHAKE ships **only as fixed-length digests**
  (`SHAKE128-256`, `SHAKE256-512`) added in **JDK 25** (JDK-8355510). There is
  **no variable-output SHAKE/XOF** in JCA on any release. This directly affects
  the dispatch bridge: on the project's JDK 21 toolchain, `MessageDigest.SHAPE`
  cannot produce SHAKE256. See ticket #35.
- **Android:** No `MessageDigest`/Keystore SHAKE on minSdk 21 … API 37; the
  Android Keystore ML-DSA path (API 37) is signature-only, no XOF. Pure-K is
  the path. See ticket #35.
- **iOS:** CommonCrypto exposes `CC_SHA3-*` (iOS 16.0+/macOS 13.0+) but **not**
  SHAKE as a C symbol. iOS 26 CryptoKit adds `SHAKE256` (Swift-only, not
  cinteroperable — see `docs/proposals/0002-pqc-support-analysis.md`
  §"iOS"). Pure-K is the path. See ticket #35.
- **Others surveyed (not KMP-native, omitted from matrix):** `ctz/keccak`
  (Python), `phusion/node-sha3`, `corus/keccak-tiny` (C), `fmerg/fips202-XOFs`
  (Rust), `filecoin-project/go-keccak`, `johanns/sha3` (Ruby, wraps the
  Keccak C XKCP). None are Kotlin/Java and none are portable-to-Kotlin
  references beyond the C ones already covered by PQClean.

## 6. Native SHAKE availability matrix (drives the CryptoBridge / ticket #35)

| Target | Mechanism | SHAKE256 XOF? | Pure-K required? |
|---|---|---|---|
| JVM (JDK 21) | `java.security.MessageDigest` / `KEM` | No — only SHA3 since JDK 9; SHAKE only as fixed `SHAKE256-512` in JDK 25 | **Yes** |
| Android | Android Keystore | No (no XOF / no SHAKE) | **Yes** |
| iOS arm64 | CommonCrypto `CC_SHA3` / iOS 26 CryptoKit (Swift-only) | No cinteroperable C SHAKE; CryptoKit SHAKE256 is Swift-only | **Yes** |

Conclusion for the `expect/actual` dispatch: on every current target the
`shake256Native(...)` bridge returns `null`, so the pure-K path is the
**primary** implementation, not a fallback. The bridge stub should still be
scaffolded (ADR-0002 keeps the per-primitive native-or-pure-K pattern) so a
future iOS-26-via-CryptoProvider-injection (Swift) path, or a JDK 25+ fixed-
output path, can slot in without API churn. This is the concrete input to
ticket #37 (Dispatch integration).

## 7. Mapping to the MeshLink-crypto registration chain (ADR-0002/0005)

Recommended port skeleton, following `docs/how-to/add-primitive.md`:

- **Step 2 (pure-K):** `crypto/.../SHAKE256PureK` over `LongArray(25)` state;
  core permutation = kotlincrypto `F1600.keccakP` ported to Kotlin: scalar `Long`
  locals a00..a24, `rotateLeft`, `^` (no `BigInteger`, 64-bit words per ADR-0001;
  branch-free per ADR-0003). `@Secret` the message param on
  `digest`/`update`/`squeeze`.
- **Streaming hasher:** `SHAKE256Hasher` mirroring `SHA256Hasher` —
  `update(data, offset, length)` absorbs whole rate (136-byte) blocks then
  permutes; a partial tail is carried in a 136-byte buffer. `digest(outputLength)`
  applies the pad: buffer the `0x1F` domain byte, set pad10\*1 (0x80 in last
  rate byte / bit 63 of lane 135), permute, then squeeze. `squeeze(out, len)`
  supports incremental XOF extraction (re-permuting every 136 bytes) — the
  PQClean `keccak_inc_squeeze` shape.
- **Step 3 (expect):** `internal expect object SHAKE256` with
  `fun digest(@Secret message: ByteArray, outputLength: Int): ByteArray` and
  optionally streaming `update`/`squeeze`.
- **Steps 4a–4c (actuals):** each `actual object SHAKE256` =
  `shake256Native(message, outputLength) ?: SHAKE256PureK.digest(...)` (returns
  `null` on all current targets → pure-K).
- **Step 5 (CryptoBridge):** add `shake256Native(message, outputLength):
  ByteArray?` (no `@Secret` params) per `jvmMain`/`androidMain`/`iosMain`
  CryptoBridge.kt, returning `null` today (ticket #35 to wire native).
- **Step 6 (facade):** extend `Hasher` with
  `shake256(message, outputLength): Result<ByteArray>`; XOF streaming is a
  future `Aead`-style `ShakeXof` handle.
- **Step 7 (CryptoProvider):** `supportsShake256(): Boolean` (false today) +
  `shake256(...)` for injected native providers (ticket #37).
- **Tests (Step 8):** FIPS 202 / NIST CAVP known-answer vectors (primary;
  SHAKE256("") = `46b9dd2b…50c27646ed5762f` over 64 bytes as a sanity vector,
  plus multi-block and streaming/squeeze cases). The Wycheproof corpus does
  not carry a `shake256` file in its published set, so inline RFC/FIPS known-answers
  (as `SHA256Test.kt` does) are the correct harness. Tag
  `@Tag("positive")`, `@Tag("critical-path")`.

## 8. Recommendation (ranked)

1. **Port the permutation from kotlincrypto `sponges.keccak` `F1600.keccakP`.**
   Flat `LongArray(25)`, scalar registers, branch-free, KMP, one self-contained
   file, no external deps. Exact match for ADR-0001/0003.
2. **Use BouncyCastle `KeccakPermutation()` + `SHAKEDigest.doOutput` as the
   readable structural twin** to diff/cross-check the port (same algorithm,
   Java `long` → Kotlin `Long` rename).
3. **Use PQClean `fips202.c` for the sponge control flow** (`keccak_inc_absorb`,
   `keccak_inc_finalize` domain+pad10\*1, `keccak_inc_squeeze`) — the canonical
   incremental XOF shape and the fixed output-length contract.
4. **Use KeccakKotlin's `KeccakParameter`/cSHAKE pre-padding only for
   future cSHAKE/KMAC** work, not for the SHAKE256 port itself.

Net: a faithful pure-Kotlin `SHAKE256PureK` is a one-file permutation port plus
a ~40-line sponge hasher — no BigInteger, constant-time, and structurally
identical to the existing `SHA256PureK`/`SHA256Hasher` pair already in the
repo.
