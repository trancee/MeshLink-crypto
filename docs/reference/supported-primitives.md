# Supported Primitives

> **Reference.** This page lists every primitive the library provides. It states facts only. For background, see [Architecture](../explanation/architecture.md).

## Overview

The library implements seven RFC-standard cryptographic primitives. Each primitive is available as a pure-Kotlin implementation. Each primitive also has a native fallback path where the host platform provides the same operation. The library selects per-primitive at each call site. Callers never choose a provider.

| Primitive | RFC | Pure-K | JVM native | Android native | iOS native |
|---|---|---|---|---|---|
| SHA-256 | [RFC 6234 §5.1](https://datatracker.ietf.org/doc/html/rfc6234#section-5.1) | Yes | JCA (`MessageDigest`) | JCA (`MessageDigest`) | CommonCrypto (`CC_SHA256`) |
| SHA-512 | [RFC 6234 §5.2](https://datatracker.ietf.org/doc/html/rfc6234#section-5.2) | Yes | JCA (`MessageDigest`) | JCA (`MessageDigest`) | CommonCrypto (`CC_SHA512`) |
| HMAC-SHA256 | [RFC 2104](https://datatracker.ietf.org/doc/html/rfc2104) | Yes | JCA (`Mac`) | JCA (`Mac`) | CommonCrypto (`CCHmac`) |
| HKDF-SHA256 | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | Yes | JCA HMAC (`Mac`) | JCA HMAC (`Mac`) | CCHmac (`CCHmac`) |
| X25519 | [RFC 7748 §5](https://datatracker.ietf.org/doc/html/rfc7748#section-5) | Yes | JCA (`KeyAgreement`) | JCA (`KeyAgreement`, API 29+) | Security.framework (`SecKeyCopyKeyExchangeResult`, iOS 14+) |
| Ed25519 | [RFC 8032 §5.1](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1) | Yes | JCA (`Signature`) | JCA (`Signature`, API 29+) | Security.framework (`SecKeyCreateSignature`, iOS 14+) |
| ChaCha20-Poly1305 | [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) | Yes | JCA (`Cipher`) | JCA (`Cipher`, API 29+) | CryptoKit provider only (see note) |

## Native availability by API level

On Android, SHA-256, SHA-512, HMAC-SHA256, and HKDF-SHA256 are available on all supported API levels (21+). X25519, Ed25519, and ChaCha20-Poly1305 require API 29 or higher for the JCA native path. On devices below that level, the library falls back to the pure-Kotlin implementation automatically.

| Primitive | Android minimum for native path | Fallback when below |
|---|---|---|
| SHA-256 | API 21 (always available) | N/A |
| SHA-512 | API 21 (always available) | N/A |
| HMAC-SHA256 | API 21 (always available) | N/A |
| HKDF-SHA256 | API 21 (uses HMAC) | Pure-K |
| X25519 | API 29 | Pure-K |
| Ed25519 | API 29 | Pure-K |
| ChaCha20-Poly1305 | API 29 | Pure-K |

## iOS native path note

iOS targets reach native crypto through Kotlin/Native interop with Apple C frameworks. SHA-256, SHA-512, HMAC-SHA256, and HKDF use CommonCrypto and Security.framework C APIs directly.

ChaCha20-Poly1305 has **no C API in CommonCrypto**. The native path on iOS is exclusively the injected `CryptoProvider` (CryptoKit). If no provider is injected, the library falls back to the pure-Kotlin implementation.

See [ADR-0002](../adr/0002-fallback-strategy.md) for the dispatch rationale and [ADR-0001](../adr/0001-field-arithmetic-radix-2-26.md) for the field engine.

## Output sizes

| Primitive | Output size | Key size |
|---|---|---|
| SHA-256 | 32 bytes | N/A |
| SHA-512 | 64 bytes | N/A |
| HMAC-SHA256 | 32 bytes | Any (keys > 64 bytes are pre-hashed) |
| HKDF-SHA256 | Variable (up to 8160 bytes) | Same as HMAC-SHA256 |
| X25519 | 32 bytes | 32 bytes (scalar) |
| Ed25519 | 64 bytes (signature) | 32 bytes (seed) |
| ChaCha20-Poly1305 | Plaintext length + 28 bytes (12 nonce + 16 tag) | 32 bytes |

## Public key derivation

The library provides public key derivation as a convenience API layered on top of the X25519 and Ed25519 primitives. This is the same scalar multiplication used during key agreement and signing — the public key is derived from the private key material using the standard base point (X25519) or the RFC 8032 algorithm (Ed25519).

| Operation | Facade | Input | Output |
||---|---|---|
| X25519 public key | `Crypto.deriveX25519PublicKey` / `KeyExchange.deriveX25519PublicKey` | `PrivateKey` (32-byte scalar) | 32-byte u-coordinate |
| Ed25519 public key | `Crypto.ed25519PublicKeyFromPrivate` / `Signer.ed25519PublicKeyFromPrivate` | `PrivateKey` (32-byte seed) | 32-byte public key |
| Random bytes | `Crypto.randomBytes` | `size: Int` | `size` random bytes |
