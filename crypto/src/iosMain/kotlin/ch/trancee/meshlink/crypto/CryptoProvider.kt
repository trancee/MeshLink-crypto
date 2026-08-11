/*
 * iOS actual for [setCryptoProvider].
 *
 * Holds the injected CryptoKit provider (or null) as a package-level var.
 * The provider is set once at app startup; the PureK fallback covers any
 * visibility race.
 *
 * This file contains NO @Secret parameters — all branching over the provider
 * variable lives here or in CryptoBridge.kt, keeping the ConstantTimeRule
 * (ADR-0003) from flagging provider-selection branches.
 */
package ch.trancee.meshlink.crypto

internal var cryptoProvider: CryptoProvider? = null

actual fun setCryptoProvider(provider: CryptoProvider?) {
  cryptoProvider = provider
}
