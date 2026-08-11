/*
 * Android actual for [setCryptoProvider].
 *
 * Holds the injected crypto provider (or null) as a package-level var.
 * Android does NOT inherit jvmMain in KMP, so this declares its own copy
 * of the provider var.
 *
 * This file contains NO @Secret parameters — the provider-variable branches
 * live in CryptoBridge.kt (also no @Secret params), keeping the detekt
 * ConstantTimeRule (ADR-0003) from flagging provider-selection branches.
 */
package ch.trancee.meshlink.crypto

import kotlin.jvm.JvmName

@set:JvmName("setCryptoProviderInternal") internal var cryptoProvider: CryptoProvider? = null

actual fun setCryptoProvider(provider: CryptoProvider?) {
  cryptoProvider = provider
}
