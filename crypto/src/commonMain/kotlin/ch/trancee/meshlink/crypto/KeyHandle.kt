/*
 * Public API key handles (ADR-0005).
 *
 * Typed AutoCloseable wrappers around secret key material. The backing byte array
 * is zeroed on close(), so callers must use { } / use { } to scope the key
 * handle's lifetime.
 */
package ch.trancee.meshlink.crypto

/**
 * A symmetric secret key handle.
 *
 * The backing byte array is zeroed on [close]. Callers must scope usage with `use { }` or manually
 * call `close()` before the handle goes out of scope.
 *
 * @param material the raw key bytes (ownership transfers to the handle)
 */
public class SecretKey(
    @Secret private val material: ByteArray,
) : AutoCloseable {
  /** Returns a defensive copy of the key bytes. */
  public val bytes: ByteArray
    get() = material.copyOf()

  /** Zeroes the backing byte array. */
  override fun close() {
    material.fill(0)
  }
}

/**
 * A private key handle.
 *
 * The backing byte array is zeroed on [close].
 */
public class PrivateKey(
    @Secret private val material: ByteArray,
) : AutoCloseable {
  public val bytes: ByteArray
    get() = material.copyOf()

  override fun close() {
    material.fill(0)
  }
}

/**
 * A public key handle.
 *
 * Although public keys are not secret, [close] still zeroes the backing array for uniform lifecycle
 * management.
 */
public class PublicKey(
    private val material: ByteArray,
) : AutoCloseable {
  public val bytes: ByteArray
    get() = material.copyOf()

  override fun close() {
    material.fill(0)
  }
}
