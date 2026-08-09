package ch.trancee.meshlink.crypto

internal actual object X25519 {
  actual fun compute(@Secret scalar: ByteArray, @Secret u: ByteArray): ByteArray =
      X25519PureK.compute(scalar, u)
}
