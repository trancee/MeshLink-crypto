package ch.trancee.meshlink.crypto

/**
 * Marks a value that **must** be handled in constant time.
 *
 * Primitives annotate their secret inputs (`key`, `nonce`, `hash state`, …) with `@Secret`. The
 * `:crypto-detekt-rules` `ConstantTimeRule` then statically bans any data-dependent branch
 * (`if`/`when`) or secret-dependent array index that touches a `@Secret` value, so timing leakage
 * is caught at compile time (ADR-0003, ticket 02).
 */
@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.BINARY)
public annotation class Secret
