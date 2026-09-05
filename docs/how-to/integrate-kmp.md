# How to: Integrate MeshLink-crypto into a KMP Project

> **How-to guide.** This guide shows you how to add the library to an existing Kotlin Multiplatform project and call it from common code. It assumes you have a KMP project with at least one target configured.

## Option A: From a local Maven publish

1. Build and publish the library locally:

```bash
cd /path/to/MeshLink-crypto
./gradlew :crypto:publishToMavenLocal --rerun-tasks --no-build-cache
```

2. Add `mavenLocal()` to your project's `settings.gradle.kts` or `build.gradle.kts`:

```kotlin
dependencyResolution {
    repositories {
        mavenLocal()
        google()
        mavenCentral()
    }
}
```

3. Add the dependency in your shared module:

```kotlin
// shared/build.gradle.kts
kotlin {
    jvm()
    android()
    iosArm64()
    // ... your targets

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("ch.trancee.meshlink:meshlink-crypto:0.1.1-SNAPSHOT")
            }
        }
    }
}
```

## Option B: Via Gradle composite build

1. Add the library as a composite build in your `settings.gradle.kts`:

```kotlin
includeBuild("../path/to/MeshLink-crypto") {
    // The library's :crypto project is the dependency target.
    nameOverride = "MeshLink-crypto"
}
```

2. Add the dependency:

```kotlin
// shared/build.gradle.kts
val commonMain by sourceSets.getting {
    dependencies {
        implementation("ch.trancee.meshlink:meshlink-crypto")
    }
}
```

## Calling the library from common code

Import the public API in your shared module's Kotlin code:

```kotlin
import ch.trancee.meshlink.crypto.Crypto
import ch.trancee.meshlink.crypto.SecretKey
import ch.trancee.meshlink.crypto.PrivateKey
import ch.trancee.meshlink.crypto.PublicKey

// Hash
val digest = Crypto.sha256(data).getOrThrow()

// Key exchange (X25519)
val secret = Crypto.x25519(PrivateKey(myScalar), PublicKey(theirPublic)).getOrThrow()

// HKDF
val sessionKey = Crypto.hkdfSha256(secret, salt, info, 32).getOrThrow()

// Encrypt with derived session key
SecretKey(sessionKey).use { key ->
    val ciphertext = Crypto.chacha20Poly1305Encrypt(key, plaintext).getOrThrow()
}
```

## iOS: Injecting CryptoKit for Secure Enclave support

On iOS, the library uses CommonCrypto and Security.framework by default. If you need Secure Enclave-backed keys, inject a CryptoKit provider:

1. Create a Swift class that implements the `CryptoProvider` protocol:

```swift
// App.swift
import CryptoKit

class CryptoKitProvider: NSObject, CryptoProvider {
    func supportsX25519() -> Bool { true }
    func supportsEd25519() -> Bool { true }
    func supportsChaCha20Poly1305() -> Bool { true }
    // ... implement each method
}
```

2. Set it at app startup:

```swift
KMP.setCryptoProvider(CryptoKitProvider())
```

The library checks the provider first. It falls back to C-API native, then to pure-Kotlin, automatically.

## Verifying the integration

Run your app. If the build succeeds and calls return results, the integration worked. See [Run Checks](../how-to/run-checks.md) for running the test suite locally.
