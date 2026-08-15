# How to: Get Started with MeshLink-crypto

> **How-to guide.** This guide shows you how to add the library to a Kotlin project and make your first calls. It assumes you know Kotlin and Gradle. For a step-by-step learning lesson, see the [First Encryption tutorial](../tutorials/first-encryption.md).

## Prerequisites

- Kotlin Multiplatform 2.4.10
- JDK 21 (pinned at `jvmToolchain(21)`)
- Android SDK (if you build the Android target)
- A Mac with Xcode (if you build the iOS target)

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

## Step 1: Add the dependency

The library is not yet published to a public Maven repository. Until release, use one of two options:

### Option A: Local Maven publish

1. Build and publish to your local Maven cache:

```bash
./gradlew :crypto:publishToMavenLocal --rerun-tasks --no-build-cache
```

2. Add the local repository and dependency to your project's `build.gradle.kts`:

```kotlin
repositories {
    mavenLocal()
    // ... your other repositories
}

kotlin {
    jvm()
    android()
    iosArm64()
    // ... your other targets
}

dependencies {
    implementation("ch.trancee.meshlink:crypto:0.1.0-SNAPSHOT")
}
```

### Option B: Gradle composite build

1. Clone this repository alongside your project.
2. Add a composite build entry in `settings.gradle.kts`:

```kotlin
includeBuild("../MeshLink-crypto")
```

3. Add the dependency:

```kotlin
dependencies {
    implementation("ch.trancee.meshlink:crypto")
}
```

## Step 2: Make your first call

Hash a message with SHA-256:

```kotlin
import ch.trancee.meshlink.crypto.Hasher

val digest = Hasher.sha256("hello".encodeToByteArray()).getOrThrow()
```

Sign a message with Ed25519:

```kotlin
import ch.trancee.meshlink.crypto.Signer
import ch.trancee.meshlink.crypto.PrivateKey

val key = PrivateKey(secretKeyBytes)
val signature = Signer.ed25519Sign(key, message).getOrThrow()
```

Derive a key with HKDF:

```kotlin
import ch.trancee.meshlink.crypto.Kdf

val okm = Kdf.hkdfSha256(ikm, salt, info, outputLength = 32).getOrThrow()
```

Encrypt with ChaCha20-Poly1305:

```kotlin
import ch.trancee.meshlink.crypto.Aead
import ch.trancee.meshlink.crypto.SecretKey

SecretKey(keyBytes).use { key ->
    val encrypted = Aead.chacha20Poly1305Encrypt(key, message).getOrThrow()
}
```

## Step 3: (Optional) Inject a native provider

On iOS, you can inject a CryptoKit-backed provider for hardware acceleration:

```swift
// In your iOS app startup
import Shared
import CryptoKit

let provider = CryptoKitProvider() // your Swift class implementing CryptoProvider
KMP.setCryptoProvider(provider)
```

If you do not set a provider, the library uses its native C-API path (CommonCrypto, Security.framework, JCA) or the pure-Kotlin fallback. See [Architecture](../explanation/architecture.md).

## Next steps

- [First Encryption tutorial](../tutorials/first-encryption.md)
- [Integrate into an existing KMP project](../how-to/integrate-kmp.md)
- [Run the test suite and quality gates](../how-to/run-checks.md)
- [Full API reference](../reference/api-reference.md)
