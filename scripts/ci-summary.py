#!/usr/bin/env python3
"""Generate an inline GitHub Actions summary from kover XML + JUnit XML reports.

Produces three sections in the GitHub Actions step summary:
  1. Coverage summary (kover branch + instruction coverage)
  2. Test results (per-platform pass/fail/skipped)
  3. Crypto dispatch verification (per-test dispatch path: native vs PureK)

Dispatch tests are in jvmTest (DispatchVerificationTest, PureKFallbackVerificationTest,
DispatchBridgeTest) and commonTest (runs on iOS too). The `COMPILE_SDK` env var
(from the android-matrix job) is compile-time only — tests always run on JVM (JDK 21).
"""

import xml.etree.ElementTree as ET
import glob
import os
import sys


# Map test method names to (primitive, operation). Used for both
# DispatchVerificationTest (native path), PureKFallbackVerificationTest
# (PureK path), and DispatchBridgeTest (reflection-based fallback simulation).
DISPATCH_TEST_MAP = {
    # DispatchVerificationTest (native path via public API)
    "sha256_dispatchProducesCorrectDigest": ("SHA-256", "digest"),
    "sha512_dispatchProducesCorrectDigest": ("SHA-512", "digest"),
    "hmacSha256_digestProducesCorrectTag": ("HMAC-SHA-256", "digest"),
    "hmacSha256_verifyAcceptsCorrectTag": ("HMAC-SHA-256", "verify"),
    "hkdfSha256_dispatchProducesCorrectOutput": ("HKDF-SHA-256", "derive"),
    "x25519_dispatchProducesCorrectSharedSecret": ("X25519", "compute"),
    "ed25519_dispatchSignsCorrectly": ("Ed25519", "sign+verify"),
    "chacha20Poly1305_dispatchRoundTripsCorrectly": ("ChaCha20-Poly1305", "encrypt+decrypt"),
    "chacha20Poly1305_dispatchRejectsTamperedCiphertext": ("ChaCha20-Poly1305", "AEAD reject"),
    # PureKFallbackVerificationTest (PureK path, calling PureK objects directly)
    "sha256_pureKFallbackProducesCorrectDigest": ("SHA-256", "digest"),
    "sha512_pureKFallbackProducesCorrectDigest": ("SHA-512", "digest"),
    "hmacSha256_pureKFallbackProducesCorrectTag": ("HMAC-SHA-256", "digest"),
    "hmacSha256_pureKFallbackVerifyAcceptsCorrectTag": ("HMAC-SHA-256", "verify"),
    "hkdfSha256_pureKFallbackProducesCorrectOutput": ("HKDF-SHA-256", "derive"),
    "x25519_pureKFallbackProducesCorrectSharedSecret": ("X25519", "compute"),
    "ed25519_pureKFallbackSignsCorrectly": ("Ed25519", "sign+verify"),
    "chacha20Poly1305_pureKFallbackRoundTripsCorrectly": ("ChaCha20-Poly1305", "encrypt+decrypt"),
    "chacha20Poly1305_pureKFallbackRejectsTamperedCiphertext": ("ChaCha20-Poly1305", "AEAD reject"),
    # DispatchBridgeTest (reflection-based: simulate Android < API 29 by setting
    # fallback flags to true, then verify the elvis pattern falls back to PureK)
    "x25519_nativePathProducesCorrectResult": ("X25519", "compute (native)"),
    "x25519_fallbackPathActivatesWhenFlagSet": ("X25519", "fallback (simulated)"),
    "ed25519_nativePathSignsAndVerifies": ("Ed25519", "sign+verify (native)"),
    "ed25519_fallbackPathActivatesWhenFlagSet": ("Ed25519", "fallback (simulated)"),
    "chacha20Poly1305_nativePathRoundTrips": ("ChaCha20-Poly1305", "encrypt+decrypt (native)"),
    "chacha20Poly1305_fallbackPathActivatesWhenFlagSet": ("ChaCha20-Poly1305", "fallback (simulated)"),
    "hmacSha256_fallbackFlagExistsButUnused": ("HMAC-SHA-256", "flag check (native)"),
}

# Per-platform dispatch path for each primitive. On JVM the native path is JCA
# (all primitives available on JDK 21). On iOS the native path is Darwin
# (CommonCrypto / Security.framework), except ChaCha20-Poly1305 which has no
# CryptoKit C-API and uses PureK.
PLATFORM_DISPATCH = {
    "jvmTest": {
        "SHA-256": "native (JCA)",
        "SHA-512": "native (JCA)",
        "HMAC-SHA-256": "native (JCA)",
        "HKDF-SHA-256": "native (JCA)",
        "X25519": "native (JCA)",
        "Ed25519": "native (JCA)",
        "ChaCha20-Poly1305": "native (JCA)",
    },
    "iosSimulatorArm64Test": {
        "SHA-256": "native (Darwin)",
        "SHA-512": "native (Darwin)",
        "HMAC-SHA-256": "native (Darwin)",
        "HKDF-SHA-256": "native (Darwin)",
        "X25519": "native (Darwin)",
        "Ed25519": "native (Darwin)",
        "ChaCha20-Poly1305": "PureK fallback",
    },
}


def parse_testsuite(path):
    """Return (tests, failures, skipped, name) for a JUnit XML file, or None."""
    try:
        root = ET.parse(path).getroot()
        ts = root if root.tag == "testsuite" else root.find("testsuite")
        if ts is None:
            return None
        t = int(ts.get("tests", "0"))
        fa = int(ts.get("failures", "0"))
        sk = int(ts.get("skipped", "0"))
        name = ts.get("name", os.path.basename(path))
        return t, fa, sk, name
    except Exception:
        return None


def parse_dispatch_tests(path):
    """Parse <testcase> elements from a JUnit XML and return per-test results.

    Returns a list of (primitive, operation, passed, dispatch_path, platform_label) tuples.
    """
    try:
        root = ET.parse(path).getroot()
        ts = root if root.tag == "testsuite" else root.find("testsuite")
        if ts is None:
            return []
        suite_dir = os.path.basename(os.path.dirname(path))
        platform_label = friendly_label(suite_dir)
        results = []
        for tc in ts.findall("testcase"):
            name = tc.get("name", "")
            classname = tc.get("classname", "")
            # Strip JUnit5 parameterized suffixes: "[jvm]" / "[iosSimulatorArm64]"
            method = name.split("(")[0].split("[")[0]
            if method not in DISPATCH_TEST_MAP:
                continue
            primitive, operation = DISPATCH_TEST_MAP[method]
            failure = tc.find("failure") is not None
            error = tc.find("error") is not None
            passed = not failure and not error
            # Determine dispatch path
            is_purek = "PureKFallbackVerificationTest" in classname
            if is_purek:
                dpath = "PureK fallback"
            elif "DispatchBridgeTest" in classname:
                if "fallbackPath" in method:
                    dpath = "PureK fallback (simulated)"
                else:
                    dpath = dispatch_label(suite_dir, primitive)
            else:
                dpath = dispatch_label(suite_dir, primitive)
            results.append((platform_label, primitive, operation, dpath, passed))
        return results
    except Exception:
        return []


def friendly_label(suite_dir):
    """Map Gradle test-result directory names to friendly platform labels.

    When COMPILE_SDK is set (matrix job), include it in the label to make
    clear that compilation targets a specific Android API, while tests run
    on the JVM — compileSdk does NOT affect runtime dispatch.
    """
    compile_sdk = os.environ.get("COMPILE_SDK", "")
    if suite_dir == "jvmTest":
        if compile_sdk:
            return f"JVM [JDK 21] / compileSdk={compile_sdk}"
        return "JVM [JDK 21]"
    if suite_dir == "iosSimulatorArm64Test":
        return "iOS Simulator (arm64)"
    return suite_dir.replace("Test", "")


def dispatch_label(suite_dir, primitive):
    """Return the human-readable dispatch path for a primitive on a platform."""
    table = PLATFORM_DISPATCH.get(suite_dir, {})
    return table.get(primitive, "native")


def main():
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        print("GITHUB_STEP_SUMMARY not set — skipping summary generation.", file=sys.stderr)
        sys.exit(0)

    lines = []

    # --- Kover branch + instruction coverage ---
    total_branch_m = total_branch_c = 0
    total_inst_m = total_inst_c = 0
    missed_classes = []
    kover_available = False
    try:
        root = ET.parse("crypto/build/reports/kover/report.xml").getroot()
        kover_available = True
        for cls in root.iter("class"):
            name = cls.get("name", "").split("/")[-1]
            for c in cls.iter("counter"):
                if c.get("type") == "BRANCH":
                    m = int(c.get("missed", "0"))
                    cv = int(c.get("covered", "0"))
                    total_branch_m += m
                    total_branch_c += cv
                    if m > 0 and name:
                        missed_classes.append((name, m, cv))
                elif c.get("type") == "INSTRUCTION":
                    total_inst_m += int(c.get("missed", "0"))
                    total_inst_c += int(c.get("covered", "0"))
    except FileNotFoundError:
        pass

    if kover_available:
        total_b = total_branch_m + total_branch_c
        pct = round(100 * total_branch_c / total_b, 2) if total_b > 0 else 0
        total_i = total_inst_m + total_inst_c
        inst_pct = round(100 * total_inst_c / total_i, 2) if total_i > 0 else 0

        lines.append("## Coverage Summary (kover)")
        lines.append("")
        lines.append("| Metric | Coverage | Covered | Missed |")
        lines.append("|---|---|---|---|")
        lines.append(f"| Branch | {pct}% | {total_branch_c} | {total_branch_m} |")
        lines.append(f"| Instruction | {inst_pct}% | {total_inst_c} | {total_inst_m} |")
        lines.append("")
        if missed_classes:
            lines.append("| Class | Missed | Covered |")
            lines.append("|---|---|---|")
            for name, m, cv in sorted(missed_classes):
                lines.append(f"| {name} | {m} | {cv} |")
        else:
            lines.append("_No missed branches_")
        lines.append("")

    # --- JUnit test results ---
    test_files = sorted(glob.glob("crypto/build/test-results/*/*.xml"))
    if test_files:
        total_t = total_f = total_s = 0
        failures = []
        for f in test_files:
            result = parse_testsuite(f)
            if result is None:
                continue
            t, fa, sk, name = result
            total_t += t
            total_f += fa
            total_s += sk
            if fa > 0:
                failures.append(name)

        passed = total_t - total_f - total_s

        lines.append("## Test Results Summary")
        lines.append("")
        lines.append("| Platform | Tests | Passed | Failed | Skipped |")
        lines.append("|---|---|---|---|---|")

        seen = set()
        for f in test_files:
            suite_dir = os.path.basename(os.path.dirname(f))
            if suite_dir in seen:
                continue
            seen.add(suite_dir)
            s_t = s_f = s_s = 0
            for f2 in sorted(glob.glob(f"crypto/build/test-results/{suite_dir}/*.xml")):
                result = parse_testsuite(f2)
                if result is None:
                    continue
                t, fa, sk, _ = result
                s_t += t
                s_f += fa
                s_s += sk
            s_p = s_t - s_f - s_s
            label = friendly_label(suite_dir)
            lines.append(f"| {label} | {s_t} | {s_p} | {s_f} | {s_s} |")

        lines.append(f"| **Total** | **{total_t}** | **{passed}** | **{total_f}** | **{total_s}** |")

        # --- Crypto dispatch verification (per-test) ---
        dispatch_tests = []
        for f in test_files:
            for platform_label, prim, op, dpath, passed_test in parse_dispatch_tests(f):
                dispatch_tests.append((platform_label, prim, op, dpath, passed_test))

        if dispatch_tests:
            lines.append("")
            lines.append("### Crypto Dispatch Verification")
            lines.append("")
            lines.append("| Platform | Primitive | Operation | Dispatch | Result |")
            lines.append("|---|---|---|---|---|")
            for label, prim, op, dpath, passed_test in dispatch_tests:
                status = "pass" if passed_test else "FAIL"
                lines.append(f"| {label} | {prim} | {op} | {dpath} | {status} |")

            # --- SDK-level dispatch notes ---
            compile_sdk = os.environ.get("COMPILE_SDK", "")
            if compile_sdk:
                lines.append("")
                lines.append(
                    f"_Matrix job: **compileSdk={compile_sdk}** (compile-time only). "
                    + "Tests run on **JVM (JDK 21)**, not on Android runtime. "
                    + "On JDK 21, JCA handles all primitives, so dispatch is always `native (JCA)`. "
                    + "On physical Android < API 29, JCA lacks X25519/Ed25519/ChaCha20-Poly1305, "
                    + "so those primitives fall back to PureK. "
                    + "DispatchBridgeTest (jvmTest) verifies this fallback via reflection._"
                )

        if failures:
            lines.append("")
            lines.append(f"**Failed suites:** {', '.join(failures)}")

    if lines:
        with open(summary_path, "a") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
