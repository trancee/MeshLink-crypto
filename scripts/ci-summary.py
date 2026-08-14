#!/usr/bin/env python3
"""Generate an inline GitHub Actions summary from kover XML + JUnit XML reports.

Appends coverage and test-result markdown to $GITHUB_STEP_SUMMARY so reviewers
can inspect results directly in the Actions UI without downloading artifacts.

Usage:
  python3 scripts/ci-summary.py
  (expects GITHUB_STEP_SUMMARY env var to be set by the runner)
"""
import xml.etree.ElementTree as ET
import glob
import os
import sys


  # Map test method names to (primitive, operation). Used for both
  # DispatchVerificationTest (native path) and PureKFallbackVerificationTest
  # (PureK path). The dispatch path itself is determined by the test class name.
DISPATCH_TEST_MAP = {
    # DispatchVerificationTest (native path)
    "sha256_dispatchProducesCorrectDigest": ("SHA-256", "digest"),
    "sha512_dispatchProducesCorrectDigest": ("SHA-512", "digest"),
    "hmacSha256_digestProducesCorrectTag": ("HMAC-SHA-256", "digest"),
    "hmacSha256_verifyAcceptsCorrectTag": ("HMAC-SHA-256", "verify"),
    "hkdfSha256_dispatchProducesCorrectOutput": ("HKDF-SHA-256", "derive"),
    "x25519_dispatchProducesCorrectSharedSecret": ("X25519", "compute"),
    "ed25519_dispatchSignsCorrectly": ("Ed25519", "sign+verify"),
    "chacha20Poly1305_dispatchRoundTripsCorrectly": ("ChaCha20-Poly1305", "encrypt+decrypt"),
    "chacha20Poly1305_dispatchRejectsTamperedCiphertext": ("ChaCha20-Poly1305", "AEAD reject"),
    # PureKFallbackVerificationTest (PureK fallback path)
    "sha256_pureKFallbackProducesCorrectDigest": ("SHA-256", "digest"),
    "sha512_pureKFallbackProducesCorrectDigest": ("SHA-512", "digest"),
    "hmacSha256_pureKFallbackProducesCorrectTag": ("HMAC-SHA-256", "digest"),
    "hmacSha256_pureKFallbackVerifyAcceptsCorrectTag": ("HMAC-SHA-256", "verify"),
    "hkdfSha256_pureKFallbackProducesCorrectOutput": ("HKDF-SHA-256", "derive"),
    "x25519_pureKFallbackProducesCorrectSharedSecret": ("X25519", "compute"),
    "ed25519_pureKFallbackSignsCorrectly": ("Ed25519", "sign+verify"),
    "chacha20Poly1305_pureKFallbackRoundTripsCorrectly": ("ChaCha20-Poly1305", "encrypt+decrypt"),
    "chacha20Poly1305_pureKFallbackRejectsTamperedCiphertext": ("ChaCha20-Poly1305", "AEAD reject"),
    # DispatchBridgeTest (reflection-based fallback verification on JVM)
    "x25519_nativePathProducesCorrectResult": ("X25519", "compute"),
    "x25519_fallbackPathActivatesWhenFlagSet": ("X25519", "fallback"),
    "ed25519_nativePathSignsAndVerifies": ("Ed25519", "sign+verify"),
    "ed25519_fallbackPathActivatesWhenFlagSet": ("Ed25519", "fallback"),
    "chacha20Poly1305_nativePathRoundTrips": ("ChaCha20-Poly1305", "encrypt+decrypt"),
    "chacha20Poly1305_fallbackPathActivatesWhenFlagSet": ("ChaCha20-Poly1305", "fallback"),
    "hmacSha256_fallbackFlagExistsButUnused": ("HMAC-SHA-256", "flag check"),
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
    """Parse <testcase> elements from a JUnit XML and return per-test results
    for DispatchVerificationTest (native path), PureKFallbackVerificationTest
    (PureK path), and DispatchBridgeTest (reflection-based fallback verification).

    Returns a list of (primitive, operation, passed, is_purek, test_class) tuples.
    is_purek is True for PureKFallbackVerificationTest, False for native dispatch.
    DispatchBridgeTest tests are tagged as is_purek when the method name
    contains 'fallbackPath'.
    """
    try:
        root = ET.parse(path).getroot()
        ts = root if root.tag == "testsuite" else root.find("testsuite")
        if ts is None:
            return []
        results = []
        for tc in ts.findall("testcase"):
            name = tc.get("name", "")
            classname = tc.get("classname", "")
            # Strip JUnit5 parameterized suffixes: "[jvm]" / "[iosSimulatorArm64]"
            method = name.split("(")[0].split("[")[0]
            is_purek = "PureKFallbackVerificationTest" in classname
            is_bridge = "DispatchBridgeTest" in classname
            if not is_purek and "DispatchVerificationTest" not in classname and not is_bridge:
                continue
            if method not in DISPATCH_TEST_MAP:
                continue
            primitive, operation = DISPATCH_TEST_MAP[method]
            failure = tc.find("failure") is not None
            error = tc.find("error") is not None
            passed = not failure and not error
            # For DispatchBridgeTest, the *PathActivatesWhenFlagSet methods test
            # the simulated fallback — mark as is_purek for the summary table.
            if is_bridge and "fallbackPath" in method:
                is_purek = True
            results.append((primitive, operation, passed, is_purek, classname))
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
        # Collect dispatch info per source set directory
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

        # Per-source-set breakdown
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
            suite_dir = os.path.basename(os.path.dirname(f))
            platform_label = friendly_label(suite_dir)
            for primitive, operation, passed, is_purek, test_class in parse_dispatch_tests(f):
                if is_purek:
                    dpath = "PureK fallback"
                else:
                    dpath = dispatch_label(suite_dir, primitive)
                # For DispatchBridgeTest fallback tests, note this is simulated
                if "DispatchBridgeTest" in test_class and is_purek:
                    dpath = "PureK fallback (simulated)"
                dispatch_tests.append((platform_label, primitive, operation, dpath, passed))

        if dispatch_tests:
            lines.append("")
            lines.append("### Crypto Dispatch Verification")
            lines.append("")
            lines.append("| Platform | Primitive | Operation | Dispatch | Result |")
            lines.append("|---|---|---|---|---|")
            for label, prim, op, dpath, passed in dispatch_tests:
                status = "pass" if passed else "FAIL"
                lines.append(f"| {label} | {prim} | {op} | {dpath} | {status} |")

            # --- SDK-level dispatch notes ---
            compile_sdk = os.environ.get("COMPILE_SDK", "")
            if compile_sdk:
                lines.append("")
                lines.append(f"_Matrix job: **compileSdk={compile_sdk}** (compile-time only). "
                             + "Tests run on **JVM (JDK 21)**, not on Android runtime. "
                             + "On JDK 21, JCA provides all primitives natively, so dispatch "
                             + "is always `native (JCA)` regardless of compileSdk. "
                             + "On physical Android < API 29, JCA lacks X25519/Ed25519/"
                             + "ChaCha20-Poly1305, so those primitives fall back to PureK "
                             + "at runtime. PureK fallback correctness is verified "
                             + "independently by PureKFallbackVerificationTest (listed below "
                             + "as `PureK fallback`)._")
            # --- Expected Android SDK dispatch matrix ---
            lines.append("")
            lines.append("### Expected Android SDK Dispatch Matrix")
            lines.append("")
            lines.append(
                "_compileSdk (matrix job) is compile-time only. Tests run on JVM (JDK 21)."
            )
            lines.append("Actual runtime dispatch on physical Android depends on the SDK level:")
            lines.append("")
            lines.append("| Primitive | Android SDK 21–28 | Android SDK 29+ | JVM (JDK 21) | iOS (arm64) |")
            lines.append("|---|---|---|---|---|")
            sdk_matrix = [
                ("SHA-256", "JCA", "JCA", "JCA", "Darwin"),
                ("SHA-512", "JCA", "JCA", "JCA", "Darwin"),
                ("HMAC-SHA-256", "JCA", "JCA", "JCA", "Darwin"),
                ("HKDF-SHA-256", "JCA", "JCA", "JCA", "Darwin"),
                ("X25519", "PureK", "JCA", "JCA", "Darwin"),
                ("Ed25519", "PureK", "JCA", "JCA", "Darwin"),
                ("ChaCha20-Poly1305", "PureK", "JCA", "JCA", "PureK"),
            ]
            for prim, sdk21, sdk29, jvm, ios in sdk_matrix:
                lines.append(f"| {prim} | {sdk21} | {sdk29} | {jvm} | {ios} |")
            lines.append("")
            lines.append(
                "_DispatchBridgeTest (jvmTest) verifies the elvis fallback pattern "
                "(`nativeFn(args) ?: PureKFn(args)`) by setting fallback flags via reflection, "
                "simulating Android SDK < 29._"
            )

        if failures:
            lines.append("")
            lines.append(f"**Failed suites:** {', '.join(failures)}")

    # --- JMH benchmark results ---
    bench_file = os.environ.get("BENCH_RESULTS_FILE", "")
    bench_lines = []
    if bench_file and os.path.isfile(bench_file):
        try:
            with open(bench_file) as f:
                bench_lines = [line.strip() for line in f if line.strip()]
        except Exception:
            bench_lines = []

    if bench_lines:
        lines.append("## JMH Benchmark Results (PureK path)")
        lines.append("")
        lines.append("| Benchmark | Mode | Ops | Mean | Error | Unit |")
        lines.append("|---|---|---|---|---|---|")
        for line in bench_lines:
            parts = line.split()
            if len(parts) >= 7:
                bench_name = parts[0]
                mode = parts[1]
                ops = parts[2]
                mean = parts[3]
                err = parts[5]  # parts[4] is "±"
                unit = parts[6]
                lines.append(f"| {bench_name} | {mode} | {ops} | {mean} | ±{err} | {unit} |")
        lines.append("")
        lines.append("_Benchmarked on the PureK path (JMH, 2 warmups + 3 iterations, 1s each)._")
        lines.append("_See `crypto/src/jvmBenchmark/` for benchmark source code._")

    if lines:
        with open(summary_path, "a") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
