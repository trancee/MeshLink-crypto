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


def parse_dispatch_info(path):
    """Extract the DISPATCH_INFO line from a JUnit XML's <system-out>.

    The DispatchVerificationTest emits a marker line like:
      DISPATCH_INFO: provider=none(default), path=native, fallback=PureK
    This is captured in the JUnit XML's <system-out> element for CI visibility.
    """
    try:
        root = ET.parse(path).getroot()
        ts = root if root.tag == "testsuite" else root.find("testsuite")
        if ts is None:
            return None
        so = ts.find("system-out")
        if so is not None and so.text:
            for line in so.text.strip().splitlines():
                if line.startswith("DISPATCH_INFO:"):
                    return line
    except Exception:
        pass
    return None


def friendly_label(suite_dir, dispatch_info=None):
    """Map Gradle test-result directory names to friendly platform labels.

    If dispatch_info is available, append the active crypto path.
    """
    if suite_dir == "jvmTest":
        base = "JVM"
    elif suite_dir == "iosSimulatorArm64Test":
        base = "iOS Simulator (arm64)"
    else:
        base = suite_dir.replace("Test", "")
    if dispatch_info:
        # Extract just the path= part from "DISPATCH_INFO: provider=..., path=..., fallback=..."
        parts = dict(p.strip().split("=", 1) for p in dispatch_info.replace("DISPATCH_INFO: ", "").split(", "))
        path_type = parts.get("path", "unknown")
        if path_type == "native":
            if suite_dir == "jvmTest":
                path_type = "native (JCA)"
            elif suite_dir == "iosSimulatorArm64Test":
                path_type = "native (Darwin)"
        return f"{base} ({path_type})"
    return base


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
        dispatch_per_dir = {}
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
            # Parse dispatch info
            info = parse_dispatch_info(f)
            suite_dir = os.path.basename(os.path.dirname(f))
            if info and suite_dir not in dispatch_per_dir:
                dispatch_per_dir[suite_dir] = info

        passed = total_t - total_f - total_s

        lines.append("## Test Results Summary")
        lines.append("")
        lines.append("| Platform (dispatch) | Tests | Passed | Failed | Skipped |")
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
            label = friendly_label(suite_dir, dispatch_per_dir.get(suite_dir))
            lines.append(f"| {label} | {s_t} | {s_p} | {s_f} | {s_s} |")

        lines.append(f"| **Total** | **{total_t}** | **{passed}** | **{total_f}** | **{total_s}** |")
        if dispatch_per_dir:
            lines.append("")
            lines.append("### Crypto dispatch path")
            lines.append("")
            for suite_dir, info in sorted(dispatch_per_dir.items()):
                label = friendly_label(suite_dir, None)
                # Strip "DISPATCH_INFO: " prefix for display
                detail = info.replace("DISPATCH_INFO: ", "").strip()
                lines.append(f"- **{label}**: `{detail}`")
        if failures:
            lines.append("")
            lines.append(f"**Failed suites:** {', '.join(failures)}")

    if lines:
        with open(summary_path, "a") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
