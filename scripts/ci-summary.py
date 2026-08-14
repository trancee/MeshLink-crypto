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


def friendly_label(suite_dir):
    """Map Gradle test-result directory names to friendly platform labels."""
    if suite_dir == "jvmTest":
        return "JVM"
    if suite_dir == "iosSimulatorArm64Test":
        return "iOS Simulator (arm64)"
    return suite_dir.replace("Test", "")


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
    try:
        root = ET.parse("crypto/build/reports/kover/report.xml").getroot()
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
        total_branch_m = total_branch_c = -1

    total_b = total_branch_m + total_branch_c
    pct = round(100 * total_branch_c / total_b, 2) if total_b > 0 else 0
    total_i = total_inst_m + total_inst_c
    inst_pct = round(100 * total_inst_c / total_i, 2) if total_i > 0 else 0

    lines.append("## Coverage Summary (kover)")
    lines.append("")
    if total_b < 0:
        lines.append("_kover report not found — check step failed_")
    else:
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
            lines.append("_100% branch coverage — no missed branches_")

    lines.append("")
    lines.append("## Test Results Summary")
    lines.append("")
    lines.append("| Platform | Tests | Passed | Failed | Skipped |")
    lines.append("|---|---|---|---|---|")

    # Compute totals across all source sets
    total_t = total_f = total_s = 0
    failures = []
    for f in sorted(glob.glob("crypto/build/test-results/*/*.xml")):
        result = parse_testsuite(f)
        if result is None:
            continue
        t, fa, sk, name = result
        total_t += t
        total_f += fa
        total_s += sk
        if fa > 0:
            failures.append(name)

    # Per-source-set breakdown
    seen = set()
    for f in sorted(glob.glob("crypto/build/test-results/*/*.xml")):
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
    passed = total_t - total_f - total_s

    lines.append(f"| **Total** | **{total_t}** | **{passed}** | **{total_f}** | **{total_s}** |")
    if failures:
        lines.append("")
        lines.append(f"**Failed suites:** {', '.join(failures)}")

    with open(summary_path, "a") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
