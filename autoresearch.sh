#!/bin/bash
# Autoresearch benchmark script for SHAKE128 throughput optimization.
# Runs the ArBenchmark test and parses the METRIC line from output.
set -e

echo "=== Running SHAKE128 throughput benchmark ==="

cd "$(dirname "$0")"

# Run the benchmark test (Gradle test with only the ArBenchmark class)
OUTPUT_FILE="crypto/build/ar-benchmark-output.txt"
rm -f "$OUTPUT_FILE"

./gradlew :crypto:jvmTest --tests "ch.trancee.meshlink.crypto.ArBenchmark" --rerun-tasks --no-build-cache 2>&1 | tail -5

# Parse the metric from the output file
if [ -f "$OUTPUT_FILE" ]; then
  METRIC_LINE=$(cat "$OUTPUT_FILE")
  echo "$METRIC_LINE"
  
  # Extract the metric value
  METRIC_VALUE=$(echo "$METRIC_LINE" | sed -n 's/.*shake128_throughput_mbps=\([0-9.]*\).*/\1/p')
  echo "RESULT: shake128_throughput_mbps=${METRIC_VALUE}"
else
  echo "ERROR: benchmark output not found"
  exit 1
fi
