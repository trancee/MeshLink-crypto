# Benchmark regression check: mandatory JMH benchmarks per primitive and before/after comparison on every primitive code change

## Status

accepted

## Context

This library checks correctness with Wycheproof. It checks constant-time safety with a static lint and a timing harness (ADR-0003). It checks build quality with ktfmt, detekt, and kover. Coverage must be 100% on the pure-K path (ADR-0007).

The library did not check performance. A refactor can widen a loop. A refactor can add a data-dependent branch. A refactor can shift work between the pure-K path and the native fallback. These changes can lower throughput. The existing gates do not catch this.

The pure-K path runs on every KMP target. A slowdown in the pure-K path slows every consumer.

## Note on Wycheproof coverage

ADR-0003 uses Wycheproof as the correctness oracle. The two shipped primitives, SHA-256
and SHA-512, **do not have Wycheproof vectors**. They use RFC 6234 Appendix B known-answer
vectors instead.

- Correctness oracle for primitives with a Wycheproof corpus: Wycheproof.
- Correctness oracle for SHA-256 and SHA-512: RFC 6234 Appendix B.

## Decision

1. **Every crypto primitive ships a JMH microbenchmark.**
   - Location: `crypto/src/jvmBenchmark/`.
   - Coverage: the one-shot path and the incremental path, at block-size boundaries.
   - Template: `SHA256Benchmark` and `SHA512Benchmark`.
   - A primitive is not shipped until its benchmark exists alongside its correctness
     vectors.

2. **Any code change to a pure-K crypto primitive requires a before/after benchmark
   comparison.**
   - Command: `./gradlew :crypto:jvmBenchmarkBenchmark` (see `docs/agents/build.md`).
   - Host: a quiet host, not a CI runner. The JVM is not deterministic.
   - Record: mean ns/op and ops/s for each benchmark in the PR.

3. **A regression blocks merge.**
   - Definition: more than 10% slower on any benchmarked path, same host.
   - An improvement of any size is accepted. The comparison is the gate, not the
     direction.

4. **Native-fallback changes where the pure-K path is unchanged are exempt from the
   comparison.**
   - Reason: the pure-K benchmark covers all KMP targets.
   - Requirement: the benchmark must still exist for the primitive.

5. **Each new benchmark class is excluded from the kover coverage gate.**
   - Mechanism: `classes("ch.trancee.meshlink.crypto.*Benchmark")` in the kover
     excludes block (`crypto/build.gradle.kts`).
   - Reason: benchmarks are dev-only tooling. They have no tests. They must not
     lower the 100% pure-K gate (ADR-0007). One wildcard covers every new
     primitive, so no manual edit is needed.

## Consequences

- Benchmarks are part of the definition of done for a primitive. They are not optional.
- The kover exclude uses one wildcard. New primitives do not need a manual edit to
  the exclude list.
- The comparison is developer-run. CI does not gate on it. The committed benchmark
  source lets CI replay any regression at will.
- Primitives without an existing benchmark have no "before". Rule 2 applies only to
  changes against a previously-shipped benchmark.

## Corroborating research

See `docs/agents/build.md` for the capture-and-compare procedure.
