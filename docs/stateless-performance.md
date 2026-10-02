# Stateless inventory performance

Measured October 2, 2026 on an arm64 Mac, macOS 27.0 (26A428), official Rust 1.93.0.
These are local development measurements, not a speed comparison with DiskTree,
MacTree, DiskHound or a shipping MacAudit release.

## Method

`cargo bench --bench inventory` creates isolated temporary fixtures, warms them,
then records 30 traversals per shape. Each traversal uses eight filesystem
workers, a separate inventory aggregator, bounded projection and JSON encoding.
The publication probe performs a bounded projection of the first nonempty
inventory. When traversal finishes before a publication deadline, the reported
first-ready time is final serialized-scene availability instead.

Criterion additionally uses 20 samples, one second of warmup and three seconds
of target measurement time. It measures only the Rust walker/inventory path:
classification, global audits, UniFFI, Swift decoding, scene geometry, native
rendering and user input are not included. The directory arena remains retained;
a complete file inventory does not.

## Warm fixture results

| Shape | Entries | Total p50 / p95 | First inventory or completion p50 / p95 | Scene JSON |
| --- | ---: | ---: | ---: | ---: |
| Flat | 10,000 files | 8.754 / 9.112 ms | 8.754 / 9.112 ms | 240 B |
| Wide | 10,000 folders + 10,000 files | 113.458 / 114.819 ms | 107.183 / 107.427 ms | 94,558 B |
| Deep | 128 levels + 4,096 files | 9.497 / 10.135 ms | 9.497 / 10.135 ms | 618 B |
| Hardlinked | 10,000 file entries, 100 unique files | 8.485 / 8.760 ms | 8.485 / 8.760 ms | 234 B |

An additional 10,000-file / 100-folder fixture records 2.968 / 3.317 ms p50/p95
and 19,943 B JSON. Projecting 500 rows from a 100,000-directory arena takes
approximately 419 microseconds in Criterion. Final scenes preserve residual
allocation instead of expanding all files into rows or tiles.

The process-wide engine reservation high-water mark is 10,276,166 B across this
sequence. This includes earlier measurements in the same process; it is not an
independent per-fixture memory measurement. Running the benchmark executable
directly under `/usr/bin/time -l` records 139,575,296 B maximum RSS and 133,841,520 B
peak memory footprint. RSS includes allocator, runtime, Criterion, fixtures and
framework costs and is not equivalent to engine reservations. Compiler RSS is
excluded from that direct-executable measurement.

## Interpretation and remaining measurements

Warm timings vary with filesystem cache and development workloads. This run
starts after native builds and the validation suites finish; compiler RSS is
not included. Criterion estimates are about 3.77 ms for the 100-folder scan,
115 ms for the wide scan, 8.79 ms for the deep scan and 9.67 ms for hardlinks;
they are separate from the manual p50/p95 samples. The stored intermediate
Criterion baseline reports approximately 12% slower deep traversal, but it
used a different Rust compiler and earlier implementation. Other shapes are
faster against that same uncontrolled baseline. These deltas cannot establish
a product regression or speedup. Repeat a controlled old/new full-pipeline
comparison before attributing them to architecture changes.

Native first useful display, FFI query p50/p95, main-actor duration, blocked-I/O
cancellation latency and a controlled old/new full-application comparison are
still separate measurements. Opt-in engine and Swift traces provide their
instrumentation. Real File Provider, macOS 14, VoiceOver and distribution-signing
checks remain the native release gates documented in `stateless-validation.md`.
