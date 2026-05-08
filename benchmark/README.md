# Fuzzing benchmark

Reference projects we use to validate the fuzzing taskflow end-to-end. Each
entry is a small or well-known C/C++ project where AFL++ instrumentation works
out of the box.

Run any benchmark target with:

```bash
./scripts/fuzzing/run_fuzzing.sh <owner/repo>
```

(The fuzzing taskflow always operates on a single GitHub repository, so the
benchmark file lists repos one per row rather than wrapping them in a custom
runner.)

## Projects

| # | Repo | Why it's interesting | Notes |
|---|------|----------------------|-------|
| 1 | `tukaani-project/xz` | Real-world parser-heavy library (`liblzma`); rich filter chain + integer/VLI parsing surface | Our baseline |
| 2 | `DaveGamble/cJSON` | Small single-file C JSON parser; trivial CMake; classic fuzz target | Quick smoke for the pipeline |
| 3 | `akheron/jansson` | Compact C JSON library with documented `json_loadb()` byte-buffer entry point | CMake; very fast exec/sec |
| 4 | `libexpat/libexpat` | Mature streaming XML parser; large attack surface; many historical CVEs | CMake or autotools; classic fuzz target |
| 5 | `kkos/oniguruma` | Regex engine with state-machine compiler; takes attacker pattern + subject | Autotools; pattern compilation is the hot path |

## Most-recent benchmark results

These numbers come from end-to-end runs through the full v4 pipeline on the
codespace dev image. Coverage and crash counts depend on the underlying LLM and
the time budget cap (≈32 min/target).

| Repo | Targets | Harnesses built | AFL runs | Crashes | Verdicts seen |
|------|---------|-----------------|----------|---------|---------------|
| `tukaani-project/xz` | 8 | 8 | 48 | 0 | — |
| `DaveGamble/cJSON` | 6 | 6 | 36 | 0 | — |
| `akheron/jansson` | 7 | 7 | 35 | 10 | `harness_bug`, `library_hardening`, `duplicate`, `needs_investigation` |
| `libexpat/libexpat` | 3 | 3 | 18 | 0 | — |
| `kkos/oniguruma` | 10 | 10 | 60 | 13 | `vulnerability` (×2, OOB read in `regerror.c`), `library_hardening`, `harness_bug`, `non_reproducible` |

The xz / cJSON / libexpat zero-crash results are expected: those projects are
heavily fuzzed upstream. The two `vulnerability`-classified findings in
oniguruma are real out-of-bounds reads in the warning-formatting code path of
`onig_snprintf_with_pattern` (one-byte read past `pat_end` when the pattern
ends with a backslash); the per-crash markdown reports include suggested
patches.

## Adding a project

Add an entry to `projects.yaml` and (optionally) document why in this README.
Anything that the existing `analyze_build_system` stage can build with `clang`
+ AFL++ flags is a reasonable candidate. Pure-C parsers, decoders, and
serialisers tend to work best.

## Reading results

Each run writes:
- SQLite DB: `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_context/fuzz_context.db`
- Per-repo report: `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/repo/<owner>__<repo>/REPORT.md`
- Per-crash vuln reports: same directory, `vuln_<id>.md`
- Live dashboard during the run: <http://127.0.0.1:8765>
- Programmatic JSON snapshot: <http://127.0.0.1:8765/api/json> (or with `?repo=...`)
