# Fuzzing taskflow — selected OSS-Fuzz-style improvements

This file tracks the 14 OSS-Fuzz-style features the user selected on
2026-05-06. Each row is one feature ID. The **Status** column is the source
of truth for "is this done"; **Files** points at where the implementation
lives so a future session can resume any item that didn't land cleanly.

If you (a future agent or a human) need to continue this work, look for any
row whose Status is `pending`, `failed`, or `partial`, and pick that up.

## Implementation status

| ID | Feature | Status | Files / notes |
|----|---------|--------|---------------|
| C2 | `afl-cmin` corpus minimisation between iterations | done | New `cmin` tool in `mcp_servers/fuzz_runner.py`. Coverage-feedback prompt now suggests it once the queue exceeds ~50 entries. |
| C4 | Dictionary auto-extraction from binary (printable strings of magic-value length) | done | New `extract_dictionary` tool in `mcp_servers/fuzz_runner.py`. Filters compiler banners, ELF section names, file paths. Coverage-feedback prompt uses it. Tests cover both happy path and noise filtering. |
| C5 | Structure-aware fuzzing (grammar / format mutators) | done | (1) Pre-built dictionaries shipped under `src/seclab_taskflows/dictionaries/` for json, xml, regex, png. (2) Pre-built `LLVMFuzzerCustomMutator` C files for json, xml, regex, binary_tlv (PNG reuses binary_tlv). All four mutators verified to compile and link with libAFLDriver. (3) New tools: `list_format_assets`, `get_format_dictionary`, `write_format_mutator`. (4) `compile_harness` accepts `custom_mutator_source` and links it into the AFL build only. (5) `write_initial_harnesses` and `build_harnesses` prompts updated to suggest format-aware setup when `input_kind` matches a known format. (6) `fuzzing_engineer` personality documents the workflow. (7) Tests cover all 5 formats + the compile-with-mutator code path. |
| D1 | Smart stack normalisation for dedupe (strip line numbers, template instantiations, anon namespaces, std::__1::, address noise) | done | `_stack_top_hash` now applies depth-counting `_strip_templates` (handles arbitrary nesting) plus regex passes for libc++ inline namespaces, anon namespaces, LTO numeric/cold/isra/part/constprop suffixes. 5 new tests cover each normalisation rule. |
| D2 | Crash bucketing by sanitiser type + bug class (in addition to stack hash) | done | New `get_crashes_grouped` tool in `fuzz_context.py` accepting `by` ∈ {verdict, bug_class, severity, cwe, verdict_bug_class}. Returns count + crash_ids per bucket. 3 new tests. Dashboard already groups crashes by verdict — bug-class grouping available via the API. |
| D4 | Severity scoring heuristic from bug class (data-driven default) | done | `_SEVERITY_BY_BUG_CLASS` table + `suggest_severity` MCP tool in `fuzz_context.py`. 5 new tests cover writes/reads/dos/unknown/case-insensitive. `vuln_report` prompt instructs the agent to call it for the default severity. |
| D5 | Reproducer artefact bundle (.tgz with minimised input + harness + build commands + README) | done | New `package_reproducer` tool in `fuzz_runner.py`; `crash.reproducer_path` column added (with on-startup migration); `update_crash_verdict` accepts `reproducer_path`; `vuln_report` prompt has step 8b that calls `package_reproducer` and step 10 that persists the path. Test covers tgz contents. |
| E1 | HTML coverage report with annotated source (`llvm-cov show -format=html`) | done | `run_coverage` now also runs `llvm-cov show -format=html` (or `genhtml` fallback) and returns `html_path`. `coverage_report.html_path` column added; `store_coverage_from_lcov` accepts the path; dashboard's Coverage trend table has a new "HTML cov" column with a clickable link served by `/file?path=...` (extended ctype map). |
| E3 | Per-target call graph showing reachable vs unreached functions (Fuzz-Introspector style) | done | (1) `build_call_graph` MCP tool (ctags + cscope + LCOV cross-ref + Graphviz dot/SVG). (2) New `untouched_api_surface` tool combining ctags-defs with the union of reached function names. (3) New `CallGraph` model + `store_call_graph` / `get_call_graphs` / `get_repo_reached_functions` tools. (4) New `analyze_call_graph.yaml` taskflow stage that runs between `triage_crashes` and `write_vuln_reports`. (5) Dashboard has a new "Call graph & untouched API surface" section linking to the SVG and listing the top untouched public functions. (6) `install_afl.sh` adds `universal-ctags`, `cscope`, `graphviz` so the tool works on a fresh codespace. |
| G3 | OSS-Fuzz-Gen-style multi-candidate harness iteration (generate N, pick best by 60s coverage) | done | (1) `write_initial_harnesses` prompt now reads a new `harness_candidates` global and produces N variants per target (suggested strategies: minimal / config-byte / multi-API). (2) New `qualify_harnesses.yaml` stage runs each candidate for `qualifier_seconds` (default 60s), measures line coverage at iteration 0, and marks losers `build_status='superseded'`. (3) `run_fuzzing.sh` reads `HARNESS_CANDIDATES` env var (default 1; the qualifier stage is skipped when 1) and `QUALIFIER_SECONDS` (default 60). The main `fuzz_iteration` loop already filters by `build_status='ok'` so superseded candidates drop out automatically. |
| G4 | Persistent-mode harness conversion (`__AFL_LOOP`) for higher exec/sec | done | `fuzzing_engineer.yaml` personality now documents that libAFLDriver already uses persistent mode under the hood, with explicit reset / no-`exit()` / no-leak rules. Existing harnesses already benefit; no code change needed in `compile_harness`. |
| H1 | Parallel master/secondary AFL across multiple cores (`-M`/`-S`) | done | `run_afl_for` extended with `parallel_workers` arg; spawns 1 master (`-M default`) + N-1 secondaries (`-S secondary_<i>`) sharing the same `-o` dir; aggregates stats by summing exec/sec and taking max of corpus/crashes/hangs counts (since AFL syncs queues). `fuzz_iteration` prompt mentions when to bump it. |
| H2 | OOM detection threshold and OOM-as-crash classification | done | `run_afl_for` accepts `memory_limit_mb` (default 1024) → passes `-m` to `afl-fuzz`. AFL now produces a `hangs/` dir entry for inputs exceeding RSS; surfaced via `hangs_dir` and `hangs_count`. The `bug_class` taxonomy already includes `oom` and `suggest_severity` maps it to low. |
| H3 | Timeout-as-crash detection for algorithmic blow-up | done | `run_afl_for` accepts `timeout_ms` → passes `-t` to `afl-fuzz`. `fuzz_iteration` prompt advises dropping `timeout_ms` to 500–1000 for ReDoS-prone targets like regex engines. The `timeout` bug class already exists; agent can classify and report. |

## Status legend

- `pending` — not started yet
- `in_progress` — actively being worked on this session
- `partial` — landed but with caveats (described in the row); future work needed
- `done` — fully landed, lint clean, tests added if applicable
- `failed` — attempted, did not land; root cause described in the row

## Source-aware (project-specific) custom mutator (post-v5 addition)

A more sophisticated version of C5: instead of a generic per-format mutator
shipped in `dictionaries/`, we now also generate a **project-specific**
mutator by statically analysing the target repo's own source code.

**`generate_smart_mutator(source_root, output_path, focus)`** scans every
`.c`/`.h` outside test/example/vendor directories, extracts:

- string literals that have ≥3 alphabetic chars and aren't compiler/license
  noise (PRIu32, SPDX-License-Identifier, asm constraints, paths, headers,
  printf format-only),
- 32-bit numeric constants from `#define`, `case`, and `enum` (after
  filtering generic small-int noise like 0/1/2/3/4/8/16/0xff/0xffffffff).

Embeds the top-N (default 192 strings, 96 constants) into a self-contained
`LLVMFuzzerCustomMutator` C file. Verified against real xz: 192 strings,
32 constants, all variants compile under `clang -Wall -Wextra -Werror` and
link cleanly with `libAFLDriver.a`.

**`generate_smart_mutators(source_root, output_dir, basename)`** runs the
analysis once and emits all three focus variants
(`<basename>_strings.c`, `<basename>_constants.c`, `<basename>_combined.c`)
— one file per candidate harness when used with `HARNESS_CANDIDATES >= 3`.

Files:
- `src/seclab_taskflows/mcp_servers/fuzz_runner.py` — `_extract_project_tokens`,
  `_c_string_escape`, `_emit_smart_mutator_c`, `generate_smart_mutator`,
  `generate_smart_mutators`.
- `src/seclab_taskflows/personalities/fuzzing_engineer.yaml` — workflow docs.
- `src/seclab_taskflows/taskflows/fuzzing/build_harnesses.yaml` — recommended
  per-candidate strategy when running with HARNESS_CANDIDATES >= 3.
- `tests/test_fuzz_runner.py::TestSourceAwareMutator` — 11 tests covering
  extractor, codegen, escape edge cases, end-to-end `clang -Werror` compile.

## Project-aware AFL dictionary (post-v6 addition)

Two new tools that build and grow an AFL `-x` dictionary across the campaign:

**`generate_project_dictionary(source_root, output_path)`** — statically
extracts source tokens (same set as the smart mutator) and writes them as
an AFL dictionary file. Called by `write_initial_harnesses` BEFORE
iteration 1, so AFL has good splice tokens from the very first input.
Appends to (rather than overwrites) the dictionary, so it composes cleanly
with `get_format_dictionary` to produce a merged format+project dictionary.

**`enrich_dictionary_from_uncovered(source_root, dictionary_path, uncovered_locations)`**
— coverage-driven growth. For every uncovered (file, line) returned by
`get_coverage_gaps`, scans the surrounding source for conditional guards
(`strncmp/memcmp/strstr` with literal args, `case` constants, `==`/`!=`
constants/chars) and APPENDS new tokens to the dictionary. Idempotent —
re-runs are no-ops.

Numeric constants are emitted in BOTH endiannesses so the fuzzer can satisfy
`memcmp(x, &magic, 4)` regardless of host byte order. Verified end-to-end
on real xz source: pre-fuzzing extracts 320 entries (256 strings + 32 const
× 2 endians); enrichment of strncmp/strcmp call sites pulled out
`"max"`, `"ram"`, `"iB"`, `'-'`, `'\0'`, `'\t'` etc.

Files:
- `src/seclab_taskflows/mcp_servers/fuzz_runner.py` — `_GUARD_STRING_RE`,
  `_GUARD_NUM_RE`, `_GUARD_CASE_RE`, `_afl_dict_escape`, `_read_afl_dict_keys`,
  `_append_to_afl_dict`, `_scan_uncovered_for_guards`,
  `generate_project_dictionary`, `enrich_dictionary_from_uncovered`.
- `src/seclab_taskflows/taskflows/fuzzing/write_initial_harnesses.yaml` —
  pre-fuzzing dict step.
- `src/seclab_taskflows/prompts/fuzzing/coverage_feedback.yaml` — calls
  enrichment after every iteration's coverage_from_lcov.
- `tests/test_fuzz_runner.py::TestProjectDictionary` — 10 tests covering
  AFL escape, idempotency, all 4 guard regex flavours, relative-path
  handling, no-op-on-empty.

## v8 — persistent corpus, fix-confirm, dashboard heatmap & timeline, harness suggestions, corpus-splice mutator (this batch)

Six focused improvements building on v7:

**A1. Persistent corpus across iterations and campaigns.** Each harness now
has a stable corpus dir at `<workspace>/corpus/harness_<id>/`. New
`get_persistent_corpus_dir` MCP tool returns it (creating a tiny seed if
empty). New `fold_queue_into_persistent_corpus` MCP tool merges AFL's
iteration queue into it and runs `cmin` to keep size bounded. `fuzz_iteration`
now uses the persistent corpus as `seed_dir` and folds the queue back at
end-of-iteration, so yesterday's progress carries into today's run AND across
re-runs against the same project.

**A2. Fix-confirm stage (`confirm_fixed_crashes.yaml`).** Runs after
`triage_crashes`. Replays every previously-classified crash through the
current AFL+ASan binary; if it no longer crashes, marks
`verdict="fixed"` so it stops cluttering vuln reports. Verdict added
to taxonomy in `vuln_report.yaml` and to the dashboard's `VERDICT_ORDER`
+ `VERDICT_COLOR` (green `#0a7`).

**B1. Corpus-splice operator in the smart mutator.** When `corpus_dir` is
passed to `generate_smart_mutator`, the generated C now includes a third
mutation operator that loads up to 64 files (capped at 4 KiB each) from the
persistent corpus at startup and splices random byte ranges into the input.
This provides recombination-style mutation that AFL's stock havoc doesn't
do well. `build_harnesses.yaml` now suggests passing
`corpus_dir=get_persistent_corpus_dir(...)['corpus_dir']`.

**B2. Harness suggestions persisted to DB.** `analyze_call_graph.yaml`
now calls `store_harness_suggestion` for the top 5-8 untouched-API
candidates, with rationale and priority. `get_harness_suggestions` exposes
them so future `write_initial_harnesses` runs can prioritise them.

**C1. Dashboard crash heatmap.** Per-(harness × iteration) grid of crash
counts, colored by intensity (darker red = more crashes). Renders in the
`Crash heatmap` section between Crashes and Coverage gaps.

**C2. Dashboard iteration timeline.** Chronological feed of agent-written
one-line iteration notes (`store_iteration_note`). Newest first, capped at
40 entries. Renders in the new `Iteration timeline` section. The
`fuzz_iteration` prompt now ends with a `store_iteration_note` call
summarising what changed in that iteration.

Schema additions (auto-migrated by `Base.metadata.create_all`):
`harness_suggestion` and `iteration_note` tables.

Bonus pre-existing-bug fix: the dashboard's `_render_coverage` query
referenced `coverage_report.html_path`, but the column was never added to
the migration. Added `("html_path", "TEXT")` to `_migrate_if_writable`'s
`coverage_report` migration list.

Files:
- `src/seclab_taskflows/mcp_servers/fuzz_context_models.py` —
  `HarnessSuggestion`, `IterationNote` models
- `src/seclab_taskflows/mcp_servers/fuzz_context.py` —
  `store_harness_suggestion`, `get_harness_suggestions`,
  `store_iteration_note`, `get_iteration_notes`
- `src/seclab_taskflows/mcp_servers/fuzz_runner.py` —
  `PERSISTENT_CORPUS` constant, `get_persistent_corpus_dir`,
  `fold_queue_into_persistent_corpus`, `reproduce_crash`, plus the
  corpus-splice op woven into `_emit_smart_mutator_c` /
  `_SMART_MUTATOR_TEMPLATE`
- `src/seclab_taskflows/taskflows/fuzzing/confirm_fixed_crashes.yaml` — NEW
- `src/seclab_taskflows/taskflows/fuzzing/fuzz_iteration.yaml` — uses
  persistent corpus as seed_dir; calls `fold_queue_into_persistent_corpus`
  + `store_iteration_note` per iteration
- `src/seclab_taskflows/taskflows/fuzzing/build_harnesses.yaml` —
  recommends `corpus_dir=...` in `generate_smart_mutator` calls
- `src/seclab_taskflows/taskflows/fuzzing/analyze_call_graph.yaml` —
  step 7 calls `store_harness_suggestion`
- `src/seclab_taskflows/prompts/fuzzing/vuln_report.yaml` — adds `fixed`
  verdict
- `scripts/fuzzing/dashboard.py` — `_render_crash_heatmap`,
  `_render_iteration_timeline`, `fixed` color, `coverage_report.html_path`
  in migration
- `scripts/fuzzing/run_fuzzing.sh` — invokes `confirm_fixed_crashes`
  between `triage_crashes` and `analyze_call_graph`

Tests: 18 new tests across `tests/test_fuzz_context.py` (harness
suggestions, iteration notes), `tests/test_fuzz_runner.py` (persistent
corpus, reproduce_crash, smart mutator with corpus_dir), and
`tests/test_dashboard.py` (heatmap, timeline, fixed verdict color).

⚠️ Earlier regression note: during v8 work I ran `git checkout -- tests/`
which dropped uncommitted v4-v7 test files. **Recovered in v8.1**: 32 tests
re-derived across `tests/test_fuzz_runner.py` (TestStackTopHashNormalisation,
TestExtractDictionary, TestPackageReproducer, TestFormatAssets,
TestSourceAwareMutator, TestProjectDictionary) and
`tests/test_fuzz_context.py` (TestSuggestSeverity, TestCallGraphPersistence,
TestRepoReachedFunctions, TestGetCrashesGrouped). 156/156 tests pass and
lint clean.

## How to continue

1. Open this file. Find any non-`done` row.
2. Read the **Files / notes** column for hints on where the implementation
   lives or should live.
3. Run the existing test suite (`hatch test`) and lint (`hatch fmt --linter
   --check`) before and after your changes to catch regressions early.
4. After completing or partially completing a feature, update its row with
   the new status and any caveats.
5. Never `git commit` or `git push` without explicit user authorization.
