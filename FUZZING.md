# Fuzzing Taskflow — Complete Reference

> An LLM-driven, OSS-Fuzz-style fuzzing pipeline for native C/C++ projects.
> AFL++ for execution, clang+lcov for coverage, an LLM agent for
> harness writing, coverage-feedback decisions, triage, and reporting.

This document is the single comprehensive reference for the fuzzing taskflow
shipped in this repository. If you want a 10-line quickstart, jump to
[Quick start](#quick-start). If you want to know what knob to turn, jump to
[Tunable knobs](#tunable-knobs-environment-variables). If you want to add
a new feature, read [Architecture](#architecture) and
[Adding a new stage](#extending-the-pipeline) end-to-end.

---

## Table of contents

1. [What this is](#what-this-is)
2. [Quick start](#quick-start)
3. [Architecture](#architecture)
4. [The pipeline, stage by stage](#the-pipeline-stage-by-stage)
5. [The coverage-feedback loop](#the-coverage-feedback-loop)
6. [Structure-aware fuzzing](#structure-aware-fuzzing)
7. [Persistent corpus across iterations and campaigns](#persistent-corpus-across-iterations-and-campaigns)
8. [Triage and vulnerability reports](#triage-and-vulnerability-reports)
9. [Live dashboard](#live-dashboard)
10. [Output files](#output-files)
11. [Database schema](#database-schema)
12. [MCP tools (the agent's vocabulary)](#mcp-tools-the-agents-vocabulary)
13. [Tunable knobs (environment variables)](#tunable-knobs-environment-variables)
14. [Extending the pipeline](#extending-the-pipeline)
15. [Benchmark projects and results](#benchmark-projects-and-results)
16. [Limitations and gotchas](#limitations-and-gotchas)
17. [Security warning](#security-warning)
18. [Development: testing, linting, contributing](#development-testing-linting-contributing)
19. [Glossary](#glossary)

---

## What this is

This taskflow is a fully autonomous fuzzing pipeline. Given a GitHub repo
of a native C/C++ project, it will:

1. install AFL++ + clang/llvm/lcov + ctags/cscope/graphviz if missing,
2. fetch the source,
3. identify candidate fuzz targets (parsers, decoders, validators, …),
4. analyse the build system,
5. write one or more harness candidates per target, build each as both an
   AFL-instrumented `.afl` binary and a coverage-instrumented `.cov` binary,
6. (optionally) qualify candidates by 60-second coverage and keep the best,
7. run a fuzz/coverage/improve loop with doubling time budgets,
8. triage every crash, confirm previously-known crashes still reproduce, and
   write per-crash markdown vuln reports with verdicts, exploitability,
   suggested patches, and regression-test sketches,
9. build a Fuzz-Introspector-style call graph + untouched-API report for the
   next campaign,
10. publish everything to a live HTML dashboard.

The pipeline is **OSS-Fuzz-style** in spirit: it uses many of the same
techniques (per-format mutators and dictionaries, structure-aware token
splicing, coverage-driven harness improvements, machine-readable reports,
deduped stack-hashed crashes) but it is much smaller and self-contained.

---

## Quick start

```bash
# Inside the codespace (or a host with python + git available):
./scripts/fuzzing/run_fuzzing.sh tukaani-project/xz
```

That's the whole interface. The script is autonomous; it will install AFL++
on first run, then drive the rest of the taskflow. Output files are written
to `~/.local/share/seclab-taskflow-agent/seclab-taskflows/`.

The dashboard auto-starts in the background; in a Codespace, port `8765` is
auto-forwarded — open it in any browser to watch progress live.

For a quick smoke-test, use a small target:

```bash
./scripts/fuzzing/run_fuzzing.sh DaveGamble/cJSON
```

---

## Architecture

Three layers, top to bottom:

```
┌────────────────────────────────────────────────────────────────────┐
│  scripts/fuzzing/run_fuzzing.sh                                    │
│      shell driver; chains the taskflow stages with `set +e`        │
└────────────────────┬───────────────────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────────┐
│  src/seclab_taskflows/taskflows/fuzzing/*.yaml                     │
│      LLM agent prompts; one YAML per pipeline stage                │
└────────────────────┬───────────────────────────────────────────────┘
                     │  (calls MCP tools)
                     ▼
┌────────────────────────────────────────────────────────────────────┐
│  src/seclab_taskflows/mcp_servers/                                 │
│   ├ fuzz_context.py    persistence (SQLite via SQLAlchemy)         │
│   └ fuzz_runner.py     subprocess wrappers (AFL, clang, lcov, ...) │
│                                                                    │
│  scripts/fuzzing/dashboard.py                                      │
│   read-only HTML view of fuzz_context.db                           │
└────────────────────────────────────────────────────────────────────┘
```

Key design rules:

- **No global state in MCP tools.** Every tool function takes explicit
  arguments; persistent state lives in `fuzz_context.db`.
- **LLM agents own decisions, MCP tools own execution.** The agent decides
  *what* to fuzz, *what* harness to write, *what* gap to chase next; the
  MCP tools just expose `run_afl_for`, `compile_harness`, `store_crash`, etc.
- **Idempotency wherever cheap.** Re-running the pipeline against the same
  repo upserts targets/harnesses/runs rather than duplicating them. This is
  what makes the persistent corpus and the cross-campaign carryover work.
- **Two binaries per harness.** AFL's edge instrumentation is unsuitable for
  human-readable coverage reports, so each harness is built twice: once with
  `afl-clang-lto -fsanitize=address,undefined` (the `.afl` binary) and once
  with `clang -fprofile-instr-generate -fcoverage-mapping` (the `.cov`
  binary). The `.afl` binary fuzzes; the `.cov` binary replays the AFL
  queue to produce real source-line/function/branch coverage.

---

## The pipeline, stage by stage

| # | Stage | Taskflow YAML |
|---|-------|---------------|
| 1 | Install AFL++ + tooling | `scripts/fuzzing/install_afl.sh` |
| 2 | Fetch source | `seclab_taskflows.taskflows.audit.fetch_source_code` |
| 3 | Identify fuzz targets | `seclab_taskflows.taskflows.fuzzing.identify_fuzz_targets` |
| 4 | Analyse build system | `seclab_taskflows.taskflows.fuzzing.analyze_build_system` |
| 5a | Write initial harnesses (×N candidates if requested) | `seclab_taskflows.taskflows.fuzzing.write_initial_harnesses` |
| 5b | Build harnesses (AFL + coverage) | `seclab_taskflows.taskflows.fuzzing.build_harnesses` |
| 5c | Qualify candidates (when `HARNESS_CANDIDATES > 1`) | `seclab_taskflows.taskflows.fuzzing.qualify_harnesses` |
| 6 | Fuzz/coverage/improve loop (×N iterations) | `seclab_taskflows.taskflows.fuzzing.fuzz_iteration` |
| 7 | Triage crashes | `seclab_taskflows.taskflows.fuzzing.triage_crashes` |
| 8 | Confirm previously-known crashes still reproduce | `seclab_taskflows.taskflows.fuzzing.confirm_fixed_crashes` |
| 9 | Build call graph + untouched-API report | `seclab_taskflows.taskflows.fuzzing.analyze_call_graph` |
| 10 | Write per-crash vuln reports | `seclab_taskflows.taskflows.fuzzing.write_vuln_reports` |
| 11 | Write campaign report | `seclab_taskflows.taskflows.fuzzing.write_report` |

Each stage is a self-contained taskflow YAML that the agent runs
end-to-end. Stages communicate exclusively through the SQLite database
in `fuzz_context.db` — there is no in-memory hand-off.

---

## The coverage-feedback loop

This is the heart of the pipeline. Time budgets double every iteration:

```
30s → 60s → 120s → 240s → 480s → 960s    (≈ 32 min/target)
```

Per iteration, per harness, the agent:

1. Asks `get_persistent_corpus_dir(harness_id)` for this harness's stable
   corpus dir.
2. Calls `run_afl_for(afl_binary_path, seed_dir=<persistent corpus>,
   output_dir=<run dir>, seconds=<budget>, dictionary=<auto.dict>)`.
3. Calls `run_coverage(cov_binary_path, inputs_dir=<run>/default/queue,
   output_dir=<run>/coverage)` to produce an LCOV tracefile and HTML report.
4. Calls `store_coverage_from_lcov(run_id, lcov_path, html_path)` to persist
   a `coverage_report` row + per-uncovered-item `coverage_gap` rows.
5. Calls `fold_queue_into_persistent_corpus(...)` to merge AFL's iteration
   queue into the persistent corpus and run `cmin` to keep size bounded.
6. Reads `get_coverage_summary` + `get_coverage_gaps`, then either:
   - adds a new seed (tagged `coverage_feedback`) to reach an uncovered
     branch,
   - edits the harness source to call an additional API,
   - calls `enrich_dictionary_from_uncovered(...)` to auto-add dictionary
     entries for the magic constants AFL needs to satisfy a guard, or
   - skips the gap (cold error path / vendor code).
7. Calls `store_iteration_note(repo, iteration_number, harness_id, note=<one
   line summary>)` so the dashboard's iteration timeline tracks what
   changed.

**Plateau detection.** The loop exits early once two consecutive iterations
have both gained < `FUZZ_PLATEAU_THRESHOLD_PCT` (default `1.0`) absolute
percentage points of line coverage.

---

## Structure-aware fuzzing

Three complementary mechanisms produce stronger inputs than raw byte mutation.

### 1. Per-format dictionaries + custom mutators

For targets whose `input_kind` matches a known format, the taskflow ships
pre-built dictionaries and `LLVMFuzzerCustomMutator` C source files:

| Format | Dictionary | Mutator | Notes |
|--------|------------|---------|-------|
| `json` | `json.dict` | `json_mutator.c` | Token splice, balanced bracket dup/drop, type flip |
| `xml` | `xml.dict` | `xml_mutator.c` | Tags, entities, DTDs, billion-laughs tokens |
| `regex` | `regex.dict` | `regex_mutator.c` | Anchors, classes, quantifiers, real ReDoS patterns |
| `binary_tlv` | _(none)_ | `binary_tlv_mutator.c` | Length-prefixed records: length-overflow / dup / drop |
| `png` | `png.dict` | _(reuses binary_tlv)_ | PNG dictionary + binary_tlv mutator |

These are picked up automatically by `write_initial_harnesses` (dictionary
copied next to seeds) and `build_harnesses` (mutator linked into the AFL
binary). Each mutator delegates 50% of mutations to AFL's default byte
mutator so we don't lose the engine's randomisation.

To add a new format: drop a `<name>.dict` and/or a `<name>_mutator.c` into
`src/seclab_taskflows/dictionaries/`, then register it in the
`_FORMAT_ASSETS` map at the bottom of `fuzz_runner.py`.

### 2. Source-aware (project-specific) smart mutator

For unfamiliar formats, or whenever you want stronger project-specific
tokens, `generate_smart_mutator` scans the target repo's own `.c`/`.h`
files and emits an `LLVMFuzzerCustomMutator` C file whose splice
dictionaries are extracted from:

- string literals with ≥3 alphabetic chars (after filtering compiler/license
  noise, paths, headers, asm constraints, format specifiers),
- 32-bit numeric constants from `#define`, `case`, and `enum` (after
  filtering generic small-int noise like 0, 1, 256, 0xff…).

Three focuses are available:

| Focus | What it splices | When to use |
|-------|-----------------|-------------|
| `strings` | Project string literals only | Text formats (JSON, XML, YAML, CSV) |
| `constants` | 32-bit numeric magic values only | Binary protocols, headers with magic numbers |
| `combined` | Both | Default; usually best |

Pair `generate_smart_mutators(...)` (plural) with `HARNESS_CANDIDATES >= 3`
so each focus becomes a candidate harness in the qualifier round.

### 3. Project-aware AFL dictionary + coverage-driven enrichment

Two complementary tools build and grow an AFL `-x` dictionary as the
campaign progresses:

- **`generate_project_dictionary(source_root, output_path)`** — runs once
  before iteration 1, statically extracts the same source-token set used by
  the smart mutator and writes it as an AFL dictionary. Numeric constants
  are emitted in BOTH endiannesses so the fuzzer can satisfy
  `memcmp(x, &magic, 4)` regardless of host byte order.

- **`enrich_dictionary_from_uncovered(source_root, dictionary_path,
  uncovered_locations)`** — runs after every iteration's coverage step,
  scans the surrounding source for conditional guards
  (`strncmp/memcmp/strstr`, `case 0xN:`, `== 0xN`, `== 'X'`) near the
  uncovered lines, and APPENDS any new tokens to the dictionary. Idempotent:
  never re-adds an entry that's already present.

### 4. Corpus-splice op

When `corpus_dir` is passed to `generate_smart_mutator`, the generated C
also gets a corpus-splice operator: on first call it loads up to 64 files
from that directory (capped at 4 KiB each), and from then on can splice
random sub-regions of those files into the mutated input. This gives the
mutator a recombination-style operator that AFL's stock havoc doesn't do
well. Pair with `get_persistent_corpus_dir(...)` so the splice library
is "remix what AFL has already discovered".

---

## Persistent corpus across iterations and campaigns

Each harness has a stable corpus directory at:

```
<workspace>/corpus/harness_<id>/
```

This is what `fuzz_iteration` uses as `seed_dir` for `run_afl_for` (rather
than `<harness>/seeds`). At the end of every iteration,
`fold_queue_into_persistent_corpus(...)` merges AFL's iteration queue into
this dir and runs `afl-cmin` to keep it bounded.

The result: yesterday's queue carries into today's run AND across re-runs
of the same project. A stop-and-restart of the campaign loses no progress.

---

## Triage and vulnerability reports

After the fuzz/coverage/improve loop finishes, three stages run automatically:

### 1. `triage_crashes`

For every crash file in `<run>/default/crashes/`:

- `afl-tmin` to minimise the input,
- `replay_under_asan` to capture a stack trace and `stack_top_hash`
  (top-N normalised frames; templates, libcxx inline namespaces, anonymous
  namespaces, and LTO numeric suffixes are stripped so semantically
  identical crashes hash identically),
- dedupe by hash, persist a `crash` row with bug-class classification +
  confidence note (high / medium / low).

### 2. `confirm_fixed_crashes`

Replays every previously-classified crash (whose verdict isn't already
`fixed`/`duplicate`/`non_reproducible`) through the current AFL+ASan binary.
If it no longer crashes, marks `verdict="fixed"`. Useful when re-running a
campaign against a project that has had upstream fixes applied since the
last campaign.

### 3. `write_vuln_reports`

For every unique crash, the agent reads the harness source + the crashing
function's source, walks the call chain from the public API, then assigns
one of ten OSS-Fuzz-style verdicts and writes a markdown vuln report:

| Verdict | Meaning |
|---------|---------|
| `vulnerability` | Real, exploitable through a public API |
| `library_hardening` | Real bug but no realistic public-API path; library should still defend itself |
| `harness_bug` | The bug is in our harness, not the library |
| `non_reproducible` | Replay does not reproduce the crash on the minimised input |
| `oom` | Out-of-memory; vuln only if attacker-controllable size is unbounded |
| `timeout` | DoS via algorithmic blow-up |
| `assertion_failure` | `assert()` hit; security relevance varies |
| `fixed` | Set by `confirm_fixed_crashes`: input no longer reproduces |
| `duplicate` | Same root cause as another crash with a different stack hash |
| `needs_investigation` | Could not determine; flagged for human review |

Each vuln report includes:

- Verdict + bug class + CWE + severity + **confidence**
- Root-cause analysis with file:line references
- Reachability from public API (concrete call chain)
- Exploitability assessment (read vs. write, attacker control, mitigations)
- **Suggested fix as a unified diff** (marked "review required")
- Regression-test sketch

---

## Live dashboard

The dashboard is started automatically in the background by
`run_fuzzing.sh`. Disable with `FUZZ_NO_DASHBOARD=1`; override the port
with `FUZZ_DASHBOARD_PORT` (default `8765`).

In a Codespace, port `8765` is auto-forwarded — open the forwarded URL in
any browser. The page auto-refreshes every 5 s and shows:

- **Verdict summary chips** — counts per verdict category, total runs,
  paths, total exec count, crashes
- **Live "running" pulse** indicator — per repo and per harness with an
  in-flight `fuzz_run`
- **Coverage trend table** with inline SVG sparklines and a per-iteration
  delta column
- **Call graph & untouched API surface** — the Fuzz-Introspector-lite
  snapshot
- **Crashes table** — sorted by verdict (`vulnerability` first), linking
  to each vuln report and minimised input
- **Crash heatmap** — per-(harness × iteration) grid of crash counts,
  opacity scales with count
- **Iteration timeline** — chronological feed of agent-written one-line
  notes describing what changed each iteration
- **Top uncovered functions** — collapsed by default

### JSON API

The dashboard also exposes a tiny read-only JSON API for scripts:

```bash
# All known repos
curl http://127.0.0.1:8765/api/json

# Per-repo: harnesses, per-iteration coverage, crashes with verdicts
curl 'http://127.0.0.1:8765/api/json?repo=kkos/oniguruma' | jq .
```

---

## Output files

All under `~/.local/share/seclab-taskflow-agent/seclab-taskflows/`.

| Path | Contents |
|------|----------|
| `fuzz_context/fuzz_context.db` | SQLite — targets, harnesses, runs, coverage, crashes, verdicts, call graphs, harness suggestions, iteration notes |
| `fuzz_runner/builds/` | Built `.afl` and `.cov` binaries |
| `fuzz_runner/runs/` | AFL output dirs + LCOV files + HTML coverage reports |
| `fuzz_runner/corpus/harness_<id>/` | Persistent corpus per harness (carries across iterations & campaigns) |
| `fuzz_runner/repo/<owner>__<repo>/REPORT.md` | Markdown campaign summary, crashes grouped by verdict |
| `fuzz_runner/repo/<owner>__<repo>/vuln_<crash_id>.md` | Per-crash markdown vuln report |
| `fuzz_runner/repo/<owner>__<repo>/call_graph.{dot,svg,md}` | Static call graph + reached/unreached overlay |

---

## Database schema

Tables in `fuzz_context.db` (SQLite via SQLAlchemy):

| Table | Columns of interest |
|-------|--------------------|
| `fuzz_target` | `repo, file, function, signature, input_kind` |
| `harness` | `target_id, repo, harness_path, afl_binary_path, cov_binary_path, build_status, version, sanitizers` |
| `seed_corpus` | `target_id, source, path, bytes_count, added_in_iteration` |
| `fuzz_run` | `harness_id, iteration_number, exec_per_sec, paths_total, crashes_count, status, output_dir, started_at, ended_at` |
| `coverage_report` | `run_id, lines_total, lines_hit, line_pct, fns_*, branches_*, lcov_path, html_path` |
| `coverage_gap` | `report_id, file, function, line, kind, reason_hint` |
| `crash` | `run_id, input_blob_path, minimized_path, stack_top_hash, sanitizer_output, verdict, bug_class, cwe, severity, vuln_report_path, reproducer_path, classification, notes` |
| `call_graph` | `repo, target_id, dot_path, svg_path, functions_total, functions_in_graph, functions_reached, functions_unreached, untouched_surface_json` |
| `harness_suggestion` | `repo, function_name, file, rationale, input_kind, priority` |
| `iteration_note` | `repo, harness_id, iteration_number, note, created_at` |

Schema migrations live in `_migrate()` in `fuzz_context.py`. New TABLES are
auto-created by `Base.metadata.create_all()`; only new COLUMNS need
PRAGMA-based `ALTER TABLE`.

---

## MCP tools (the agent's vocabulary)

The agent never calls AFL or clang directly — it composes the pipeline by
calling MCP tools. The full set, grouped by purpose:

### Persistence (`fuzz_context.py`)

- `store_fuzz_target`, `get_fuzz_targets`
- `store_harness`, `update_harness_build`, `get_harnesses`
- `store_seed`, `start_fuzz_run`, `finish_fuzz_run`, `get_fuzz_runs`
- `store_coverage_from_lcov`, `get_coverage_summary`, `get_coverage_gaps`,
  `coverage_plateau_reached`
- `store_crash`, `update_crash_verdict`, `get_crashes`,
  `get_crashes_grouped`, `suggest_severity`
- `store_call_graph`, `get_call_graphs`, `get_repo_reached_functions`
- `store_harness_suggestion`, `get_harness_suggestions`
- `store_iteration_note`, `get_iteration_notes`

### Build / fuzz / coverage (`fuzz_runner.py`)

- `check_tooling`, `workspace_paths`
- `compile_harness` — builds `.afl` and `.cov` binaries
- `run_afl_for`, `cmin`, `tmin`, `replay_under_asan`, `reproduce_crash`
- `run_coverage` — replays AFL queue against the `.cov` binary, exports LCOV
- `extract_dictionary` — mine printable strings from a binary
- `package_reproducer` — bundle a single-crash `.tgz`

### Persistent corpus (v8)

- `get_persistent_corpus_dir`, `fold_queue_into_persistent_corpus`

### Format assets (C5)

- `list_format_assets`, `get_format_dictionary`, `write_format_mutator`

### Smart mutator + project-aware dictionary

- `generate_smart_mutator`, `generate_smart_mutators`
- `generate_project_dictionary`, `enrich_dictionary_from_uncovered`

Tool functions are decorated with `@mcp.tool()` (FastMCP). Inside tests,
invoke them via the `.fn` attribute, e.g.
`fr.run_afl_for.fn(afl_binary_path=..., ...)`.

---

## Tunable knobs (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HARNESS_CANDIDATES` | `1` | Number of candidate harnesses written per target. Set to 2 or 3 for OSS-Fuzz-Gen-style competition. The qualifier stage runs each for `QUALIFIER_SECONDS` and keeps the best by line %. |
| `QUALIFIER_SECONDS` | `60` | Per-candidate wall-clock budget in the qualifier stage. |
| `FUZZ_PLATEAU_THRESHOLD_PCT` | `1.0` | Line-coverage gain (in absolute pp) below which two consecutive iterations are considered a plateau and the loop stops early. |
| `FUZZ_DASHBOARD_PORT` | `8765` | Port for the live dashboard. |
| `FUZZ_NO_DASHBOARD` | (unset) | Set to `1` to skip starting the dashboard. |
| `FUZZ_RUNNER_TIMEOUT` | `1200` | Per-tool subprocess timeout in `fuzz_runner` (seconds). |
| `LOCAL_SHELL_TIMEOUT` | `180` | Per-command timeout in `local_shell` (seconds). |

Plus the standard agent variables (`COPILOT_TOKEN`, `LOG_DIR`,
`FUZZ_CONTEXT_DIR`, …). See the project root README for the full list.

---

## Extending the pipeline

### Adding a new format (mutator + dictionary)

1. Drop `dictionaries/<name>.dict` (AFL `-x` format) and/or
   `dictionaries/<name>_mutator.c` (libFuzzer custom mutator).
2. Register in `_FORMAT_ASSETS` at the bottom of `fuzz_runner.py`:
   ```python
   "<name>": {
       "dictionary": "<name>.dict",
       "mutator": "<name>_mutator.c",
       "description": "Short one-liner about the format",
   },
   ```
3. The agent will pick it up automatically through `list_format_assets()`.

### Adding a new MCP tool

1. Add a `@mcp.tool()`-decorated function in `fuzz_context.py` (for
   persistence) or `fuzz_runner.py` (for subprocess work).
2. Use `Annotated[type, Field(description=...)]` for every arg — the
   description is what the LLM sees.
3. Add a unit test in `tests/test_fuzz_context.py` /
   `tests/test_fuzz_runner.py`. Invoke the tool via its `.fn` attribute
   (FastMCP convention).
4. Reference the new tool in the relevant taskflow YAML's `user_prompt`.

### Adding a new pipeline stage

1. Create a new YAML in `src/seclab_taskflows/taskflows/fuzzing/`. Use
   one of the existing files (e.g. `triage_crashes.yaml`) as a template.
2. Wire it into `scripts/fuzzing/run_fuzzing.sh` between the right two
   existing stages.
3. (Optional) add a stage-specific dashboard section in
   `scripts/fuzzing/dashboard.py`.

### Schema migration

When adding a new SQL table:

- Add the SQLAlchemy model in `fuzz_context_models.py`.
- Nothing else needed — `Base.metadata.create_all()` is called at engine
  init and creates new tables automatically.

When adding a new COLUMN to an existing table:

- Update the SQLAlchemy model.
- Add a `PRAGMA table_info` + `ALTER TABLE ADD COLUMN` block in
  `_migrate()` in `fuzz_context.py` so old DBs are upgraded transparently.
- If the column is read by the dashboard, also update
  `_migrate_if_writable()` in `scripts/fuzzing/dashboard.py`.

---

## Benchmark projects and results

`benchmark/projects.yaml` lists the reference projects. They're chosen so
the full v4+ pipeline can run end-to-end on a codespace dev image without
human intervention.

| # | Repo | Why it's interesting | Notes |
|---|------|----------------------|-------|
| 1 | `tukaani-project/xz` | Real-world parser-heavy library (`liblzma`); rich filter chain + integer/VLI parsing surface | Baseline |
| 2 | `DaveGamble/cJSON` | Small single-file C JSON parser; trivial CMake | Quick smoke for the pipeline |
| 3 | `akheron/jansson` | Compact C JSON library with documented `json_loadb()` byte-buffer entry point | CMake; very fast exec/sec |
| 4 | `libexpat/libexpat` | Mature streaming XML parser; many historical CVEs | CMake or autotools |
| 5 | `kkos/oniguruma` | Regex engine; takes attacker pattern + subject | Autotools; pattern compilation is the hot path |

Reference numbers from a full v4-pipeline run on the codespace dev image
(≈32 min/target):

| Repo | Targets | Harnesses | AFL runs | Crashes | Verdicts |
|------|---------|-----------|----------|---------|----------|
| `tukaani-project/xz` | 8 | 8 | 48 | 0 | — |
| `DaveGamble/cJSON` | 6 | 6 | 36 | 0 | — |
| `akheron/jansson` | 7 | 7 | 35 | 10 | `harness_bug`, `library_hardening`, `duplicate`, `needs_investigation` |
| `libexpat/libexpat` | 3 | 3 | 18 | 0 | — |
| `kkos/oniguruma` | 10 | 10 | 60 | 13 | `vulnerability` (×2 OOB read in `regerror.c`), `library_hardening`, `harness_bug`, `non_reproducible` |

The xz / cJSON / libexpat zero-crash results are expected: those projects
are heavily fuzzed upstream. The two `vulnerability`-classified findings
in oniguruma are real out-of-bounds reads in the warning-formatting code
path of `onig_snprintf_with_pattern` (one-byte read past `pat_end` when
the pattern ends with a backslash); the per-crash markdown reports
include suggested patches.

To add a new benchmark project, add an entry to `benchmark/projects.yaml`
and (optionally) document why in `benchmark/README.md`. Anything that the
existing `analyze_build_system` stage can build with `clang` + AFL++ flags
is a reasonable candidate. Pure-C parsers, decoders, and serialisers tend
to work best.

---

## Limitations and gotchas

- **C / C++ only.** AFL++ is a native-instrumentation fuzzer.
- **Build-system dependent.** Projects with non-trivial build systems
  (custom Bazel rules, vendored libc, proprietary build tools) may fail to
  build with clang/AFL flags. The agent marks those targets `BUILD_FAILED:`
  and skips them.
- **Codespace AFL warnings.** AFL++ wants `kernel.core_pattern=core` and a
  CPU governor tweak. In a Codespace these are unavailable, so the
  taskflow exports `AFL_SKIP_CPUFREQ=1` and
  `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` by default. AFL prints
  warnings but still finds crashes via libFuzzer-style abort handling.
- **Model bound.** The agent's harness-writing quality is bounded by the
  underlying model's understanding of the target code.
- **POSIX-only smart mutator corpus splice.** The corpus-splice op uses
  `<dirent.h>`. Fine for Linux/macOS; would not compile on Windows.
- **stdin mode caveat.** AFL binaries built via `compile_harness` use
  libAFLDriver in argv mode. `replay_under_asan` and `tmin` therefore
  default to `stdin_input=False` because libAFLDriver loops forever when
  driven via stdin.
- **`generate_smart_mutator` + `generate_smart_mutators` use Python
  `.format()`** — every literal `{` / `}` in the C template must be doubled
  (`{{` / `}}`). If you edit the template and start seeing `KeyError`,
  that's why.

---

## Security warning

This taskflow runs `afl-fuzz`, `clang`, `llvm-cov`, **and arbitrary build
commands chosen by the LLM**, **directly on the host** (no container). A
prompt-injected agent could in principle do anything your user can. Run
only:

- inside disposable environments (GitHub Codespaces, throwaway VMs, etc.),
- without elevated privileges,
- with network access scoped to what `git`, `apt`, and the build system
  need.

The `local_shell` toolbox is **NOT** behind a confirmation prompt — the
taskflow is autonomous and runs without a human in the loop, so an
interactive confirmation would just block forever. Every shell command is
logged to `$LOG_DIR/mcp_local_shell.log` for after-the-fact review.

---

## Development: testing, linting, contributing

```bash
# Run the test suite (Python 3.11+ required by hatch-test envs)
hatch test

# Run the linter
hatch fmt --linter --check

# Auto-fix lint issues
hatch fmt --linter

# Lint a single file
hatch fmt --linter --check -- src/seclab_taskflows/mcp_servers/fuzz_runner.py
```

Codebase conventions (see also `benchmark/improvements.md` for the
campaign-history version of these):

- Use `os.environ.get(NAME) or "default"` rather than
  `os.environ.get(NAME, "default")`. Empty strings from YAML template
  substitution would otherwise be returned.
- Use `X | None` (PEP 604) in new annotations, not `Optional[X]`.
- Tests invoke MCP tools via `.fn(...)`, not the decorated name directly.
- Avoid `/tmp/...` literals in tests — use the `tmp_path` pytest fixture
  (lint rule `S108`).
- All inline imports inside test methods need `# noqa: PLC0415` if you
  can't move them to the top of the file (e.g. when conditionally imported
  after a `pytest.skip`).
- Single-assertion-per-line for compound truth tests (lint rule `PT018`).

The improvements tracker (`benchmark/improvements.md`) is the persistent
log of what's been added to the pipeline across versions. When you add a
substantive feature, add a section there describing what changed, where it
lives, and what tests guard it.

---

## Glossary

- **AFL++** — Coverage-guided greybox fuzzer; the execution engine here.
- **libAFLDriver** — Static library that lets AFL++ harnesses use the
  libFuzzer entry-point convention (`LLVMFuzzerTestOneInput`).
- **LCOV** — Industry-standard coverage tracefile format. We export to it
  via `llvm-cov export -format=lcov` and parse it ourselves.
- **`stack_top_hash`** — A 16-char hash of the top N normalised frames of
  an ASan/UBSan stack trace. Used for crash deduplication.
- **Persistent corpus** — Per-harness directory at
  `<workspace>/corpus/harness_<id>/` that carries AFL's interesting inputs
  across iterations and re-runs of the same campaign.
- **Smart mutator** — A `LLVMFuzzerCustomMutator` whose splice tokens are
  extracted from the target's own source code (`generate_smart_mutator`).
- **Custom mutator (libFuzzer)** — A user-supplied C function called by
  the engine with full freedom over how to mutate a buffer; AFL++ supports
  the same ABI.
- **MCP tool** — A FastMCP-decorated function the LLM agent can call.
- **OSS-Fuzz / Fuzz-Introspector** — Google's open-source-fuzzing
  infrastructure and its companion call-graph/coverage analysis tool.
  Several of this taskflow's features (per-format mutators, dedup-by-stack,
  call-graph + untouched API report, multi-candidate harnesses) are
  inspired by them.
