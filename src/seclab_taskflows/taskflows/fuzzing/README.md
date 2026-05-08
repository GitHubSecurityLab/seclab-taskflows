# Fuzzing Taskflow

Coverage-guided fuzzing of native C/C++ projects with AFL++ and an LLM-driven
feedback loop.

```bash
./scripts/fuzzing/run_fuzzing.sh <owner/repo>
```

The script is fully autonomous: it installs AFL++ if missing, fetches the
source, identifies fuzz targets, builds harnesses, runs them, uses
**source-level coverage** (via `llvm-cov` or `gcov`) to improve harnesses and
seed corpora between iterations, triages any crashes, and writes a markdown
report.

## Pipeline

| # | Stage | Taskflow |
|---|-------|----------|
| 1 | Install AFL++ + clang/llvm/lcov + ctags/cscope/graphviz | `scripts/fuzzing/install_afl.sh` |
| 2 | Fetch source | `seclab_taskflows.taskflows.audit.fetch_source_code` |
| 3 | Identify fuzz targets | `seclab_taskflows.taskflows.fuzzing.identify_fuzz_targets` |
| 4 | Analyse build system | `seclab_taskflows.taskflows.fuzzing.analyze_build_system` |
| 5a | Write initial harnesses (×N candidates if requested) | `seclab_taskflows.taskflows.fuzzing.write_initial_harnesses` |
| 5b | Build harnesses (AFL + coverage) | `seclab_taskflows.taskflows.fuzzing.build_harnesses` |
| 5c | **G3** Qualify candidates (only if `HARNESS_CANDIDATES > 1`) | `seclab_taskflows.taskflows.fuzzing.qualify_harnesses` |
| 6 | Fuzz/coverage/improve loop (×N iterations) | `seclab_taskflows.taskflows.fuzzing.fuzz_iteration` |
| 7 | Triage crashes | `seclab_taskflows.taskflows.fuzzing.triage_crashes` |
| 8 | **E3** Build call graph + untouched-API report | `seclab_taskflows.taskflows.fuzzing.analyze_call_graph` |
| 9 | Write per-crash vuln reports | `seclab_taskflows.taskflows.fuzzing.write_vuln_reports` |
| 10 | Write campaign report | `seclab_taskflows.taskflows.fuzzing.write_report` |

## The coverage-feedback loop

Every iteration doubles the previous time budget:

```
30s → 60s → 120s → 240s → 480s → 960s   (≈ 32 min/target)
```

Each iteration, per harness:

1. Run `afl-fuzz` for the assigned budget (using the `.afl` binary).
2. Replay the entire AFL queue against the `.cov` binary, then export an LCOV
   tracefile via `llvm-cov export -format=lcov` (falls back to `gcov + lcov`).
3. Parse the LCOV file → persist a `coverage_report` row + per-uncovered-item
   `coverage_gap` rows in the SQLite database.
4. The agent reads `get_coverage_summary` + `get_coverage_gaps`, then either:
   - adds a new seed (tagged `coverage_feedback`) to reach an uncovered branch,
   - edits the harness source to call an additional API,
   - adds an AFL dictionary entry for a magic value, or
   - skips the gap (cold error path / vendor code).
5. If the harness changed, rebuild it.

The loop exits early once two consecutive iterations have both gained
< `FUZZ_PLATEAU_THRESHOLD_PCT` (default **1.0**) line coverage.

## Why two binaries per harness?

AFL's edge instrumentation isn't suitable for human-readable coverage reports.
Each harness is therefore built **twice**:

| Binary | Compiler | Flags | Used for |
|--------|----------|-------|----------|
| `<harness>.afl` | `afl-clang-lto` | `-fsanitize=address,undefined` | actual fuzzing campaign |
| `<harness>.cov` | `clang` | `-fprofile-instr-generate -fcoverage-mapping` | LCOV replay of the AFL queue |

This gives you real **source-line / function / branch** coverage, not just
edge counts.

## Structure-aware fuzzing (C5)

For targets whose `input_kind` matches a known format, the taskflow ships
pre-built **dictionaries** + **`LLVMFuzzerCustomMutator` source files**:

| Format | Dictionary | Mutator | Notes |
|--------|------------|---------|-------|
| `json` | `dictionaries/json.dict` | `dictionaries/json_mutator.c` | JSON token splice + balanced bracket dup/drop + type flip |
| `xml` | `dictionaries/xml.dict` | `dictionaries/xml_mutator.c` | Tags, entities, DTDs, billion-laughs tokens |
| `regex` | `dictionaries/regex.dict` | `dictionaries/regex_mutator.c` | Anchors, classes, quantifiers, real ReDoS patterns |
| `binary_tlv` | _(none)_ | `dictionaries/binary_tlv_mutator.c` | Length-prefixed records: length-overflow / dup / drop |
| `png` | `dictionaries/png.dict` | _(reuses binary_tlv)_ | PNG dictionary + binary_tlv mutator |

The agent automatically picks these up from `list_format_assets()` during
`write_initial_harnesses` (dictionary copied next to seeds) and
`build_harnesses` (mutator linked into the AFL binary). Each mutator
delegates 50% of mutations to the engine's default byte mutator so we don't
lose AFL's randomisation.

To add a new format: drop a `<name>.dict` (AFL format) and/or a `<name>_mutator.c`
(libFuzzer custom mutator) into `src/seclab_taskflows/dictionaries/`, then
register it in the `_FORMAT_ASSETS` map at the bottom of `fuzz_runner.py`.

## Source-aware (project-specific) mutators

For unfamiliar formats — or whenever you want stronger, project-specific
tokens — use the source-aware mutator generator. It scans the target repo's
own `.c`/`.h` files and emits a `LLVMFuzzerCustomMutator` C file whose
splice dictionaries are extracted from:

- string literals with ≥3 alphabetic chars (after filtering compiler/license
  noise, paths, headers, asm constraints, format specifiers),
- 32-bit numeric constants from `#define`, `case`, and `enum` (after
  filtering generic small-int noise).

```text
generate_smart_mutator(source_root="<unpacked repo root>",
                       output_path="<harness dir>/smart.c",
                       focus="combined")
        → emits one self-contained .c file with embedded tokens.

generate_smart_mutators(source_root="<unpacked repo root>",
                        output_dir="<harness dir>",
                        basename="smart")
        → one analysis pass, three focus variants:
          smart_strings.c, smart_constants.c, smart_combined.c
        Pair with HARNESS_CANDIDATES >= 3 so each variant becomes a
        candidate harness in the qualifier round.
```

End-to-end-verified on real xz source: 192 string tokens (`"OPTS"`,
`"lzma"`, `"lzma2"`, `"FILTERS"`, `".tar"`, `".tlz"`, `".txz"`, error
strings) and 32 numeric constants (filter IDs, error codes, mode bits)
extracted; all three variants link with `libAFLDriver.a`. cJSON: extracts
JSON-Patch keywords (`"add"`, `"remove"`, `"replace"`, `"path"`, `"value"`)
and JSON literals (`"null"`, `"false"`).

## Project-aware AFL dictionary + coverage-driven enrichment

Two complementary tools build and grow an AFL `-x` dictionary as the
campaign progresses:

### `generate_project_dictionary(source_root, output_path)` — pre-fuzzing

Statically extracts the same source-token set used by the smart mutator
and writes it as an AFL dictionary file. Called by `write_initial_harnesses`
*after* `get_format_dictionary` (so the result is the union of: format-aware
keywords + project-specific strings + project-specific numeric constants).
The dictionary path is the same `auto.dict` that `run_afl_for` reads, so
AFL has high-leverage tokens from iteration 1.

Numeric constants are emitted in BOTH endiannesses (`0xFEEDFACE` →
`\xce\xfa\xed\xfe` AND `\xfe\xed\xfa\xce`) so the fuzzer can satisfy
`memcmp(x, &magic, 4)` regardless of host byte order.

### `enrich_dictionary_from_uncovered(source_root, dictionary_path, uncovered_locations)` — after each iteration

For every uncovered (file, line) returned by `get_coverage_gaps`, this
scans the surrounding source for **conditional guards** that AFL needs to
satisfy to reach the uncovered code:

- `strncmp(p, "TOK", 3)` / `memcmp(p, "MAGIC", 5)` / `strstr(s, "Content-Type")`
- `if (foo == 0xDEADBEEF)`
- `case 0xFEEDFACE:`
- `if (s[0] == 'X')` / `case 'X':`

Any new tokens are APPENDED to the existing dictionary (idempotent — never
re-adds an entry that's already present). The next `run_afl_for` call uses
the grown dictionary automatically. Verified to extract real xz tokens
(`"max"`, `"ram"`, `"iB"`, `"-"`, `'\0'`, `'\t'`) from real strcmp call
sites in `src/xz/util.c`, `main.c`, etc.

The agent calls this from the `coverage_feedback` prompt after every
iteration's coverage step. Total cost is sub-second on real projects.

## Multi-candidate harnesses (G3)

OSS-Fuzz-Gen-style: the agent generates N candidate harnesses per target and
the qualifier picks the best by 60s coverage:

```bash
HARNESS_CANDIDATES=3 ./scripts/fuzzing/run_fuzzing.sh tukaani-project/xz
```

The qualifier stage runs each `build_status='ok'` candidate for
`QUALIFIER_SECONDS` (default 60), measures line coverage, and marks losers
with `build_status='superseded'` so the main loop skips them.

## Call graph & untouched API surface (E3)

After triage, a Fuzz-Introspector-style stage builds a static call graph
using ctags + cscope, cross-references with the union of all coverage reports,
and writes:

- A Graphviz `.dot` file + rendered SVG (green = reached, red = defined but
  unreached, grey = external) at
  `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/repo/<owner>__<repo>/call_graph.{dot,svg}`
- A `call_graph.md` summary listing the top untouched public-API functions
  with hints for the next campaign.
- A persistent `CallGraph` row that the dashboard renders in a dedicated section.



| Path | Contents |
|------|----------|
| `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_context/fuzz_context.db` | SQLite — targets, harnesses, runs, coverage, crashes, **verdicts** |
| `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/builds/` | Built `.afl` and `.cov` binaries |
| `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/runs/` | AFL output dirs + LCOV files |
| `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/repo/<owner>__<repo>/REPORT.md` | Markdown campaign summary, crashes grouped by verdict |
| `~/.local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_runner/repo/<owner>__<repo>/vuln_<crash_id>.md` | Per-crash markdown vuln report (verdict, root cause, exploitability, suggested patch, regression-test sketch) |

### Live dashboard

The dashboard is started automatically in the background by `run_fuzzing.sh`
(disable with `FUZZ_NO_DASHBOARD=1`, override port with `FUZZ_DASHBOARD_PORT`).

In a Codespace, port 8765 is auto-forwarded — open the forwarded URL in any
browser. The page auto-refreshes every 5 s and shows:

- **Verdict summary chips** at the top (counts per verdict category, plus
  total runs, paths, total exec count, crashes)
- **Live "running" pulse** indicator per repo and per harness (any harness
  with an in-flight `fuzz_run`)
- **Coverage trend table** with inline SVG sparklines and per-iteration line %
  delta column
- **Crashes table** sorted by verdict (`vulnerability` first), linking to each
  vuln report and minimised input
- **Top uncovered functions** (collapsed by default)

### JSON API

The dashboard also exposes a tiny read-only JSON API for scripts:

```bash
# All known repos
curl http://127.0.0.1:8765/api/json

# Per-repo: harnesses, per-iteration coverage, crashes with verdicts
curl 'http://127.0.0.1:8765/api/json?repo=kkos/oniguruma' | jq .
```

## Triage / vuln-report stages

After the fuzz/coverage/improve loop, two stages run automatically:

1. **`triage_crashes`** — for every crash file in `<run>/default/crashes/`:
   - `afl-tmin` to minimise the input,
   - `replay_under_asan` to capture a stack trace and `stack_top_hash`,
   - dedupe by hash, persist a `crash` row with bug-class classification +
     confidence note (high / medium / low).

2. **`write_vuln_reports`** — for every unique crash, the agent reads the
   harness source + the crashing function's source, walks the call chain from
   the public API, then assigns one of nine OSS-Fuzz-style verdicts and writes
   a markdown vuln report to disk:

   | Verdict | Meaning |
   |---------|---------|
   | `vulnerability` | Real, exploitable through a public API |
   | `library_hardening` | Real bug but no realistic public-API path; library should still defend itself |
   | `harness_bug` | The bug is in our harness, not the library |
   | `non_reproducible` | Replay does not reproduce the crash on the minimised input |
   | `oom` | Out-of-memory; vuln only if attacker-controllable size is unbounded |
   | `timeout` | DoS via algorithmic blow-up |
   | `assertion_failure` | `assert()` hit; security relevance varies |
   | `duplicate` | Same root cause as another crash with a different stack hash |
   | `needs_investigation` | Could not determine; flagged for human review |

   Each vuln report includes:
   - Verdict + bug class + CWE + severity + **confidence**
   - Root cause analysis with file:line references
   - Reachability from public API (concrete call chain)
   - Exploitability assessment (read vs. write, attacker control, mitigations)
   - **Suggested fix as a unified diff** (marked "review required")
   - Regression test sketch

## ⚠️ Security warning

This taskflow runs `afl-fuzz`, `clang`, `llvm-cov`, **and arbitrary build
commands chosen by the LLM**, **directly on the host** (no container). A
prompt-injected agent could in principle do anything your user can. Run only:

- Inside disposable environments (GitHub Codespaces, throwaway VMs, etc.).
- Without elevated privileges.
- With network access scoped to what `git`, `apt` and the build system need.

The `local_shell` toolbox is **NOT** behind a confirmation prompt — the
taskflow is autonomous and runs without a human in the loop, so an interactive
confirmation would just block forever. Every shell command is logged to
`$LOG_DIR/mcp_local_shell.log` for after-the-fact review.

## Tunable knobs (env vars)

| Variable | Default | Purpose |
|----------|---------|---------|
| `HARNESS_CANDIDATES` | `1` | **G3** Number of candidate harnesses written per target. Set to 2 or 3 for OSS-Fuzz-Gen-style competition. The qualifier stage runs each for `QUALIFIER_SECONDS` and keeps the best by line %. |
| `QUALIFIER_SECONDS` | `60` | **G3** Per-candidate wall-clock budget in the qualifier stage. |
| `FUZZ_PLATEAU_THRESHOLD_PCT` | `1.0` | Line-coverage gain (in absolute pp) below which two consecutive iterations are considered a plateau and the loop stops early. |
| `FUZZ_DASHBOARD_PORT` | `8765` | Port for the live dashboard. |
| `FUZZ_NO_DASHBOARD` | (unset) | Set to `1` to skip starting the dashboard. |
| `FUZZ_RUNNER_TIMEOUT` | `1200` | Per-tool subprocess timeout in `fuzz_runner` (seconds). |
| `LOCAL_SHELL_TIMEOUT` | `180` | Per-command timeout in `local_shell` (seconds). |

## Limitations

- **C / C++ only** — AFL++ is a native-instrumentation fuzzer.
- Projects with non-trivial build systems (custom Bazel rules, vendored libc,
  proprietary build tools) may fail to build with clang/AFL flags. The agent
  marks those targets `BUILD_FAILED:` and skips them.
- AFL++ wants `kernel.core_pattern=core` and a CPU governor tweak. In a
  Codespace these are unavailable, so the taskflow exports
  `AFL_SKIP_CPUFREQ=1` and `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` by
  default. AFL will print warnings but still find crashes via libFuzzer-style
  abort handling.
- The agent's harness writing quality is bounded by the underlying model's
  understanding of the target code.
