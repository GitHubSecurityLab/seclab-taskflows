# Container Shell Taskflows

Runs arbitrary CLI commands inside an isolated Docker container. One container
per MCP server process — started on the first `container_shell_exec` call, stopped on
exit. An optional host directory is mounted at `/workspace` inside the container.

By default the container is egress-locked: it runs with `--network none`, so
outbound access (`curl`, `wget`, `git` remote operations) is disabled until a
toolbox opts in by setting `CONTAINER_NETWORK` (for example `bridge`).

Different container profiles are provided. Each has its own Dockerfile, toolbox
YAML, and demo taskflow.

## Profiles

**base** (`ghcr.io/githubsecuritylab/seclab-shell-base:latest`)
General-purpose. Includes bash, coreutils, python3, file, binutils, xxd,
curl, wget, git.

**malware-analysis** (`ghcr.io/githubsecuritylab/seclab-shell-malware-analysis:latest`)
Static binary and firmware analysis. Extends base with radare2, binwalk,
yara, exiftool, checksec, capstone, pwntools, volatility3.

**network-analysis** (`ghcr.io/githubsecuritylab/seclab-shell-network-analysis:latest`)
Packet capture analysis and network recon. Extends base with nmap, tcpdump,
tshark, netcat, dig, jq, httpie.

**source-access** (`ghcr.io/githubsecuritylab/seclab-shell-source-access:latest`)
Source access and code exploration. Includes tgrep, fd, tree, universal-ctags,
GNU global, cscope, and git. Does not extend base.

**sast** (`ghcr.io/githubsecuritylab/seclab-shell-sast:latest`)
Static analysis and code exploration. Extends base with semgrep, pyan3,
universal-ctags, GNU global, cscope, graphviz, ripgrep, fd, tree.

## Building the images

Run from the repository root:

```
./scripts/build_container_images.sh
```

To build a single profile (the base image is always built first when needed):

```
./scripts/build_container_images.sh base
./scripts/build_container_images.sh malware
./scripts/build_container_images.sh network
./scripts/build_container_images.sh source-access
./scripts/build_container_images.sh sast
```

Images only need to be rebuilt when a Dockerfile changes.

## Source search with tgrep

The source-access image installs [Microsoft tgrep](https://github.com/microsoft/tgrep)
instead of ripgrep. Its Linux release is version-pinned and SHA-256 verified for
amd64 and arm64. When updating `TGREP_VERSION`, also update the corresponding
`TGREP_SHA256_AMD64` and `TGREP_SHA256_ARM64` build arguments.

After rebuilding the image, stop and remove any existing persistent source-access
container so the next MCP call creates one from the new image. Restarting only the
MCP server reuses the old container.

Run these commands **inside the container**, after the source is mounted:

```sh
tgrep index /workspace --index-path /tmp/tgrep-index
tgrep -n --index-path /tmp/tgrep-index '<pattern>' /workspace
tgrep -n -i -g '*.py' -C 3 --index-path /tmp/tgrep-index '<pattern>' /workspace
```

Before the first search in each session, build the index and wait for success.
For `container_shell_exec`, use `timeout=300` for indexing, or longer for large
repositories. Plain searches do not build an index automatically. The toolbox
instructs the agent to perform this indexing step; no background server is needed.
Keep `--index-path /tmp/tgrep-index` on every indexed search. This stores the index
outside the source tree and preserves it while the container persists.

Rebuild after source changes or checkouts to avoid stale results. Use `-F` for
literal text, `-l` for filenames only, and `--stats` to see index candidate counts.
For a fresh scan without an index or the default 64 MiB file-size cap, use
`tgrep --no-index --no-max-filesize -n '<pattern>' /workspace`. Hidden, ignored,
and binary files are still skipped by default; `--hidden` and `--no-ignore`
include their respective file sets and bypass the index.

## Environment variables

`CONTAINER_WORKSPACE` — host path to mount at `/workspace`. Optional; omit if
you do not need to pass files into the container.

`CONTAINER_TIMEOUT` — default command timeout in seconds.

`LOG_DIR` — where to write `container_shell.log`.

`CONTAINER_PERSIST` — whether to leave the container running after the MCP
server exits. The source-access toolbox defaults this to `true` so
source indexes and other analysis state survive across audit task steps.

## Running the demos

Create a workspace directory with a target file, then run the agent:

**Base demo** — inspects any ELF binary using standard binutils:

```
cp /bin/ls /tmp/demo/hello
CONTAINER_WORKSPACE=/tmp/demo python -m seclab_taskflow_agent \
    -t seclab_taskflows.taskflows.container_shell.demo_base
```

**Malware analysis demo** — static triage of a suspicious ELF (not executed):

```
cp /bin/ls /tmp/samples/suspicious.elf
CONTAINER_WORKSPACE=/tmp/samples python -m seclab_taskflow_agent \
    -t seclab_taskflows.taskflows.container_shell.demo_malware_analysis
```

Override the target filename with `-g target=<name>`.

**Network analysis demo** — analyses a pcap file:

```
CONTAINER_WORKSPACE=/tmp/captures python -m seclab_taskflow_agent \
    -t seclab_taskflows.taskflows.container_shell.demo_network_analysis \
    -g capture=sample.pcap
```

**SAST demo** — static analysis and call graph extraction for a source repo:

```
CONTAINER_WORKSPACE=/path/to/src python -m seclab_taskflow_agent \
    -t seclab_taskflows.taskflows.container_shell.demo_sast
```

If no source is present the runner script generates a demo Python file with a
shell-injection anti-pattern so semgrep has something to find:

```
./scripts/run_container_shell_demo.sh sast
```

Override the analysis target with `-g target=<path>` (relative to /workspace).

## Using container_shell in your own taskflows

Reference the appropriate toolbox and set `CONTAINER_WORKSPACE` in `env`:

```yaml
taskflow:
  - task:
      agents:
        - seclab_taskflow_agent.personalities.assistant
      toolboxes:
        - seclab_taskflows.toolboxes.container_shell_malware_analysis
      env:
        CONTAINER_WORKSPACE: "{{ env('SAMPLE_DIR') }}"
      user_prompt: |
        Analyse the binary at /workspace/target.elf using static analysis only.
```

`container_shell_exec` requires user confirmation by default (`confirm: [container_shell_exec]` in
all toolbox YAMLs). Pass `headless: true` at the task level to skip
confirmation in automated pipelines.

## Notes

- The container is shared across all `container_shell_exec` calls within a single
  taskflow run. State (files written, processes started) persists between calls.
- The source-access toolbox keeps its containers alive by default
  and reuses persistent containers for the same image and mounted workspace.
- `--rm` is set on `docker run`, so the container is removed automatically when
  stopped. Persistent containers are not started with `--rm`.
- The container name follows the pattern `seclab-shell-<8 hex chars>` and is
  visible in `docker ps`.
- If `docker run` fails (e.g. image not found), `container_shell_exec` returns an error
  string rather than raising, so the agent can report the problem cleanly.
