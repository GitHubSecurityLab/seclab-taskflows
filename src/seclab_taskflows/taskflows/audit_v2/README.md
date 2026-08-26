# Audit v2

A vulnerability discovery pipeline that treats a finding as a claim to be
prosecuted, not a report to be filed.

## Why this exists

The v1 audit taskflows ask a model to read code and say what looks wrong. That
works, and it also produces a lot of confident prose about vulnerabilities that
do not exist. The two things it is missing are adversarial review and proof.

Audit v2 adds both, and makes them structural rather than advisory:

1. **Every candidate is contested.** A prosecutor argues the finding is real, a
   defender argues it is not, and a third model from a different family
   adjudicates. Findings that survive are marked `confirmed`; the rest are
   `rejected` with a reason.
2. **Confirmed findings must be shown reachable.** The reproduction stage stands
   the target up in a container and dynamically demonstrates that
   attacker-controlled input reaches the dangerous sink at runtime, using a
   benign marker or lightweight instrumentation. Only an observed reachable flow
   promotes a finding to `reproduced`.

It is also not web-specific. The survey stage asks where untrusted data crosses
a trust boundary, which is a question you can ask of a parser, a daemon, a
library or a build plugin just as well as of a web app.

## The lifecycle is enforced in code

The important design decision is that a finding's state is derived by the
`finding_ledger` MCP server, never set by a model.

```
                 store_finding
                       |
                       v
                  [candidate] ------ merge_duplicate_finding ---> [duplicate]
                       |
              adjudicate_finding
                    /     \
                   v       v
            [rejected]   [confirmed]
                              |
                  store_reproduction_attempt
                     (outcome: reproduced)
                              |
                              v
                        [reproduced]
```

No tool accepts a state as an argument. A model can record evidence, and the
backend decides what that evidence entitles the finding to:

- `adjudicate_finding` is the only path to `confirmed`, and it is only
  reachable after both sides of the contest have filed their arguments.
- `store_reproduction_attempt` only promotes a finding that is already
  `confirmed`, and only when it observed the flow reach the sink at runtime.
- A `reproduced` finding is immune to later adjudication. Once something has
  been demonstrated reachable, no amount of subsequent argument un-demonstrates
  it.
- `merge_duplicate_finding` only folds `candidate` findings, refuses to merge a
  finding into itself or into another duplicate, and refuses to merge across
  repositories.

This matters because prompts are advice and code is not. A model that decides
mid-run that its finding is obviously real cannot promote it by saying so.

## Convergence is signal, not noise

Three hunters from three model families run over each component. When two of
them independently land on the same path, `merge_duplicate_finding` unions
their `proposed_by` labels rather than discarding the duplicate's provenance.
A finding proposed by three families is a materially different object from one
proposed by a single model, and the adjudicator gets to see that.

Those labels come from the runner, not from the hunters. A branch cannot
reliably name the model it is running as, and asking it to guess is worse than
useless here: two hunters that both answer `unknown` union down to one label,
so a path two families found independently reads as a single opinion. The
multi-model task publishes `{model, item, result}` per branch, where `model` is
the slot named in `models:` (`hunt_claude`, not `claude-opus-5`), so the
label survives swapping the model behind a slot. The hunt task sets
`capture: response` so each branch's `result` is the JSON object it ends with,
listing the ids it filed; a following task hands the whole set to
`attribute_findings` in one call.

## Model assignment

Defined in `configs/model_config_audit_v2.yaml`.

| Role | Model | Why |
| --- | --- | --- |
| `general_tasks` | gpt-5.4 | Cheap bookkeeping: fetching and summarising ledger state |
| `survey` | gpt-5.6-sol | Long-context mapping work |
| `hunt_gpt` | gpt-5.6-sol | |
| `hunt_claude` | claude-opus-5 | Different family, different blind spots |
| `hunt_gemini` | gemini-3.6-flash | Third family |
| `prosecution` | gpt-5.6-sol | |
| `defense` | claude-opus-5 | |
| `adjudication` | gemini-3.6-flash | Deliberately not a sibling of either advocate |
| `reproduction` | claude-opus-4.8 | Long agentic tool-use loops in a container |
| `reporting` | gpt-5.6-sol | |

The adjudicator's family is the point. A model grading an argument written by a
sibling shares its priors, including the wrong ones; the adjudicator writes
neither advocate's argument.

No role uses xAI. CAPI rejects `grok-4.5` for security analysis at the platform
rather than the model level: any request whose content is vulnerability
analysis returns `403 permission-denied ... Failed check:
SAFETY_CHECK_TYPE_CYBER`, down to a five-line snippet, so it cannot fill any
role here.

`hunt_gemini` is the least reliable slot. `gemini-3.6-flash` answers security
questions put to it directly, but in the hunt loop it has refused after reading
the target and produced nothing. The stage is built to survive that --
`completion: any` and `must_complete: false` mean a refusing branch costs a
branch and nothing else -- but do not count on three opinions. Swap any entry
for a model your account is entitled to. Use
`model_config_audit_v2_lowercost.yaml` for exploratory runs.

## Running it

Build the reproduction image once:

```bash
./scripts/build_container_images.sh reproduction
```

Then run the pipeline:

```bash
./scripts/audit_v2/run_audit_v2.sh <owner/repo>
```

Useful variants:

```bash
# Cheaper exploratory run
./scripts/audit_v2/run_audit_v2.sh -m seclab_taskflows.configs.model_config_audit_v2_lowercost <owner/repo>

# Static stages only; findings top out at `confirmed`
./scripts/audit_v2/run_audit_v2.sh --no-reproduce <owner/repo>

# Resume after a stage failed
./scripts/audit_v2/run_audit_v2.sh --from contest <owner/repo>

# One stage on its own
./scripts/audit_v2/run_audit_v2.sh -s report <owner/repo>
```

## The stages

| Stage | What it does | Ledger effect |
| --- | --- | --- |
| `survey` | Fetches the source, decomposes it into components, maps where untrusted data enters each one | populates the v2 survey store |
| `hunt` | Three model families hunt each component in parallel, then a dedup pass folds convergent findings | creates `candidate`s, some `duplicate` |
| `contest` | Prosecution, defense, adjudication | `candidate` → `confirmed` or `rejected` |
| `reproduce` | Builds and runs the target in a container, drives the path with a control case first, then a benign marker to show the flow reaches the sink | `confirmed` → `reproduced` |
| `report` | Writes the report, then verifies every claim in it against the ledger | read-only |

Each stage is a separate taskflow because each is expensive and each ends at a
durable checkpoint. Rerunning `contest` does not re-run `hunt`.

Stage state lives in the ledger rather than in taskflow outputs for a concrete
reason: multi-model tasks do not feed the implicit last-tool-result channel, so
a fan-out across model families has nowhere else to meet. The ledger is that
meeting point, and it happens to also be the thing that survives a crash.

## Reproduction safety

The reproduction container is the only place in the pipeline where code is
executed. It runs with `--network none` by default; loopback still works, so a
server started inside the container is reachable at 127.0.0.1 from the same
container. If a target genuinely cannot be built without fetching its
dependencies, the reproduction engineer is instructed to say so rather than
guess, and the operator can rerun with `CONTAINER_NETWORK=bridge`.

Reproduction runs one finding at a time. All branches of a task share a single
container process, so concurrent reproductions would fight over ports, files
and processes, and a failure in one would be indistinguishable from a failure
in another.

Unlike the other container toolboxes, the reproduction toolbox does not set
`confirm` on `container_shell_exec`, because the stage is useless if every
command needs a human. The isolation is the container, not the prompt.

## Caveats

1. This will consume a large amount of model quota. Three hunters plus a
   three-model contest per finding is the cost of not shipping false positives.
2. Everything here should still be reviewed by a human before it is reported to
   anyone. A reproduced finding is strong evidence, not a disclosure.
