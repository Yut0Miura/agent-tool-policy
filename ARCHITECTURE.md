# Architecture

## Purpose

Decide, deterministically and locally, whether a proposed agent tool call is authorized, before the host application executes it.

## System Boundary

Inside: policy loading, policy validation, compilation, argument checking, authorization budgets, the decision.

Outside: tool execution, language models, transport, persistence, audit, approval workflows, anything about what a tool does once it runs.

The library is a policy decision point. The host application is the policy enforcement point.

## Components

```text
policy/     library: loading, validation, compilation, evaluation
internal/cli/  command line wrapper: validate, evaluate, JSONL handling
cmd/agent-tool-policy/  entry point, no logic
```

`policy` has no knowledge of the CLI. The CLI adds no policy behaviour: it parses input, calls the library and formats decisions.

## Policy Loading

`LoadFile` reads at most one byte beyond the 1 MiB limit, so an oversized file is rejected rather than truncated. `Load` works on bytes already in memory. The pipeline is fixed:

1. bounded read
2. reject an empty or whitespace-only document
3. parse into a YAML node tree
4. require exactly one document
5. reject anchors and aliases
6. reject merge keys
7. reject duplicate mapping keys at every level
8. decode the same bytes with unknown fields rejected
9. semantic validation
10. compile an immutable engine

Structure is checked before values, so a document that could mean two things is rejected before anything is interpreted.

## Policy Validation

Validation is semantic: version, default effect, budget bounds, at least one tool, identifier rules, effect-specific rules, supported argument types and the constraint set each type allows, and the relationship between tool and global budgets. Errors are reported as `<path>: <message>` and name the first problem found. Tools and arguments are validated in sorted order so the reported error is stable.

## Policy Compilation

A validated configuration becomes an `Engine`: the global budget and a map of compiled tools. Each compiled tool holds its effect, its budget, its argument lookup, and two precomputed sorted name lists — all arguments and the required ones. Sorting at compile time is what makes evaluation independent of map iteration order.

The configuration structs are unexported and are not kept: the `Engine` is the only representation that survives loading, and it is immutable.

## Evaluation Flow

```text
validate tool identifier
resolve tool rule (unknown -> DENY)
explicit deny -> DENY
validate supplied argument identifiers
required arguments (alphabetical)
unexpected arguments (alphabetical)
configured constraints (alphabetical)
lock run
global budget, then tool budget
increment both
unlock
ALLOW
```

Every failure is a DENY decision with a code and a reason; `Evaluate` returns no error. Cheap and structural checks come first, budgets last, so a rejected call never consumes authorization.

## Argument Constraints

Each argument has a type and the constraints that type allows. A present argument is checked in a fixed order: type, `max_length`, `enum`, `prefix`, `min`, `max`. Absent optional arguments are skipped; a supplied `null` is a wrong type.

Numbers arrive as any Go numeric type or as `json.Number`. One helper normalizes them to `float64` after proving the value is finite and inside the exactly representable domain, so comparisons never depend on silent precision loss.

## Authorization Budgets

A `Run` holds the global counter and a per-tool counter, guarded by one mutex. Budgets count ALLOW decisions. The check and both increments happen in a single critical section, so concurrent calls cannot exceed a budget. There is no refund and no persistence: a new `Run` starts at zero.

## Concurrency

`Engine` is read-only after loading and can be shared by any number of goroutines and `Run`s. A `Run` is safe for concurrent `Evaluate` calls. Determinism is a property of policy and state, not of scheduling: with the same engine, the same call and the same run state the decision is identical, but which goroutine takes the last available slot is not specified.

## Decision vs Enforcement

The library returns ALLOW or DENY. It cannot stop a tool from running. A consumer that ignores the decision gets no protection from it.

## Non-Goals

No tool execution, model calls, adapters, network, persistence, audit storage, approval flows, third decision state, policy includes, regular expressions, path or URL semantics, or tool-output inspection.
