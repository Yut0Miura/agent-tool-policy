# Agent Tool Policy

**Deterministic pre-execution policy for AI agent tool calls in Go.**

Agent Tool Policy is a small Go library for evaluating proposed AI agent tool calls immediately before execution. It applies local default-deny policy, strict argument allowlists and finite per-run authorization budgets, returning a deterministic ALLOW or DENY decision.

The library does not execute tools, call language models or contact external services. The host application remains responsible for enforcing the returned decision before performing a side effect.

## Why

Model-generated tool calls should not automatically become authorization to perform side effects.

```text
proposed tool call
        ↓
deterministic policy
        ↓
ALLOW / DENY
        ↓
host enforcement
```

A model can propose any call: a tool that is not part of the task, an argument that was never meant to be reachable, or the same expensive call a hundred times. The decision whether that call is authorized belongs in code the operator controls, written down as policy, evaluated the same way every time.

## How It Works

```text
AI Agent / LLM
      │
      ▼
 proposed ToolCall
      │
      ▼
Agent Tool Policy
      │
      ├── tool rule
      ├── argument allowlist
      ├── constraints
      └── authorization budget
      │
      ▼
 ALLOW / DENY
      │
      ▼
Host application
      │
      ▼
optional actual tool execution
```

A policy file is loaded once and compiled into an immutable `Engine`. Each agent run creates a `Run`, which carries the authorization budgets. Every proposed call is checked against the tool rule, then its arguments, then the budgets, and the result is a `Decision`.

## What This Is / Is Not

This is:

- an embedded Go policy library
- a pre-execution decision layer
- a default-deny tool policy
- a strict argument validator
- a finite in-memory authorization budget

This is not:

- a tool executor
- an AI safety framework
- a sandbox
- an agent runtime
- an MCP server
- a network service
- a persistent authorization system
- an audit system
- a prompt-injection detector

## Features

- Local YAML policy with `default: deny` and explicit allow and deny rules.
- Strict argument allowlists: every supplied argument must be declared.
- String constraints (`prefix`, `enum`, `max_length`), numeric bounds (`min`, `max`) and boolean arguments.
- Finite global and per-tool authorization budgets, enforced atomically.
- Deterministic decisions with a closed set of codes and reasons.
- Strict bounded YAML loading: one document, no anchors, aliases, merge keys, duplicate keys or unknown fields.
- Offline `validate` and `evaluate` commands.
- Thread-safe evaluation, verified under the race detector.

Fail-closed within the supported policy model: unknown tools, malformed calls, invalid arguments, constraint violations and exhausted authorization budgets return DENY. Invalid policy prevents Engine creation.

## Quick Start

```bash
go build -trimpath -o bin/agent-tool-policy ./cmd/agent-tool-policy

./bin/agent-tool-policy validate -policy examples/policy.yaml
./bin/agent-tool-policy evaluate -policy examples/policy.yaml < examples/calls.jsonl
```

```text
{"decision":"allow","tool":"search_docs","code":"allowed","reason":"tool allowed"}
{"decision":"allow","tool":"read_resource","code":"allowed","reason":"tool allowed"}
{"decision":"allow","tool":"service_status","code":"allowed","reason":"tool allowed"}
{"decision":"deny","tool":"delete_resource","code":"tool_denied","reason":"tool explicitly denied"}
{"decision":"deny","tool":"unknown_tool","code":"unknown_tool","reason":"unknown tool"}
```

## Policy Format

```yaml
version: 1

default: deny

budget:
  max_calls: 6

tools:
  search_docs:
    effect: allow
    max_calls: 3
    arguments:
      query:
        type: string
        required: true
        max_length: 200

      limit:
        type: number
        required: false
        min: 1
        max: 10

  delete_resource:
    effect: deny
```

Rules of the format:

- `version` must be `1`, `default` must be `deny`.
- `budget.max_calls` is mandatory; `1 <= max_calls <= 1000000000`. There is no unlimited mode.
- Every `allow` tool must declare `max_calls`, which may not exceed the global budget.
- A `deny` tool declares neither `max_calls` nor arguments.
- Tool and argument names are 1 to 64 ASCII characters from `A-Z`, `a-z`, `0-9`, `_`, `.`, `-`.
- The policy file is at most 1 MiB, must be a single YAML document, and must not use anchors, aliases, merge keys, duplicate keys or unknown fields.

## Decision Model

A decision is one of two effects with a code and a reason:

```json
{"decision":"allow","tool":"search_docs","code":"allowed","reason":"tool allowed"}
```

| Code | Meaning |
|------|---------|
| `allowed` | the call is authorized |
| `invalid_call` | the tool or an argument name is not a valid identifier |
| `unknown_tool` | no rule declares this tool |
| `tool_denied` | an explicit deny rule |
| `missing_argument` | a required argument was not supplied |
| `unexpected_argument` | an argument the policy does not declare |
| `argument_type_mismatch` | the value has the wrong type, or is an unsupported number |
| `string_prefix_mismatch`, `string_enum_mismatch`, `string_too_long` | string constraints |
| `number_below_min`, `number_above_max` | numeric bounds |
| `global_budget_exhausted`, `tool_budget_exhausted` | authorization budgets |

The evaluation order is fixed: tool identifier, tool rule, argument identifiers, required arguments, unexpected arguments, configured constraints, then budgets. Arguments are examined in alphabetical order, so the reported reason never depends on map iteration order.

## Argument Constraints

| Type | Constraints |
|------|-------------|
| `string` | `required`, `prefix`, `enum`, `max_length` |
| `number` | `required`, `min`, `max` |
| `boolean` | `required` |

Constraints combine with AND and are checked in a fixed order: type, `max_length`, `enum`, `prefix`, `min`, `max`. `max_length` counts runes, not bytes. Enum and prefix comparisons are exact and case-sensitive. Numbers are compared inside the exactly representable domain `abs(value) <= 9007199254740991`; a value outside it, `NaN` or an infinity is an `argument_type_mismatch`. A supplied `null` is a value of the wrong type, not an absent argument.

String prefix constraints are lexical checks only. They do not provide filesystem, URL, shell or network sandboxing.

## Authorization Budgets

A `Run` is one logical agent run. It holds a global budget and one budget per tool, both finite, both in memory only.

Authorization budgets count ALLOW decisions, not confirmed tool executions. An ALLOW decision consumes budget immediately and is not refunded if the host later skips the tool or the tool itself fails.

DENY decisions consume nothing. The global budget is checked before the per-tool budget, so an exhausted global budget is reported as `global_budget_exhausted`. Budgets reset when a new `Run` is created; nothing is persisted, and a new process or a new CLI invocation starts from zero.

## Go Library Usage

```go
engine, err := policy.LoadFile("policy.yaml")
if err != nil {
    return err
}

run := engine.NewRun()

decision := run.Evaluate(policy.ToolCall{
    Tool: "search_docs",
    Arguments: map[string]any{
        "query": "deployment guide",
        "limit": 5,
    },
})

if decision.Effect != policy.EffectAllow {
    // Do not execute the tool.
}
```

`Engine` is immutable once loaded and safe for concurrent use, including creating independent `Run`s. A `Run` is safe for concurrent `Evaluate` calls, and its budgets can never be exceeded by a race; which goroutine receives the last available slot is not specified. `Evaluate` never returns an error and never mutates the caller's argument map.

## CLI Usage

```text
usage: agent-tool-policy <validate|evaluate> -policy <path>
```

`validate` prints `policy valid` and exits 0. `evaluate` reads JSONL from stdin, one tool call per line, and writes one compact decision per line. All lines of one invocation share a single `Run`, and therefore one set of budgets.

Exit codes: `0` when the command completed, including DENY decisions; `1` for a policy load or validation error; `2` for a usage or input error.

Input lines are at most 1 MiB. Blank lines are ignored but still count towards the physical line number. A line must contain exactly one JSON value with only the `tool` and `arguments` fields, no duplicate object member at any depth, and nesting no deeper than 64. Malformed input stops processing; decisions already written stay written.

## Decision vs Enforcement

Agent Tool Policy is a decision engine, not an enforcement boundary by itself. A DENY decision protects the system only when the consumer checks the decision before executing the tool.

Agent Tool Policy makes a decision. The host application enforces it. The library cannot prevent side effects if the caller ignores a DENY result.

## Security Model

The policy file is trusted operator configuration. Tool calls and their arguments are untrusted runtime input: they are bounded, parsed strictly and rejected by default.

The library runtime, `validate`, `evaluate`, tests and demo perform no external network requests and require no LLM, API key, Docker, database, cloud account or paid service. Dependency installation and vulnerability-database access used by `govulncheck` are development/CI concerns and are not runtime dependencies.

See [SECURITY.md](SECURITY.md) for the threat model and for the boundaries this project does not provide.

## Limitations

- The policy language is deliberately small: no regular expressions, globs, URL or path semantics, no policy includes or inheritance, no remote policy.
- Arguments are flat: objects and arrays can only be rejected, not described.
- Budgets are per process and per `Run`; they are not shared across processes and are not persisted.
- Decisions are not recorded; the library keeps no audit trail.
- Nothing here inspects tool output or detects prompt injection.

## Development

```bash
make check             # fmt-check, vet, test, test-race, vuln, build
make validate-example  # validate examples/policy.yaml
make demo              # evaluate examples/calls.jsonl
```

The only runtime dependency is `go.yaml.in/yaml/v3`. Go 1.27.1 is the pinned toolchain.

## Testing

```bash
go test ./...
go test -race ./...
```

The suite covers the loader, policy validation, every argument constraint, decision codes and reasons, budget semantics and concurrency: with a budget of 10 and 100 concurrent calls, exactly 10 decisions are ALLOW.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
