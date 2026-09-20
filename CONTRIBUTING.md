# Contributing

## Requirements

- Go 1.27.1, the pinned toolchain.
- Everything must pass before a change is proposed:

```bash
gofmt -l .
go vet ./...
go test ./...
go test -race ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

`make check` runs all of them and builds the binary.

## Rules

- The runtime performs no network requests. `govulncheck` and module downloads are development and CI concerns.
- No new policy feature without an issue describing the problem it solves. The policy language is intentionally small.
- No new dependency without justification in the pull request.
- Every exported symbol carries a GoDoc comment, including its concurrency expectations where they matter.
- New behaviour comes with tests; behaviour around budgets and concurrency comes with tests that fail without the change.
- Decision codes and reasons are part of the public contract. Changing one is a breaking change.

## Scope

This repository is a decision primitive: it evaluates proposed tool calls. Tool execution, model calls, adapters, servers, persistence and approval flows are out of scope.
