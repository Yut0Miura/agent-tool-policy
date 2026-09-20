GO ?= go
BINARY := bin/agent-tool-policy
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

.PHONY: build fmt fmt-check vet test test-race vuln check validate-example demo

build:
	$(GO) build -trimpath -o $(BINARY) ./cmd/agent-tool-policy

fmt:
	gofmt -w .

fmt-check:
	@files=$$(gofmt -l .); \
	if [ -n "$$files" ]; then echo "gofmt needed:"; echo "$$files"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vuln:
	$(GO) run $(GOVULNCHECK) ./...

check: fmt-check vet test test-race vuln build

validate-example: build
	./$(BINARY) validate -policy examples/policy.yaml

demo: build
	./$(BINARY) evaluate -policy examples/policy.yaml < examples/calls.jsonl
