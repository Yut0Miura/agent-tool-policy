package policy

import "sync"

// Run holds the authorization budgets of one agent run. A Run is safe for
// concurrent use; its budgets can never be exceeded by concurrent calls.
type Run struct {
	engine      *Engine
	mu          sync.Mutex
	globalCalls int
	toolCalls   map[string]int
}

// Evaluate decides whether a proposed tool call is authorized. It never
// executes the tool and never returns an error: unknown tools, malformed
// calls, rejected arguments and exhausted budgets are DENY decisions.
//
// An ALLOW decision consumes one global and one per-tool authorization slot
// immediately and is never refunded; a DENY decision consumes nothing.
func (r *Run) Evaluate(call ToolCall) Decision {
	if !validIdentifier(call.Tool) {
		return deny("", codeInvalidCall, "invalid tool call")
	}

	tool, known := r.engine.tools[call.Tool]
	if !known {
		return deny(call.Tool, codeUnknownTool, "unknown tool")
	}
	if tool.effect == EffectDeny {
		return deny(call.Tool, codeToolDenied, "tool explicitly denied")
	}

	arguments := call.Arguments
	if arguments == nil {
		arguments = map[string]any{}
	}

	for _, name := range sortedKeys(arguments) {
		if !validIdentifier(name) {
			return deny(call.Tool, codeInvalidCall, "invalid tool call")
		}
	}

	for _, name := range tool.required {
		if _, present := arguments[name]; !present {
			return deny(call.Tool, codeMissingArgument, "required argument "+quote(name)+" is missing")
		}
	}

	for _, name := range sortedKeys(arguments) {
		if _, declared := tool.arguments[name]; !declared {
			return deny(call.Tool, codeUnexpectedArgument, "unexpected argument "+quote(name))
		}
	}

	for _, name := range tool.names {
		value, present := arguments[name]
		if !present {
			continue
		}
		if code, reason := checkArgument(name, tool.arguments[name], value); code != "" {
			return deny(call.Tool, code, reason)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.globalCalls >= r.engine.globalMaxCalls {
		return deny(call.Tool, codeGlobalBudget, "global authorization budget exhausted")
	}
	if r.toolCalls[call.Tool] >= tool.maxCalls {
		return deny(call.Tool, codeToolBudget, "tool authorization budget exhausted")
	}
	r.globalCalls++
	r.toolCalls[call.Tool]++

	return allow(call.Tool)
}

func quote(s string) string {
	return `"` + s + `"`
}
