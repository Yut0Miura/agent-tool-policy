// Package policy decides whether a proposed AI agent tool call is authorized,
// before the host application executes it. A policy document is loaded once
// into an immutable Engine; each agent run creates a Run, which evaluates
// calls against the policy and holds the authorization budgets.
//
// The package makes decisions only. It never executes a tool, calls a model
// or performs a network request: enforcing a decision is the caller's
// responsibility.
package policy

// ToolCall is a tool call proposed by an agent, before it is executed.
//
// Arguments may be nil, which is equivalent to an empty argument object. The
// library never mutates the map; the caller must not mutate it concurrently
// with an Evaluate call.
type ToolCall struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}
