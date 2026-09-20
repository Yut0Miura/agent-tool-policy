package policy

// Engine is a compiled policy. It is immutable after Load or LoadFile returns
// and is safe for concurrent use, including creating independent Runs.
type Engine struct {
	globalMaxCalls int
	tools          map[string]compiledTool
}

// NewRun starts a new authorization scope: one logical agent run or session.
// Budgets are counted per Run, live in memory only and are never shared
// between Runs.
func (e *Engine) NewRun() *Run {
	return &Run{engine: e, toolCalls: make(map[string]int, len(e.tools))}
}
