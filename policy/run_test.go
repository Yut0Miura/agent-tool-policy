package policy

import (
	"sync"
	"testing"
)

const budgetPolicy = `version: 1
default: deny
budget:
  max_calls: 3
tools:
  alpha:
    effect: allow
    max_calls: 2
  beta:
    effect: allow
    max_calls: 3
  denied:
    effect: deny
`

func TestAllowConsumesBudget(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	if decision := run.Evaluate(ToolCall{Tool: "alpha"}); decision.Effect != EffectAllow {
		t.Fatalf("decision = %+v", decision)
	}
	if run.globalCalls != 1 || run.toolCalls["alpha"] != 1 {
		t.Fatalf("global = %d, tool = %d, want 1 and 1", run.globalCalls, run.toolCalls["alpha"])
	}
}

func TestDenyConsumesNothing(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	run.Evaluate(ToolCall{Tool: "denied"})
	run.Evaluate(ToolCall{Tool: "unknown"})
	run.Evaluate(ToolCall{Tool: ""})
	if run.globalCalls != 0 || len(run.toolCalls) != 0 {
		t.Fatalf("global = %d, tools = %v, want nothing consumed", run.globalCalls, run.toolCalls)
	}
}

func TestToolBudgetExhaustion(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	run.Evaluate(ToolCall{Tool: "alpha"})
	run.Evaluate(ToolCall{Tool: "alpha"})
	decision := run.Evaluate(ToolCall{Tool: "alpha"})
	if decision.Code != codeToolBudget {
		t.Fatalf("code = %q, want %q", decision.Code, codeToolBudget)
	}
	if decision.Reason != "tool authorization budget exhausted" {
		t.Errorf("reason = %q", decision.Reason)
	}
	// The global budget still has one slot for another tool.
	if decision := run.Evaluate(ToolCall{Tool: "beta"}); decision.Effect != EffectAllow {
		t.Errorf("decision = %+v, want allow", decision)
	}
}

func TestGlobalBudgetExhaustion(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	for i := 0; i < 3; i++ {
		if decision := run.Evaluate(ToolCall{Tool: "beta"}); decision.Effect != EffectAllow {
			t.Fatalf("call %d: decision = %+v", i, decision)
		}
	}
	decision := run.Evaluate(ToolCall{Tool: "beta"})
	if decision.Code != codeGlobalBudget {
		t.Fatalf("code = %q, want %q", decision.Code, codeGlobalBudget)
	}
	if decision.Reason != "global authorization budget exhausted" {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestGlobalExhaustionWinsOverToolExhaustion(t *testing.T) {
	engine := mustLoad(t, `version: 1
default: deny
budget:
  max_calls: 1
tools:
  alpha:
    effect: allow
    max_calls: 1
`)
	run := engine.NewRun()
	run.Evaluate(ToolCall{Tool: "alpha"})
	if decision := run.Evaluate(ToolCall{Tool: "alpha"}); decision.Code != codeGlobalBudget {
		t.Fatalf("code = %q, want %q", decision.Code, codeGlobalBudget)
	}
}

func TestRunsHaveIndependentBudgets(t *testing.T) {
	engine := mustLoad(t, budgetPolicy)
	first := engine.NewRun()
	for i := 0; i < 3; i++ {
		first.Evaluate(ToolCall{Tool: "beta"})
	}
	if decision := first.Evaluate(ToolCall{Tool: "beta"}); decision.Effect != EffectDeny {
		t.Fatalf("first run: decision = %+v, want deny", decision)
	}

	second := engine.NewRun()
	if decision := second.Evaluate(ToolCall{Tool: "beta"}); decision.Effect != EffectAllow {
		t.Fatalf("second run: decision = %+v, want allow", decision)
	}
}

func TestConcurrentEvaluateNeverExceedsBudget(t *testing.T) {
	engine := mustLoad(t, `version: 1
default: deny
budget:
  max_calls: 10
tools:
  alpha:
    effect: allow
    max_calls: 10
`)
	run := engine.NewRun()

	const calls = 100
	decisions := make([]Decision, calls)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := 0; i < calls; i++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			decisions[index] = run.Evaluate(ToolCall{Tool: "alpha"})
		}(i)
	}
	start.Done()
	done.Wait()

	allowed := 0
	for _, decision := range decisions {
		if decision.Effect == EffectAllow {
			allowed++
		}
	}
	if allowed != 10 {
		t.Fatalf("allowed = %d, want exactly 10", allowed)
	}
	if run.globalCalls != 10 || run.toolCalls["alpha"] != 10 {
		t.Fatalf("global = %d, tool = %d, want 10 and 10", run.globalCalls, run.toolCalls["alpha"])
	}
}

func TestConcurrentRunsShareImmutableEngine(t *testing.T) {
	engine := mustLoad(t, budgetPolicy)
	var wait sync.WaitGroup
	for i := 0; i < 50; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			run := engine.NewRun()
			run.Evaluate(ToolCall{Tool: "alpha", Arguments: map[string]any{}})
		}()
	}
	wait.Wait()
}
