package policy

import (
	"reflect"
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

func freshBudgetSnapshot() BudgetSnapshot {
	return BudgetSnapshot{
		Global: BudgetUsage{Limit: 3, Used: 0, Remaining: 3},
		Tools: map[string]BudgetUsage{
			"alpha": {Limit: 2, Used: 0, Remaining: 2},
			"beta":  {Limit: 3, Used: 0, Remaining: 3},
		},
	}
}

func assertBudgetSnapshot(t *testing.T, run *Run, want BudgetSnapshot) {
	t.Helper()
	if got := run.BudgetSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

func TestBudgetSnapshotOfNewRun(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	assertBudgetSnapshot(t, run, freshBudgetSnapshot())
}

func TestBudgetSnapshotCountsAllow(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	if decision := run.Evaluate(ToolCall{Tool: "alpha"}); decision.Effect != EffectAllow {
		t.Fatalf("decision = %+v", decision)
	}
	want := freshBudgetSnapshot()
	want.Global = BudgetUsage{Limit: 3, Used: 1, Remaining: 2}
	want.Tools["alpha"] = BudgetUsage{Limit: 2, Used: 1, Remaining: 1}
	assertBudgetSnapshot(t, run, want)
}

func TestBudgetSnapshotIgnoresDeny(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	calls := []ToolCall{
		{Tool: "denied"},
		{Tool: "unknown"},
		{Tool: ""},
		{Tool: "alpha", Arguments: map[string]any{"extra": 1}},
	}
	for _, call := range calls {
		if decision := run.Evaluate(call); decision.Effect != EffectDeny {
			t.Fatalf("call %+v: decision = %+v, want deny", call, decision)
		}
	}
	assertBudgetSnapshot(t, run, freshBudgetSnapshot())
}

func TestBudgetSnapshotTracksGlobalAndToolBudgets(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	run.Evaluate(ToolCall{Tool: "alpha"})
	run.Evaluate(ToolCall{Tool: "alpha"})

	want := freshBudgetSnapshot()
	want.Global = BudgetUsage{Limit: 3, Used: 2, Remaining: 1}
	want.Tools["alpha"] = BudgetUsage{Limit: 2, Used: 2, Remaining: 0}
	assertBudgetSnapshot(t, run, want)

	// The exhausted tool budget denies without consuming the global budget.
	if decision := run.Evaluate(ToolCall{Tool: "alpha"}); decision.Code != codeToolBudget {
		t.Fatalf("code = %q, want %q", decision.Code, codeToolBudget)
	}
	assertBudgetSnapshot(t, run, want)

	if decision := run.Evaluate(ToolCall{Tool: "beta"}); decision.Effect != EffectAllow {
		t.Fatalf("decision = %+v, want allow", decision)
	}
	want.Global = BudgetUsage{Limit: 3, Used: 3, Remaining: 0}
	want.Tools["beta"] = BudgetUsage{Limit: 3, Used: 1, Remaining: 2}
	assertBudgetSnapshot(t, run, want)

	// The exhausted global budget denies beta although its own budget is left.
	if decision := run.Evaluate(ToolCall{Tool: "beta"}); decision.Code != codeGlobalBudget {
		t.Fatalf("code = %q, want %q", decision.Code, codeGlobalBudget)
	}
	assertBudgetSnapshot(t, run, want)
}

func TestBudgetSnapshotIsIndependentCopy(t *testing.T) {
	run := mustLoad(t, budgetPolicy).NewRun()
	snapshot := run.BudgetSnapshot()
	snapshot.Global.Used = 3
	snapshot.Tools["alpha"] = BudgetUsage{Limit: 0, Used: 2, Remaining: 0}
	delete(snapshot.Tools, "beta")
	snapshot.Tools["denied"] = BudgetUsage{Limit: 1}

	assertBudgetSnapshot(t, run, freshBudgetSnapshot())
	if decision := run.Evaluate(ToolCall{Tool: "alpha"}); decision.Effect != EffectAllow {
		t.Fatalf("decision = %+v, want allow", decision)
	}
	if got := snapshot.Tools["alpha"]; got.Used != 2 {
		t.Fatalf("earlier snapshot changed: alpha = %+v", got)
	}
}

func TestBudgetSnapshotsOfRunsAreIndependent(t *testing.T) {
	engine := mustLoad(t, budgetPolicy)
	first := engine.NewRun()
	second := engine.NewRun()
	first.Evaluate(ToolCall{Tool: "beta"})

	want := freshBudgetSnapshot()
	want.Global = BudgetUsage{Limit: 3, Used: 1, Remaining: 2}
	want.Tools["beta"] = BudgetUsage{Limit: 3, Used: 1, Remaining: 2}
	assertBudgetSnapshot(t, first, want)
	assertBudgetSnapshot(t, second, freshBudgetSnapshot())
}

func TestConcurrentEvaluateAndBudgetSnapshot(t *testing.T) {
	engine := mustLoad(t, `version: 1
default: deny
budget:
  max_calls: 10
tools:
  alpha:
    effect: allow
    max_calls: 6
  beta:
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
		done.Add(2)
		tool := "alpha"
		if i%2 == 1 {
			tool = "beta"
		}
		go func(index int, tool string) {
			defer done.Done()
			start.Wait()
			decisions[index] = run.Evaluate(ToolCall{Tool: tool})
		}(i, tool)
		go func() {
			defer done.Done()
			start.Wait()
			snapshot := run.BudgetSnapshot()
			used := 0
			for name, usage := range snapshot.Tools {
				if usage.Used > usage.Limit || usage.Remaining != usage.Limit-usage.Used {
					t.Errorf("%s: inconsistent usage %+v", name, usage)
				}
				used += usage.Used
			}
			if snapshot.Global.Used != used || snapshot.Global.Used > snapshot.Global.Limit {
				t.Errorf("global = %+v, sum of tools = %d", snapshot.Global, used)
			}
		}()
	}
	start.Done()
	done.Wait()

	allowed := map[string]int{}
	for _, decision := range decisions {
		if decision.Effect == EffectAllow {
			allowed[decision.Tool]++
		}
	}
	snapshot := run.BudgetSnapshot()
	if snapshot.Global.Used != allowed["alpha"]+allowed["beta"] || snapshot.Global.Used != 10 {
		t.Fatalf("global = %+v, allowed = %v", snapshot.Global, allowed)
	}
	for _, name := range []string{"alpha", "beta"} {
		if got := snapshot.Tools[name].Used; got != allowed[name] {
			t.Errorf("%s: used = %d, allowed = %d", name, got, allowed[name])
		}
	}
}
