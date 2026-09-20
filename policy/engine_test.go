package policy

import "testing"

const decisionPolicy = `version: 1
default: deny
budget:
  max_calls: 100
tools:
  search_docs:
    effect: allow
    max_calls: 100
    arguments:
      alpha:
        type: string
        required: true
      beta:
        type: string
        required: true
      gamma:
        type: string
        required: false
        max_length: 3
  delete_resource:
    effect: deny
`

func TestInvalidToolIdentifier(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	for _, tool := range []string{"", "bad name", "naïve", "a/b", string(make([]byte, 65))} {
		decision := run.Evaluate(ToolCall{Tool: tool})
		if decision.Code != codeInvalidCall {
			t.Errorf("tool %q: code = %q, want %q", tool, decision.Code, codeInvalidCall)
		}
		if decision.Tool != "" {
			t.Errorf("tool %q: Decision.Tool = %q, want empty", tool, decision.Tool)
		}
		if decision.Reason != "invalid tool call" {
			t.Errorf("tool %q: reason = %q", tool, decision.Reason)
		}
	}
}

func TestUnknownToolKeepsName(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{Tool: "other_tool"})
	if decision.Code != codeUnknownTool || decision.Tool != "other_tool" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.Reason != "unknown tool" {
		t.Errorf("reason = %q", decision.Reason)
	}
}

func TestExplicitDenySkipsArgumentValidation(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{
		Tool:      "delete_resource",
		Arguments: map[string]any{"undeclared": 1},
	})
	if decision.Code != codeToolDenied {
		t.Fatalf("code = %q, want %q", decision.Code, codeToolDenied)
	}
	if decision.Reason != "tool explicitly denied" {
		t.Errorf("reason = %q", decision.Reason)
	}
	if run.globalCalls != 0 {
		t.Errorf("globalCalls = %d, want 0", run.globalCalls)
	}
}

func TestInvalidArgumentIdentifierKeepsToolName(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{
		Tool:      "search_docs",
		Arguments: map[string]any{"bad name": "x"},
	})
	if decision.Code != codeInvalidCall {
		t.Fatalf("code = %q, want %q", decision.Code, codeInvalidCall)
	}
	if decision.Tool != "search_docs" {
		t.Errorf("Decision.Tool = %q, want %q", decision.Tool, "search_docs")
	}
}

func TestMissingRequiredArgumentIsAlphabetical(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{Tool: "search_docs"})
	if decision.Code != codeMissingArgument {
		t.Fatalf("code = %q, want %q", decision.Code, codeMissingArgument)
	}
	if decision.Reason != `required argument "alpha" is missing` {
		t.Errorf("reason = %q, want the alphabetically first missing argument", decision.Reason)
	}
}

func TestMissingArgumentIsReportedBeforeUnexpected(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{
		Tool:      "search_docs",
		Arguments: map[string]any{"alpha": "a", "zulu": "z"},
	})
	if decision.Code != codeMissingArgument || decision.Reason != `required argument "beta" is missing` {
		t.Fatalf("decision = %+v, want the missing required argument first", decision)
	}
}

func TestUnexpectedArgumentIsAlphabetical(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{
		Tool:      "search_docs",
		Arguments: map[string]any{"alpha": "a", "beta": "b", "zulu": "z", "delta": "d"},
	})
	if decision.Code != codeUnexpectedArgument {
		t.Fatalf("code = %q, want %q", decision.Code, codeUnexpectedArgument)
	}
	if decision.Reason != `unexpected argument "delta"` {
		t.Errorf("reason = %q, want the alphabetically first unexpected argument", decision.Reason)
	}
}

func TestConfiguredArgumentsCheckedAlphabetically(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	// Both alpha and gamma are invalid; alpha is checked first.
	decision := run.Evaluate(ToolCall{
		Tool:      "search_docs",
		Arguments: map[string]any{"alpha": 1, "beta": "b", "gamma": "toolong"},
	})
	if decision.Code != codeArgumentTypeMismatch || decision.Reason != `argument "alpha" has invalid type` {
		t.Fatalf("decision = %+v, want alpha to be reported first", decision)
	}
}

func TestAllowDecisionShape(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	decision := run.Evaluate(ToolCall{
		Tool:      "search_docs",
		Arguments: map[string]any{"alpha": "a", "beta": "b"},
	})
	want := Decision{Effect: EffectAllow, Tool: "search_docs", Code: codeAllowed, Reason: "tool allowed"}
	if decision != want {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
}

func TestNilArgumentsMeanEmptyObject(t *testing.T) {
	engine := mustLoad(t, `version: 1
default: deny
budget:
  max_calls: 2
tools:
  ping:
    effect: allow
    max_calls: 2
`)
	decision := engine.NewRun().Evaluate(ToolCall{Tool: "ping"})
	if decision.Effect != EffectAllow {
		t.Fatalf("decision = %+v, want allow", decision)
	}
}

func TestEvaluateDoesNotMutateArguments(t *testing.T) {
	run := mustLoad(t, decisionPolicy).NewRun()
	arguments := map[string]any{"alpha": "a", "beta": "b"}
	run.Evaluate(ToolCall{Tool: "search_docs", Arguments: arguments})
	if len(arguments) != 2 {
		t.Fatalf("arguments = %v, want the caller's map untouched", arguments)
	}
}
