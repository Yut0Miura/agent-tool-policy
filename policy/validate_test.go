package policy

import (
	"strings"
	"testing"
)

func policyWithTool(tool string) string {
	return "version: 1\ndefault: deny\nbudget:\n  max_calls: 6\ntools:\n" + tool
}

func policyWithArgument(argument string) string {
	return policyWithTool("  search_docs:\n    effect: allow\n    max_calls: 3\n    arguments:\n" + argument)
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     string
	}{
		{
			"version not one",
			"version: 2\ndefault: deny\nbudget:\n  max_calls: 1\ntools:\n  a:\n    effect: deny\n",
			"policy.version: must equal 1",
		},
		{
			"default allow",
			"version: 1\ndefault: allow\nbudget:\n  max_calls: 1\ntools:\n  a:\n    effect: deny\n",
			`policy.default: must equal "deny"`,
		},
		{
			"global budget zero",
			"version: 1\ndefault: deny\nbudget:\n  max_calls: 0\ntools:\n  a:\n    effect: deny\n",
			"policy.budget.max_calls: must be between 1 and 1000000000",
		},
		{
			"global budget above limit",
			"version: 1\ndefault: deny\nbudget:\n  max_calls: 1000000001\ntools:\n  a:\n    effect: deny\n",
			"policy.budget.max_calls: must be between 1 and 1000000000",
		},
		{
			"no tools",
			"version: 1\ndefault: deny\nbudget:\n  max_calls: 1\ntools: {}\n",
			"policy.tools: at least one tool is required",
		},
		{
			"invalid tool name",
			policyWithTool("  \"bad name\":\n    effect: deny\n"),
			`policy.tools["bad name"]: invalid tool name`,
		},
		{
			"unsupported effect",
			policyWithTool("  a:\n    effect: warn\n"),
			`policy.tools["a"].effect: must equal "allow" or "deny"`,
		},
		{
			"allow without max_calls",
			policyWithTool("  a:\n    effect: allow\n"),
			`policy.tools["a"].max_calls: required for allow rule`,
		},
		{
			"allow max_calls zero",
			policyWithTool("  a:\n    effect: allow\n    max_calls: 0\n"),
			`policy.tools["a"].max_calls: must be between 1 and 1000000000`,
		},
		{
			"allow max_calls above limit",
			policyWithTool("  a:\n    effect: allow\n    max_calls: 1000000001\n"),
			`policy.tools["a"].max_calls: must be between 1 and 1000000000`,
		},
		{
			"tool budget above global",
			policyWithTool("  a:\n    effect: allow\n    max_calls: 7\n"),
			`policy.tools["a"].max_calls: must be <= policy.budget.max_calls`,
		},
		{
			"deny with max_calls",
			policyWithTool("  a:\n    effect: deny\n    max_calls: 1\n"),
			`policy.tools["a"].max_calls: not allowed for deny rule`,
		},
		{
			"deny with arguments",
			policyWithTool("  a:\n    effect: deny\n    arguments:\n      q:\n        type: string\n"),
			`policy.tools["a"].arguments: not allowed for deny rule`,
		},
		{
			"deny with empty arguments",
			policyWithTool("  a:\n    effect: deny\n    arguments: {}\n"),
			`policy.tools["a"].arguments: not allowed for deny rule`,
		},
		{
			"deny with null arguments",
			policyWithTool("  a:\n    effect: deny\n    arguments: null\n"),
			"policy: explicit null values are not supported",
		},
		{
			"invalid argument name",
			policyWithArgument("      \"bad name\":\n        type: string\n"),
			`policy.tools["search_docs"].arguments["bad name"]: invalid argument name`,
		},
		{
			"unsupported argument type",
			policyWithArgument("      q:\n        type: object\n"),
			`.type: must equal "string", "number" or "boolean"`,
		},
		{
			"numeric constraint on string",
			policyWithArgument("      q:\n        type: string\n        min: 1\n"),
			`.min: not allowed for a string argument`,
		},
		{
			"string constraint on number",
			policyWithArgument("      q:\n        type: number\n        prefix: \"a\"\n"),
			`.prefix: not allowed for a number argument`,
		},
		{
			"enum on number",
			policyWithArgument("      q:\n        type: number\n        enum:\n          - \"1\"\n"),
			`.enum: not allowed for a number argument`,
		},
		{
			"max_length on boolean",
			policyWithArgument("      q:\n        type: boolean\n        max_length: 2\n"),
			`.max_length: not allowed for a boolean argument`,
		},
		{
			"empty prefix",
			policyWithArgument("      q:\n        type: string\n        prefix: \"\"\n"),
			`.prefix: must not be empty`,
		},
		{
			"empty configured enum",
			policyWithArgument("      q:\n        type: string\n        enum: []\n"),
			`.enum: must contain at least one value`,
		},
		{
			"empty enum member",
			policyWithArgument("      q:\n        type: string\n        enum:\n          - \"\"\n"),
			`.enum: values must not be empty`,
		},
		{
			"duplicate enum member",
			policyWithArgument("      q:\n        type: string\n        enum:\n          - a\n          - a\n"),
			`.enum: duplicate value "a"`,
		},
		{
			"max_length zero",
			policyWithArgument("      q:\n        type: string\n        max_length: 0\n"),
			`.max_length: must be >= 1`,
		},
		{
			"NaN minimum",
			policyWithArgument("      q:\n        type: number\n        min: .nan\n"),
			`.min: must be a finite number within 9007199254740991`,
		},
		{
			"infinite maximum",
			policyWithArgument("      q:\n        type: number\n        max: .inf\n"),
			`.max: must be a finite number within 9007199254740991`,
		},
		{
			"minimum outside safe domain",
			policyWithArgument("      q:\n        type: number\n        min: -9007199254740992\n"),
			`.min: must be a finite number within 9007199254740991`,
		},
		{
			"minimum above maximum",
			policyWithArgument("      q:\n        type: number\n        min: 5\n        max: 4\n"),
			`.min: must be <= max`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Load([]byte(test.document))
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("Load() error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestValidateRejectsEnumNull(t *testing.T) {
	// An explicit enum: null is refused; an absent enum means no enum.
	_, err := Load([]byte(policyWithArgument("      q:\n        type: string\n        enum: null\n")))
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if want := "policy: explicit null values are not supported"; !strings.Contains(err.Error(), want) {
		t.Errorf("Load() error = %q, want it to contain %q", err, want)
	}
}

func TestValidateAcceptsToolBudgetEqualToGlobal(t *testing.T) {
	mustLoad(t, policyWithTool("  a:\n    effect: allow\n    max_calls: 6\n"))
}

func TestValidateAcceptsArgumentSections(t *testing.T) {
	tests := []struct {
		name     string
		document string
	}{
		{"deny without arguments", policyWithTool("  a:\n    effect: deny\n")},
		{"allow without arguments", policyWithTool("  a:\n    effect: allow\n    max_calls: 1\n")},
		{"allow with empty arguments", policyWithTool("  a:\n    effect: allow\n    max_calls: 1\n    arguments: {}\n")},
		{"allow with declared arguments", policyWithArgument("      q:\n        type: string\n")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mustLoad(t, test.document)
		})
	}
}

func TestAllowWithoutDeclaredArgumentsAcceptsOnlyEmptyArguments(t *testing.T) {
	// An absent arguments section and an empty one both declare no arguments.
	for _, section := range []string{"", "    arguments: {}\n"} {
		run := mustLoad(t, policyWithTool("  a:\n    effect: allow\n    max_calls: 2\n"+section)).NewRun()

		if decision := run.Evaluate(ToolCall{Tool: "a"}); decision.Code != codeAllowed {
			t.Errorf("section %q, no arguments: code = %q, want %q", section, decision.Code, codeAllowed)
		}
		decision := run.Evaluate(ToolCall{Tool: "a", Arguments: map[string]any{"q": "x"}})
		if decision.Code != codeUnexpectedArgument {
			t.Errorf("section %q, one argument: code = %q, want %q", section, decision.Code, codeUnexpectedArgument)
		}
	}
}
