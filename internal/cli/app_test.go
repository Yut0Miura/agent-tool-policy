package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const examplePolicy = `version: 1
default: deny
budget:
  max_calls: 2
tools:
  search_docs:
    effect: allow
    max_calls: 2
    arguments:
      query:
        type: string
        required: true
        max_length: 20
  delete_resource:
    effect: deny
`

func writePolicy(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func runCLI(t *testing.T, input string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Run(args, strings.NewReader(input), &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageErrors(t *testing.T) {
	path := writePolicy(t, examplePolicy)
	tests := []struct {
		name string
		args []string
	}{
		{"no command", nil},
		{"unknown command", []string{"explain", "-policy", path}},
		{"missing policy flag", []string{"validate"}},
		{"empty policy flag", []string{"validate", "-policy", ""}},
		{"unknown flag", []string{"validate", "-policy", path, "-verbose"}},
		{"extra positional argument", []string{"validate", "-policy", path, "extra"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "", test.args...)
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.Contains(stderr, "usage: agent-tool-policy <validate|evaluate> -policy <path>") {
				t.Errorf("stderr = %q, want the usage line", stderr)
			}
		})
	}
}

func TestValidateSuccess(t *testing.T) {
	code, stdout, stderr := runCLI(t, "", "validate", "-policy", writePolicy(t, examplePolicy))
	if code != 0 {
		t.Fatalf("exit code = %d (%s), want 0", code, stderr)
	}
	if stdout != "policy valid\n" {
		t.Errorf("stdout = %q, want %q", stdout, "policy valid\n")
	}
}

func TestPolicyFailure(t *testing.T) {
	path := writePolicy(t, "version: 2\ndefault: deny\nbudget:\n  max_calls: 1\ntools:\n  a:\n    effect: deny\n")
	code, stdout, stderr := runCLI(t, "", "validate", "-policy", path)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.HasPrefix(stderr, "policy error: ") {
		t.Errorf("stderr = %q, want a policy error", stderr)
	}
}

func TestMissingPolicyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.yaml")
	if code, _, stderr := runCLI(t, "", "evaluate", "-policy", path); code != 1 {
		t.Fatalf("exit code = %d (%s), want 1", code, stderr)
	}
}

func TestEvaluateAllowAndDeny(t *testing.T) {
	input := `{"tool":"search_docs","arguments":{"query":"deployment"}}
{"tool":"delete_resource","arguments":{}}
{"tool":"other","arguments":{}}
`
	code, stdout, stderr := runCLI(t, input, "evaluate", "-policy", writePolicy(t, examplePolicy))
	if code != 0 {
		t.Fatalf("exit code = %d (%s), want 0", code, stderr)
	}
	want := `{"decision":"allow","tool":"search_docs","code":"allowed","reason":"tool allowed"}
{"decision":"deny","tool":"delete_resource","code":"tool_denied","reason":"tool explicitly denied"}
{"decision":"deny","tool":"other","code":"unknown_tool","reason":"unknown tool"}
`
	if stdout != want {
		t.Errorf("stdout =\n%s\nwant\n%s", stdout, want)
	}
}

func TestEvaluateEmptyToolIsADecisionNotAnInputError(t *testing.T) {
	code, stdout, stderr := runCLI(t, "{\"tool\":\"\"}\n", "evaluate", "-policy", writePolicy(t, examplePolicy))
	if code != 0 {
		t.Fatalf("exit code = %d (%s), want 0", code, stderr)
	}
	want := `{"decision":"deny","tool":"","code":"invalid_call","reason":"invalid tool call"}` + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestEvaluateSharesOneRun(t *testing.T) {
	input := strings.Repeat(`{"tool":"search_docs","arguments":{"query":"a"}}`+"\n", 3)
	_, stdout, _ := runCLI(t, input, "evaluate", "-policy", writePolicy(t, examplePolicy))
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if !strings.Contains(lines[2], "global_budget_exhausted") {
		t.Errorf("third decision = %q, want the shared budget to be exhausted", lines[2])
	}
}

func TestEachInvocationStartsANewRun(t *testing.T) {
	path := writePolicy(t, examplePolicy)
	input := strings.Repeat(`{"tool":"search_docs","arguments":{"query":"a"}}`+"\n", 2)
	for invocation := 0; invocation < 2; invocation++ {
		_, stdout, _ := runCLI(t, input, "evaluate", "-policy", path)
		if strings.Contains(stdout, "budget_exhausted") {
			t.Fatalf("invocation %d: stdout = %q, want a fresh budget", invocation, stdout)
		}
	}
}
