package cli

import (
	"strings"
	"testing"
)

func evaluateInput(t *testing.T, input string) (code int, stdout, stderr string) {
	t.Helper()
	return runCLI(t, input, "evaluate", "-policy", writePolicy(t, examplePolicy))
}

func TestArgumentsContainerForms(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		want  string
		code  int
		isErr bool
	}{
		{name: "omitted", line: `{"tool":"delete_resource"}`, want: "tool_denied"},
		{name: "null", line: `{"tool":"delete_resource","arguments":null}`, want: "tool_denied"},
		{name: "empty object", line: `{"tool":"delete_resource","arguments":{}}`, want: "tool_denied"},
		{name: "array", line: `{"tool":"delete_resource","arguments":[]}`, code: 2, isErr: true},
		{name: "string", line: `{"tool":"delete_resource","arguments":"x"}`, code: 2, isErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := evaluateInput(t, test.line+"\n")
			if test.isErr {
				if code != 2 {
					t.Fatalf("exit code = %d, want 2", code)
				}
				if !strings.HasPrefix(stderr, "line 1: invalid tool call: ") {
					t.Errorf("stderr = %q", stderr)
				}
				return
			}
			if code != 0 {
				t.Fatalf("exit code = %d (%s), want 0", code, stderr)
			}
			if !strings.Contains(stdout, test.want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, test.want)
			}
		})
	}
}

func TestInputErrors(t *testing.T) {
	deepArray := strings.Repeat("[", 65) + strings.Repeat("]", 65)
	tests := []struct {
		name string
		line string
		want string
	}{
		{"malformed JSON", `{"tool":`, "unexpected end of JSON input"},
		{"not an object", `"search_docs"`, "json: cannot unmarshal"},
		{"unknown top-level field", `{"tool":"search_docs","extra":1}`, `unknown field "extra"`},
		{"duplicate JSON key", `{"tool":"search_docs","tool":"delete_resource"}`, `duplicate object key "tool"`},
		{"duplicate nested key", `{"tool":"search_docs","arguments":{"query":"a","query":"b"}}`, `duplicate object key "query"`},
		{"two JSON values", `{"tool":"search_docs"} {"tool":"delete_resource"}`, "unexpected data after the first JSON value"},
		{"nesting too deep", `{"tool":"search_docs","arguments":{"query":` + deepArray + `}}`, "nesting exceeds 64 levels"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stdout, stderr := evaluateInput(t, test.line+"\n")
			if code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if !strings.HasPrefix(stderr, "line 1: invalid tool call: ") || !strings.Contains(stderr, test.want) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, test.want)
			}
		})
	}
}

func TestNestingAtLimitIsAccepted(t *testing.T) {
	// The top-level object plus 62 arrays stays inside the 64-level limit.
	nested := strings.Repeat("[", 62) + strings.Repeat("]", 62)
	line := `{"tool":"search_docs","arguments":{"query":` + nested + `}}`
	code, stdout, stderr := evaluateInput(t, line+"\n")
	if code != 0 {
		t.Fatalf("exit code = %d (%s), want 0", code, stderr)
	}
	if !strings.Contains(stdout, "argument_type_mismatch") {
		t.Errorf("stdout = %q, want the array to be rejected by the policy, not the parser", stdout)
	}
}

func TestBlankLinesAreIgnoredButCounted(t *testing.T) {
	input := "\n   \n" + `{"tool":` + "\n"
	code, stdout, stderr := evaluateInput(t, input)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.HasPrefix(stderr, "line 3: ") {
		t.Errorf("stderr = %q, want the physical line number 3", stderr)
	}
}

func TestProcessingStopsAtFirstBadLineAndKeepsOutput(t *testing.T) {
	input := `{"tool":"delete_resource"}
{"tool":
{"tool":"delete_resource"}
`
	code, stdout, stderr := evaluateInput(t, input)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.HasPrefix(stderr, "line 2: ") {
		t.Errorf("stderr = %q, want line 2", stderr)
	}
	if lines := strings.Count(stdout, "\n"); lines != 1 {
		t.Errorf("stdout = %q, want the one decision written before the bad line", stdout)
	}
}

func TestOversizedLine(t *testing.T) {
	long := `{"tool":"search_docs","arguments":{"query":"` + strings.Repeat("a", maxLineBytes) + `"}}`
	code, stdout, stderr := evaluateInput(t, long+"\n")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if stderr != "line 1: input exceeds 1048576 bytes\n" {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestOversizedLineBeyondScannerBuffer(t *testing.T) {
	// Longer than the scanner buffer itself, so the limit is reported from
	// the scanner error rather than from the line length check.
	long := `{"tool":"a","arguments":{"query":"` + strings.Repeat("a", maxLineBytes+128*1024) + `"}}`
	code, _, stderr := evaluateInput(t, long+"\n")
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if stderr != "line 1: input exceeds 1048576 bytes\n" {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestLineAtSizeLimitIsAccepted(t *testing.T) {
	prefix := `{"tool":"search_docs","arguments":{"query":"`
	suffix := `"}}`
	padding := maxLineBytes - len(prefix) - len(suffix)
	line := prefix + strings.Repeat("a", padding) + suffix
	if len(line) != maxLineBytes {
		t.Fatalf("line length = %d, want %d", len(line), maxLineBytes)
	}
	code, stdout, stderr := evaluateInput(t, line+"\n")
	if code != 0 {
		t.Fatalf("exit code = %d (%s), want 0", code, stderr)
	}
	if !strings.Contains(stdout, "string_too_long") {
		t.Errorf("stdout = %q, want the policy to reject the long query", stdout)
	}
}

func TestEmptyInput(t *testing.T) {
	code, stdout, stderr := evaluateInput(t, "")
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
}
