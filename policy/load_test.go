package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPolicy = `version: 1
default: deny
budget:
  max_calls: 6
tools:
  search_docs:
    effect: allow
    max_calls: 3
    arguments:
      query:
        type: string
        required: true
        max_length: 200
  delete_resource:
    effect: deny
`

func mustLoad(t *testing.T, document string) *Engine {
	t.Helper()
	engine, err := Load([]byte(document))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return engine
}

func TestLoadValidPolicy(t *testing.T) {
	engine := mustLoad(t, validPolicy)
	if engine.globalMaxCalls != 6 {
		t.Errorf("globalMaxCalls = %d, want 6", engine.globalMaxCalls)
	}
	if len(engine.tools) != 2 {
		t.Errorf("tools = %d, want 2", len(engine.tools))
	}
	if got := engine.tools["delete_resource"].effect; got != EffectDeny {
		t.Errorf("delete_resource effect = %q, want %q", got, EffectDeny)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := []struct {
		name     string
		document string
		want     string
	}{
		{"empty", "", "policy: file is empty"},
		{"whitespace only", "   \n\t\n", "policy: file is empty"},
		{"malformed YAML", "version: 1\n  default: deny\n", "policy:"},
		{"unknown field", validPolicy + "extra: 1\n", "field extra not found"},
		{"second document", validPolicy + "---\nversion: 1\n", "policy: multiple YAML documents are not allowed"},
		{"duplicate top-level key", validPolicy + "default: deny\n", `policy: duplicate YAML key "default"`},
		{"duplicate nested key", strings.Replace(validPolicy, "    max_calls: 3\n", "    max_calls: 3\n    max_calls: 2\n", 1), `policy: duplicate YAML key "max_calls"`},
		{"duplicate tool key", validPolicy + "  search_docs:\n    effect: deny\n", `policy: duplicate YAML key "search_docs"`},
		{"anchor", "version: &v 1\ndefault: deny\nbudget:\n  max_calls: 1\ntools:\n  a:\n    effect: deny\n", "policy: YAML anchors and aliases are not supported"},
		{"alias", "version: 1\ndefault: &d deny\nbudget:\n  max_calls: 1\ntools:\n  a:\n    effect: *d\n", "policy: YAML anchors and aliases are not supported"},
		{"merge key", "version: 1\ndefault: deny\nbudget:\n  max_calls: 1\ntools:\n  a:\n    <<:\n      effect: deny\n", "policy: YAML merge keys are not supported"},
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

func TestLoadRejectsOversizedPolicy(t *testing.T) {
	padding := strings.Repeat("#", maxPolicyBytes)
	_, err := Load([]byte(validPolicy + padding))
	if err == nil || !strings.Contains(err.Error(), "policy: exceeds 1048576 bytes") {
		t.Fatalf("Load() error = %v, want the size limit", err)
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(validPolicy), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := LoadFile(path); err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
}

func TestLoadFileOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	document := validPolicy + strings.Repeat("#", maxPolicyBytes)
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := LoadFile(path)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1048576 bytes") {
		t.Fatalf("LoadFile() error = %v, want the size limit", err)
	}
}

func TestLoadFileMissing(t *testing.T) {
	if _, err := LoadFile(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Fatal("LoadFile() error = nil, want error")
	}
}

func TestLoadFileAcceptsExactLimit(t *testing.T) {
	// A document of exactly the limit is still accepted; the comment padding
	// keeps the policy itself valid.
	padding := strings.Repeat("#", maxPolicyBytes-len(validPolicy))
	if _, err := Load([]byte(validPolicy + padding)); err != nil {
		t.Fatalf("Load() error = %v, want the document at the limit to be accepted", err)
	}
}
