package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// maxPolicyBytes is the largest policy document accepted, 1 MiB.
const maxPolicyBytes = 1048576

// Load compiles a policy document into an Engine. It applies the strict YAML
// rules of the policy format and full semantic validation; an invalid policy
// never produces an Engine.
func Load(data []byte) (*Engine, error) {
	if len(data) > maxPolicyBytes {
		return nil, fmt.Errorf("policy: exceeds %d bytes", maxPolicyBytes)
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("policy: file is empty")
	}

	if err := checkYAMLStructure(data); err != nil {
		return nil, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var config policyConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}

	if err := validate(&config); err != nil {
		return nil, err
	}
	return compile(&config), nil
}

// LoadFile reads a policy from a local file and compiles it. The path is a
// filesystem path; remote policy locations are not supported.
func LoadFile(path string) (*Engine, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	defer file.Close()

	// One byte beyond the limit is read so that oversized files are rejected
	// rather than silently truncated.
	data, err := io.ReadAll(io.LimitReader(file, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return Load(data)
}
