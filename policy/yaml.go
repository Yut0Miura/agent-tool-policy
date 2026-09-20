package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	yaml "go.yaml.in/yaml/v3"
)

// checkYAMLStructure enforces the structural rules of the policy format
// before any value is decoded: exactly one document, no anchors, no aliases,
// no merge keys and no duplicate mapping key at any level.
func checkYAMLStructure(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))

	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("policy: file is empty")
		}
		return fmt.Errorf("policy: %w", err)
	}

	var second yaml.Node
	switch err := decoder.Decode(&second); {
	case err == nil:
		return errors.New("policy: multiple YAML documents are not allowed")
	case errors.Is(err, io.EOF):
	default:
		return fmt.Errorf("policy: %w", err)
	}

	return checkNode(&document)
}

func checkNode(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return errors.New("policy: YAML anchors and aliases are not supported")
	}

	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Tag == "!!merge" || key.Value == "<<" {
				return errors.New("policy: YAML merge keys are not supported")
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return fmt.Errorf("policy: duplicate YAML key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}

	for _, child := range node.Content {
		if err := checkNode(child); err != nil {
			return err
		}
	}
	return nil
}
