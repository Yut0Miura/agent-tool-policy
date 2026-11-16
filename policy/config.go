package policy

// policyConfig mirrors the YAML policy document. The configuration structs
// are deliberately unexported: the public API exposes the compiled Engine
// only.
type policyConfig struct {
	Version int                   `yaml:"version"`
	Default string                `yaml:"default"`
	Budget  budgetConfig          `yaml:"budget"`
	Tools   map[string]toolConfig `yaml:"tools"`
}

type budgetConfig struct {
	MaxCalls int `yaml:"max_calls"`
}

type toolConfig struct {
	Effect    string                     `yaml:"effect"`
	MaxCalls  *int                       `yaml:"max_calls"`
	Arguments *map[string]argumentConfig `yaml:"arguments"`
}

// argumentConfigs returns the declared arguments. Arguments is a pointer so
// that an absent section can be told apart from an explicitly empty one; an
// absent section declares no arguments.
func (tool toolConfig) argumentConfigs() map[string]argumentConfig {
	if tool.Arguments == nil {
		return nil
	}
	return *tool.Arguments
}

type argumentConfig struct {
	Type      string       `yaml:"type"`
	Required  bool         `yaml:"required"`
	Prefix    *string      `yaml:"prefix"`
	Enum      []string     `yaml:"enum"`
	MaxLength *int         `yaml:"max_length"`
	Min       *numberBound `yaml:"min"`
	Max       *numberBound `yaml:"max"`
}
