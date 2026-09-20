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
	Effect    string                    `yaml:"effect"`
	MaxCalls  *int                      `yaml:"max_calls"`
	Arguments map[string]argumentConfig `yaml:"arguments"`
}

type argumentConfig struct {
	Type      string   `yaml:"type"`
	Required  bool     `yaml:"required"`
	Prefix    *string  `yaml:"prefix"`
	Enum      []string `yaml:"enum"`
	MaxLength *int     `yaml:"max_length"`
	Min       *float64 `yaml:"min"`
	Max       *float64 `yaml:"max"`
}
