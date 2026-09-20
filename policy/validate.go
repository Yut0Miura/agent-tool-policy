package policy

import (
	"fmt"
	"math"
)

// maxBudget is the largest authorization budget a policy may configure.
const maxBudget = 1000000000

// validate checks the semantics of a decoded policy. Errors are reported as
// "<path>: <message>" and describe the first problem found.
func validate(config *policyConfig) error {
	if config.Version != 1 {
		return fmt.Errorf("policy.version: must equal 1")
	}
	if config.Default != "deny" {
		return fmt.Errorf("policy.default: must equal %q", "deny")
	}
	if config.Budget.MaxCalls < 1 || config.Budget.MaxCalls > maxBudget {
		return fmt.Errorf("policy.budget.max_calls: must be between 1 and %d", maxBudget)
	}
	if len(config.Tools) == 0 {
		return fmt.Errorf("policy.tools: at least one tool is required")
	}

	for _, name := range sortedKeys(config.Tools) {
		if err := validateTool(name, config.Tools[name], config.Budget.MaxCalls); err != nil {
			return err
		}
	}
	return nil
}

func validateTool(name string, tool toolConfig, globalMaxCalls int) error {
	path := fmt.Sprintf("policy.tools[%q]", name)
	if !validIdentifier(name) {
		return fmt.Errorf("%s: invalid tool name", path)
	}

	switch tool.Effect {
	case "allow":
		if tool.MaxCalls == nil {
			return fmt.Errorf("%s.max_calls: required for allow rule", path)
		}
		if *tool.MaxCalls < 1 || *tool.MaxCalls > maxBudget {
			return fmt.Errorf("%s.max_calls: must be between 1 and %d", path, maxBudget)
		}
		if *tool.MaxCalls > globalMaxCalls {
			return fmt.Errorf("%s.max_calls: must be <= policy.budget.max_calls", path)
		}
	case "deny":
		if tool.MaxCalls != nil {
			return fmt.Errorf("%s.max_calls: not allowed for deny rule", path)
		}
		if len(tool.Arguments) > 0 {
			return fmt.Errorf("%s.arguments: not allowed for deny rule", path)
		}
		return nil
	default:
		return fmt.Errorf("%s.effect: must equal %q or %q", path, "allow", "deny")
	}

	for _, argument := range sortedKeys(tool.Arguments) {
		if err := validateArgument(path, argument, tool.Arguments[argument]); err != nil {
			return err
		}
	}
	return nil
}

func validateArgument(toolPath, name string, argument argumentConfig) error {
	path := fmt.Sprintf("%s.arguments[%q]", toolPath, name)
	if !validIdentifier(name) {
		return fmt.Errorf("%s: invalid argument name", path)
	}

	switch argument.Type {
	case "string":
		if argument.Min != nil {
			return fmt.Errorf("%s.min: not allowed for a string argument", path)
		}
		if argument.Max != nil {
			return fmt.Errorf("%s.max: not allowed for a string argument", path)
		}
		return validateStringConstraints(path, argument)
	case "number":
		if argument.Prefix != nil {
			return fmt.Errorf("%s.prefix: not allowed for a number argument", path)
		}
		if argument.Enum != nil {
			return fmt.Errorf("%s.enum: not allowed for a number argument", path)
		}
		if argument.MaxLength != nil {
			return fmt.Errorf("%s.max_length: not allowed for a number argument", path)
		}
		return validateNumberConstraints(path, argument)
	case "boolean":
		switch {
		case argument.Prefix != nil:
			return fmt.Errorf("%s.prefix: not allowed for a boolean argument", path)
		case argument.Enum != nil:
			return fmt.Errorf("%s.enum: not allowed for a boolean argument", path)
		case argument.MaxLength != nil:
			return fmt.Errorf("%s.max_length: not allowed for a boolean argument", path)
		case argument.Min != nil:
			return fmt.Errorf("%s.min: not allowed for a boolean argument", path)
		case argument.Max != nil:
			return fmt.Errorf("%s.max: not allowed for a boolean argument", path)
		}
		return nil
	default:
		return fmt.Errorf("%s.type: must equal %q, %q or %q", path, "string", "number", "boolean")
	}
}

func validateStringConstraints(path string, argument argumentConfig) error {
	if argument.Prefix != nil && *argument.Prefix == "" {
		return fmt.Errorf("%s.prefix: must not be empty", path)
	}
	if argument.Enum != nil {
		if len(argument.Enum) == 0 {
			return fmt.Errorf("%s.enum: must contain at least one value", path)
		}
		seen := make(map[string]struct{}, len(argument.Enum))
		for _, value := range argument.Enum {
			if value == "" {
				return fmt.Errorf("%s.enum: values must not be empty", path)
			}
			if _, duplicate := seen[value]; duplicate {
				return fmt.Errorf("%s.enum: duplicate value %q", path, value)
			}
			seen[value] = struct{}{}
		}
	}
	if argument.MaxLength != nil && *argument.MaxLength < 1 {
		return fmt.Errorf("%s.max_length: must be >= 1", path)
	}
	return nil
}

func validateNumberConstraints(path string, argument argumentConfig) error {
	if argument.Min != nil && !inSafeDomain(*argument.Min) {
		return fmt.Errorf("%s.min: must be a finite number within %d", path, safeInteger)
	}
	if argument.Max != nil && !inSafeDomain(*argument.Max) {
		return fmt.Errorf("%s.max: must be a finite number within %d", path, safeInteger)
	}
	if argument.Min != nil && argument.Max != nil && *argument.Min > *argument.Max {
		return fmt.Errorf("%s.min: must be <= max", path)
	}
	return nil
}

func inSafeDomain(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) &&
		value >= -safeInteger && value <= safeInteger
}
