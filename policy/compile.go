package policy

import "sort"

type compiledArgument struct {
	kind      string
	required  bool
	prefix    *string
	enum      []string
	maxLength *int
	min       *numberBound
	max       *numberBound
}

type compiledTool struct {
	effect    Effect
	maxCalls  int
	arguments map[string]compiledArgument
	// Names are sorted at compile time so that decisions never depend on map
	// iteration order.
	names    []string
	required []string
}

// compile turns a validated configuration into the immutable Engine
// representation used at evaluation time.
func compile(config *policyConfig) *Engine {
	engine := &Engine{
		globalMaxCalls: config.Budget.MaxCalls,
		tools:          make(map[string]compiledTool, len(config.Tools)),
	}

	for name, tool := range config.Tools {
		if tool.Effect == "deny" {
			engine.tools[name] = compiledTool{effect: EffectDeny}
			continue
		}

		arguments := tool.argumentConfigs()
		compiled := compiledTool{
			effect:    EffectAllow,
			maxCalls:  *tool.MaxCalls,
			arguments: make(map[string]compiledArgument, len(arguments)),
		}
		for argumentName, argument := range arguments {
			compiled.arguments[argumentName] = compiledArgument{
				kind:      argument.Type,
				required:  argument.Required,
				prefix:    argument.Prefix,
				enum:      argument.Enum,
				maxLength: argument.MaxLength,
				min:       argument.Min,
				max:       argument.Max,
			}
			compiled.names = append(compiled.names, argumentName)
			if argument.Required {
				compiled.required = append(compiled.required, argumentName)
			}
		}
		sort.Strings(compiled.names)
		sort.Strings(compiled.required)
		engine.tools[name] = compiled
	}
	return engine
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
