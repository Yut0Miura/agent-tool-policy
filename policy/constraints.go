package policy

import (
	"strings"
	"unicode/utf8"
)

// checkArgument applies the configured constraints of one supplied argument
// in a fixed order: type, max_length, enum, prefix, min, max. It returns an
// empty code when the value is accepted.
func checkArgument(name string, argument compiledArgument, value any) (code, reason string) {
	switch argument.kind {
	case "string":
		text, ok := value.(string)
		if !ok {
			return codeArgumentTypeMismatch, "argument " + quote(name) + " has invalid type"
		}
		if argument.maxLength != nil && utf8.RuneCountInString(text) > *argument.maxLength {
			return codeStringTooLong, "argument " + quote(name) + " exceeds maximum length"
		}
		if argument.enum != nil && !contains(argument.enum, text) {
			return codeStringEnumMismatch, "argument " + quote(name) + " is not an allowed value"
		}
		if argument.prefix != nil && !strings.HasPrefix(text, *argument.prefix) {
			return codeStringPrefixMismatch, "argument " + quote(name) + " does not match required prefix"
		}
		return "", ""

	case "number":
		number, ok := normalizeNumber(value)
		if !ok {
			return codeArgumentTypeMismatch, "argument " + quote(name) + " has invalid type"
		}
		if argument.min != nil && number < *argument.min {
			return codeNumberBelowMin, "argument " + quote(name) + " is below minimum"
		}
		if argument.max != nil && number > *argument.max {
			return codeNumberAboveMax, "argument " + quote(name) + " is above maximum"
		}
		return "", ""

	default:
		if _, ok := value.(bool); !ok {
			return codeArgumentTypeMismatch, "argument " + quote(name) + " has invalid type"
		}
		return "", ""
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
