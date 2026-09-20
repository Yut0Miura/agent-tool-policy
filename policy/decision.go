package policy

// Effect is the outcome of a policy evaluation. There are exactly two
// effects: a call is either allowed or denied.
type Effect string

const (
	// EffectAllow means the proposed tool call is authorized.
	EffectAllow Effect = "allow"
	// EffectDeny means the proposed tool call is not authorized.
	EffectDeny Effect = "deny"
)

// Decision is the result of evaluating one proposed tool call. It is a
// decision only: the host application is responsible for enforcing it before
// the tool runs.
type Decision struct {
	Effect Effect `json:"decision"`
	Tool   string `json:"tool"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// Decision codes. The set is closed; no other code is ever returned.
const (
	codeAllowed              = "allowed"
	codeInvalidCall          = "invalid_call"
	codeUnknownTool          = "unknown_tool"
	codeToolDenied           = "tool_denied"
	codeMissingArgument      = "missing_argument"
	codeUnexpectedArgument   = "unexpected_argument"
	codeArgumentTypeMismatch = "argument_type_mismatch"
	codeStringPrefixMismatch = "string_prefix_mismatch"
	codeStringEnumMismatch   = "string_enum_mismatch"
	codeStringTooLong        = "string_too_long"
	codeNumberBelowMin       = "number_below_min"
	codeNumberAboveMax       = "number_above_max"
	codeGlobalBudget         = "global_budget_exhausted"
	codeToolBudget           = "tool_budget_exhausted"
)

func allow(tool string) Decision {
	return Decision{Effect: EffectAllow, Tool: tool, Code: codeAllowed, Reason: "tool allowed"}
}

func deny(tool, code, reason string) Decision {
	return Decision{Effect: EffectDeny, Tool: tool, Code: code, Reason: reason}
}
