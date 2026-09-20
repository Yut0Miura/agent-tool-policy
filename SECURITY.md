# Security

## Threat Model

Asset: the set of side effects an agent can cause through tool calls.

In scope: tool calls proposed by a model or by any caller, including calls for tools that are not part of the task, arguments outside what the policy declares, values that are malformed or extreme, unbounded repetition of an allowed call, ambiguous policy or input encodings, and concurrent evaluation.

Out of scope: a compromised operator or host, the trustworthiness of the model, what a tool implementation does once the host executes it, and the security of the systems those tools reach.

## Policy Trust

The policy file is trusted operator configuration. It is read from the local filesystem only; there is no remote policy loading, no includes and no inheritance. Invalid policy never produces an Engine, so a deployment fails to start rather than running with a policy nobody verified.

## Untrusted Tool Calls

Tool calls and their arguments are untrusted input. The tool name must be a valid identifier and must match a rule exactly. Every supplied argument name must be a valid identifier and must be declared by the policy: there is no option to permit undeclared arguments. Values are checked against the constraints of their declared type before any budget is touched.

## Fail-Closed Behaviour

Fail-closed within the supported policy model: unknown tools, malformed calls, invalid arguments, constraint violations and exhausted authorization budgets return DENY. Invalid policy prevents Engine creation. The default is `deny` and no other default is accepted. This is not a claim that every internal panic becomes a DENY.

## Strict Argument Allowlists

An allow rule describes exactly which arguments may appear. Extra arguments are refused, required arguments must be present, and a supplied `null` is a value of the wrong type rather than an absent argument. Unsupported argument shapes — objects, arrays — can only be rejected.

## Finite Authorization Budgets

Every policy declares a finite global budget, and every allow rule declares a finite per-tool budget that may not exceed it. There is no unlimited mode. Budgets count ALLOW decisions, are consumed immediately and are never refunded, so a failed or skipped execution cannot be retried indefinitely inside one run.

## Concurrency

Budget checks and increments happen inside one critical section, so concurrent evaluation cannot exceed a configured budget. This is covered by a test that issues 100 concurrent calls against a budget of 10 and by the race detector in CI.

## Decision vs Enforcement

Agent Tool Policy is a decision engine, not an enforcement boundary by itself. A DENY decision protects the system only when the consumer checks the decision before executing the tool.

## Prefix Limitations

String prefix constraints are lexical checks only. They do not provide filesystem, URL, shell or network sandboxing, and they do not prevent path traversal: `docs:../secret` matches the prefix `docs:`.

## Numeric Domain

Numeric comparison is defined only inside the exactly representable domain `abs(value) <= 9007199254740991`. Values outside it, `NaN` and infinities are refused as type mismatches instead of being compared with silent precision loss. Policy bounds are validated against the same domain.

## Input Bounds

A policy file is at most 1 MiB and must be a single YAML document without anchors, aliases, merge keys, duplicate keys or unknown fields. A CLI input line is at most 1 MiB, must hold exactly one JSON value, may nest at most 64 levels and may not repeat an object member at any depth. Duplicate keys are rejected rather than resolved, so no input can mean one thing to the parser and another to a reader.

## Unsupported Security Boundaries

This project gives no guarantees for filesystem safety, network safety, shell safety, SQL safety, URL safety, prompt injection, malicious model detection, tool-output validation, OS sandboxing or container sandboxing. It evaluates pre-execution tool-call input only and never inspects tool output.

## Vulnerability Reporting

Please report vulnerabilities privately through GitHub's **Report a vulnerability** option on this repository rather than in a public issue, with the affected component and steps to reproduce.
