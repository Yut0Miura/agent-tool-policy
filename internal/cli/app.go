package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/Yut0Miura/agent-tool-policy/policy"
)

const usage = "usage: agent-tool-policy <validate|evaluate> -policy <path>"

// Run executes one CLI invocation and returns the process exit code: 0 for a
// completed command (including DENY decisions), 1 for a policy error and 2
// for a usage or input error.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing command")
	}

	command := args[0]
	if command != "validate" && command != "evaluate" {
		return usageError(stderr, fmt.Sprintf("unknown command %q", command))
	}

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("policy", "", "path to the policy file")
	if err := flags.Parse(args[1:]); err != nil {
		return usageError(stderr, err.Error())
	}
	if flags.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("unexpected argument %q", flags.Arg(0)))
	}
	if *path == "" {
		return usageError(stderr, "missing -policy")
	}

	engine, err := policy.LoadFile(*path)
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return 1
	}

	if command == "validate" {
		fmt.Fprintln(stdout, "policy valid")
		return 0
	}
	return evaluateStream(engine.NewRun(), stdin, stdout, stderr)
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "agent-tool-policy: %s\n%s\n", message, usage)
	return 2
}
