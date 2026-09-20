// Command agent-tool-policy validates a policy file and evaluates proposed
// agent tool calls offline. All behaviour lives in the library and the
// internal CLI package.
package main

import (
	"os"

	"github.com/Yut0Miura/agent-tool-policy/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
