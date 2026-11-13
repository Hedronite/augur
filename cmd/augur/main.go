// Command augur classifies Prometheus Alertmanager alerts as GREEN, YELLOW or RED.
package main

import (
	"os"

	"github.com/Hedronite/augur/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
