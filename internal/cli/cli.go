package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
)

// version is set at build time with -ldflags "-X github.com/Hedronite/augur/internal/cli.version=...".
var version = "dev"

// Execute runs augur with args and returns the process exit code. It never
// panics: a panic inside a command is recovered and reported as ExitInternal,
// so a crash can never be read as a RED verdict.
func Execute(args []string, stdout, stderr io.Writer) int {
	return execute(newRoot(), args, stdout, stderr)
}

func execute(root *cobra.Command, args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			_, _ = fmt.Fprintf(stderr, "augur: internal error: %v\n", r)
			code = ExitInternal
		}
	}()

	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.Execute()
	if err == nil {
		return ExitGreen
	}
	var ee *exitError
	if errors.As(err, &ee) {
		// A verdict exit (0 to 2) and an error whose detail was already
		// written (empty msg) print nothing here.
		if ee.msg != "" {
			_, _ = fmt.Fprintf(stderr, "augur: %s\n", ee.msg)
		}
		return ee.code
	}
	// Anything else is a usage error from the flag parser: unknown command or flag, missing flag.
	_, _ = fmt.Fprintf(stderr, "augur: %s\nRun 'augur --help' for usage.\n", err)
	return ExitConfig
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "augur",
		Short:         "Classify Alertmanager alerts as GREEN, YELLOW or RED",
		Long:          "Augur reads alerts from Prometheus Alertmanager and classifies them as GREEN, YELLOW or RED, with machine-readable reasons. It only advises: it never silences, acknowledges or routes alerts.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A bare "augur" must not exit 0: that would read as GREEN with no verdict.
		RunE: func(*cobra.Command, []string) error {
			return &exitError{code: ExitConfig, msg: "no command given; run 'augur --help' for usage"}
		},
	}
	root.AddCommand(newEvaluate(), newValidate(), newServe(), newVersion())
	return root
}

func newEvaluate() *cobra.Command {
	var alerts, policy, now string
	var asJSON, quiet bool
	cmd := &cobra.Command{
		Use:   "evaluate --alerts FILE --policy FILE [--now RFC3339] [--json|--quiet]",
		Short: "Classify one saved Alertmanager alert set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEvaluate(cmd, alerts, policy, now, asJSON, quiet)
		},
	}
	cmd.Flags().StringVar(&alerts, "alerts", "", "file holding the Alertmanager v2 /api/v2/alerts response")
	cmd.Flags().StringVar(&policy, "policy", "", "policy file (augur.policy/v0, YAML)")
	cmd.Flags().StringVar(&now, "now", "", "evaluation time as RFC3339; defaults to the wall clock")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the verdict document alone on stdout")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "print nothing; only set the exit code")
	cmd.MarkFlagsMutuallyExclusive("json", "quiet")
	_ = cmd.MarkFlagRequired("alerts")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func newValidate() *cobra.Command {
	var policy string
	var quiet bool
	cmd := &cobra.Command{
		Use:   "validate --policy FILE [--quiet]",
		Short: "Check a policy file and report every error",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runValidate(cmd, policy, quiet) },
	}
	cmd.Flags().StringVar(&policy, "policy", "", "policy file (augur.policy/v0, YAML)")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "print nothing on success; only set the exit code")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func newServe() *cobra.Command {
	var policy, alertmanager, out string
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   "serve --policy FILE --alertmanager URL --out FILE [--interval 30s]",
		Short: "Poll Alertmanager and write each verdict to a file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, policy, alertmanager, out, interval)
		},
	}
	cmd.Flags().StringVar(&policy, "policy", "", "policy file (augur.policy/v0, YAML)")
	cmd.Flags().StringVar(&alertmanager, "alertmanager", "", "Alertmanager base URL; must be loopback")
	cmd.Flags().StringVar(&out, "out", "", "file the verdict is written to, atomically")
	cmd.Flags().DurationVar(&interval, "interval", 30*time.Second, "poll interval")
	_ = cmd.MarkFlagRequired("policy")
	_ = cmd.MarkFlagRequired("alertmanager")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the augur version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "augur %s\n", version)
		},
	}
}
