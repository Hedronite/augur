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
		_, _ = fmt.Fprintf(stderr, "augur: %s\n", ee.msg)
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
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newEvaluate(), newValidate(), newServe(), newVersion())
	return root
}

// notImplemented is the A0 stub body. The commands exist so the CLI surface is
// frozen and testable; their behaviour lands in A1 (evaluate, validate) and A2 (serve).
func notImplemented(name, phase string) error {
	return &exitError{code: ExitInternal, msg: fmt.Sprintf("%s is not implemented yet (planned for %s)", name, phase)}
}

func newEvaluate() *cobra.Command {
	var alerts, policy, now string
	var asJSON, quiet bool
	cmd := &cobra.Command{
		Use:   "evaluate --alerts FILE --policy FILE [--now RFC3339] [--json|--quiet]",
		Short: "Classify one saved Alertmanager alert set",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return notImplemented("evaluate", "A1") },
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
	cmd := &cobra.Command{
		Use:   "validate --policy FILE",
		Short: "Check a policy file and report every error",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return notImplemented("validate", "A1") },
	}
	cmd.Flags().StringVar(&policy, "policy", "", "policy file (augur.policy/v0, YAML)")
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
		RunE:  func(*cobra.Command, []string) error { return notImplemented("serve", "A2") },
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
