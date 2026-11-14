package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Hedronite/augur/internal/serve"
)

// serveDepsHook lets tests replace the effects (clock, ticker, client, writer)
// before the loop starts. It is nil in production.
var serveDepsHook func(*serve.Deps)

func runServe(cmd *cobra.Command, policyPath, amURL, out string, interval time.Duration) error {
	// Startup refusals are exit 5 and nothing is written. An invalid policy
	// that was read is still exit 4 (loadPolicy).
	if err := serve.CheckInterval(interval); err != nil {
		return &exitError{code: ExitConfig, msg: err.Error()}
	}
	u, err := serve.ParseAlertmanagerURL(amURL)
	if err != nil {
		return &exitError{code: ExitConfig, msg: err.Error()}
	}
	if err := serve.CheckOut(out); err != nil {
		return &exitError{code: ExitConfig, msg: err.Error()}
	}
	pol, err := loadPolicy(policyPath, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	hupSig := make(chan os.Signal, 1)
	signal.Notify(hupSig, syscall.SIGHUP)
	defer signal.Stop(hupSig)
	hup := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupSig:
				select {
				case hup <- struct{}{}:
				default:
				}
			}
		}
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deps := serve.Deps{
		Ticks:  ticker.C,
		Hup:    hup,
		Logger: slog.New(slog.NewJSONHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{Level: slog.LevelInfo})),
	}
	if serveDepsHook != nil {
		serveDepsHook(&deps)
	}

	err = serve.Run(ctx, serve.Config{Policy: pol, URL: u, Out: out, Interval: interval, Version: version}, deps)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, serve.ErrVerdictTooLarge):
		return &exitError{code: ExitInternal, msg: "serve stopped: the verdict is larger than the 4 MiB reader cap; the last file is left to go stale"}
	default:
		return &exitError{code: ExitInternal, msg: fmt.Sprintf("serve stopped: %v", err)}
	}
}
