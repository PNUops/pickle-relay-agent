// relay-agent converges the relay's nftables DNAT rules to the platform's
// desired mapping set (port forwarding: public band ports → VM targets).
//
// Modes:
//
//	relay-agent apply -file <snapshot.json>   one-shot apply + persist
//	relay-agent run                           boot re-apply, then poll loop
//
// Configuration is environment-only (see internal/config); the agent fails
// closed when the target CIDR, band, or public interface is missing.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pnuops/pickle-relay-agent/internal/agent"
	"github.com/pnuops/pickle-relay-agent/internal/config"
	"github.com/pnuops/pickle-relay-agent/internal/nftctl"
	"github.com/pnuops/pickle-relay-agent/internal/snapshot"
	"github.com/pnuops/pickle-relay-agent/internal/source"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: relay-agent <apply|run> [flags]")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	switch os.Args[1] {
	case "apply":
		fs := flag.NewFlagSet("apply", flag.ExitOnError)
		file := fs.String("file", "", "snapshot JSON to apply (required)")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *file == "" {
			return fmt.Errorf("apply: -file is required")
		}
		body, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		s, err := snapshot.Parse(body, cfg.Limits)
		if err != nil {
			return err
		}
		if err := nftctl.Apply(cfg.PublicIface, nftctl.Plan(s), cfg.Guards); err != nil {
			return err
		}
		if err := s.Persist(cfg.SnapshotPath()); err != nil {
			return fmt.Errorf("applied, but persist failed: %w", err)
		}
		log.Info("applied", "generation", s.Generation, "mappings", len(s.Mappings))
		return nil

	case "run":
		// config.Load already guarantees these are mutually exclusive
		var src source.Source
		switch {
		case cfg.SyncURL != "":
			src = source.NewHTTP(cfg.SyncURL, cfg.SyncToken)
		case cfg.SourceFile != "":
			src = source.FileSource{Path: cfg.SourceFile}
		default:
			return fmt.Errorf("run: set PICKLE_RELAY_SYNC_URL (HTTP sync) or PICKLE_RELAY_SOURCE_FILE (local file)")
		}
		ag := agent.New(cfg, src, agent.NFTKernel{}, log)
		if err := ag.BootReapply(); err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer stop()
		err := ag.Run(ctx)
		if ctx.Err() != nil {
			log.Info("shutting down")
			return nil
		}
		return err

	default:
		return fmt.Errorf("unknown mode %q (want apply or run)", os.Args[1])
	}
}
