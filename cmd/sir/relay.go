package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/somoore/sir/pkg/relay"
	"github.com/somoore/sir/pkg/telemetry"
)

// cmdRelay runs the central Slack relay server. Workstations point
// SIR_SLACK_RELAY at this process; it forwards deduplicated, curated alerts to
// one downstream Slack webhook (SIR_SLACK_WEBHOOK), keeping webhook secrets and
// per-event spam off individual machines.
func cmdRelay(args []string) {
	addr := ":8787"
	dedup := 10 * time.Minute
	digest := time.Hour
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr":
			if i+1 >= len(args) {
				fatal("--addr requires a value, e.g. :8787")
			}
			addr = args[i+1]
			i++
		case "--dedup":
			if i+1 >= len(args) {
				fatal("--dedup requires a duration, e.g. 10m")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("parse --dedup: %v", err)
			}
			dedup = d
			i++
		case "--digest":
			if i+1 >= len(args) {
				fatal("--digest requires a duration, e.g. 1h (0 disables)")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("parse --digest: %v", err)
			}
			digest = d
			i++
		default:
			fatal("usage: sir relay [--addr :8787] [--dedup 10m] [--digest 1h]")
		}
	}

	webhook := strings.TrimSpace(os.Getenv(telemetry.SlackWebhookEnvVar))
	if webhook == "" {
		fatal("sir relay needs a downstream Slack webhook: set %s", telemetry.SlackWebhookEnvVar)
	}
	r, err := relay.New(webhook, relay.Options{
		DedupWindow: dedup,
		DigestEvery: digest,
		Logger:      log.New(os.Stderr, "sir-relay ", log.LstdFlags|log.LUTC),
	})
	if err != nil {
		fatal("%v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go r.Run(ctx)

	srv := &http.Server{
		Addr:              addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Printf("sir relay listening on %s (dedup=%s, digest=%s)\n", addr, dedup, digest)
	fmt.Printf("  workstations: export SIR_SLACK_RELAY=http://<this-host>%s/v1/detections\n", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal("relay server: %v", err)
	}
}
