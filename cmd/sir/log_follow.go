package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/somoore/sir/pkg/ledger"
)

// cmdLogFollow tails the decision ledger, printing new entries as the agent
// works — the live "what is sir deciding right now" stream. It polls under the
// ledger's shared read lock (no extra deps) and exits cleanly on Ctrl-C.
func cmdLogFollow(projectRoot string) {
	printed := -1
	render := func(entries []ledger.Entry) {
		for _, e := range entries {
			if e.Index <= printed {
				continue
			}
			fmt.Printf("[%s] #%d %s %s → %s (%s)\n",
				e.Timestamp.Format("15:04:05"), e.Index, e.Verb, e.Target, e.Decision, e.Reason)
			printed = e.Index
		}
	}

	if entries, err := ledger.ReadAll(projectRoot); err == nil {
		render(entries)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Fprintln(os.Stderr, "Following sir decisions (Ctrl-C to stop)…")
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if entries, err := ledger.ReadAll(projectRoot); err == nil {
				render(entries)
			}
		}
	}
}
