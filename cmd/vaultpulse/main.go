// Package main is the entry point for the vaultpulse CLI tool.
// It wires together configuration, Vault client, monitors, and notifiers
// into a runnable command-line application.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/vaultpulse/internal/config"
	"github.compulse/internal/notify"
	"github.com/yourusername/vaultpulse/internal/vault"
)

func main() {
	cPath := flag.String("config", "vaultpulse.yaml", "Path to configuration file")
	once := flag.Bool("once", false, "Run a single scan and exit")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	client, err := vault.NewClient(cfg.Vault.Address, cfg.Vault.Token)
	if err != nil {
		log.Fatalf("failed to create vault client: %v", err)
	}

	// Build the multi-notifier from configured channels.
	var notifiers []notify.Notifier

	if cfg.Notify.Webhook.URL != "" {
		notifiers = append(notifiers, notify.NewWebhookNotifier(cfg.Notify.Webhook.URL, 0))
	}
	if cfg.Notify.Slack.URL != "" {
		notifiers = append(notifiers, notify.NewSlackNotifier(cfg.Notify.Slack.URL, cfg.Notify.Slack.Channel, 0))
	}
	if cfg.Notify.PagerDuty.RoutingKey != "" {
		notifiers = append(notifiers, notify.NewPagerDutyNotifier(cfg.Notify.PagerDuty.RoutingKey, 0))
	}
	if cfg.Notify.OpsGenie.APIKey != "" {
		notifiers = append(notifiers, notify.NewOpsGenieNotifier(cfg.Notify.OpsGenie.APIKey, 0))
	}

	multi := notify.NewMultiNotifier(notifiers...)

	monitor := vault.NewMonitor(client, cfg.Paths, multi)

	if *once {
		runScan(monitor, *verbose)
		return
	}

	interval := time.Duration(cfg.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	log.Printf("vaultpulse starting — polling every %s", interval)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on startup, then on each tick.
	runScan(monitor, *verbose)

	for {
		select {
		case <-ticker.C:
			runScan(monitor, *verbose)
		case <-ctx.Done():
			log.Println("vaultpulse shutting down")
			return
		}
	}
}

// runScan executes a single monitoring pass and logs results.
func runScan(monitor *vault.Monitor, verbose bool) {
	alerts, err := monitor.Scan(context.Background())
	if err != nil {
		log.Printf("scan error: %v", err)
		return
	}

	if len(alerts) == 0 {
		if verbose {
			log.Println("scan complete — no alerts")
		}
		return
	}

	for _, a := range alerts {
		fmt.Printf("[%s] %s — %s\n", a.Severity, a.Path, a.Message)
	}
}
