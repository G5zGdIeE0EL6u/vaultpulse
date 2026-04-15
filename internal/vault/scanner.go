package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// ScanResult holds the result of scanning a single secret path.
type ScanResult struct {
	Path      string
	Alert     *Alert
	ScannedAt time.Time
	Err       error
}

// Scanner scans a list of secret paths and returns alerts.
type Scanner struct {
	client  *Client
	monitor *Monitor
	paths   []string
}

// NewScanner creates a new Scanner for the given paths.
func NewScanner(client *Client, monitor *Monitor, paths []string) *Scanner {
	return &Scanner{
		client:  client,
		monitor: monitor,
		paths:   paths,
	}
}

// Scan iterates over all configured paths, reads each secret, and
// returns a ScanResult per path. Errors are captured per-result so
// a single failure does not abort the entire scan.
func (s *Scanner) Scan(ctx context.Context) []ScanResult {
	results := make([]ScanResult, 0, len(s.paths))

	for _, path := range s.paths {
		result := ScanResult{
			Path:      path,
			ScannedAt: time.Now(),
		}

		secret, err := s.client.ReadSecret(ctx, path)
		if err != nil {
			result.Err = fmt.Errorf("read secret %q: %w", path, err)
			log.Warn().Err(result.Err).Str("path", path).Msg("scanner: failed to read secret")
			results = append(results, result)
			continue
		}

		alert, err := s.monitor.Evaluate(path, secret)
		if err != nil {
			result.Err = fmt.Errorf("evaluate secret %q: %w", path, err)
			log.Warn().Err(result.Err).Str("path", path).Msg("scanner: failed to evaluate secret")
			results = append(results, result)
			continue
		}

		result.Alert = alert
		results = append(results, result)
	}

	return results
}

// Alerts filters the scan results and returns only those that produced an alert.
func Alerts(results []ScanResult) []*Alert {
	var alerts []*Alert
	for _, r := range results {
		if r.Alert != nil {
			alerts = append(alerts, r.Alert)
		}
	}
	return alerts
}
