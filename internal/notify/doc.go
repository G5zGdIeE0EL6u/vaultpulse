// Package notify provides notification backends for vaultpulse alerts.
//
// Supported backends:
//   - Webhook: generic HTTP webhook
//   - Slack: Slack incoming webhooks
//   - Email: SMTP email notifications
//   - PagerDuty: PagerDuty Events API v2
//   - OpsGenie: OpsGenie Alerts API v2
//
// All backends implement the Notifier interface, allowing them to be composed
// via MultiNotifier for fan-out delivery.
//
// Example usage:
//
//	slack := notify.NewSlackNotifier(webhookURL, 10*time.Second)
//	pd := notify.NewPagerDutyNotifier(routingKey, 10*time.Second)
//	mn := notify.NewMultiNotifier(slack, pd)
//	_ = mn.Send(ctx, notify.Alert{
//		SecretPath: "secret/myapp/db",
//		Message:    "Secret expires in 2 hours",
//		Severity:   "warning",
//	})
package notify
