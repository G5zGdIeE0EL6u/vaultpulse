# vaultpulse

> A lightweight CLI for monitoring HashiCorp Vault secret expiry and lease renewals with alerting hooks.

---

## Installation

```bash
go install github.com/youruser/vaultpulse@latest
```

Or download a pre-built binary from the [Releases](https://github.com/youruser/vaultpulse/releases) page.

---

## Usage

Set your Vault address and token, then run `vaultpulse` to start monitoring:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="s.your-vault-token"

# Monitor secrets and alert when expiry is within 48 hours
vaultpulse watch --path secret/myapp --threshold 48h

# List all tracked leases and their TTLs
vaultpulse leases list

# Renew a specific lease
vaultpulse leases renew --id lease-id-here

# Run with a webhook alert hook on expiry
vaultpulse watch --path secret/myapp --alert-webhook https://hooks.example.com/notify
```

### Configuration File

`vaultpulse` also supports a `vaultpulse.yaml` config file in the working directory:

```yaml
vault_addr: https://vault.example.com
threshold: 48h
paths:
  - secret/myapp
  - secret/db
alert_webhook: https://hooks.example.com/notify
```

---

## Requirements

- Go 1.21+
- HashiCorp Vault 1.10+

---

## Contributing

Pull requests and issues are welcome. Please open an issue before submitting large changes.

---

## License

[MIT](LICENSE) © youruser