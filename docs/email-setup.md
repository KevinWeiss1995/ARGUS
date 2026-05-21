# Email alerting for ARGUS

ARGUS does **not** send email directly. It exposes Prometheus metrics; an
Alertmanager instance turns those metrics into routed alerts and sends mail.
This separation is a feature: Alertmanager handles grouping, deduplication,
silences, and digest scheduling — none of which belong in a node-local
agent.

## Architecture

```
argusd → /metrics → Prometheus → alert_rules.yml → Alertmanager → SMTP relay → ops mailbox
                                                  ↘ webhook (optional)
```

## Configure the SMTP relay

Edit `deploy/observability/alertmanager.yml` and replace the `[REQUIRED]`
lines. The minimum set for an HPC site:

```yaml
global:
  smtp_smarthost: "mail.example.org:25"      # the site mail bastion or local postfix
  smtp_from: "argus-alerts@example.org"
  smtp_require_tls: false                    # flip true for SMTPS + auth

receivers:
  - name: argus_email
    email_configs:
      - to: "argus-ops@example.org"          # digest list
  - name: argus_email_critical
    email_configs:
      - to: "argus-pager@example.org"        # paging list — often a different DL
```

If your relay requires authentication:

```yaml
global:
  smtp_smarthost: "smtp.example.org:587"
  smtp_require_tls: true
  smtp_auth_username: "argus"
  smtp_auth_password_file: /etc/alertmanager/smtp.pass
```

`smtp_auth_password_file` is preferable to inlining the password —
mount the file into the alertmanager container with `0600` ownership.

## Choose where mail comes from

For sites that already run a Postfix smarthost on the monitoring node, point
`smtp_smarthost: 127.0.0.1:25` and let the local relay forward outbound.
That's the most common HPC pattern and means the relay's TLS / auth config
stays out of Alertmanager.

## Test before going live

```bash
# Validate config syntax
amtool check-config deploy/observability/alertmanager.yml

# Send a fake alert through Alertmanager
amtool alert add \
  alertname=ArgusTest severity=DEGRADED instance=node07 \
  --annotation=summary="test alert from $(hostname)"

# In the digest mailbox you should see one mail with the
# 'ArgusTest' subject within ~30 seconds.
```

If you don't see the mail:

1. `journalctl -u alertmanager -e` for SMTP errors.
2. Hit the Alertmanager UI at port 9093, find the test alert in **Alerts** —
   if it's there but not delivered, the SMTP path is wrong.
3. `swaks --to argus-ops@example.org --from argus-alerts@example.org \
   --server mail.example.org:25` from the monitoring host to confirm the
   relay accepts mail from this source.

## Routing rules

The shipped `alertmanager.yml` has two routes:

| Match           | Receiver               | Behaviour                                           |
| --------------- | ---------------------- | --------------------------------------------------- |
| `severity=CRIT` | `argus_email_critical` | 5s group_wait, 1h repeat — go to the pager list     |
| `severity=DEG`  | `argus_email`          | 5m group, 4h repeat — digest to the ops list        |
| default         | `argus_email`          | other ARGUS alerts also flow to the ops digest list |

Tune `repeat_interval` if your pager fatigue tolerance is different. The
shipped values match typical HPC ops expectations (one re-page per hour for
unresolved Criticals, one daily digest for sustained Degraded).

## Inhibit rules

When a node goes Critical, the shipped config suppresses the noisier
`ArgusNodeDegraded` alert for the same instance — operators want the worst
state, not both. Add more inhibit rules if a noisy alert correlates with a
calmer one in your environment (e.g. suppress `ArgusCongestion` when
`ArgusLinkDowned` fires for the same port).

## Common pitfalls

- **Recipient rejected.** Most enterprise mail systems require the
  `smtp_from` address to exist or to be allowlisted. Coordinate with mail
  admins before pointing at the production relay.
- **No TLS / wrong port.** Submission (587) needs `smtp_require_tls: true`;
  legacy SMTPS (465) needs `tls_config:` blocks that Alertmanager's email
  receiver doesn't fully support — prefer 587 STARTTLS.
- **`{{ . }}` syntax in templates.** The shipped `templates/email.tmpl` uses
  Alertmanager's Go template syntax. If you edit the template, restart
  Alertmanager — templates are not hot-reloaded.
- **Silencing during maintenance.** Use `amtool silence add` rather than
  commenting out alert rules; silences are auditable and time-bound.

## What gets emailed

Each digest groups alerts by `(alertname, node, severity)` and shows one
block per alert with severity, node, device/port, start time, summary, and
the runbook link. The HTML version color-codes the left border by severity
(red = CRITICAL, orange = DEGRADED, blue = informational).

See `deploy/observability/templates/email.tmpl` for the exact format and
edit it if your ops team prefers a different layout.
