# Zabbix integration

For sites that already run Zabbix as their primary monitoring stack, ARGUS
ships a Zabbix 6.x / 7.x template that scrapes the agent's Prometheus
endpoint via HTTP-agent items and converts the exposition format directly.

No `zabbix_agentd` or UserParameter shim is required — Zabbix talks to
each argusd over the same port 9100 that Prometheus would scrape, and the
template's preprocessing pipeline extracts metrics with `prometheus pattern`
preprocessing steps.

## Architecture

```
Zabbix server  ──HTTP GET /metrics──>  argusd:9100  (each cluster node)
       │
       │ stores items, runs triggers, sends notifications
       ▼
    media types (email, Slack, PagerDuty, …)
```

The shipped template lives at `deploy/zabbix/argus_template.yaml`.

## Import

1. **Zabbix UI** → **Configuration** → **Templates** → **Import**.
2. Upload `argus_template.yaml`. Zabbix 6.4+ accepts YAML natively; for
   older versions, paste into the YAML→XML converter at
   `Configuration → Import` and import the result.
3. The template lands in **Templates/Applications** group as `ARGUS`.

## Link to hosts

For each host running argusd:

1. **Configuration** → **Hosts** → click the host → **Templates** tab.
2. Add **ARGUS Adaptive RDMA Guard** to the linked templates.
3. **Macros** tab — override any of the defaults:
   - `{$ARGUS_PORT}` — default `9100`
   - `{$ARGUS_SCHEME}` — `http` or `https`
   - `{$ARGUS_TOKEN}` — Bearer token if you configured `auth_token` on argusd
   - `{$ARGUS_IDLE_MAX}` — informational idle-seconds threshold (default 86400 = 24h)

That's all the per-host configuration needed. The discovery rule picks up
per-port items automatically the next time it runs (default 1 hour; force
with **Latest data** → **Execute now**).

## What you get

### Host-level items

| Key                              | What                                                 |
| -------------------------------- | ---------------------------------------------------- |
| `argus.health.state`             | 0/1/2/3 mapped through the value map to a label      |
| `argus.health.score`             | Composite health score in milliunits (0–1000)         |
| `argus.health.up`                | 1 if `/health` returned 200, 0 otherwise              |
| `argus.fabric.idle`              | 1 when every IB port has been idle for ≥1 window      |
| `argus.fabric.idle.max_seconds`  | Largest idle-seconds value across all ports          |
| `argus.events`                   | Cumulative event count                                |

### Per-port items (discovered)

Discovery finds every `(device, port)` from
`argus_ib_port_idle_seconds{device,port}` labels and creates:

- `argus.ib.port.idle[device,port]` — idle seconds
- `argus.ib.port.symbol_errors[device,port]` — per-window delta
- `argus.ib.port.link_downed[device,port]` — per-window delta
- `argus.ib.port.link_error_recovery[device,port]` — per-window delta

### Triggers

| Trigger                                    | Severity | Notes                                  |
| ------------------------------------------ | -------- | -------------------------------------- |
| ARGUS agent unreachable                    | High     | `/health` is failing                   |
| ARGUS CRITICAL                             | High     | Composite health = Critical            |
| ARGUS DEGRADED                             | Average  | Composite health = Degraded            |
| IB link DOWN (per port)                    | Disaster | link_downed_delta > 0                  |
| IB link recovery (per port)                | Warning  | Predictor of cable failure             |
| IB high symbol errors (per port)           | Average  | >10 per window                         |
| ARGUS IB fabric idle >24h (still monitor)  | Info     | Sanity check — passive monitoring only |

## Tuning false positives

The defaults are conservative for production HPC. For test or development
clusters, you'll likely want to:

- **Raise `{$ARGUS_IDLE_MAX}`** to 7 days or disable that trigger entirely
  on clusters that batch-process and sit idle between jobs.
- **Adjust the symbol-error trigger threshold.** Sites with old IB cables
  in non-mission-critical mode may see >10 per window normally; edit the
  trigger prototype to `> 100` for those hosts and link a per-host override.
- **Suppress DEGRADED notifications during scheduled maintenance.** Use
  Zabbix's *Maintenance periods* feature rather than disabling triggers —
  silences are auditable.

## TLS + bearer auth

If you protect `/metrics` with TLS and a bearer token:

1. Install your CA on the Zabbix server so HTTPS works.
2. Set `{$ARGUS_SCHEME}` to `https`.
3. Set `{$ARGUS_TOKEN}` to the token string. Zabbix sends it as
   `Authorization: Bearer <token>` on every poll.

The shipped template already wires the `Authorization` header on both
the master `argus.metrics.raw` item and the `argus.health.up` HTTP item.

## Limitations

- The template doesn't poll `/scheduler/hold` or `/scheduler/release` —
  those are deliberate write actions for operators, not telemetry.
- Per-port `port_xmit_wait` and Soft-RoCE counters aren't in the default
  template to keep item count low on large clusters. Extend the discovery
  prototype block in `argus_template.yaml` if you need them.
- BER (bit-error rate) isn't a separately exposed metric on the agent
  side — Zabbix users can compute it as a calculated item from
  `argus.ib.port.symbol_errors` and a known throughput-rate item, or skip
  it and rely on the symbol-error trigger directly.
