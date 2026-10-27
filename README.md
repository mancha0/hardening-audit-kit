# Hardening Audit Kit — Community Edition 🔒

Fast Linux security posture check. **One Python file, zero dependencies, zero telemetry.**

Drop it on your server, run one command, get a score (0–100) and the findings that matter:

```bash
python3 hardening_audit.py            # full report → hardening_report.md
python3 hardening_audit.py --quiet    # score only (for scripts/cron/CI)
```

## Included checks (7)

| Severity | Check |
|----------|-------|
| CRITICAL | SSH root login · SSH password auth |
| HIGH | Empty passwords · World-writable files · Unattended security updates · Firewall active |
| MEDIUM | Non-standard SSH port |

Each finding comes with the **exact fix command** — not "review your firewall", but the actual line to change.

## Requirements

Python 3.8+ (stdlib only). Debian, Ubuntu, RHEL, CentOS and derivatives. Read-only: it never modifies anything on your system.

```
SCORE: 67/100 (C — Aceptable, riesgo medio)
```

Exit code is `0` when score ≥ 60, `1` otherwise — handy as a CI gate:

```yaml
- name: Security posture
  run: python3 hardening_audit.py --quiet || exit 1
```

## ⭐ PRO Edition

The **PRO edition** (coming soon on Gumroad) adds:

- All **15 checks** (SUID files, NOPASSWD sudoers, stale kernels, listening services, umask, /tmp nosuid, core dumps, default cloud hostnames…)
- **HTML report** — client-ready, send it to your CISO or customer
- **JSON output** for CI/CD pipelines and baselines
- 1 year of updates as standards evolve

> Community edition: MIT. PRO edition: commercial license, no redistribution of source.

## License

MIT (community edition). See the PRO page for commercial terms.
