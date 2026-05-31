# Usage Notes

## Running the Scanner

```bash
python scan.py --config config.yaml
```

## Output Formats

- `--output json` — machine-readable JSON report
- `--output html` — human-readable HTML report
- `--output csv` — spreadsheet-compatible CSV

## Interpreting Results

| Severity | Description |
|----------|-------------|
| CRITICAL | Immediate remediation required |
| HIGH     | Address within 24 hours |
| MEDIUM   | Address within 7 days |
| LOW      | Address in next sprint |

## Common Flags

- `--rules all` — run all HIPAA rules (default)
- `--rules phi` — PHI-focused checks only
- `--rules access` — access control checks only
- `--dry-run` — validate config without scanning

## Scheduling

For continuous compliance monitoring, add to cron:

```cron
0 6 * * * /usr/bin/python /opt/hipaa-risk-scanner/scan.py --config /etc/hipaa/config.yaml --output json >> /var/log/hipaa-scan.log 2>&1
```

## Exit Codes

- `0` — no findings
- `1` — findings below threshold
- `2` — findings at or above threshold (use in CI gates)
