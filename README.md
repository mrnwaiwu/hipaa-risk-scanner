# hipaa-risk-scanner

AWS HIPAA compliance auditor. Scans your cloud infrastructure across 8 service categories, scores each finding by severity, and generates a full HTML risk report — all from a single command.

## What it checks

| Category | Checks |
|----------|--------|
| S3 | Encryption, public access blocks, versioning, logging |
| IAM | Password policy, MFA on root, least privilege, unused credentials |
| CloudTrail | Multi-region logging, log validation, S3 access logging |
| RDS | Encryption at rest, automated backups, public accessibility |
| KMS | Key rotation enabled |
| VPC | Flow logs enabled |
| CloudWatch | Alarms for root login, unauthorized API calls, config changes |
| Secrets Manager | Rotation enabled for stored secrets |

## Setup

```bash
pip install boto3 jinja2

# Configure AWS credentials
aws configure   # or use environment variables / IAM role

python scanner.py                          # scans default region
python scanner.py --region us-east-1       # specific region
python scanner.py --profile prod --region us-west-2 --output report.html
```

## Output
- Color-coded HTML report with risk scores
- JSON findings file for SIEM ingestion
- Summary: CRITICAL / HIGH / MEDIUM / LOW counts with weighted risk score

## Tech Stack
Python · boto3 · Jinja2 · AWS (S3, IAM, CloudTrail, RDS, KMS, VPC, CloudWatch)
