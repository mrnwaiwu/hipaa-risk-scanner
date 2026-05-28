# HIPAA Risk Categories

This document describes the risk categories evaluated by the scanner.

## Administrative Safeguards (§164.308)

| Check ID | Description | Severity |
|---|---|---|
| ADM-001 | Security officer designation | HIGH |
| ADM-002 | Workforce training records | MEDIUM |
| ADM-003 | Access management policy | HIGH |
| ADM-004 | Contingency plan existence | MEDIUM |
| ADM-005 | Audit controls documented | HIGH |

## Physical Safeguards (§164.310)

| Check ID | Description | Severity |
|---|---|---|
| PHY-001 | Facility access controls | HIGH |
| PHY-002 | Workstation use policy | MEDIUM |
| PHY-003 | Device and media controls | HIGH |

## Technical Safeguards (§164.312)

| Check ID | Description | Severity |
|---|---|---|
| TEC-001 | Unique user identification | HIGH |
| TEC-002 | Automatic logoff enabled | MEDIUM |
| TEC-003 | Encryption at rest | HIGH |
| TEC-004 | Encryption in transit (TLS 1.2+) | HIGH |
| TEC-005 | Audit log integrity | HIGH |
| TEC-006 | PHI access audit trail | HIGH |

## Scoring

- **HIGH** findings contribute 10 points each to the risk score
- **MEDIUM** findings contribute 5 points each
- **LOW** findings contribute 1 point each

Scores above 50 are flagged as critical risk.
