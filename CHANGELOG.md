# Changelog

## [Unreleased]
- Planned: extended PHI pattern detection
- Planned: report export to PDF

## [1.3.0] - 2026-06-06
- Added HIPAA § 164.312(b) audit controls check for activity log review
- Extended PHI detection patterns to cover structured data fields (SSN, MRN, DOB)
- Introduced risk severity bucketing: Critical, High, Medium, Low
- Added unit tests for new PHI pattern matchers

## [1.2.0] - 2026-06-03
- Improved audit log handling for access control checks
- Added validation for HIPAA § 164.312(a)(2)(iv) encryption requirements
- Minor refactor of risk scoring weights for technical safeguards

## [1.1.0] - 2026-05-28
- Minor improvements to risk scoring logic
- Added additional HIPAA safeguard checks for transmission security

## [1.0.0] - 2026-05-01
- Initial release
- Basic HIPAA risk scanning for common PHI patterns
- JSON report output
