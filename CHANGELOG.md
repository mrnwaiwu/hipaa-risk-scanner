# Changelog

## [Unreleased]
- Planned: extended PHI pattern detection
- Planned: report export to PDF

## [1.3.2] - 2026-06-17
- Improved handling of nested JSON structures during PHI field scans
- Added guard against empty input files to avoid scanner crashes
- Clarified remediation guidance text for HIPAA § 164.308(a)(5) findings

## [1.3.1] - 2026-06-14
- Added detection for HIPAA § 164.308(a)(5) security awareness training gaps
- Extended PHI pattern matching to cover device identifiers and account numbers
- Improved false-positive filtering in structured data field scans
- Refactored risk scoring to normalize weights across safeguard categories

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
