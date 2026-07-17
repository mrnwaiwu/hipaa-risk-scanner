# Changelog

## [Unreleased]
- Planned: extended PHI pattern detection
- Planned: report export to PDF

## [1.3.8] - 2026-07-17
- Added detection for HIPAA § 164.312(c)(1) integrity controls to verify PHI has not been improperly altered or destroyed
- Extended PHI pattern matching to cover full-face photographic images and comparable image field references
- Improved scan pipeline to emit structured JSON output per finding for easier downstream parsing
- Added unit tests for integrity control detection logic

## [1.3.7] - 2026-07-10
- Added detection for HIPAA § 164.312(e)(1) transmission security gaps in outbound integration configs
- Extended PHI pattern matching to cover health plan beneficiary numbers and certificate/license numbers
- Improved risk report to flag findings that overlap multiple safeguard categories with a cross-reference note
- Added regression tests covering the biometric identifier matchers introduced in 1.3.6

## [1.3.6] - 2026-07-06
- Added detection for HIPAA § 164.308(a)(8) evaluation requirements for periodic technical and non-technical assessments
- Extended PHI pattern matching to cover biometric identifiers including fingerprint and retinal scan field references
- Improved risk report summary to include total finding count grouped by HIPAA safeguard category
- Added configurable exclusion list for known-safe test data fields to reduce false positives in dev environments

## [1.3.5] - 2026-06-28
- Added detection for HIPAA § 164.308(a)(7) contingency plan requirements (data backup, disaster recovery, emergency mode operation)
- Extended PHI pattern matching to cover geographic subdivisions smaller than state level
- Improved remediation guidance text with direct links to HHS guidance documents
- Refactored scanner report output to include HIPAA rule reference citations per finding

## [1.3.4] - 2026-06-24
- Added detection for HIPAA § 164.310(d)(1) device and media controls for workstation security
- Extended audit log parser to capture failed authentication events as potential risk indicators
- Improved scanner output formatting for better readability in CI environments
- Minor performance improvements to PHI pattern matching pipeline

## [1.3.3] - 2026-06-20
- Added detection for HIPAA § 164.308(a)(6) security incident response policy gaps
- Extended PHI redaction logic to handle multi-line free-text fields
- Improved scanner performance for large structured data files via lazy loading
- Added unit tests for incident response safeguard checks

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
