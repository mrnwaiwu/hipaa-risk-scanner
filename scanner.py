"""
hipaa-risk-scanner
-------------------
AWS HIPAA compliance auditor.
Scans cloud infrastructure across 6 service categories and generates
a scored HTML risk report mapped to HIPAA Administrative, Physical,
and Technical Safeguards.

Usage:
  python scanner.py
  python scanner.py --region us-east-1
  python scanner.py --profile prod --region us-west-2 --output report.html

Requires: pip install boto3 jinja2
"""

import boto3
import json
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from jinja2 import Template


@dataclass
class Finding:
    service: str
    control_id: str
    title: str
    severity: str
    status: str
    detail: str
    hipaa_safeguard: str
    remediation: str
    resource: Optional[str] = None

    @property
    def weight(self) -> int:
        return {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3}.get(self.severity, 0)


class HIPAARiskScanner:
    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        session = boto3.Session(profile_name=profile, region_name=region)
        self.region   = region
        self.s3       = session.client("s3")
        self.iam      = session.client("iam")
        self.trail    = session.client("cloudtrail")
        self.rds      = session.client("rds")
        self.kms      = session.client("kms")
        self.ec2      = session.client("ec2")
        self.findings: list[Finding] = []

    def _add(self, **kwargs):
        self.findings.append(Finding(**kwargs))

    def check_s3(self):
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b["Name"]
                try:
                    self.s3.get_bucket_encryption(Bucket=name)
                    enc_status, enc_detail = "PASS", "Server-side encryption enabled."
                except Exception:
                    enc_status = "FAIL"
                    enc_detail = f"Bucket '{name}' has no server-side encryption."
                self._add(service="S3", control_id="S3-01", title="Bucket Encryption",
                          severity="CRITICAL", status=enc_status, detail=enc_detail,
                          hipaa_safeguard="Technical", resource=name,
                          remediation="Enable AES-256 or aws:kms encryption on the bucket.")

                try:
                    pub = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                    all_blocked = all(pub.get(k) for k in [
                        "BlockPublicAcls", "IgnorePublicAcls",
                        "BlockPublicPolicy", "RestrictPublicBuckets"])
                    pub_status = "PASS" if all_blocked else "FAIL"
                    pub_detail = "All public access blocks enabled." if all_blocked \
                        else f"Bucket '{name}' has partial/no public access blocks."
                except Exception:
                    pub_status = "FAIL"
                    pub_detail = f"Could not verify public access block on '{name}'."
                self._add(service="S3", control_id="S3-02", title="Public Access Block",
                          severity="CRITICAL", status=pub_status, detail=pub_detail,
                          hipaa_safeguard="Technical", resource=name,
                          remediation="Enable all four S3 Block Public Access settings.")

                ver = self.s3.get_bucket_versioning(Bucket=name).get("Status", "")
                self._add(service="S3", control_id="S3-03", title="Bucket Versioning",
                          severity="MEDIUM",
                          status="PASS" if ver == "Enabled" else "FAIL",
                          detail="Versioning enabled." if ver == "Enabled"
                              else f"Versioning not enabled on '{name}'.",
                          hipaa_safeguard="Administrative", resource=name,
                          remediation="Enable versioning to protect against accidental deletion of PHI.")
        except Exception as e:
            self._add(service="S3", control_id="S3-00", title="S3 Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete S3 scan: {e}",
                      hipaa_safeguard="Technical",
                      remediation="Verify IAM permissions include s3:ListAllMyBuckets.")

    def check_iam(self):
        try:
            try:
                policy = self.iam.get_account_password_policy()["PasswordPolicy"]
                issues = []
                if policy.get("MinimumPasswordLength", 0) < 12:
                    issues.append("min length < 12")
                if not policy.get("RequireUppercaseCharacters"):
                    issues.append("no uppercase required")
                if not policy.get("RequireSymbols"):
                    issues.append("no symbols required")
                if not policy.get("MaxPasswordAge"):
                    issues.append("no password expiry")
                self._add(service="IAM", control_id="IAM-01", title="Password Policy",
                          severity="HIGH",
                          status="FAIL" if issues else "PASS",
                          detail=f"Policy weaknesses: {', '.join(issues)}." if issues
                              else "Password policy meets HIPAA requirements.",
                          hipaa_safeguard="Administrative",
                          remediation="Enforce min 12 chars, uppercase, symbols, 90-day expiry.")
            except self.iam.exceptions.NoSuchEntityException:
                self._add(service="IAM", control_id="IAM-01", title="Password Policy",
                          severity="HIGH", status="FAIL",
                          detail="No account password policy set.",
                          hipaa_safeguard="Administrative",
                          remediation="Create an IAM password policy with HIPAA-compliant settings.")

            summary = self.iam.get_account_summary()["SummaryMap"]
            root_mfa = summary.get("AccountMFAEnabled", 0)
            self._add(service="IAM", control_id="IAM-02", title="Root Account MFA",
                      severity="CRITICAL",
                      status="PASS" if root_mfa else "FAIL",
                      detail="Root MFA enabled." if root_mfa
                          else "MFA is NOT enabled on the root account.",
                      hipaa_safeguard="Technical",
                      remediation="Enable MFA on root immediately. Use a hardware MFA device.")

            users = self.iam.list_users()["Users"]
            no_mfa = []
            for u in users:
                mfa_devices = self.iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
                if not mfa_devices:
                    try:
                        self.iam.get_login_profile(UserName=u["UserName"])
                        no_mfa.append(u["UserName"])
                    except self.iam.exceptions.NoSuchEntityException:
                        pass
            self._add(service="IAM", control_id="IAM-03", title="User MFA Enforcement",
                      severity="HIGH",
                      status="FAIL" if no_mfa else "PASS",
                      detail=f"{len(no_mfa)} console user(s) without MFA: "
                             f"{', '.join(no_mfa[:5])}{'...' if len(no_mfa) > 5 else ''}." if no_mfa
                          else "All console users have MFA enabled.",
                      hipaa_safeguard="Technical",
                      remediation="Enforce MFA via SCP or IAM policy for all console users.")
        except Exception as e:
            self._add(service="IAM", control_id="IAM-00", title="IAM Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete IAM scan: {e}",
                      hipaa_safeguard="Administrative",
                      remediation="Verify IAM permissions include iam:GetAccountPasswordPolicy.")

    def check_cloudtrail(self):
        try:
            trails = self.trail.describe_trails(includeShadowTrails=False)["trailList"]
            if not trails:
                self._add(service="CloudTrail", control_id="CT-01", title="CloudTrail Enabled",
                          severity="CRITICAL", status="FAIL",
                          detail="No CloudTrail trails found in this region.",
                          hipaa_safeguard="Administrative",
                          remediation="Enable CloudTrail with multi-region logging and log file validation.")
                return
            for t in trails:
                name = t["Name"]
                status = self.trail.get_trail_status(Name=name)
                logging_on  = status.get("IsLogging", False)
                validated   = t.get("LogFileValidationEnabled", False)
                multi_region = t.get("IsMultiRegionTrail", False)
                self._add(service="CloudTrail", control_id="CT-01", title="Trail Logging Active",
                          severity="CRITICAL", resource=name,
                          status="PASS" if logging_on else "FAIL",
                          detail=f"Trail '{name}' logging is {'ON' if logging_on else 'OFF'}.",
                          hipaa_safeguard="Administrative",
                          remediation="Start logging on the trail via the console or CLI.")
                self._add(service="CloudTrail", control_id="CT-02", title="Log File Validation",
                          severity="MEDIUM", resource=name,
                          status="PASS" if validated else "FAIL",
                          detail=f"Log file validation {'enabled' if validated else 'disabled'} on '{name}'.",
                          hipaa_safeguard="Technical",
                          remediation="Enable log file validation to detect tampering.")
                self._add(service="CloudTrail", control_id="CT-03", title="Multi-Region Trail",
                          severity="MEDIUM", resource=name,
                          status="PASS" if multi_region else "FAIL",
                          detail=f"Multi-region trail: {'Yes' if multi_region else 'No'}.",
                          hipaa_safeguard="Administrative",
                          remediation="Enable multi-region trail to capture events in all regions.")
        except Exception as e:
            self._add(service="CloudTrail", control_id="CT-00", title="CloudTrail Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete CloudTrail scan: {e}",
                      hipaa_safeguard="Administrative",
                      remediation="Verify IAM permissions include cloudtrail:DescribeTrails.")

    def check_rds(self):
        try:
            instances = self.rds.describe_db_instances()["DBInstances"]
            for db in instances:
                iid      = db["DBInstanceIdentifier"]
                encrypted = db.get("StorageEncrypted", False)
                public    = db.get("PubliclyAccessible", False)
                backup    = db.get("BackupRetentionPeriod", 0)
                self._add(service="RDS", control_id="RDS-01", title="RDS Encryption at Rest",
                          severity="CRITICAL", resource=iid,
                          status="PASS" if encrypted else "FAIL",
                          detail=f"Instance '{iid}' encryption: {'enabled' if encrypted else 'DISABLED'}.",
                          hipaa_safeguard="Technical",
                          remediation="Encrypt RDS instance. Create encrypted snapshot and restore.")
                self._add(service="RDS", control_id="RDS-02", title="RDS Public Accessibility",
                          severity="HIGH", resource=iid,
                          status="FAIL" if public else "PASS",
                          detail=f"Instance '{iid}' is {'publicly accessible' if public else 'private'}.",
                          hipaa_safeguard="Technical",
                          remediation="Set PubliclyAccessible=false and use VPC private subnets.")
                self._add(service="RDS", control_id="RDS-03", title="Automated Backups",
                          severity="MEDIUM", resource=iid,
                          status="PASS" if backup >= 7 else "FAIL",
                          detail=f"Backup retention: {backup} day(s). HIPAA recommends >= 7 days.",
                          hipaa_safeguard="Administrative",
                          remediation="Set backup retention to at least 7 days.")
        except Exception as e:
            self._add(service="RDS", control_id="RDS-00", title="RDS Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete RDS scan: {e}",
                      hipaa_safeguard="Technical",
                      remediation="Verify IAM permissions include rds:DescribeDBInstances.")

    def check_kms(self):
        try:
            for k in self.kms.list_keys()["Keys"]:
                try:
                    meta = self.kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                    if meta.get("KeyManager") == "AWS" or meta.get("KeyState") != "Enabled":
                        continue
                    rotation = self.kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"]
                    self._add(service="KMS", control_id="KMS-01", title="KMS Key Rotation",
                              severity="MEDIUM", resource=k["KeyId"],
                              status="PASS" if rotation else "FAIL",
                              detail=f"Key rotation: {'enabled' if rotation else 'DISABLED'}.",
                              hipaa_safeguard="Technical",
                              remediation="Enable automatic annual rotation on all customer-managed KMS keys.")
                except Exception:
                    continue
        except Exception as e:
            self._add(service="KMS", control_id="KMS-00", title="KMS Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete KMS scan: {e}",
                      hipaa_safeguard="Technical",
                      remediation="Verify IAM permissions include kms:ListKeys.")

    def check_vpc(self):
        try:
            vpcs = self.ec2.describe_vpcs()["Vpcs"]
            flow_logs = {fl["ResourceId"]: fl for fl in self.ec2.describe_flow_logs()["FlowLogs"]}
            for vpc in vpcs:
                vid = vpc["VpcId"]
                has_logs = vid in flow_logs
                self._add(service="VPC", control_id="VPC-01", title="VPC Flow Logs",
                          severity="HIGH", resource=vid,
                          status="PASS" if has_logs else "FAIL",
                          detail=f"VPC '{vid}' flow logs: {'enabled' if has_logs else 'NOT enabled'}.",
                          hipaa_safeguard="Technical",
                          remediation="Enable VPC flow logs and ship to CloudWatch Logs or S3.")
        except Exception as e:
            self._add(service="VPC", control_id="VPC-00", title="VPC Scan Error",
                      severity="LOW", status="MANUAL",
                      detail=f"Could not complete VPC scan: {e}",
                      hipaa_safeguard="Technical",
                      remediation="Verify IAM permissions include ec2:DescribeVpcs.")

    def run_all(self):
        print(f"Starting HIPAA risk scan -- region: {self.region}")
        for check_fn in [self.check_s3, self.check_iam, self.check_cloudtrail,
                         self.check_rds, self.check_kms, self.check_vpc]:
            svc = check_fn.__name__.replace("check_", "").upper()
            print(f"  Scanning {svc}...")
            check_fn()
        print(f"  Done. {len(self.findings)} findings generated.")
        return self.findings


def score_findings(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total  = 0
    for f in findings:
        if f.status == "FAIL":
            counts[f.severity] = counts.get(f.severity, 0) + 1
            total += f.weight
    risk_level = ("CRITICAL" if total >= 80 else
                  "HIGH"     if total >= 40 else
                  "MEDIUM"   if total >= 15 else "LOW")
    return {"counts": counts, "risk_score": total, "risk_level": risk_level}


REPORT_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>HIPAA Risk Scan Report</title>
<style>
  body{font-family:Arial,sans-serif;background:#0f1923;color:#e0e6f0;margin:0}
  header{background:#1a2a3a;padding:20px 40px;border-bottom:3px solid #1f3864}
  header h1{color:#5fa8d3;margin:0;font-size:1.6rem}
  header p{color:#7a8fa6;margin:4px 0 0;font-size:.85rem}
  .wrap{max-width:1100px;margin:0 auto;padding:30px 20px}
  .cards{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:32px}
  .card{background:#1a2a3a;border-radius:8px;padding:18px;text-align:center;border-top:4px solid}
  .card.score{border-color:#5fa8d3}.card.critical{border-color:#e63946}
  .card.high{border-color:#f4a261}.card.medium{border-color:#e9c46a}.card.low{border-color:#2a9d8f}
  .card .num{font-size:2.2rem;font-weight:700}.card .lbl{font-size:.75rem;color:#7a8fa6;text-transform:uppercase;margin-top:4px}
  .card.score .num{color:#5fa8d3}.card.critical .num{color:#e63946}
  .card.high .num{color:#f4a261}.card.medium .num{color:#e9c46a}.card.low .num{color:#2a9d8f}
  table{width:100%;border-collapse:collapse;background:#1a2a3a;border-radius:8px;overflow:hidden;margin-bottom:24px}
  th{background:#162030;padding:10px 14px;text-align:left;font-size:.78rem;color:#7a8fa6;text-transform:uppercase}
  td{padding:10px 14px;border-top:1px solid #1f3060;font-size:.84rem;vertical-align:top}
  .badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.72rem;font-weight:700}
  .badge.CRITICAL{background:#e63946;color:#fff}.badge.HIGH{background:#f4a261;color:#1a1a1a}
  .badge.MEDIUM{background:#e9c46a;color:#1a1a1a}.badge.LOW{background:#2a9d8f;color:#fff}
  .badge.PASS{background:#2a9d8f;color:#fff}.badge.FAIL{background:#e63946;color:#fff}.badge.MANUAL{background:#7a8fa6;color:#fff}
  .sec{font-size:1rem;font-weight:600;color:#5fa8d3;margin:24px 0 12px;text-transform:uppercase}
  footer{text-align:center;padding:20px;color:#3a4f66;font-size:.78rem}
</style></head><body>
<header>
  <h1>HIPAA Risk Scan Report</h1>
  <p>Generated: {{ timestamp }} &nbsp;|&nbsp; Region: {{ region }} &nbsp;|&nbsp; Risk Level: <strong>{{ score.risk_level }}</strong></p>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card score">  <div class="num">{{ score.risk_score }}</div><div class="lbl">Risk Score</div></div>
    <div class="card critical"><div class="num">{{ score.counts.CRITICAL }}</div><div class="lbl">Critical</div></div>
    <div class="card high">   <div class="num">{{ score.counts.HIGH }}</div><div class="lbl">High</div></div>
    <div class="card medium"> <div class="num">{{ score.counts.MEDIUM }}</div><div class="lbl">Medium</div></div>
    <div class="card low">    <div class="num">{{ score.counts.LOW }}</div><div class="lbl">Low</div></div>
  </div>
  {% for svc in services %}
  <div class="sec">{{ svc }}</div>
  <table><thead><tr><th>Control</th><th>Check</th><th>Status</th><th>Severity</th><th>Safeguard</th><th>Detail</th><th>Remediation</th></tr></thead>
  <tbody>
  {% for f in by_svc[svc] %}
  <tr><td>{{f.control_id}}</td><td>{{f.title}}</td>
  <td><span class="badge {{f.status}}">{{f.status}}</span></td>
  <td><span class="badge {{f.severity}}">{{f.severity}}</span></td>
  <td>{{f.hipaa_safeguard}}</td><td>{{f.detail}}</td>
  <td>{{f.remediation if f.status=='FAIL' else '&mdash;'}}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endfor %}
</div>
<footer>HIPAA Risk Scanner &mdash; Built by Michael N. &mdash; CONFIDENTIAL</footer>
</body></html>
"""


def generate_report(findings, score, region, output_html):
    services = sorted(set(f.service for f in findings))
    by_svc   = {s: [f for f in findings if f.service == s] for s in services}
    html = Template(REPORT_HTML).render(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        region=region, score=score, services=services, by_svc=by_svc)
    with open(output_html, "w") as fh:
        fh.write(html)
    print(f"HTML report -> {output_html}")
    json_out = output_html.replace(".html", ".json")
    with open(json_out, "w") as fh:
        json.dump({"score": score, "findings": [asdict(f) for f in findings]}, fh, indent=2)
    print(f"JSON report -> {json_out}")


def main():
    parser = argparse.ArgumentParser(description="HIPAA Risk Scanner")
    parser.add_argument("--region",  default="us-east-1")
    parser.add_argument("--profile", default=None)
    parser.add_argument("--output",  default="hipaa_report.html")
    args = parser.parse_args()
    scanner  = HIPAARiskScanner(region=args.region, profile=args.profile)
    findings = scanner.run_all()
    score    = score_findings(findings)
    fails = sum(1 for f in findings if f.status == "FAIL")
    print(f"\nRisk Score : {score['risk_score']} ({score['risk_level']})")
    print(f"Failures   : {fails}/{len(findings)}")
    print(f"Breakdown  : CRITICAL={score['counts']['CRITICAL']}  HIGH={score['counts']['HIGH']}  "
          f"MEDIUM={score['counts']['MEDIUM']}  LOW={score['counts']['LOW']}")
    generate_report(findings, score, args.region, args.output)


if __name__ == "__main__":
    main()
