"""
Setup:
    pip install boto3
    aws configure          # or set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars

Run:
    python3 soc2_scanner.py

This checks 4 controls to start:
    CC6.1 - IAM users have MFA enabled
    CC6.2 - No stale (90+ day unused) credentials
    CC6.6 - S3 buckets have default encryption enabled
    CC6.7 - No security groups open to the world on risky ports
"""
import csv
import io
import time
from datetime import datetime, timezone

import boto3

def finding(control_id, control_name, resource, status, detail):
    return {
        "control_id": control_id,
        "control_name": control_name,
        "resource": resource,
        "status": status,  # "PASS" or "FAIL"
        "detail": detail,
    }


def check_iam_mfa(iam):
    results = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if mfa_devices:
                results.append(finding(
                    "CC6.1", "MFA enforced for IAM users",
                    username, "PASS", "MFA device attached",
                ))
            else:
                results.append(finding(
                    "CC6.1", "MFA enforced for IAM users",
                    username, "FAIL", "No MFA device registered",
                ))
    return results


# ---------------------------------------------------------------------------
# CC6.2 - Access provisioning: flag credentials unused 90+ days
# ---------------------------------------------------------------------------
def check_stale_credentials(iam, stale_days=90):
    # The credential report is generated async by AWS - request it, then
    # poll until it's ready (usually 1-2 seconds, occasionally longer).
    iam.generate_credential_report()
    while True:
        try:
            report = iam.get_credential_report()
            break
        except iam.exceptions.CredentialReportNotPresentException:
            time.sleep(2)
        except iam.exceptions.CredentialReportInProgressExecption:
            time.sleep(2)
        except iam.exceptions.CredentialReportExpiredException:
            iam.generate_credential_report()
            time.sleep(2)

    csv_data = report["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(csv_data))

    results = []
    now = datetime.now(timezone.utc)
    for row in reader:
        username = row["user"]
        last_used = row.get("password_last_used", "N/A")
        if last_used in ("N/A", "no_information", "not_supported"):
            continue
        last_used_dt = datetime.strptime(
            last_used, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=timezone.utc)
        age_days = (now - last_used_dt).days
        status = "FAIL" if age_days > stale_days else "PASS"
        results.append(finding(
            "CC6.2", "Inactive credentials removed within policy window",
            username, status, f"Last used {age_days} days ago",
        ))
    return results


# ---------------------------------------------------------------------------
# CC6.6 - Encryption at rest: S3 buckets must have default encryption
# ---------------------------------------------------------------------------
def check_s3_encryption(s3):
    results = []
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
            results.append(finding(
                "CC6.6", "S3 buckets encrypted at rest",
                name, "PASS", "Default encryption configured",
            ))
        except s3.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                results.append(finding(
                    "CC6.6", "S3 buckets encrypted at rest",
                    name, "FAIL", "No default encryption configured",
                ))
            else:
                results.append(finding(
                    "CC6.6", "S3 buckets encrypted at rest",
                    name, "ERROR", str(e),
                ))
    return results


# ---------------------------------------------------------------------------
# CC6.7 - Network restriction: security groups open to the world on risky ports
# ---------------------------------------------------------------------------
RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}


def check_open_security_groups(ec2):
    results = []
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        group_id = sg["GroupId"]
        exposed = []
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0" and from_port in RISKY_PORTS:
                    exposed.append(RISKY_PORTS[from_port])
        if exposed:
            results.append(finding(
                "CC6.7", "No unrestricted inbound access on sensitive ports",
                group_id, "FAIL", f"Open to 0.0.0.0/0 on: {', '.join(exposed)}",
            ))
        else:
            results.append(finding(
                "CC6.7", "No unrestricted inbound access on sensitive ports",
                group_id, "PASS", "No risky ports open to the world",
            ))
    return results


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------
def print_report(all_findings):
    total = len(all_findings)
    failed = [f for f in all_findings if f["status"] == "FAIL"]
    print(f"\nSOC 2 Compliance Scan — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{total} checks run, {len(failed)} failed\n")
    print(f"{'Control':<8} {'Resource':<30} {'Status':<6} Detail")
    print("-" * 90)
    for f in all_findings:
        print(f"{f['control_id']:<8} {f['resource'][:28]:<30} {f['status']:<6} {f['detail']}")


def export_csv(all_findings, path="soc2_scan_report.csv"):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["control_id", "control_name", "resource", "status", "detail"]
        )
        writer.writeheader()
        writer.writerows(all_findings)
    print(f"\nSaved evidence report to {path}")


def main():
    session = boto3.Session()  # picks up credentials from `aws configure` or env vars
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
 
    all_findings = []
 
    print("Checking IAM MFA enforcement (CC6.1)...")
    all_findings += check_iam_mfa(iam)
 
    print("Checking for stale credentials (CC6.2)...")
    all_findings += check_stale_credentials(iam)
 
    print("Checking S3 default encryption (CC6.6)...")
    all_findings += check_s3_encryption(s3)
 
    print("Checking security groups for open risky ports (CC6.7)...")
    all_findings += check_open_security_groups(ec2)
 
    print_report(all_findings)
    export_csv(all_findings)
 
 
if __name__ == "__main__":
    main()
