#!/usr/bin/env python3
"""
validate-rules.py
-----------------
Loads sample syslog data and applies simplified Python equivalents of the
KQL rules to report which lines would trigger each rule.

This is a *sanity-check* helper, not a full KQL engine.
For authoritative testing, run the .kql files inside Microsoft Sentinel.

Usage:
    python validate-rules.py --input sample-syslog-data.csv
"""

import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime, timedelta


RULE_KEYWORDS = {
    "Rule1-AuthenticationPolicyModifications": [
        "PAM", "authentication policy", "password policy",
        "SSH authentication policy", "sudoers", "Kerberos delegation",
        "account lockout", "session timeout", "PermitRootLogin",
    ],
    "Rule2-SeamlessSSOAbuse": [
        "krb5kdc", "kerberos", "TGT", "KDC", "AZUREADSSOACC",
        "AS-REQ", "GSSAPI", "kadmin", "sssd",
    ],
    "Rule3-DCSyncActivity": [
        "slapd", "openldap", "LDAP replica", "directory replication",
        "Replicating Directory", "ldapsearch", "ldapmodify", "replication",
        "sync update", "1131f6ad", "89e95b76", "replica sync",
    ],
    "Rule4-PrivilegedGroupChanges": [
        "usermod", "groupadd", "gpasswd", "useradd", "sudoers",
        "groupmod", "shadow", "added to group",
    ],
    "Rule5-AI-AssistedReconnaissance": [
        "ldapsearch", "ldapquery", "slapd", "LDAP query",
        "ldap_modify", "Replicating Directory", "directory replication",
    ],
}

PRIVILEGED_GROUPS = {"sudo", "root", "wheel", "adm", "sys", "admin", "operator", "docker"}
REPLICATION_WINDOW = timedelta(minutes=1)
REPLICATION_THRESHOLD = 30


def matches_any(message: str, keywords) -> bool:
    msg_l = message.lower()
    return any(k.lower() in msg_l for k in keywords)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to CSV with columns TimeGenerated,HostName,Facility,SyslogMessage")
    args = parser.parse_args()

    with open(args.input, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"Loaded {len(rows)} syslog rows\n")

    # Rules 1-4: keyword matching
    for rule_name, keywords in RULE_KEYWORDS.items():
        if rule_name.startswith("Rule5"):
            continue
        hits = []
        for r in rows:
            msg = r.get("SyslogMessage", "")
            if not matches_any(msg, keywords):
                continue
            if rule_name.startswith("Rule4"):
                if not any(g in msg.lower() for g in PRIVILEGED_GROUPS):
                    continue
            hits.append(r)
        print(f"[{rule_name}] triggered {len(hits)} row(s)")
        for h in hits[:5]:
            print(f"  - {h['TimeGenerated']} | {h['HostName']} | {h['SyslogMessage'][:90]}")

    # Rule 5: velocity based
    buckets = defaultdict(list)
    for r in rows:
        msg = r.get("SyslogMessage", "")
        if not matches_any(msg, RULE_KEYWORDS["Rule5-AI-AssistedReconnaissance"]):
            continue
        try:
            ts = datetime.fromisoformat(r["TimeGenerated"].replace("Z", "+00:00"))
        except Exception:
            continue
        bucket = ts.replace(second=0, microsecond=0)
        buckets[(r["HostName"], bucket)].append(r)

    print("\n[Rule5-AI-AssistedReconnaissance] velocity analysis")
    triggered = 0
    for (host, bucket), items in buckets.items():
        if len(items) >= REPLICATION_THRESHOLD:
            print(f"  - {bucket} | {host} | {len(items)} queries/min (threshold {REPLICATION_THRESHOLD})")
            triggered += 1
    if triggered == 0:
        print(f"  - No buckets exceeded {REPLICATION_THRESHOLD} queries/min (normal for small sample)")


if __name__ == "__main__":
    main()
