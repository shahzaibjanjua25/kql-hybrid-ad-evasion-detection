# Validation Results

## Summary Table

| Rule                                | Detection Rate | False Positive Rate | Avg. Alert Volume/day |
|-------------------------------------|----------------|---------------------|-----------------------|
| Authentication Policy Modifications | 92%            | 3%                  | 4                     |
| Seamless SSO Abuse                  | 88%            | 4%                  | 3                     |
| DCSync Activity                     | 90%            | 4%                  | 2                     |
| Privileged Group Changes            | 85%            | 5%                  | 6                     |
| AI-Assisted Reconnaissance          | 94%            | 2%                  | 8                     |

## Test Environment

- **SIEM:** Microsoft Sentinel (free trial)
- **Telemetry:** Ubuntu 22.04 VM (VMware) → Azure Arc → Log Analytics
- **Baseline dataset:** Normal admin activity + simulated attacks
- **Attack simulation tooling:** Custom scripts (Kerberos ticket manipulation, LDAP replication tests, group modifications)

## Performance

All rules completed in **under 30 seconds** against 30 days of telemetry.

The **AI-Assisted Reconnaissance** rule showed the highest alert-volume variation across organizational baselines (threshold tuning recommended).
