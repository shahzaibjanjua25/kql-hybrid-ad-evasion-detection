# MITRE ATT&CK Mapping

| Rule   | Tactic              | Technique ID | Technique Name                        |
|--------|---------------------|--------------|---------------------------------------|
| Rule 1 | Defense Evasion     | T1556        | Modify Authentication Process         |
| Rule 2 | Credential Access   | T1558        | Steal or Forge Kerberos Tickets       |
| Rule 2 | Credential Access   | T1558.003    | Kerberoasting                         |
| Rule 3 | Credential Access   | T1003.006    | OS Credential Dumping: DCSync         |
| Rule 3 | Defense Evasion     | T1207        | Rogue Domain Controller               |
| Rule 4 | Persistence         | T1098        | Account Manipulation                  |
| Rule 4 | Privilege Escalation| T1098.007    | Additional Local or Domain Groups     |
| Rule 5 | Reconnaissance      | T1590        | Gather Victim Network Information     |
| Rule 5 | Discovery           | T1087        | Account Discovery                     |

## Tactic Coverage Summary

- **Defense Evasion (TA0005):** Rule 1, Rule 3
- **Credential Access (TA0006):** Rule 2, Rule 3
- **Privilege Escalation (TA0004):** Rule 4
- **Persistence (TA0003):** Rule 4
- **Discovery (TA0007):** Rule 5
- **Reconnaissance (TA0043):** Rule 5
- **Lateral Movement (TA0008):** Rule 3 (supporting)
