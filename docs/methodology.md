# Detection Engineering Methodology

This document summarizes the four-phase approach used to develop and validate the rules in this repository.

## Phase 1: Threat Modeling

Identified critical hybrid AD attack vectors based on:
- Black Hat USA 2025 research (Dirk-jan Mollema)
- Real-world incident analysis
- MITRE ATT&CK mapping

**Focus techniques:**
- Seamless SSO key manipulation (OnPremAuthenticationFlowPolicy tampering)
- Exchange hybrid certificate abuse (service-to-service tokens)
- Low-privilege cloud account escalation
- DCShadow / DCSync
- AI-accelerated reconnaissance

## Phase 2: Telemetry Analysis

Available sources surveyed:
- Microsoft Defender for Identity
- Azure AD Identity Protection
- Microsoft Sentinel `Syslog` table
- Azure Arc-connected Linux VMs

**Observation:** Many hybrid attacks produce minimal audit logs; behavior-driven detection is essential.

## Phase 3: KQL Rule Development

Design principles:
1. **Behavioral patterns > static signatures**
2. **Threshold-based detection** for velocity attacks
3. **Contextual anomaly identification**
4. **Explicit tuning sections** in each rule file

## Phase 4: Rule Validation

Test environment:
- Azure Sentinel (free trial)
- Ubuntu VM in VMware
- Azure Arc connected via Log Analytics agent

Metrics:
- Detection Rate (DR) = true positives / total attack scenarios
- False Positive Rate (FPR) = false positives / total benign events
- Avg. Alert Volume/day

**Results:** DR 85–94%, FPR 2–5%.

## Known Limitations

- Only Linux syslog telemetry (Windows Event Logs and Entra ID audit logs not covered)
- Lab-scale validation only
- Simulated (not full adversarial) attack patterns
- Audit-log-free techniques (e.g., Seamless SSO key manipulation) require secondary indicators
