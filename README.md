# Custom KQL Rules for Detecting Post-Compromise Active Directory Evasion in Cloud-Hybrid Frameworks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Microsoft Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-blue)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)
[![KQL](https://img.shields.io/badge/Query-KQL-green)](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/)

This repository contains five original Kusto Query Language (KQL) detection rules designed to identify post-compromise Active Directory evasion techniques in hybrid cloud environments using Microsoft Sentinel.

**Author:** Shah Zaib Sajid ([shahzaibjanjua25@gmail.com](mailto:shahzaibjanjua25@gmail.com))  
**Affiliation:** Security Engineer, Ebryx (Pvt) Ltd.  
**Date:** July 6, 2026

---

## 📋 Abstract

The integration of on-premises Active Directory and cloud identity systems like Microsoft Entra ID has revealed fresh attack techniques enabling hackers to move laterally across hybrid environments free from standard detection tools. This project develops and benchmarks five KQL detection rules targeting Active Directory evasion techniques following a compromise—including Seamless SSO key manipulation, abuse of Exchange hybrid certificates, and AI-enhanced reconnaissance.

**Validation Results:**
- Detection rates: **85% – 94%**
- False positive rates: **2% – 5%**

---

## 🎯 Detected Attack Techniques

| Rule | Technique                           | MITRE ATT&CK | Detection Rate | FP Rate |
|------|-------------------------------------|--------------|----------------|---------|
| 1    | Authentication Policy Modifications | T1556        | 92%            | 3%      |
| 2    | Seamless SSO Abuse                  | T1558        | 88%            | 4%      |
| 3    | DCShadow/DCSync Activity            | T1003.006    | 90%            | 4%      |
| 4    | Privileged Group Changes            | T1098        | 85%            | 5%      |
| 5    | AI-Assisted Reconnaissance          | T1590        | 94%            | 2%      |

---

## 🚀 Quick Start

### Prerequisites
- Microsoft Sentinel workspace
- Azure Arc-connected Linux VM (or syslog forwarder)
- `Syslog` table populated in Log Analytics

### Deploy All Rules

```powershell
cd deployment
./deploy-all-rules.ps1 -ResourceGroup "your-rg" -WorkspaceName "your-sentinel-workspace"
```

### Manual Deployment
1. Navigate to **Microsoft Sentinel → Analytics → Create → Scheduled query rule**
2. Copy the content from each `.kql` file in `rules/`
3. Set severity, entity mapping, and alert threshold per the comments in each file

---

## 📁 Repository Structure

```
.
├── rules/          # Individual KQL detection rules
├── deployment/     # Automated deployment scripts
├── testing/        # Sample data & validation scripts
├── docs/           # Methodology, validation, MITRE mapping
└── images/         # Screenshots and diagrams
```

---

## 🔧 Rule Tuning

Each rule file contains a `// TUNING` section. Key parameters:

- **Thresholds**: Adjust `QueryCount > threshold` based on your environment baseline
- **Facility filters**: Extend `Facility in (...)` if your syslog sources differ
- **Group lists**: Update the `dynamic([...])` arrays for privileged groups
- **Time windows**: Rules default to 30d/90d/48h/1h; tune based on data retention

---

## ⚠️ Ethical Use

These rules are provided for **defensive purposes only**. All research was conducted in a controlled lab environment with explicit permission. See `LICENSE` and the Ethical Considerations section of the research paper.

---

## 📚 Citation

If you use these rules in your research or product, please cite:

```bibtex
@techreport{sajid2026kql,
  title  = {Developing and Benchmarking Custom KQL Rules for Detecting
            Post-Compromise Active Directory Evasion in Cloud-Hybrid Frameworks},
  author = {Sajid, Shah Zaib},
  year   = {2026},
  month  = {July},
  institution = {Ebryx (Pvt) Ltd.},
  url    = {https://github.com/yourusername/kql-hybrid-ad-evasion-detection}
}
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome for:

- Additional telemetry sources (Windows Event Log, Entra ID audit logs)
- Performance optimizations
- New evasion techniques

---

## 📄 License

MIT License — see [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

- Black Hat USA 2025 (Dirk-jan Mollema) for foundational research on hybrid AD lateral movement
- Microsoft CTI-REALM benchmarking framework
- Community KQL detection repositories

