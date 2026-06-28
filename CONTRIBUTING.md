# Contributing Guidelines

Thank you for your interest in improving these KQL detection rules!

## How to Contribute

### Reporting Issues
- Use the GitHub issue tracker
- Include: rule name, Sentinel query output, expected vs. actual behavior
- For false positives, describe the benign scenario that triggered the alert

### Submitting New Rules
1. Fork the repo
2. Add your rule under `rules/` following the naming convention: `RuleN-Description.kql`
3. Include a header block:

```
// Rule Name: <name>
// Description: <what it detects>
// MITRE ATT&CK: <technique IDs>
// Data Sources: <tables required>
// Author: <your name>
// Validated: <Y/N>
```

4. Test against sample data in `testing/`
5. Update `deployment/rules-manifest.json`
6. Submit a PR with: detection logic, test evidence, and FP analysis

### Code Style
- Use `//` comments for single-line, `//` blocks for sections
- Follow existing formatting (indentation, casing)
- Keep rules under 200 lines where possible

## Code of Conduct
Be respectful. This is a defensive security project. Any contribution that
could be used to facilitate attacks will be rejected.
