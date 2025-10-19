---
name: Bug Report
about: Report a bug or module failure
title: '[BUG] '
labels: ['bug', 'triage']
assignees: ''
---

## Bug Description

<!-- A clear and concise description of the bug -->

## Module/Component Affected

<!-- Which module or component is affected? -->
- [ ] Specific module: _______________
- [ ] Web interface
- [ ] API
- [ ] CLI
- [ ] Other: _______________

## Environment

**Operating System:**
<!-- e.g., Ubuntu 22.04, macOS 14.0, Windows 11 -->

**Python Version:**
<!-- Run: python --version -->

**Installation Method:**
- [ ] Docker
- [ ] Direct (pip install)
- [ ] From source

**Version/Commit:**
<!-- e.g., v2.1.0 or commit SHA -->

**Dependencies:**
<!-- Run: pip list | grep -E "(requests|beautifulsoup4|dnspython)" -->

## Steps to Reproduce

1. 
2. 
3. 
4. 

## Expected Behavior

<!-- What should have happened? -->

## Actual Behavior

<!-- What actually happened? -->

## Error Messages and Logs

```
<!-- Paste error messages, stack traces, or relevant log output here -->
```

## Screenshots

<!-- If applicable, add screenshots to help explain the problem -->

## Additional Context

### Module Failure Report (if applicable)

**Last Working Commit:**
<!-- If this used to work, which commit was it working in? -->

**Input Used:**
```
<!-- What input caused the failure? -->
```

**Network Conditions:**
- [ ] Rate limited
- [ ] Timeout
- [ ] Connection error
- [ ] API error
- [ ] Other: _______________

**Related API/Service:**
<!-- e.g., Shodan, VirusTotal, Google, etc. -->

### Security Context

- [ ] This bug involves exposed credentials or secrets
- [ ] This bug involves a security vulnerability
- [ ] This bug could lead to data exposure

<!-- If checked, please follow the security reporting process in SECURITY.md instead -->

## Possible Solution

<!-- Optional: Suggest a fix or workaround if you have one -->

## Checklist

- [ ] I have searched existing issues for duplicates
- [ ] I have included all required information above
- [ ] I have provided error logs or stack traces
- [ ] I have tested with the latest version
- [ ] I have reviewed the documentation
- [ ] I have checked if safety helpers are properly configured (for module issues)

## Related Issues

<!-- Link any related issues here -->
