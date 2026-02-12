# Vulnerability Report Generator

This document describes the vulnerability report generation feature for SecLab Taskflows audits.

## Overview

The `generate_vuln_reports.py` script processes the `repo_context.db` database produced by audit taskflows and generates:

1. **Threat Model** (`threat-model.md`) - Architectural information, entry points, and attack surface for all components
2. **Vulnerability Reports** (`<id>/summary.md`) - Focused vulnerability analysis and findings

## Automatic Generation

When you run an audit using `run_audit_local.sh`, vulnerability reports are automatically generated at the end:

```bash
./scripts/run_audit_local.sh owner/repo
```

Reports are created in the `vulns/` directory adjacent to the database.

## Manual Generation

You can also generate reports manually from any `repo_context.db`:

```bash
python3 scripts/generate_vuln_reports.py /path/to/repo_context.db
```

Or specify a custom output directory:

```bash
python3 scripts/generate_vuln_reports.py /path/to/repo_context.db -o /custom/output/dir
```

## Report Structure

The script generates a clean separation between architectural context and vulnerability details:

```
data/
├── repo_context.db
└── vulns/
    ├── threat-model.md          # Shared architectural context
    ├── 1/
    │   └── summary.md           # SQL Injection vulnerability
    └── 12/
        └── summary.md           # IDOR vulnerability
```

## Threat Model (`threat-model.md`)

The threat model document contains architectural information shared across all vulnerabilities:

### Contents:
- **Repository Overview** - Organized by repository
- **Component Architecture** - Detailed architecture and technology descriptions
- **Entry Points** - All identified code entry points with:
  - File paths and line numbers
  - User input parameters
  - Detailed descriptions
- **Web Entry Points** - HTTP endpoints with:
  - Methods and paths
  - Authentication requirements
  - Middleware and authorization details
  - Roles and scopes

### Why Separate?
- Avoids duplication across vulnerability reports
- Provides comprehensive attack surface view
- Useful reference for security reviews and threat modeling exercises
- Can be shared with development teams for architecture documentation

## Vulnerability Reports (`<id>/summary.md`)

Individual vulnerability reports are focused on specific security findings:

### Contents:

1. **Header Information**
   - Vulnerability ID
   - Repository and component
   - Generation timestamp
   - Severity badges (🔴 TRUE POSITIVE, 🟡 NON-SECURITY ERROR, 🔵 LOW SEVERITY)

2. **Reference to Threat Model**
   - Link to `../threat-model.md` for architectural context

3. **Low Severity Justification** (if applicable)
   - Explanation of why a vulnerability is marked as low severity
   - Mitigating factors

4. **Issue Context**
   - High-level description of the vulnerability class
   - Context about where the issue was identified

5. **Vulnerability Analysis**
   - Detailed vulnerability analysis
   - Vulnerable code snippets
   - Attack scenarios
   - Impact assessment
   - Exploitation details

### Example:

```markdown
# SQL Injection

**Vulnerability ID:** `1`
**Repository:** `juice-shop/juice-shop`
**Component ID:** `1`
**Component Location:** `/`

🔴 **TRUE POSITIVE**

---

📋 **For architectural context, entry points, and threat model details, see [`../threat-model.md`](../threat-model.md)**

---

## Issue Context

The application has endpoints that accept untrusted user input...

## Vulnerability Analysis

### Vulnerability 1: SQL Injection in Login (Authentication Bypass)

**File:** `routes/login.ts`, line 34
**Endpoint:** `POST /rest/user/login`
**Vulnerable code:**
```
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'...`)
```

**Attack scenario:** ...
**Impact:** Complete authentication bypass...
```

## Database Schema

The script queries the following tables:

- `audit_result` - Main vulnerability records
- `application` - Component/application details
- `application_issue` - Issue type details
- `entry_point` - Code entry points with user input
- `web_entry_point` - HTTP endpoint details
- `low_severity_audit_result` - Low severity reasoning

## Use Cases

### 1. Security Documentation
- **Threat Model**: Provides comprehensive attack surface documentation for security teams
- **Vulnerability Reports**: Focused findings for remediation tracking

### 2. Development Teams
- **Threat Model**: Helps developers understand the application's entry points and architecture
- **Vulnerability Reports**: Clear, actionable security issues to fix

### 3. Audit Deliverables
- Professional separation of architectural analysis and specific findings
- Easy to include in security assessment reports

### 4. Knowledge Base
- Build a library of both architectural patterns and vulnerability findings
- Train teams on secure architecture and common vulnerabilities

## Benefits of Separation

✅ **No Duplication** - Architectural info written once, referenced by all vulnerabilities
✅ **Focused Reports** - Each vulnerability report is concise and actionable
✅ **Better Navigation** - Easy to understand attack surface without wading through vulnerability details
✅ **Reusable Context** - Threat model serves as standalone security documentation
✅ **Cleaner Diffs** - When updating vulnerabilities, architectural context remains stable

## Tips

- **Automatic Integration**: The script is automatically called by `scripts/run_audit_local.sh`
- **Timestamped Audits**: Each audit run creates a timestamped directory, preserving historical reports
- **Cross-References**: Vulnerability reports link back to the threat model for architectural context
- **VS Code**: Reports can be opened directly in VS Code for easy viewing and navigation
- **Markdown**: All reports use standard markdown and can be rendered anywhere
- **Version Control**: The separation makes it easier to track changes in vulnerabilities vs architecture

## Troubleshooting

### No reports generated
- Check if the database contains vulnerabilities:
  ```bash
  sqlite3 repo_context.db "SELECT COUNT(*) FROM audit_result WHERE has_vulnerability = 1;"
  ```
- Verify the database path is correct
- Check the script output for errors

### Missing information in reports
- The reports reflect the data collected during the audit
- More comprehensive audits produce more detailed reports
- Entry points, web entry points, and issue notes are populated during the audit phase

### Threat model seems too large
- This is normal for applications with many entry points
- The threat model is meant to be comprehensive
- Individual vulnerability reports remain focused and concise

## Example Output Structure

After running the script:

```
vulns/
├── threat-model.md              (42KB - architectural details)
├── 1/
│   └── summary.md              (5KB - SQL injection details)
└── 12/
    └── summary.md              (7KB - IDOR details)
```

The threat model contains all 54 entry points for juice-shop, while each vulnerability report stays focused on just the specific vulnerability findings.

## Future Enhancements

Potential additions to the structure:

```
vulns/
├── threat-model.md              # Shared architecture
├── attack-scenarios.md          # Common attack vectors
├── 1/
│   ├── summary.md              # Vulnerability report
│   ├── poc.py                  # Proof of concept
│   ├── exploit.sh              # Exploitation script
│   └── remediation.md          # Fix recommendations
└── 12/
    ├── summary.md
    └── ...
```
