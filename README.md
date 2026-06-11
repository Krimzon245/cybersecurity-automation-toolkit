# Enterprise Cybersecurity Automation & Auditing Toolkit

## Project Overview
This repository functions as a centralized security toolkit containing automated defense scripts, network analysis tools, and data-driven access compliance audits. It bridges the gap between active threat hunting and structural identity management, utilizing Python for real-time log triage and SQL for internal relational database auditing.

---

## 📁 Repository Components

### 1. Python: Defensive Automation & Threat Intelligence
Located in the `/python-defensive-scripts/` directory:

* **`file_updater.py` (Automated Access Controls):** Enforces network boundaries by safely reading an organization's active IP allow-list, cross-referencing it with an unauthorized user list, and updating system configurations using secure Python file-handling workflows.
* **`log_parser.py` (Brute-Force Detection SIEM Mockup):** Ingests simulated standard Linux authentication logs (`auth.log`). Using Regular Expressions (Regex), it isolates and counts failed login attempts, automatically triggering high-fidelity alerts when specific threshold metrics are exceeded.
* **`network_scanner.py` (Network Auditing & Banner Grabber):** Implements `socket` network socket streaming to audit targets for open TCP network vectors (SSH, FTP, HTTP) and captures service signatures to flag unauthorized software deployments.
* **`file_integrity_checker.py` (Cryptographic Hash Surveillance):** Generates and registers system-level cryptographic baseline mappings utilizing the SHA-256 standard. Performs runtime comparison evaluations to instantly pinpoint digital tampering or malware actions.

### 2. SQL: Enterprise IAM & Security Forensics
Located in the `/sql-security-audits/` directory:

* **`privilege_audit.sql`:** A robust database auditing suite engineered to process large relational database logs for infrastructure protection:
    * **IAM & Identity Controls:** Uncovers privilege creep by isolating unauthorized admin access and stale accounts.
    * **Incident Triage:** Uses log aggregation algorithms (`COUNT`, `GROUP BY`, `HAVING`) to analyze brute-force attack trends.
    * **Data Loss Prevention (DLP):** Monitors unauthorized data access on tables containing PII or Financial data outside regular business hours.
    * **Vulnerability Analysis:** Audits operating system lifecycles to target and patch non-compliant network endpoints.
