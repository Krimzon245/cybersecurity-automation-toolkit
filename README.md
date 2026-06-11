# Enterprise Cybersecurity Automation & Auditing Toolkit

## Project Overview
This repository functions as a centralized security toolkit containing automated defense scripts and data-driven access compliance audits. It bridges the gap between active threat hunting and structural identity management, utilizing Python for real-time log triage and SQL for internal relational database auditing.

---

## 📁 Repository Components

### 1. Python: Defensive Automation & Log Triage
Located in the `/python-defensive-scripts/` directory, these utilities minimize manual analysis overhead by automating threat detection logic.

* **`file_updater.py` (Automated Access Controls):** Enforces network boundaries by safely reading an organization's active IP allow-list, cross-referencing it with an unauthorized user list, and updating system configurations using secure Python file-handling workflows.
* **`log_parser.py` (Brute-Force Detection SIEM Mockup):** Ingests simulated standard Linux authentication logs (`auth.log`). Using Regular Expressions (Regex), it isolates and counts failed login attempts, automatically triggering high-fidelity alerts when specific threshold metrics are exceeded.

### 2. SQL: Enterprise IAM & Privilege Auditing
Located in the `/sql-security-audits/` directory, these scripts leverage structured query logic to audit organizational security health.

* **`privilege_audit.sql`:** Focuses on Identity & Access Management (IAM) compliance. These queries are engineered to map organizational asset databases to uncover over-privileged administrative accounts, pinpoint stale credentials vulnerable to credential stuffing, and flag lateral access violations on restricted tables.

---

## ⚙️ Core Technical Skills Demonstrated
* **Threat Hunting Automation:** Reducing incident response times through programmed log analysis and automated Indicator of Compromise (IoC) identification.
* **Data Parsing & Regex:** Implementing text pattern-matching algorithms to quickly extract actionable insights from complex system files.
* **IAM Compliance & Privilege Hardening:** Formulating verification steps to systematically enforce the Principle of Least Privilege across data infrastructure.
* **Secure Coding Operations:** Applying strict file resource containment patterns (`with` syntax blocks) and robust validation logic to prevent script failures.
