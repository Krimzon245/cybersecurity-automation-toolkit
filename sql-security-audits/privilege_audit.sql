-- ====================================================================
-- AUDIT 1: Identity & Access Management (IAM) Violation Detection
-- Objective: Enforce Least Privilege & detect high-risk stale accounts.
-- ====================================================================

-- Query A: Flag non-IT personnel with root/admin-level access controls
SELECT 
    e.employee_id, 
    e.username, 
    e.department, 
    a.access_level, 
    a.last_modified_by
FROM employee_registry AS e
INNER JOIN access_privileges AS a 
    ON e.employee_id = a.employee_id
WHERE a.access_level IN ('Root', 'Administrator', 'DB_Owner')
  AND e.department NOT IN ('IT_Security', 'Network_Engineering');


-- Query B: Hunt for inactive active accounts (Prime targets for credential stuffing)
SELECT 
    employee_id, 
    username, 
    email, 
    last_login_timestamp, 
    account_status
FROM user_credentials
WHERE account_status = 'Active'
  AND last_login_timestamp < DATE_SUB(CURDATE(), INTERVAL 90 DAY)
ORDER BY last_login_timestamp ASC;

-- ====================================================================
-- AUDIT 2: Incident Response Log Analysis & Threat Isolation
-- Objective: Triage failed authentication logs to identify active brute-force IoCs.
-- ====================================================================

SELECT 
    source_ip,
    country_code,
    COUNT(attempt_id) AS total_failed_attempts,
    MIN(login_timestamp) AS attack_start_time,
    MAX(login_timestamp) AS attack_last_seen,
    TARGET_ASSET = 'Corporate_Main_Gateway'
FROM authentication_logs
WHERE login_status = 'FAILED'
  AND device_type = 'SSH_Console'
GROUP BY source_ip, country_code
HAVING total_failed_attempts >= 5
ORDER BY total_failed_attempts DESC;

-- ====================================================================
-- AUDIT 3: Data Loss Prevention (DLP) & Insider Threat Analysis
-- Objective: Audit reads on tables holding PII or Financial Records.
-- ====================================================================

SELECT 
    access_id,
    employee_id,
    requested_table_name,
    record_count_extracted,
    ip_address,
    TIME(access_timestamp) AS execution_time
FROM database_query_logs
WHERE requested_table_name IN ('payroll_master', 'customer_credit_cards', 'healthcare_pii')
  AND (
      TIME(access_timestamp) > '18:00:00' 
      OR TIME(access_timestamp) < '07:00:00'
  )
  AND authorized_clearance != 'VIP_ACCESS'
ORDER BY record_count_extracted DESC;


-- ====================================================================
-- AUDIT 4: Asset Vulnerability Management & Patch Compliance
-- Objective: Isolate exposed systems running legacy software versions.
-- ====================================================================

SELECT 
    asset_id,
    device_name,
    assigned_user,
    operating_system,
    os_version,
    mac_address
FROM corporate_endpoints
WHERE (operating_system = 'Windows_Server' AND os_version < '2022')
   OR (operating_system = 'Ubuntu_Linux' AND os_version LIKE '18.%')
   OR (operating_system = 'macOS' AND os_version NOT LIKE '14.%')
ORDER BY operating_system DESC, os_version ASC;
