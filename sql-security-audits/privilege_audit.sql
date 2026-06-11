-- ====================================================================
-- CYBERSECURITY AUDIT: Identity & Access Management (IAM) Evaluation
-- Objective: Identify over-privileged accounts and verify least privilege compliance.
-- ====================================================================

-- 1. IDENTIFY DIRECT ACCOUNTS WITH ADMINISTRATIVE PRIVILEGES
-- Checks for users assigned to high-risk roles that bypass standard employee structures.
SELECT user_id, username, department, role, access_level 
FROM user_registry
WHERE access_level = 'Administrator' 
  AND department != 'IT_Security';


-- 2. DETECT STALE ACCOUNTS WITH ACTIVE NETWORK ACCESS
-- Flags active profiles that haven't authenticated in over 90 days (high risk for credential stuffing).
SELECT user_id, username, email, last_login_date, account_status
FROM user_registry
WHERE account_status = 'Active' 
  AND last_login_date < DATE_SUB(CURDATE(), INTERVAL 90 DAY);


-- 3. AUDIT ACCESS TO SENSITIVE FINANCIAL DATA TABLES
-- Pinpoints unauthorized internal telemetry views on restricted network assets.
SELECT employee_id, transaction_id, access_timestamp, ip_address 
FROM data_access_logs
WHERE database_table = 'payroll_records'
  AND department_authorized = 'FALSE';
