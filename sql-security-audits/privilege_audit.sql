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
