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
