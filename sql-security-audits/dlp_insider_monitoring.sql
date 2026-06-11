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
