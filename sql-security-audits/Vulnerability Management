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
