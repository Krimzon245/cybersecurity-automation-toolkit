import re
from collections import Counter

# Simulated Linux auth.log data showing successful and failed login attempts
SIMULATED_LOGS = """
June 11 10:01:22 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.105 port 54321 ssh2
June 11 10:01:25 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.105 port 54322 ssh2
June 11 10:01:28 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.105 port 54323 ssh2
June 11 10:02:01 server1 sshd[12345]: Accepted password for user daniel from 172.16.5.4 port 51122 ssh2
June 11 10:03:11 server1 sshd[12345]: Failed password for root from 10.0.0.45 port 49152 ssh2
June 11 10:04:12 server1 sshd[12345]: Failed password for invalid user guest from 192.168.1.105 port 54324 ssh2
"""

def analyze_ssh_failures(log_data, threshold=3):
    """
    Parses system logs using Regular Expressions (Regex) to detect 
    Potential Brute-Force Attacks based on a failed login threshold.
    """
    print("[INFO] Starting Log Analysis for Indicator of Compromise (IoC)...")
    
    # Regex pattern to extract IP addresses from standard "Failed password" log lines
    failed_ip_pattern = r"Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    
    # Find all matching failed IPs in the log data
    failed_ips = re.findall(failed_ip_pattern, log_data)
    
    # Count occurrences of each offending IP
    ip_counts = Counter(failed_ips)
    
    # Flag IPs exceeding our acceptable security threshold
    flagged_ips = {ip: count for ip, count in ip_counts.items() if count >= threshold}
    
    if flagged_ips:
        for ip, count in flagged_ips.items():
            print(f"[ALERT] Potential Brute-Force Detected! IP: {ip} generated {count} failed login attempts.")
    else:
        print("[INFO] Analysis complete. No suspicious behavior detected.")
        
    return flagged_ips

if __name__ == "__main__":
    # In a production environment, this would ingest a live file like open('/var/log/auth.log')
    analyze_ssh_failures(SIMULATED_LOGS)
