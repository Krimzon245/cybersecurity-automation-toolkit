import socket
import sys
from datetime import datetime

def scan_target(target_host, ports_to_scan):
    """
    Simulates a network port scanner to identify open ports 
    and perform basic service banner grabbing for vulnerability analysis.
    """
    print("-" * 50)
    print(f"[INFO] Initializing Network Scan For Host: {target_host}")
    print(f"[INFO] Scan Started At: {str(datetime.now())}")
    print("-" * 50)

    try:
        # Resolve target hostname to IP address
        target_ip = socket.gethostbyname(target_host)
        print(f"[INFO] Target IP Resolved: {target_ip}")
    except socket.gaierror:
        print("\n[ERROR] Hostname could not be resolved.")
        sys.exit()

    open_ports = []

    for port in ports_to_scan:
        # Set up an AF_INET (IPv4), SOCK_STREAM (TCP) socket connection
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a low timeout so the scanner doesn't hang indefinitely on closed ports
        s.settimeout(1.0)
        
        # Attempt to establish a connection (returns 0 if successful)
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            print(f"[ALERT] Port {port}: OPEN")
            open_ports.append(port)
            
            # Attempt basic banner grabbing to identify the service type
            try:
                s.send(b'Hello\r\n')
                banner = s.recv(1024).decode().strip()
                if banner:
                    print(f"   └── [Service Banner Extracted]: {banner}")
            except:
                print("   └── [Service Banner Extracted]: Unable to grab banner (No response).")
        
        # Explicitly close the socket resource connection
        s.close()

    print("\n" + "-" * 50)
    print(f"[SUCCESS] Scan Complete. Found {len(open_ports)} open network entryways.")
    print("-" * 50)
    return open_ports

if __name__ == "__main__":
    # Standard security ports to audit: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS)
    common_ports = [21, 22, 80, 443, 8080]
    
    # Using localhost (127.0.0.1) as a safe, legal diagnostic testing target
    scan_target("localhost", common_ports)
