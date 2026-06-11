import hashlib
import os
import json

def calculate_sha256(file_path):
    """
    Calculates the SHA-256 cryptographic checksum/hash of a file
    to verify its digital integrity.
    """
    sha256_hash = hashlib.sha256()
    
    try:
        # Open file in binary read mode to prevent line-ending encoding errors
        with open(file_path, "rb") as f:
            # Read file in chunks to optimize memory utilization for larger files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"[ERROR] Target file not found at: {file_path}")
        return None

def monitor_integrity(monitored_files_dict, baseline_db_path="hash_baseline.json"):
    """
    Compares current file hashes against a baseline ledger database 
    to detect unauthorized modifications or tampering (Rootkit detection logic).
    """
    print("[INFO] Auditing system file integrity baselines...")
    tamper_detected = False
    
    # Load existing baseline hashes if they exist
    if os.path.exists(baseline_db_path):
        with open(baseline_db_path, "r") as db:
            baseline_data = json.load(db)
    else:
        # Create a new baseline if none exists
        print(f"[INFO] Baseline database not found. Creating new blueprint registry at {baseline_db_path}...")
        baseline_data = {}
        for friendly_name, path in monitored_files_dict.items():
            if os.path.exists(path):
                baseline_data[friendly_name] = calculate_sha256(path)
        
        with open(baseline_db_path, "w") as db:
            json.dump(baseline_data, db, indent=4)
        print("[SUCCESS] Baseline baseline established successfully.\n")
        return

    # Compare active runtime integrity hashes against baseline records
    for friendly_name, path in monitored_files_dict.items():
        if os.path.exists(path):
            current_hash = calculate_sha256(path)
            expected_hash = baseline_data.get(friendly_name)
            
            if current_hash != expected_hash:
                print(f"[CRITICAL ALERT] TAMPERING DETECTED on asset: '{friendly_name}' ({path})")
                print(f"   └── Expected Baseline: {expected_hash}")
                print(f"   └── Active Real-time Hash:   {current_hash}")
                tamper_detected = True
            else:
                print(f"[PASS] Integrity Verified: '{friendly_name}' is secure.")
        else:
            print(f"[WARNING] Monitored file missing or moved: {path}")

    if not tamper_detected:
        print("\n[SUCCESS] Integrity audit complete. Zero unauthorized file edits found.")

if __name__ == "__main__":
    # Create two temporary test text assets to verify the script functionality
    with open("critical_system.cfg", "w") as f: f.write("SYSTEM_ALLOW_ACCESS=TRUE")
    with open("user_database.csv", "w") as f: f.write("id,username,role\n1,daniel,admin")

    # Define registry paths to be placed under structural integrity surveillance
    files_to_guard = {
        "System Configuration File": "critical_system.cfg",
        "User Database Records": "user_database.csv"
    }
    
    # Execution Step 1: Establishes baseline blueprint
    monitor_integrity(files_to_guard)
    
    # Execution Step 2: Simulating an adversary injection/unauthorized alteration
    print("\n--- [SIMULATING ADVERSARIAL FILE EDITS] ---")
    with open("critical_system.cfg", "w") as f: f.write("SYSTEM_ALLOW_ACCESS=FALSE (MALICIOUS PAYLOAD)")
    
    # Execution Step 3: Run monitor again to catch the threat actor manipulation live
    monitor_integrity(files_to_guard)
    
    # Cleanup dummy files after simulation run concludes
    for file in ["critical_system.cfg", "user_database.csv", "hash_baseline.json"]:
        if os.path.exists(file): os.remove(file)
