def update_file(import_file, remove_list):
    """
    Reads an access control file, removes unauthorized IP addresses,
    and updates the file to enforce network security policy.
    """
    # 1. Open the file that contains the allow list
    with open(import_file, "r") as file:
        
        # 2. Read the file contents as a string
        ip_addresses = file.read()

    # 3. Convert the string of IP addresses into a list
    ip_addresses = ip_addresses.split()

    # 4. Loop through the IP addresses that need to be removed
    for element in remove_list:
        
        # 5. If the unauthorized IP is in the allow list, remove it
        if element in ip_addresses:
            ip_addresses.remove(element)

    # 6. Convert the updated list back into a string with newlines
    ip_addresses = "\n".join(ip_addresses)

    # 7. Reopen the file in write mode to overwrite the old data
    with open(import_file, "w") as file:
        
        # 8. Write the secured IP list back to the file
        file.write(ip_addresses)
        
    print(f"[SUCCESS] {import_file} has been updated. Unauthorized IPs removed.")

# --- EXECUTION EXAMPLE (To test your code) ---
if __name__ == "__main__":
    # Define the file name
    target_file = "allow_list.txt"
    
    # Simulate a list of IPs that are no longer allowed on the network
    unauthorized_ips = ["192.168.1.115", "10.0.0.15", "172.16.5.22"]
    
    # Run the function
    # Note: To test this locally, make sure a file named 'allow_list.txt' 
    # exists in the same folder with some IP addresses in it!
    try:
        update_file(target_file, unauthorized_ips)
    except FileNotFoundError:
        print(f"[ERROR] Could not find {target_file}. Please create it to test the script.")
