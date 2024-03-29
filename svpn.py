import subprocess

def print_separator():
    print("-" * 50)

def configure_tun_interface():
    # Read user input for TUN interface name
    tun_name = input("Enter TUN Interface Name: ")

    # Read user input for TUN interface IP address and subnet mask
    tun_ip = input("Enter TUN Interface IP Address/Subnet Mask (e.g., 10.0.1.1/24): ")

    # Call additional shell commands to configure tun interface
    print_separator()
    print(f"Configuring TUN interface {tun_name} with IP {tun_ip}...")
    subprocess.run(["sudo", "ip", "tuntap", "add", "dev", tun_name, "mode", "tun"])
    subprocess.run(["sudo", "ip", "addr", "add", tun_ip, "dev", tun_name])
    subprocess.run(["sudo", "ip", "link", "set", "dev", tun_name, "up"])
    subprocess.run(["ip", "addr", "show"])
    print(f"TUN interface {tun_name} configured.")
    print_separator()

    return tun_name, tun_ip

def configure_iptables_forwarding():
    # Read user input for source interface
    source_interface = input("Enter Source Interface (e.g., tun0): ")

    # Read user input for destination interface
    destination_interface = input("Enter Destination Interface (e.g., docker0): ")

    # Read user input for iptables rule source IP
    source_ip = input("Enter Source IP for iptables rule (e.g., 10.0.1.2): ")

    # Configure iptables forwarding rule
    print("Configuring iptables forwarding rule...")
    subprocess.run(["sudo", "iptables", "-A", "FORWARD", "-i", source_interface, "-s", source_ip, "-o", destination_interface, "-j", "ACCEPT"])
    print("iptables forwarding rule configured.")
    print_separator()

def configure_routes():
    # Read user input for network segment and device name
    network_segment = input("Enter Network Segment (e.g., 172.17.0.0/24): ")
    device_name = input("Enter Device Name (e.g., asa0): ")

    # Configure additional route
    print(f"Configuring route for network segment {network_segment} on device {device_name}...")
    subprocess.run(["sudo", "route", "add", "-net", network_segment, device_name])
    print("Route configured.")
    print_separator()

def start_tunnel(tun_name, tun_ip):
    # Read user input for interface
    interface = input("Enter Interface: ")

    # Read user input for destination IP
    destination_ip = input("Enter Destination IP: ")

    # Read user input for encryption key
    encrypt_key = input("Enter Encryption Key: ")

    # Read user input for verification key
    verify_key = input("Enter Verification Key: ")

    # Display summary of user inputs
    print_separator()
    print("Configuration Summary:")
    print(f"Interface: {interface}")
    print(f"Destination IP: {destination_ip}")
    print(f"Encryption Key: {encrypt_key}")
    print(f"Verification Key: {verify_key}")
    print(f"TUN Interface Name: {tun_name}")
    print(f"TUN Interface IP: {tun_ip}")
    print_separator()

    # Ask user for confirmation to start the tunnel
    start_tunnel_choice = input("Do you want to start the tunnel? (y/n): ")
    print_separator()

    # Check user's choice and start the tunnel if confirmed
    if start_tunnel_choice == "y":
        print("Starting the tunnel...")
        subprocess.run(["python3", "main.py", interface, "--destination-ip", destination_ip, "--encrypt-key", encrypt_key, "--verify-key", verify_key, "--tun-int-name", tun_name])
    else:
        print("Tunnel setup canceled.")

# Display program usage information
print("=== Tunnel Program ===")

while True:
    print_separator()
    print("Choose Configuration Option:")
    print("1. Configure TUN interface")
    print("2. Configure iptables forwarding rule")
    print("3. Configure routes")
    print("4. Start Tunnel")
    print("5. Exit")

    option = input("Enter the option number (1/2/3/4/5): ")

    if option == "1":
        tun_name, tun_ip = configure_tun_interface()
    elif option == "2":
        configure_iptables_forwarding()
    elif option == "3":
        configure_routes()
    elif option == "4":
        start_tunnel(tun_name, tun_ip)
    elif option == "5":
        print("Exiting the program. Goodbye!")
        break
    else:
        print("Invalid option. Please enter a valid option.")
