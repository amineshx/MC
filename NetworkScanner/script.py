from scapy.all import ARP, Ether, srp

def discover_hosts(ip_range):
    start_ip, end_ip = ip_range.split('-')
    start_ip_parts = list(map(int, start_ip.split('.')))
    end_ip_parts = list(map(int, end_ip.split('.')))

    hosts = []

    for i in range(start_ip_parts[3], end_ip_parts[3] + 1):
        current_ip = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}.{i}"

        # Create ARP request packet for the current IP
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=current_ip)

        # Send ARP request and capture responses
        result, unanswered = srp(arp_request, timeout=3, verbose=0)

        # Extract IP and MAC addresses from the responses
        if result:
            hosts.extend([(res[1].psrc, res[1].hwsrc) for res in result])

        # Print unanswered ARP requests
        if unanswered:
            print("Unanswered ARP requests:")
            for req in unanswered:
                print(f"IP: {req[0].pdst}")

    return hosts

def main():
    # Input: IP address range (e.g., "192.168.1.1-192.168.1.10")
    ip_range = input("Enter IP address range: ")

    # Perform host discovery
    hosts = discover_hosts(ip_range)

    # Print the list of hosts with their IP and MAC addresses
    print("\nDiscovered hosts:")
    for ip, mac in hosts:
        print(f"IP: {ip}\tMAC: {mac}")

if __name__ == "__main__":
    main()
