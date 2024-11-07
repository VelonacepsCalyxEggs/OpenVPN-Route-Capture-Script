import pyshark
import ifaddr
import dns.resolver
import socket
import time
import os 
import sys 
import re

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(sys.argv[0])) 
OVPN_PATH = "./client.ovpn"

def get_default_interface():
    print("Getting adapter...")
    adapters = ifaddr.get_adapters()
    for adapter in adapters:
        print(adapter.nice_name)
    for adapter in adapters:
        if 'Ethernet' in adapter.nice_name or 'Realtek' in adapter.nice_name and 'Virtual' not in adapter.nice_name:
            print(f"Found an ethernet adapter: {adapter.nice_name}")
            adapter_name = r'\Device\NPF_' + adapter.name
            return adapter_name
    print("WARNING: NO ADAPTER FOUND WITH SPECIFIC CRITERIA!")
    return r'\Device\NPF_' + adapters[0].name

def capture_packets(interface, duration):
    print(f"Starting packet capture on {interface} for {duration} seconds...")
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=duration)
    print(f"Finished packet capture. Total packets captured: {len(capture)}")
    MAX_PACKETS_TO_ANALYZE = len(capture)  # Maximum number of packets to analyze
    return capture, MAX_PACKETS_TO_ANALYZE

def analyze_packets(packets, MAX_PACKETS_TO_ANALYZE):
    print("Analyzing packets...")
    failed_ips = []
    total_packets = len(packets)
    for index, packet in enumerate(packets):
        if index >= MAX_PACKETS_TO_ANALYZE:
            print(f"Reached maximum packets to analyze ({MAX_PACKETS_TO_ANALYZE}). Stopping analysis.")
            break
        if 'TCP' in packet:
            try:
                if hasattr(packet.tcp, 'analysis_retransmission'):
                    domain = packet.ip.dst_host
                    failed_ips.append(domain)
            except AttributeError as e:
                print(f"Packet {index}/{total_packets} skipped due to missing attribute: {e}")
        else:
            pass # non tcp packets get skipped
    print(f"Total failed domains found: {len(failed_ips)}")
    return failed_ips

def sort_ips(ips):
    print("Sorting IPs...")
    unique_ips = set()  # Using a set to track unique IPs for efficiency
    sorted_ips = []
    print(f"Unsorted list: \n {ips}")
    
    for ip in ips:
        # Skip local IP addresses
        if "192.168.0." not in ip and "127.0.0.1" not in ip and "10.8.0." not in ip:
            # Check if the IP is not already in the set of unique IPs
            if ip not in unique_ips:
                unique_ips.add(ip)
                sorted_ips.append(ip)
    
    print(f"Sorted list: \n {sorted_ips}")
    return sorted_ips

def resolve_ips(ips):
    print("Resolving IPs...")
    resolved_ips = {}
    unresolved_ips = []
    
    for ip in ips:
        try:
            # Perform reverse DNS lookup
            host_info = socket.gethostbyaddr(ip)
            host_name = host_info[0]
            print(f"Resolved {ip} to {host_name}")
            resolved_ips[host_name] = []
            
            # Now resolve the domain name back to IP addresses
            answers = dns.resolver.resolve(host_name, 'A')
            for rdata in answers:
                resolved_ips[host_name].append(rdata.address)
        except (socket.error, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer) as e:
            print(f"Could not resolve {ip}: {e}")
            unresolved_ips.append(ip)
    
    print(f"Total IPs resolved: {sum(len(v) for v in resolved_ips.values())}")
    print(f"Total IPs unresolved: {len(unresolved_ips)}")
    
    return resolved_ips, unresolved_ips

import socket
import dns.resolver

def resolve_ips(ips):
    print("Resolving IPs...")
    resolved_ips = {}
    unresolved_ips = []

    for ip in ips:
        try:
            # Perform reverse DNS lookup
            host_info = socket.gethostbyaddr(ip)
            host_name = host_info[0]
            print(f"Resolved {ip} to {host_name}")

            if host_name not in resolved_ips:
                resolved_ips[host_name] = []

            # Now resolve the domain name back to IP addresses
            answers = dns.resolver.resolve(host_name, 'A')
            i = 0
            for rdata in answers:
                if rdata.address not in resolved_ips[host_name]:
                    i+=1
                    print(f"A record #{i} for {host_name}: {ip} ")
                    resolved_ips[host_name].append(rdata.address)
        except (socket.error, dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoAnswer) as e:
            print(f"Could not resolve {ip}: {e}")
            unresolved_ips.append(ip)

    print(f"Total IPs resolved: {sum(len(v) for v in resolved_ips.values())}")
    print(f"Total IPs unresolved: {len(unresolved_ips)}")

    return resolved_ips, unresolved_ips

def update_ovpn_file(resolved_ips, unresolved_ips, ovpn_filename):
    print("Updating .ovpn file...")
    
    # Read the existing .ovpn file
    try:
        with open(ovpn_filename, 'r') as f:
            ovpn_content = f.readlines()
    except FileNotFoundError:
        ovpn_content = []

    # Ensure routes are added after 'route-nopull' line
    route_nopull_index = next((index for index, line in enumerate(ovpn_content) if 'route-nopull' in line), None)
    
    # Track existing sections
    existing_sections = {line.strip(): True for line in ovpn_content if line.strip().startswith("#")}
    found_unbound = "# Unbound IPs" in existing_sections
    try:
        with open(ovpn_filename, 'w') as f:
            if route_nopull_index is not None:
                for idx, line in enumerate(ovpn_content):
                    f.write(line)
                    if idx == route_nopull_index:
                        # Append unresolved IPs
                        if unresolved_ips:
                            if not found_unbound:
                                f.write("# Unbound IPs\n")
                                found_unbound = True
                            for ip in unresolved_ips:
                                route_line = f"route {ip} 255.255.255.255\n"
                                if route_line not in ovpn_content:
                                    f.write(route_line)
                        
                        # Append resolved IPs under respective host headers
                        for host_name, ip_list in resolved_ips.items():
                            host_header = f"# {host_name}"
                            if host_header not in existing_sections:
                                f.write(f"{host_header}\n")
                                existing_sections[host_header] = True

                            for ip in ip_list:
                                route_line = f"route {ip} 255.255.255.255\n"
                                if route_line not in ovpn_content:
                                    f.write(route_line)
            else:
                # Add route-nopull line if not found
                f.write("route-nopull\n")
                if unresolved_ips:
                    if not found_unbound:
                        f.write("# Unbound IPs\n")
                        found_unbound = True
                    for ip in unresolved_ips:
                        route_line = f"route {ip} 255.255.255.255\n"
                        if route_line not in ovpn_content:
                            f.write(route_line)

                for host_name, ip_list in resolved_ips.items():
                    host_header = f"# {host_name}"
                    if host_header not in existing_sections:
                        f.write(f"{host_header}\n")
                        existing_sections[host_header] = True
                    for ip in ip_list:
                        route_line = f"route {ip} 255.255.255.255\n"
                        if route_line not in ovpn_content:
                            f.write(route_line)
                
                # Write the remaining content
                f.writelines(ovpn_content)
    except FileNotFoundError as e:
        print(f'Error! .ovpn file not found. Are you sure it exists in {SCRIPT_DIRECTORY} and named client.ovpn?')

    print("Finished updating .ovpn file.")


### HELPERS

def check_if_ovpn_exists():
    if os.path.isfile(OVPN_PATH):
        return
    raise(f"ERROR! .ovpn file not found in {OVPN_PATH}! STOPPING...")


PP_SOFTWARE_FUNNYSIGN = """
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@                       @@@@@@@                       @@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@                       @@@@@@                        @@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@                        @@@@@@                       @@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@      @@@@@@@@@@@       @@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@       @@@@@@@@@@       @@@@@@       @@@@@@@@@@       @@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@      @@@@@@@@@@@@      @@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@      @@@@@@@@@@@@      @@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@      @@@@@@@@@@       @@@@@@       @@@@@@@@@@       @@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@      @@@@@@@@@@@       @@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@@      @@@@@@@@@@       @@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@       @@@@@@@@@@@      @@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@       @@@@@@@@@@@      @@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@       @@@@@@@@@@      @@@@@@@       @@@@@@@@@@       @@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@@      @@@@@@@@@@@      @@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@      @@@@@@@@@@@      @@@@@@       @@@@@@@@@@       @@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@    @@@@@@@@@@@@@@@@ @@@@@@@@@  @@@@@@@@@@@@@@@  @@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@      @@@        @@@@     @@        @  @@@@   @@@@  @@@@   @@@@@       @@@      @
@@  @@@@@@@  @@@@@@ @@@  @@@@@@@@@ @@@@@  @@@@   @@@@ @@@@ @  @@@@@ @@@@  @@@ @@@@@@
@@@  @@@@@  @@@@@@@ @@@ @@@@@@@@@  @@@@@@ @@@ @  @@@ @@@@ @@@ @@@@  @@@  @@@  @@@@@@
@@@@@   @@  @@@@@@  @@@    @@@@@@  @@@@@@ @@ @@@ @@ @@@@ @@@@  @@@  @@  @@@@      @@
@@@@@@  @@  @@@@@@ @@@  @@@@@@@@@ @@@@@@@ @  @@@ @ @@@@        @@@ @@@@ @@@@ @@@@@@@
@      @@@@       @@@@ @@@@@@@@@  @@@@@@@   @@@@   @@@  @@@@@@ @@  @@@@  @@       @@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
"""
def main(duration):
    interface = get_default_interface()
    print(f"Adapter found: {interface}")
    packets, MAX_PACKETS_TO_ANALYZE = capture_packets(interface, duration)
    failed_list = analyze_packets(packets, MAX_PACKETS_TO_ANALYZE)
    sorted_list = sort_ips(failed_list)
    resolved_ips, unresolved_ips = resolve_ips(sorted_list)
    update_ovpn_file(resolved_ips, unresolved_ips, OVPN_PATH)


if __name__ == "__main__":
    PP_SOFTWARE_FUNNYSIGN = PP_SOFTWARE_FUNNYSIGN.split('\n')
    for line in PP_SOFTWARE_FUNNYSIGN:
        print(line)
        time.sleep(0.01)
    check_if_ovpn_exists()
    waiting_for_user = True
    while waiting_for_user:
        duration = input("Please, input how many seconds you want to capture packets for: ")
        if duration:
            duration = re.sub("[^0-9]", "", duration)
            try:
                duration = int(duration)
                waiting_for_user = False
            except ValueError as e:
                print("You idiot sandwich, please use numbers! as in arabic numbers...")

        else:
            print("Please enter a correct duration...")
    main(duration)
