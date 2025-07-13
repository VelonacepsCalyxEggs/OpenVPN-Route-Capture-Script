import pyshark
import ifaddr
import dns.resolver
import socket
import time
import os 
import sys 
import re

SCRIPT_DIRECTORY = os.path.dirname(os.path.abspath(sys.argv[0])) 

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
    packets_caputred = len(capture)
    print(f"Finished packet capture. Total packets captured: {packets_caputred}")
    return capture, packets_caputred

def analyze_packets(packets, packets_caputred):
    print(f"Analyzing {packets_caputred} packets...")
    failed_ips = []
    total_packets = len(packets)
    for index, packet in enumerate(packets):
        if index >= packets_caputred:
            print(f"All packets ({packets_caputred}) were analyzed. Stopping analysis.")
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

def filter_and_sort_ips(ips):
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
    
    print(f"Filtered list: \n {sorted_ips}")
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
    packets, packets_caputred = capture_packets(interface, duration)
    failed_list = analyze_packets(packets, packets_caputred)
    sorted_list = filter_and_sort_ips(failed_list)
    resolved_ips, unresolved_ips = resolve_ips(sorted_list)

    print("Resolved IPs:")
    for host, ips in resolved_ips.items():
        print(f"{host}: {', '.join(ips)}")
    print("\nUnresolved IPs:")
    for ip in unresolved_ips:
        print(ip)

    print("\nAnalysis complete. Exiting...")
    exit(0)

if __name__ == "__main__":
    PP_SOFTWARE_FUNNYSIGN = PP_SOFTWARE_FUNNYSIGN.split('\n')
    for line in PP_SOFTWARE_FUNNYSIGN:
        print(line)
        time.sleep(0.01)
    waiting_for_user = True
    while waiting_for_user:
        duration = input("Please, input how many seconds you want to capture packets for: ")
        if duration:
            duration = re.sub(r"\D", "", duration)
            try:
                duration = int(duration)
                waiting_for_user = False
            except ValueError as e:
                print("You idiot sandwich, please use numbers! as in arabic numbers...")

        else:
            print("Please enter a correct duration...")
    main(duration)
