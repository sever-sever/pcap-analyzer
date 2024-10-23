#!/usr/bin/env python3

import argparse
import subprocess
from collections import Counter
from tabulate import tabulate

# Run the tcpdump command and capture the output
def get_ips(pcap_file, mode):
    if mode == "destination":
        # Get destination IPs
        command = f"tcpdump -nnr {pcap_file} 'ip' -q | awk '{{print $5}}' | cut -d '.' -f 1-4"
    elif mode == "source":
        # Get source IPs
        command = f"tcpdump -nnr {pcap_file} 'ip' -q | awk '{{print $3}}' | cut -d '.' -f 1-4"
    elif mode == "both":
        # Get both source and destination IPs
        command = f"tcpdump -nnr {pcap_file} 'ip' -q | awk '{{print $3 \"\\n\" $5}}' | cut -d '.' -f 1-4"
    else:
        raise ValueError("Invalid mode. Choose from 'destination', 'source', or 'both'.")

    # Run the command and capture the output
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    # Split the output into a list of IPs
    return result.stdout.splitlines()

# Analyze the IPs and print the top IPs
def analyze_ips(pcap_file, num_hosts, mode):
    ips = get_ips(pcap_file, mode)

    # Count the occurrences of each IP
    ip_counter = Counter(ips)

    # Get the top 'num_hosts' IPs
    top_ips = ip_counter.most_common(num_hosts)

    # Prepare data for tabulate
    table = [["IP Address", "Packet Count"]]  # Header
    for ip, count in top_ips:
        table.append([ip, count])

    # Print the table
    print(f"Top {num_hosts} {mode} IPs with the most packets:\n")
    print(tabulate(table, headers="firstrow", tablefmt="simple"))

# Main function with argument parsing
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze a pcap file and find the top IPs by packet count.')
    parser.add_argument('pcap_file', type=str, help='Path to the .pcap file to analyze')
    parser.add_argument('--num_hosts', type=int, default=10, help='Number of top IPs to display (default: 10)')
    parser.add_argument('--mode', type=str, choices=['destination', 'source', 'both'], default='destination', 
                        help="Which IPs to analyze: 'destination' (default), 'source', or 'both'")

    args = parser.parse_args()
    analyze_ips(args.pcap_file, args.num_hosts, args.mode)
