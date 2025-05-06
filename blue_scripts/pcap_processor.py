from scapy.all import sniff, IP, TCP, rdpcap
from collections import defaultdict
import os
import time
import sys

def detect_port_scan(pcap_file, host_ip, port_threshold=10, interval=5, iterations=2):
    """
    :param pcap_file: Path to the continuously updated pcap file.
    :param host_ip: Source IP to monitor for port scanning activity.
    :param port_threshold: Minimum unique destination ports to flag a scan.
    :param interval: Time interval (seconds) to check for new packets.
    """
    print(f"Monitoring {pcap_file} for port scans by {host_ip}...")
    dest_ports = defaultdict(set)  
    processed_packets = 0  

    for _ in range(iterations):
        try:
            packets = rdpcap(pcap_file)

            new_packets = packets[processed_packets:]  
            print(f"Processing {len(new_packets)} new packets...")
            for packet in new_packets:
                if IP in packet and packet[IP].src == host_ip:
                    dest_ip = packet[IP].dst
                    if TCP in packet:
                        dest_ports[dest_ip].add(packet[TCP].dport)

            processed_packets += len(new_packets) 

            potential_targets = [
                dest_ip for dest_ip, ports in dest_ports.items() if len(ports) >= port_threshold
            ]

            if potential_targets:
                print(f"Potential scan targets detected: {potential_targets}")
                print(potential_targets)
                return potential_targets
            time.sleep(interval)

        except KeyboardInterrupt:
            print("Stopping monitoring.")
            break
        except Exception as e:
            print(f"Error occurred: {e}")
            break

if __name__ == "__main__":
    pcap_file = "/home/hacker/blue_scripts/mirrored_traffic.pcap"
    host_ip = sys.argv[1]
    port_threshold = 10
    interval = 5  
    print("Starting real-time port scan detection...")
    detect_port_scan(pcap_file, host_ip, port_threshold, interval)