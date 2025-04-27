import sys
import pyshark
import json
from collections import defaultdict

def analyze_pcap(host_name):
    pcap_file_path = f"/home/captures/{host_name}.pcap"
    suspected_targets = set()
    scan_activity = defaultdict(list)  # target_ip -> list of scanned ports

    try:
        # Read the PCAP file
        capture = pyshark.FileCapture(pcap_file_path)

        for packet in capture:
            try:
                # Check for TCP packets
                if 'IP' in packet and 'TCP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    dst_port = int(packet.tcp.dstport)

                    # Check if this packet might be part of a scan
                    if src_ip.startswith('10.0.0.'):  # Host initiating the scan
                        scan_activity[dst_ip].append(dst_port)

                # Check for nmap-like UDP scanning (optional, expand if necessary)
                elif 'IP' in packet and 'UDP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    dst_port = int(packet.udp.dstport)

                    if src_ip.startswith('10.0.0.'):  # Host initiating the scan
                        scan_activity[dst_ip].append(dst_port)

            except AttributeError:
                continue  # Skip packets without relevant fields

        capture.close()

        # Analyze scanning behavior
        for target_ip, ports in scan_activity.items():
            unique_ports = set(ports)

            # If too many unique ports are probed in a short time, flag it
            if len(unique_ports) > 10:  # Threshold for port scanning
                suspected_targets.add(target_ip)

    except Exception as e:
        print(f"[ERROR] Failed to process PCAP for {host_name}: {e}")
        sys.exit(1)

    return list(suspected_targets)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[ERROR] Host name argument missing.")
        sys.exit(1)

    host_name = sys.argv[1]
    suspected_targets = analyze_pcap(host_name)
    print(json.dumps(suspected_targets))
