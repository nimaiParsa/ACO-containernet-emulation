import base64
import pyshark
import os
import time
from Blue.detector import Detector
import json

class PortScanDetector(Detector):
    def __init__(self, blue_mgr,topo, threshold=10, time_window=5.0):
        """
        blue_mgr: instance of BlueObservationManager
        pcap_directory: directory where the pcap files are stored
        threshold: number of distinct ports in time window to trigger scan detection
        time_window: seconds within which connections must occur
        """
        self.blue_mgr = blue_mgr
        self.pcap_directory = "/home/captures/"
        self.threshold = threshold
        self.time_window = time_window
        self.topo = topo

    def detect(self, host):
        """
        Detect if the given host is scanning many ports on other hosts.
        If yes, return a list of IPs being scanned.
        """
        now = time.time()
        # Gather basic connection information (already existing code)

        # Step 1: Run PCAP processing in the Blue container
        blue_host = self.topo.net.get("blue0")
        host_name = host
        result = blue_host.cmd(f"python3 /home/hacker/blue_scripts/pcap_processor.py {host_name}")
        print(result)

        try:
            suspected_targets = json.loads(result)
        except json.JSONDecodeError:
            print(f"[ERROR] Failed to parse result from PCAP processor for host {host_name}: {result}")
            return []

        # Update the BlueObservationManager with the detected targets
        victim_host_names = [self._ip_to_host(ip) for ip in suspected_targets]
        self.blue_mgr.record_port_scan(host.name, victim_host_names)
        return victim_host_names
        return False

    def _analyze_capture(self, capture):
        """
        Analyze the PCAP capture to detect scanning behavior.
        """
        scanned_targets = {}  # dst_ip -> list of (timestamp, dst_port)
        suspected_ips = []
        now = time.time()

        for packet in capture:
            if hasattr(packet, 'tcp') and hasattr(packet, 'ip'):
                dst_ip = packet.ip.dst
                dst_port = int(packet.tcp.dstport)
                timestamp = float(packet.sniff_timestamp)

                if dst_ip not in scanned_targets:
                    scanned_targets[dst_ip] = []
                scanned_targets[dst_ip].append((timestamp, dst_port))

        for target_ip, attempts in scanned_targets.items():
            # Filter attempts within the time window
            recent_attempts = [(t, port) for (t, port) in attempts if now - t <= self.time_window]
            unique_ports = set(port for (t, port) in recent_attempts)

            if len(unique_ports) >= self.threshold:
                suspected_ips.append(target_ip)

        return suspected_ips


    def record_connection(self, src_host, dst_port):
        """Record an outbound connection from src_host to dst_port."""
        now = time.time()
        if src_host not in self.connection_logs:
            self.connection_logs[src_host] = []

        self.connection_logs[src_host].append((now, dst_port))
        self._cleanup_old_connections(src_host, now)
        self._check_for_port_scan(src_host)

    def _cleanup_old_connections(self, src_host, now):
        """Remove old connections outside of time window."""
        self.connection_logs[src_host] = [
            (timestamp, port) for (timestamp, port) in self.connection_logs[src_host]
            if now - timestamp <= self.time_window
        ]

    def _check_for_port_scan(self, src_host):
        """Check if the current connection pattern suggests a port scan."""
        if src_host not in self.connection_logs:
            return

        recent_ports = [port for (_, port) in self.connection_logs[src_host]]
        unique_ports = set(recent_ports)

        if len(unique_ports) >= self.threshold:
            print(f"[DETECT] Port scan detected from {src_host}!")
            self.blue_mgr.record_port_scan(src_host)
            # Clear after detection to prevent duplicate alerts
            self.connection_logs[src_host] = []

    def _ip_to_host(self, ip):
        """Helper function to find host name by IP from BlueObservationManager."""
        for host_name, data in self.blue_mgr.observations["hosts"].items():
            for known_ip in data["ips"]:  # data["ips"] is now a list
                if str(known_ip) == str(ip):
                    return host_name
        return None
