import base64
import pyshark
import os
import time
from Blue.detector import Detector
import json
import re

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
        blue_host = self.topo.net.get('blue0')
        host_name = host.name
        host_ip = host.IP()
        result = blue_host.cmd(f"python3 /home/hacker/blue_scripts/pcap_processor.py {host_ip}")
        match = re.search(r'\[(.*?)\]', result)
        if match:
            print(f"Potential scan targets detected: {match.group(1)}")
            result = match.group(1)
        else:
            print(f"[ERROR] No valid content found in result for host {host_name}: {result}")
            return []

        print(result)

        suspected_targets = result.split(',')

        victim_host_names = [self._ip_to_host(ip) for ip in suspected_targets]
        self.record_port_scan(host.name, victim_host_names)
        # return victim_host_names
        return False
    
    def record_port_scan(self, src_host, victim_host_names):
        """
        Record a port scan event in the BlueObservationManager.
        :param src_host: Source host initiating the scan
        :param victim_host_names: List of victim host names being scanned
        """
        print(f"[DETECT] Port scan detected from {src_host} to {victim_host_names}!")
        for victim_host_name in victim_host_names:
            if victim_host_name in self.blue_mgr.observations["hosts"]:
                self.blue_mgr.get_observations()["hosts"][src_host]["port_scan_detected"].append(victim_host_name)


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
