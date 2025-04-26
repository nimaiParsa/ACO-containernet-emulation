import time
from Blue.detector import Detector

class PortScanDetector(Detector):
    def __init__(self, blue_mgr, threshold=10, time_window=5.0):
        """
        blue_mgr: instance of BlueObservationManager
        threshold: number of distinct ports in time window to trigger scan detection
        time_window: seconds within which connections must occur
        """
        self.blue_mgr = blue_mgr
        self.threshold = threshold
        self.time_window = time_window
        self.connection_logs = {}  # host -> list of (timestamp, dst_port)

    def detect(self, host):
        """Detect port scanning behavior by analyzing active connections on the host."""
        now = time.time()

        # Step 1: Fetch network connections from the host
        netstat_output = host.cmd('netstat -ant')
        
        # Step 2: Parse connections
        host_ips = host.IP()  # It may be a single IP, but BlueObservationManager tracks multiple IPs
        if isinstance(host_ips, str):
            host_ips = [host_ips]

        for line in netstat_output.splitlines():
            if 'SYN_RECV' in line:  # Only track SYN_RECV (half-open) connections
                parts = line.split()
                if len(parts) < 5:
                    continue  # skip malformed lines

                local_addr = parts[3]
                remote_addr = parts[4]

                try:
                    local_ip, local_port = local_addr.rsplit(':', 1)
                    remote_ip, remote_port = remote_addr.rsplit(':', 1)
                    local_port = int(local_port)
                    remote_port = int(remote_port)
                except ValueError:
                    continue  # skip badly formatted lines

                # Step 3: Check if this connection is incoming to this host
                if local_ip in host_ips:
                    attacker_ip = remote_ip
                    dst_port = local_port

                    attacker_name = self._ip_to_host(attacker_ip)
                    if attacker_name:
                        self.record_connection(attacker_name, dst_port)

        return False  # detect() always returns False because detection is logged internally

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
