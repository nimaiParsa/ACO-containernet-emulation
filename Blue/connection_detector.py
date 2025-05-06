import time
from Blue.detector import Detector

class ConnectionDetector(Detector):
    def __init__(self, blue_mgr):
        """
        blue_mgr: instance of BlueObservationManager
        """
        self.blue_mgr = blue_mgr

    def detect(self, host):
        """
        Returns a list of IPs that the given host has active connections with.
        """
        connected_hosts = set()
        print(f"[INFO] Detecting connections for host {host.name} with IP {host.IP()}")
        # Step 1: Fetch network connections
        netstat_output = host.cmd('netstat -ant')
        # print(netstat_output)

        host_ips = host.IP()
        if isinstance(host_ips, str):
            host_ips = [host_ips]

        for line in netstat_output.splitlines():
            if 'ESTABLISHED' in line :
                parts = line.split()
                if len(parts) < 5:
                    continue

                local_addr = parts[3]
                remote_addr = parts[4]

                try:
                    local_ip, local_port = local_addr.rsplit(':', 1)
                    remote_ip, remote_port = remote_addr.rsplit(':', 1)
                except ValueError:
                    continue
                # Only consider outgoing or incoming connections
                # print(self.blue_mgr.get_observations()["hosts"])
                if self._ip_to_host(local_ip) and self._ip_to_host(remote_ip):
                    print(f"[DEBUG] Found new connection: {local_ip} -> {remote_ip}")
                    connected_hosts.add(remote_ip)

        for host in connected_hosts:
            self.record_connection(local_ip,remote_ip)

        return False
    
    def _ip_to_host(self, ip):
        """Helper function to find host name by IP from BlueObservationManager."""
        for host_name, data in self.blue_mgr.observations["hosts"].items():
            for known_ip in data["ips"]:  # data["ips"] is now a list
                if str(known_ip) == str(ip):
                    return host_name
        return None

    
    def record_connection(self, host_name, host):
        """
        Record the connection in the BlueObservationManager.
        """
        print(f"[INFO] Recording connection from {host_name} to {host}")
        self.blue_mgr.get_observations()["hosts"][self._ip_to_host(host_name)]["connection"].append(host)
        self.blue_mgr.get_observations()["hosts"][self._ip_to_host(host)]["connection"].append(host_name)