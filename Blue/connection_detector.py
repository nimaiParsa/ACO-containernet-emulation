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
        Return a list of IPs that the given host has active connections with.
        """
        connected_hosts = set()

        # Step 1: Fetch network connections
        netstat_output = host.cmd('netstat -ant')

        host_ips = host.IP()
        if isinstance(host_ips, str):
            host_ips = [host_ips]

        for line in netstat_output.splitlines():
            if 'ESTABLISHED' in line or 'SYN_SENT' in line or 'SYN_RECV' in line:
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
                if local_ip in host_ips or remote_ip in host_ips:
                    # Add the "other side" IP
                    if local_ip in host_ips:
                        connected_hosts.add(remote_ip)
                    else:
                        connected_hosts.add(local_ip)

        for host in connected_hosts:
            host_name = self._ip_to_host(host)
            if host in self.blue_mgr.get_observations()["hosts"]:
                self.blue_mgr.get_observations()["hosts"][host]["connection"].append(host_name)

        return False
    
    def _ip_to_host(self, ip):
        """
        Convert an IP address to a host name.
        """
        for host_name, host_info in self.blue_mgr.get_observations()["hosts"].items():
            if ip in host_info["ips"]:
                return host_name
        return None