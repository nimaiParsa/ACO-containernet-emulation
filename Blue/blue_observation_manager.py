import time
import json
import ipaddress

class BlueObservationManager:
    def __init__(self):
        self.observations = {
            "hosts": {},
            "network_events": [],
            "timestamp": time.time()
        }

    def get_observations(self):
        return self.observations
    
    # -------------------
    # Host Management
    # -------------------
    def register_host(self, host_name, ip_addresses):
        """
        Register a host with one or multiple IP addresses.
        ip_addresses: str or list of str
        """
        if isinstance(ip_addresses, str):
            ip_addresses = [ip_addresses]  

        if host_name not in self.observations["hosts"]:
            self.observations["hosts"][host_name] = {
                "ips": [ipaddress.IPv4Address(ip) for ip in ip_addresses],
                "connection": [],
                "density": 0,
                "services_open": [],
                "reverse_shell_detected": False,
                "port_scan_detected": [],
                "recent_login_failures": 0,
                "isolated": False,
                "compromised": False  
            }

    def update_host_service(self, host_name, port):
        """Track open services (ports) on a host."""
        if host_name in self.observations["hosts"]:
            if port not in self.observations["hosts"][host_name]["services_open"]:
                self.observations["hosts"][host_name]["services_open"].append(port)

    def flag_compromised(self, host_name):
        """(Optional) Set host as compromised."""
        if host_name in self.observations["hosts"]:
            self.observations["hosts"][host_name]["compromised"] = True

    # -------------------
    # Traffic / Event Management
    # -------------------
    def record_connection_attempt(self, src_host, dst_ip, dst_port):
        """Record an outbound connection from a host."""
        dst_ip_obj = ipaddress.IPv4Address(dst_ip)
        dst_port = int(dst_port)
        
        if src_host in self.observations["hosts"]:
            self.observations["hosts"][src_host]["connections_out"].append((dst_ip_obj, dst_port))
            self.observations["network_events"].append({
                "type": "new_connection",
                "src": [str(ip) for ip in self.observations["hosts"][src_host]["ips"]],
                "dst": str(dst_ip_obj),
                "port": dst_port,
                "timestamp": time.time()
            })

    def record_reverse_shell(self, host_name):
        """Flag that a reverse shell was detected."""
        if host_name in self.observations["hosts"]:
            self.observations["hosts"][host_name]["reverse_shell_detected"] = True
            self.observations["network_events"].append({
                "type": "reverse_shell_detected",
                "host": host_name,
                "timestamp": time.time()
            })

    def record_port_scan(self, host_name, victim_ip):
        """Flag that a port scan was detected."""
        for name in victim_ip:
            if name in self.observations["hosts"]:
                self.observations["hosts"][host_name]["port_scan_detected"].append(name)
                self.observations["network_events"].append({
                    "type": "port_scan_detected",
                    "host": host_name,
                    "timestamp": time.time(),   
                })

    def record_login_failure(self, host_name):
        """Increment login failure count."""
        if host_name in self.observations["hosts"]:
            self.observations["hosts"][host_name]["recent_login_failures"] += 1

    def record_isolation(self, host_name):
        """Flag that a host was isolated by blue agent."""
        if host_name in self.observations["hosts"]:
            self.observations["hosts"][host_name]["isolated"] = True
            self.observations["network_events"].append({
                "type": "host_isolated",
                "host": host_name,
                "timestamp": time.time()
            })

    # -------------------
    # Utility Functions
    # -------------------
    def update_timestamp(self):
        """Update the global timestamp."""
        self.observations["timestamp"] = time.time()

    def save_to_file(self, filename="blue_observations.json"):
        """Dump observations to a file (JSON format)."""
        # Need to serialize IPs to strings
        to_save = json.loads(json.dumps(self.observations, default=str))
        with open(filename, "w") as f:
            json.dump(to_save, f, indent=2)

    def get_current_observations(self):
        """Return the current observation dictionary."""
        return self.observations

    def find_host_by_ip(self, search_ip):
        """Given an IP, find the host that owns it."""
        ip_obj = ipaddress.IPv4Address(search_ip)
        for host_name, host_data in self.observations["hosts"].items():
            if ip_obj in host_data["ips"]:
                return host_name
        return None
