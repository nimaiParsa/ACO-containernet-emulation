import yaml
import ipaddress
from mininet.net import Containernet
from mininet.node import Controller
from mininet.link import TCLink
from mininet.cli import CLI

class ACO:
    def __init__(self, topo_file, base_network="10.0.0.0/16"):
        self.topo_file = topo_file
        self.devices = {}
        self.base_network = ipaddress.ip_network(base_network)
        self.subnet_gen = self.base_network.subnets(new_prefix=24)
        self.link_ips = {}
        self.net = Containernet(controller=Controller)
        self.node_objs = {}

    def load_topology(self):
        with open(self.topo_file, "r") as f:
            self.devices = yaml.safe_load(f)
        self._assign_ips()

    def _assign_ips(self):
        assigned_links = set()
        for device, info in self.devices.items():
            for neighbor in info.get("neighbors", []):
                if (neighbor, device) in assigned_links:
                    continue
                subnet = next(self.subnet_gen)
                hosts = subnet.hosts()
                ip1 = str(next(hosts))
                ip2 = str(next(hosts))
                self.link_ips[(device, neighbor)] = (ip1, ip2)
                self.link_ips[(neighbor, device)] = (ip2, ip1)
                assigned_links.add((device, neighbor))

    def build(self, interactive=False):
        print("[+] Loading topology from YAML")
        self.load_topology()

        print("[+] Adding controller")
        self.net.addController('c0')

        print("[+] Creating nodes")
        for device, info in self.devices.items():
            dtype = info['type']
            cmds = info.get('cmds', [])

            if dtype.lower() in ["red", "blue", "op", "router"]:
                if dtype.lower() == "blue" or dtype.lower() == "router":
                    image = "blue_node"
                elif dtype.lower() == "op":
                    image = "op_node"
                else:
                    image = "red_node"
                node = self.net.addDocker(
                    device,
                    ip="0.0.0.0",  # Will be set after link creation
                    dimage=image,
                    privileged=True
                )
            elif dtype.lower() == "switch":
                node = self.net.addSwitch(device)
            else:
                raise Exception(f"[!] Unknown device type: {dtype}")

            self.node_objs[device] = node

        print("[+] Creating links")
        created_links = set()
        for device, info in self.devices.items():
            for neighbor in info.get('neighbors', []):
                if (neighbor, device) in created_links:
                    continue
                node1 = self.node_objs[device]
                node2 = self.node_objs[neighbor]
                self.net.addLink(node1, node2, cls=TCLink, bw=10)
                created_links.add((device, neighbor))

        print("[+] Starting network")
        self.net.start()

        print("[+] Assigning IP addresses")
        for (device, neighbor), (ip1, ip2) in self.link_ips.items():
            dev_node = self.node_objs[device]
            if self.devices[device]['type'].lower() == "switch":
                continue  # Switches don't need IPs
            intf = self._find_interface_to(dev_node, neighbor)
            if intf:
                dev_node.setIP(ip1, intf=intf)
            else:
                print(f"[!] Warning: Could not find interface from {device} to {neighbor}")

        print("[+] Running initial commands")
        for device, info in self.devices.items():
            cmds = info.get('cmds', [])
            node = self.node_objs[device]
            for cmd in cmds:
                if cmd.strip():
                    node.cmd(cmd)

        if interactive:
            print("[+] Starting interactive mode")
            CLI(self.net)
            self.net.stop()

    def _find_interface_to(self, node, neighbor_name):
        """Find the interface name towards a neighbor node."""
        for intf in node.intfList():
            if intf.link and neighbor_name in str(intf.link):
                return str(intf)
        return None

    def stop(self):
        print("[+] Stopping network")
        self.net.stop()
