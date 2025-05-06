import yaml
import ipaddress
from mininet.net import Containernet
from mininet.node import Controller
from mininet.link import TCLink
from mininet.cli import CLI
import re

class ACO:
    def __init__(self, topo_file, base_network="10.0.0.0/16"):
        self.topo_file = topo_file
        self.devices = {}
        self.base_network = ipaddress.ip_network(base_network)
        # /24 subnets for switch-host groups
        self.subnet_gen = self.base_network.subnets(new_prefix=24)
        # /30 subnets for router-router links
        self.router_subnet_gen = self.base_network.subnets(new_prefix=30)

        self.switch_subnets = {}  # switch -> subnet
        self.device_ips = {}      # device -> {neighbor: cidr}
        self.net = Containernet(controller=Controller)
        self.node_objs = {}

    def load_topology(self):
        with open(self.topo_file, "r") as f:
            self.devices = yaml.safe_load(f)
        self._assign_subnets_and_ips()

    def _get_next_router_subnet(self):
        while True:
            subnet = next(self.router_subnet_gen)
            if not any(subnet.subnet_of(sw) for sw in self.switch_subnets.values()):
                return subnet

    def _assign_subnets_and_ips(self):
        # Phase 1: /24 per switch
        for device, info in self.devices.items():
            if info['type'].lower() == 'switch':
                subnet = next(self.subnet_gen)
                self.switch_subnets[device] = subnet
                hosts = subnet.hosts()
                for nbr in info['neighbors']:
                    if self.devices[nbr]['type'].lower() != 'switch':
                        ip = str(next(hosts))
                        self.device_ips.setdefault(nbr, {})[device] = f"{ip}/{subnet.prefixlen}"
        # Phase 2: /30 per router-router link
        seen = set()
        for dev, info in self.devices.items():
            if info['type'].lower() == 'router':
                for nbr in info['neighbors']:
                    if self.devices.get(nbr,{}).get('type','').lower() == 'router':
                        link = tuple(sorted([dev,nbr]))
                        if link in seen: continue
                        seen.add(link)
                        subnet = self._get_next_router_subnet()
                        h = subnet.hosts()
                        ip1, ip2 = str(next(h)), str(next(h))
                        self.device_ips.setdefault(dev, {})[nbr] = f"{ip1}/{subnet.prefixlen}"
                        self.device_ips.setdefault(nbr, {})[dev] = f"{ip2}/{subnet.prefixlen}"

    def build(self, interactive=False):
        print("[+] Loading topology")
        self.load_topology()
        self.net.addController('c0')
        # create nodes
        for dev, info in self.devices.items():
            t = info['type'].lower()
            if t in ['red','blue','op','router']:
                img = f"{t}_node" if t!='router' else 'blue_node'
                n = self.net.addDocker(dev, ip='0.0.0.0/24', dimage=img, privileged=True, dcmd='/bin/bash')
            else:
                n = self.net.addSwitch(dev)
            self.node_objs[dev] = n
        # links
        created = set()
        for dev, info in self.devices.items():
            for nbr in info['neighbors']:
                l = tuple(sorted((dev,nbr)))
                if l in created: continue
                self.net.addLink(self.node_objs[dev], self.node_objs[nbr], cls=TCLink, bw=10)
                created.add(l)
        self.net.start()
        # routers forwarding
        for dev, info in self.devices.items():
            if info['type'].lower()=='router':
                self.node_objs[dev].cmd('sysctl -w net.ipv4.ip_forward=1')
        # assign IPs
        for dev, info in self.devices.items():
            if info['type'].lower()=='switch': continue
            nobj = self.node_objs[dev]
            for nbr, cidr in self.device_ips.get(dev,{}).items():
                intf = self._find_interface_to(nobj,nbr)
                if intf:
                    ip,p = cidr.split('/')
                    nobj.setIP(ip,prefixLen=int(p),intf=intf)
            if info['type'].lower()!='router':
                # default via first router neighbor
                for nbr in info['neighbors']:
                    if self.devices[nbr]['type'].lower()=='router':
                        gw = self.device_ips[dev][nbr].split('/')[0]
                        nobj.cmd(f'ip route add default via {gw}')
                        break
        # resolve & run cmds
        self._resolve_commands()
        
        
        for dev, info in self.devices.items():
            for cmd in info.get('cmds',[]):
                print(cmd)
                if cmd.strip(): self.node_objs[dev].cmd(cmd)
        if interactive: CLI(self.net); self.net.stop()

    def _resolve_commands(self):
        # build mapping in YAML neighbor order
        mapping = {}
        for dev, info in self.devices.items():
            ips = []
            for nbr in info['neighbors']:
                if nbr in self.device_ips.get(dev,{}):
                    ips.append(self.device_ips[dev][nbr].split('/')[0])
            mapping[dev]=ips
        pat = re.compile(r'\$\{(\w+)(?:\[(\d+)\])?\}')
        for dev, info in self.devices.items():
            new=[]
            for cmd in info.get('cmds',[]):
                def r(m):
                    tgt=m.group(1); i=int(m.group(2)) if m.group(2) else 0
                    return mapping[tgt][i]
                new.append(pat.sub(r,cmd))
            self.devices[dev]['cmds']=new

    def _find_interface_to(self,node,nbr):
        for i in node.intfList():
            if i.link and nbr in str(i.link): return str(i)
        return None

    def stop(self): self.net.stop()
