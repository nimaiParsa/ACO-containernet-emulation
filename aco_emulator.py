from mininet.net import Containernet
from mininet.node import Controller, Docker, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.term import makeTerm
# import os

class ACOEmulator:
    def __init__(self):
        self.net = Containernet(controller=Controller)

    def build(self, interactive: bool=False):
        print("[+] Adding controller")
        self.net.addController('c0')

        print("[+] Adding Docker containers")
        # Subnet 1
        user0 = self.net.addDocker('user0', ip='10.0.0.1/24', dimage="red_node", privileged=True)
        user1 = self.net.addDocker('user1', ip='10.0.0.2/24', dimage="red_node", privileged=True)
        user2 = self.net.addDocker('user2', ip='10.0.0.3/24', dimage="red_node", privileged=True)
        blue0 = self.net.addDocker('blue0', ip='10.0.0.4/24', dimage="blue_node", privileged=True)

        # Subnet 2
        blue = self.net.addDocker('blue', ip='10.0.1.1/24', dimage="blue_node", privileged=True)
        op = self.net.addDocker('op', ip='10.0.1.2/24', dimage="op_node", privileged=True)

        # Router
        r1 = self.net.addDocker('r1', ip='0.0.0.0', dimage="blue_node", privileged=True)

        print("[+] Adding switches\n\n")
        s1 = self.net.addSwitch('s1', cls = OVSSwitch)
        s2 = self.net.addSwitch('s2', cls = OVSSwitch)

        print("[+] Creating links\n\n")
        for u in [user0, user1, user2, blue0]:
            self.net.addLink(u, s1, cls=TCLink, bw=10)

        self.net.addLink(op, s2, cls=TCLink, bw=10)
        self.net.addLink(blue, s2, cls=TCLink, bw=10)

        self.net.addLink(r1, s1, cls=TCLink, bw=10)
        self.net.addLink(r1, s2, cls=TCLink, bw=10)

        print("[+] Starting network\n\n")
        self.net.start()

        print("[+] Configuring router\n\n")
        r1.setIP('10.0.0.254/24', intf='r1-eth0')
        r1.setIP('10.0.1.254/24', intf='r1-eth1')
        r1.cmd('sysctl -w net.ipv4.ip_forward=1')

        print("[+] Fixing routes on hosts\n\n")
        # Remove Docker bridge route and set correct default
        for h in [user0, user1, user2]:
            h.cmd('ip route del default')
            h.cmd(f'ip route add default via 10.0.0.254 dev {h.name}-eth0')

        for h in [blue, op]:
            h.cmd('ip route del default')
            h.cmd(f'ip route add default via 10.0.1.254 dev {h.name}-eth0')

        print("[+] Adding iptables rules to router\n\n")
        r1.cmd('iptables -F')  # Flush any old rules
        r1.cmd('iptables -A FORWARD -s 10.0.0.1 -d 10.0.1.2 -j DROP')
        r1.cmd('iptables -A FORWARD -s 10.0.0.2 -d 10.0.1.2 -j DROP')
        r1.cmd('iptables -A FORWARD -s 10.0.0.3 -d 10.0.1.2 -j ACCEPT')

        print("[+] Starting services on op\n\n")
        op.cmd('./home/start_services.sh')

        print("[+] Starting services on users\n\n")
        user0.cmd('service ssh start')
        user1.cmd('service ssh start')
        user2.cmd('service ssh start')
        blue0.cmd('service ssh start')
        print("[+] Starting tcpdump on blue0 to monitor users\n\n")
        capture_dir = "/home/captures"

        blue0.cmd(f"mkdir -p {capture_dir}")
        blue_port = "s1-eth4"

        # Set up mirroring
        mirror_cmd = (
            f"ovs-vsctl -- --id=@p get Port {blue_port} "
            f"-- --id=@m create Mirror name=blueMirror select-all=true output-port=@p "
            f"-- set Bridge s1 mirrors=@m"
        )
        s1.cmd(mirror_cmd)

        # Enable promiscuous mode and start tcpdump
        blue0.cmd("tcpdump -i blue0-eth0 -w /home/hacker/blue_scripts/mirrored_traffic.pcap &")
        
        for user in [user0, user1, user2]:
            user_ip = user.IP()
            pcap_file = f"{capture_dir}/{user.name}.pcap"
            # Capture only packets from that specific user's IP

            blue0.cmd(f"tcpdump -i blue0-eth0 host {user_ip} -w {pcap_file} &")

        print("[+] Storing op server info on user2")
        user2.cmd('mkdir -p /home/hacker && echo "op=10.0.1.2" > /home/hacker/secret.txt')

        if interactive:
            print("[+] Starting interactive mode")
            print("[+] Launching terminals")
            makeTerm(user0, title="user0 (Red Agent)")
            makeTerm(user1, title="user1")
            makeTerm(user2, title="user2")
            makeTerm(blue0, title="blue0")

            CLI(self.net)
            self.net.stop()

    def stop(self):
        print("[+] Stopping network")
        self.net.stop()
        