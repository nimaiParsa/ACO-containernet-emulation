from mininet.net import Containernet
from mininet.node import Controller, Docker
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.term import makeTerm
# import os

class ACOEmulator:
    def __init__(self):
        self.net = Containernet(controller=Controller)

    def build(self, interactive:bool=False):
        print("[+] Adding controller")
        self.net.addController('c0')

        print("[+] Adding Docker containers")
        # Subnet 1
        user0 = self.net.addDocker('user0', ip='10.0.0.1/24', dimage="red_node", privileged=True)
        user1 = self.net.addDocker('user1', ip='10.0.0.2/24', dimage="red_node", privileged=True)
        user2 = self.net.addDocker('user2', ip='10.0.0.3/24', dimage="red_node", privileged=True)

        # Subnet 2
        blue = self.net.addDocker('blue', ip='10.0.1.1/24', dimage="blue_node", privileged=True)
        op = self.net.addDocker('op', ip='10.0.1.2/24', dimage="op_node", privileged=True)

        # Router
        r1 = self.net.addDocker('r1', ip='0.0.0.0', dimage="blue_node", privileged=True)

        print("[+] Adding switches\n\n")
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')

        print("[+] Creating links\n\n")
        for u in [user0, user1, user2]:
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

        print("[+] Storing op server info on user2")
        user2.cmd('mkdir -p /home/hacker && echo "op_server=10.0.1.2" > /home/hacker/secret.txt')

        if interactive:
            print("[+] Starting interactive mode")
            print("[+] Launching terminals")
            makeTerm(user0, title="user0 (Red Agent)")
            makeTerm(user1, title="user1")
            makeTerm(user2, title="user2")

            CLI(self.net)
            self.net.stop()

    def stop(self):
        print("[+] Stopping network")
        self.net.stop()
        