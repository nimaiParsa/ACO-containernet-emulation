from mininet.net import Containernet
from mininet.node import Controller, Docker
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.term import makeTerm
import os

class CustomContainernetTopo:
    def __init__(self):
        self.net = Containernet(controller=Controller)

    def build(self):
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

        print("[+] Adding switches")
        s1 = self.net.addSwitch('s1')
        s2 = self.net.addSwitch('s2')

        print("[+] Creating links")
        for u in [user0, user1, user2]:
            self.net.addLink(u, s1, cls=TCLink, bw=10)

        self.net.addLink(op, s2, cls=TCLink, bw=10)
        self.net.addLink(blue, s2, cls=TCLink, bw=10)

        self.net.addLink(r1, s1, cls=TCLink, bw=10)
        self.net.addLink(r1, s2, cls=TCLink, bw=10)

        print("[+] Starting network")
        self.net.start()

        print("[+] Configuring router")
        r1.setIP('10.0.0.254/24', intf='r1-eth0')
        r1.setIP('10.0.1.254/24', intf='r1-eth1')
        r1.cmd('sysctl -w net.ipv4.ip_forward=1')

        print("[+] Fixing routes on hosts")
        # Remove Docker bridge route and set correct default
        for h in [user0, user1, user2]:
            h.cmd('ip route del default')
            h.cmd(f'ip route add default via 10.0.0.254 dev {h.name}-eth0')

        for h in [blue, op]:
            h.cmd('ip route del default')
            h.cmd(f'ip route add default via 10.0.1.254 dev {h.name}-eth0')

        print("[+] Adding iptables rules to router")
        r1.cmd('iptables -F')  # Flush any old rules
        r1.cmd('iptables -A FORWARD -s 10.0.0.1 -d 10.0.1.2 -j DROP')
        r1.cmd('iptables -A FORWARD -s 10.0.0.2 -d 10.0.1.2 -j DROP')
        r1.cmd('iptables -A FORWARD -s 10.0.0.3 -d 10.0.1.2 -j ACCEPT')

        print("[+] Starting services on op")
        op.cmd('apt-get update && apt-get install -y python3 && python3 -m http.server 8080 &')
        op.cmd('apt-get install -y openssh-server && service ssh start')

        print("[+] Storing op server info on user2")
        user2.cmd('mkdir -p /home/hacker && echo "op_server=10.0.1.2" > /home/hacker/secret.txt')

        print("[+] Launching terminals")
        makeTerm(user0, title="user0 (Red Agent)")
        makeTerm(user1, title="user1")
        makeTerm(user2, title="user2")

        CLI(self.net)
        self.net.stop()

    # def setup_weak_ssh_users(self, hostnames):
    #     for name in hostnames:
    #         print(f"[+] Setting up weak SSH user on {name}")
    #         host = self.net.get(name)
    #         host.cmd('/usr/sbin/sshd')
    #     print()

    # def setup_red_scripts(self, hostnames, local_script_dir='red_scripts', remote_dir='/home/hacker/red_scripts'):
    #     for name in hostnames:
    #         print(f"[+] Setting up red scripts for {name}")
    #         host = self.net.get(name)
    #         host.cmd(f'mkdir -p {remote_dir}')
    #         for script in os.listdir(local_script_dir):
    #             path = os.path.join(local_script_dir, script)
    #             if os.path.isfile(path):
    #                 with open(path, 'r') as f:
    #                     content = f.read().replace('$', '\\$')
    #                     host.cmd(f'echo "{content}" > {remote_dir}/{script}')
    #                     host.cmd(f'chmod +x {remote_dir}/{script}')

if __name__ == '__main__':
    setLogLevel('info')
    topo = CustomContainernetTopo()
    topo.build()
