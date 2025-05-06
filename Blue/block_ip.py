from Blue.action import Action

class BlockIPAction(Action):
    def __init__(self, blue_mgr,topo):
        self.blue_mgr = blue_mgr
        self.topo = topo

    def execute(self, host):
        """
        Blocks traffic from the specified IP address throughout the network.
        
        :param block_ip: IP address to block
        """
        block_ip = host.IP()
        print(f"[+] Blocking traffic from IP: {block_ip}")

        for host in self.blue_mgr.get_observations()["hosts"]:
            print("hello")
            host_node = self.topo.net.get(host)
            if host.startswith('r'):
                router = self.topo.net.get(host)
                router.cmd(f'iptables -A FORWARD -s {block_ip} -j DROP')
            elif host.startswith('s'):
                continue
            else:
                print(f"[+] Configuring host {host} to block IP: {block_ip}")
                host_node.cmd(f'iptables -A INPUT -s {block_ip} -j DROP')
                host_node.cmd(f'iptables -A OUTPUT -d {block_ip} -j DROP')


        print(f"[+] IP {block_ip} is now blocked across the network")