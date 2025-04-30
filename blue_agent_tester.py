from pprint import pprint
import time
from Blue.blue_observation_manager import BlueObservationManager
from Blue.port_scan_detector import PortScanDetector
from Blue.connection_detector import ConnectionDetector
from Blue.block_ip import BlockIPAction
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from mininet.net import Containernet
from time import sleep
from mininet.cli import CLI

class Action:
    def execute(self, host):
        """Override in subclass"""
        raise NotImplementedError()

class BlockHostAction(Action):
    def __init__(self, blue_mgr):
        self.blue_mgr = blue_mgr

    def execute(self, host):
        print(f"[ACTION] Blocking host {host}")
        # Here you would implement the actual blocking logic
        # For example, using iptables or a firewall API
        # self.blue_mgr.block_host(host)

# ------------------------------
# Blue Agent Core
# ------------------------------

class BlueAgent:
    def __init__(self, detection_modules, policy_fn, response_map, topo):
        self.detection_modules = detection_modules
        self.policy_fn = policy_fn
        self.response_map = response_map
        self.topo = topo

    def monitor(self, hosts):
        while True:
            for h in hosts:
                
                host = self.topo.get_host(h)
                
                if not host:
                    print(f"[ERROR] Host {h} not found in topology.")
                    continue
                
                detections = {}
                for detector in self.detection_modules:
                    detection_name = type(detector).__name__
                    detections[detection_name] = detector.detect(host)

                action_name = self.policy_fn(detections)
                if action_name:
                    action = self.response_map.get(action_name)
                    if action:
                        action.execute(host)
                        
            

            time.sleep(3)  # Monitor interval




def policy_fn(detections):
    # Simple policy: if port scan is detected, block attacker
    for det_name, detected in detections.items():
        if detected:
            return 'block_attacker'
    return None

if __name__ == "__main__":
    
    try:
        topo = ACOEmulator()
        env_red = RedTeamEnv(topo)
    
        blue_mgr = BlueObservationManager()
        port_scan_detector = PortScanDetector(blue_mgr,topo, threshold=5, time_window=5.0)
        connection_detector = ConnectionDetector(blue_mgr)
        detection_modules = [port_scan_detector]

        # response_map = {
        #     'block_attacker': BlockHostAction(blue_mgr)  # Some action you define
        # }


        # topo.build(interactive=False)

        for host in topo.net.hosts:
            ip = host.IP()
            name = host.name
            blue_mgr.register_host(name, ip)
            print(f"[INFO] Registered host {name} with IP {ip}")

            # monitor = BlueAgent(detection_modules, policy_fn, response_map, topo)
            # monitor.monitor(hosts=['user0'])
            

        # port_scan_detector.detect(topo.net.get('user0'))

        # pprint(blue_mgr.get_observations())

        ip_addr = '10.0.0.3'
        # env_red.discover_remote_systems('10.0.0.1/24')
        # env_red.discover_network(ip_addr)

        user0 = topo.net.get('user0')
        user1 = topo.net.get('user1')
        user2 = topo.net.get('user2')
        blue0 = topo.net.get('blue0')

        # pprint(env_red.observations)
        # print(topo.net.get('blue0').cmd('cd /home/captures && ls'))
        # port_scan_detector.detect(topo.net.get('user0'))
        # pprint(blue_mgr.get_observations())

        # block_ip_action = BlockIPAction(blue_mgr, topo)

        # block_ip_action.execute(topo.net.get('user0'))  
        # print(user1.cmd('tcpdump -i user1-eth0 icmp -n'))

        r1 = topo.net.get('r1')
        s1 = topo.net.get('s1')
        # print(blue0.intf())
        # print(blue0.cmd('ip addr'))

        # print(s1.cmd("ovs-vsctl list-ports s1"))

        # print(s1.cmd("ovs-vsctl show"))
        
        blue0.cmd("ip link set eth0 promisc on")

        # Wait for tcpdump to initialize

        # print(s1.cmd('ovs-vsctl list Port'))
        # print(s1.cmd('ovs-vsctl list Interface'))

        # print(s1.cmd('ovs-vsctl list Mirror'))


        # print(user1.cmd('iptables -L -v -n'))
        # print(user0.cmd('ping -c 4 10.0.0.2'))

        # user1.cmd('nc -lvnp 4444 &')
        # user2.cmd('nc 10.0.0.2 4444 &')
        # print(user1.cmd('netstat -at'))

        # pprint(blue_mgr.get_observations()["hosts"])
              
        # connection_detector.detect(topo.net.get('user0'))



        # pprint(blue_mgr.get_observations())

        # connection_detector.detect(topo.net.get('user0'))

        # pprint(blue_mgr.get_observations())
        s1.cmd('mkdir /home/captures')
        # s1.cmd("tcpdump -i s1-eth1 -w /home/captures/s1-eth1.pcap &")
        # s1.cmd("tcpdump -i s1-eth2 -w /home/captures/s1-eth2.pcap &")
        # s1.cmd("tcpdump -i s1-eth3 -w /home/captures/s1-eth3.pcap &")
        # s1.cmd("tcpdump -i s1-eth4 -w /home/captures/s1-eth4.pcap &")
        # s1.cmd("tcpdump -i s1-eth5 -w /home/captures/s1-eth5.pcap &")


        # # On the switch (s1)
        # s1.cmd("tcpdump -i s1-eth1 -U -w - | nc 10.0.0.100 9001 &")
        # s1.cmd("tcpdump -i s1-eth2 -U -w - | nc 10.0.0.100 9002 &")
        # s1.cmd("tcpdump -i s1-eth3 -U -w - | nc 10.0.0.100 9003 &")
        # s1.cmd("tcpdump -i s1-eth4 -U -w - | nc 10.0.0.100 9004 &")
        # s1.cmd("tcpdump -i s1-eth5 -U -w - | nc 10.0.0.100 9005 &")


        # blue0.cmd("nc -l -p 9001 > /home/captures/user0.pcap &")
        # blue0.cmd("nc -l -p 9002 > /home/captures/user1.pcap &")
        # blue0.cmd("nc -l -p 9003 > /home/captures/user2.pcap &")
        # blue0.cmd("nc -l -p 9004 > /home/captures/user3.pcap &")
        # blue0.cmd("nc -l -p 9005 > /home/captures/user4.pcap &")

        # On the switch
        # s1.cmd("tcpdump -i s1-eth1 -U -w - | nc 10.0.0.100 9001 &")
        # s1.cmd("tcpdump -i s1-eth2 -U -w - | nc 10.0.0.100 9002 &")
        # s1.cmd("tcpdump -i s1-eth3 -U -w - | nc 10.0.0.100 9003 &")
        # s1.cmd("tcpdump -i s1-eth4 -U -w - | nc 10.0.0.100 9004 &")
        # s1.cmd("tcpdump -i s1-eth5 -U -w - | nc 10.0.0.100 9005 &")
        # user0.cmd("mkdir -p /home/captures")
        # user0.cmd("ip link set eth0 promisc on")

# Start tcpdump in background on user0's eth0
        
        # command = "tcpdump -i user0-eth0 -w /home/captures/user0.pcap"
        # result = user0.popen(["/bin/bash", "-c", command])
        # result = result.communicate()[0]

        # result = result.decode('utf-8')

        # user0.cmd("tcpdump -i user0-eth0 -w /home/captures/user0.pcap &")




        # sleep(1)

        # # Generate traffic
        # print(user0.cmd("ping -c 4 10.0.0.2"))
        # print(user0.cmd("ping -c 4 10.0.0.3"))

        # # Wait for tcpdump to capture traffic
        # sleep(5)

        # # On blue0
        # blue0.cmd("mkdir -p /home/captures")
        # blue0.cmd("nc -l -p 9001 > /home/captures/s1-eth1.pcap &")
        # blue0.cmd("nc -l -p 9002 > /home/captures/s1-eth2.pcap &")
        # blue0.cmd("nc -l -p 9003 > /home/captures/s1-eth3.pcap &")
        # blue0.cmd("nc -l -p 9004 > /home/captures/s1-eth4.pcap &")
        # blue0.cmd("nc -l -p 9005 > /home/captures/s1-eth5.pcap &")
        
        # CLI(topo.net)

        # print(blue0.cmd('tcpdump -r /home/captures/mirrored_traffic.pcap'))
        # print(user0.cmd("ls -l /home/captures/"))
        # # for i in range(1, 6):
        # #     s1.cmd(f"scp /home/captures/s1-eth{i}.pcap {blue0.IP()}:/home/captures/")

        # sleep(5)
        # print(blue0.cmd("ls -lh /home/captures/"))

        print(user0.cmd("nmap 10.0.0.2"))
        print(blue0.cmd("ls -lh /home/hacker/blue_scripts/"))
        print(blue0.cmd("python3 /home/hacker/blue_scripts/pcap_processor.py"))



# repeat for all interfaces you care about

























    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        topo.net.stop()
        print("[INFO] Network stopped.")