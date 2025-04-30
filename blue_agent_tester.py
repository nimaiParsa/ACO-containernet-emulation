from pprint import pprint
import time
from Blue.blue_observation_manager import BlueObservationManager
from Blue.port_scan_detector import PortScanDetector
from Blue.connection_detector import ConnectionDetector
from Blue.block_ip import BlockIPAction
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from aco import ACO 
from mininet.net import Containernet
from time import sleep
from mininet.cli import CLI

class Action:
    def execute(self, host):
        """Override in subclass"""
        raise NotImplementedError()

if __name__ == "__main__":
    
    try:
        topo = ACO("scenario2.yml")
        env_red = RedTeamEnv(topo)
    
        blue_mgr = BlueObservationManager()
        port_scan_detector = PortScanDetector(blue_mgr,topo, threshold=5, time_window=5.0)
        connection_detector = ConnectionDetector(blue_mgr)
        detection_modules = [port_scan_detector]

        for host in topo.net.hosts:
            ip = host.IP()
            name = host.name
            blue_mgr.register_host(name, ip)
            print(f"[INFO] Registered host {name} with IP {ip}")

           
        ip_addr = '10.0.0.3'

        user0 = topo.net.get('user0')
        user1 = topo.net.get('user1')
        user2 = topo.net.get('user2')
        blue0 = topo.net.get('blue0')


        r1 = topo.net.get('r1')
        s1 = topo.net.get('s1')
       
        print(user0.cmd("nmap 10.0.0.3"))
        print(blue0.cmd("ls -lh /home/hacker/blue_scripts/"))
        print(blue0.cmd("python3 /home/hacker/blue_scripts/pcap_processor.py 10.0.0.2"))


    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        topo.net.stop()
        print("[INFO] Network stopped.")