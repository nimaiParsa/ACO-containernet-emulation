from pprint import pprint
import threading
from time import sleep
from Blue.blue_observation_manager import BlueObservationManager
from Blue.connection_detector import ConnectionDetector
from Blue.density_detector import DensityDetector
from Blue.port_scan_detector import PortScanDetector
from Blue.block_ip import BlockIPAction
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from mininet.log import setLogLevel
from aco import ACO
from mininet.cli import CLI


def main():
    setLogLevel('info')
    
    try:
        topo = ACOEmulator()
        env = RedTeamEnv(topo)
        blue_mgr = BlueObservationManager()
        density_detector = DensityDetector(blue_mgr, topo, threshold=5, time_window=5.0)
        port_scan_detector = PortScanDetector(blue_mgr,topo, threshold=5, time_window=5.0)
        connection_detector = ConnectionDetector(blue_mgr)
        block_ip_action = BlockIPAction(blue_mgr, topo)
        for host in topo.net.hosts:
            ip = host.IP()
            name = host.name
            blue_mgr.register_host(name, ip)
            print(f"[INFO] Registered host {name} with IP {ip}")
        
        user0 = topo.net.get('user0')
        user1 = topo.net.get('user1')

        print("--------------------------------------------------------")
        print("Initial Observation:")
        pprint(blue_mgr.get_observations())
        print("--------------------------------------------------------")
        
        ip_addr = '10.0.0.2'
        env.discover_network(ip_addr)
        user0.cmd("nmap 10.0.0.3")
        port_scan_detector.detect(env.net.get('user0'))
        print("---------------------------------------------------------")
        print("Updated Observation:")
        pprint(blue_mgr.get_observations())
        print("---------------------------------------------------------")

        user1.cmd("nc 10.0.0.2 4444 &")
        user0.cmd("nc -lvnp 4444 &")
        print("------------------------------------------------------------")
        connection_detector.detect(env.net.get('user0'))
        # print("Updated Blue Observatio
        # env.exploit('user1')
        # print("Updated Observation:")
        # pprint(env.get_observation())
        # print("\n\n")
        
        # env.update_graph("Performed Exploit on user1")n:")
        pprint(blue_mgr.get_observations())
        print("------------------------------------------------------------")

        #block IP   
        block_ip_action.execute(env.net.get('user0'))

        print("------------------------------------------------------------")
        print("Trying ping user1 from user0")
        print(user0.cmd("ping -c 4 10.0.0.2"))
        print("------------------------------------------------------------")

    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        topo.net.stop()
        
if __name__ == '__main__':
    # blue_test()
    main()
    # test()