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

# def blue_test():
#     try:
#         topo = ACO('scenario2.yml')
#         env = RedTeamEnv(topo)
        
#         blue_mgr = BlueObservationManager()
#         density_detector = DensityDetector(blue_mgr, topo, threshold=5, time_window=5.0)
#         port_scan_detector = PortScanDetector(blue_mgr,topo, threshold=5, time_window=5.0)
#         connection_detector = ConnectionDetector(blue_mgr)
#         blockAction = BlockIPAction(blue_mgr, topo)
        
#         users = [topo.net.get(f'user{i}') for i in range(6)]
        
#         # Launch for ploting the graph
#         threading.Thread(target=env.start_plot_loop, daemon=True).start()
#         env.update_graph()
        
#         print("\n\n")
#         print("Initial Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Initial Observation")
#         sleep(15)
        
#         subnet = '10.0.0.0/24'
#         env.discover_remote_systems(subnet)
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Remote Systems on subnet: 10.0.0.0/24")
#         # sleep(4)
        
#         ip_addr = '10.0.0.3'
#         env.discover_network(ip_addr)
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on user1")
#         sleep(4)
        
#         port_scan_detector.detect(users[0])
#         # ports = blue_mgr.get_observations()["hosts"]['user0']["port_scan_detected"]
#         env.update_graph(f"Performed Port Scan Detection on user0, Port Scan on {"user0"} Detected")
#         sleep(4)
        
#         env.exploit('user1')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
        
#         env.update_graph("Performed Exploit on user1")
#         sleep(4)
        
#         env.privilege_escalate('user1')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on user1")
#         # sleep(4)
        
        
#         env.discover_network('10.0.0.4')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on user2")
        
        
            
        
        
#         env.exploit('user2')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Exploit on user2")
#         sleep(4)
        
#         env.privilege_escalate('user2')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on user2")
#         sleep(4)
#         # sleep(4)

#         connections = connection_detector.detect(users[0])
        
#         # connections = blue_mgr.get_observations()["hosts"]['user0']["connections"]
#         env.update_graph(f"Performed Connection Detection on user0, Connections {connections} Detected")
#         sleep(2)
        
#         env.discover_network('10.0.1.2')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on user3")
#         sleep(4)
        
#         env.exploit('user3')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Exploit on user3")
#         sleep(4)
        
#         env.privilege_escalate('user3')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on user3")
#         sleep(4)
        
#         # block user 3
#         blockAction.execute(users[3])
        
#         # CLI(env.net)
        
#         subnet = '10.0.1.0/24'
#         result = env.discover_remote_systems(subnet, method="ping")
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph(f"Performed Discover Remote Systems on subnet: 10.0.1.0/24 failed")
#         # sleep(4)
       
        
#         env.discover_network('10.0.1.3')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on user4")
        
#         env.exploit('user4')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Exploit on user4")
#         sleep(4)
        
       
        
#         env.privilege_escalate('user4')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on user4")
        
#         env.discover_network('10.0.2.2')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on user5")
        
#         env.exploit('user5')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Exploit on user5")
#         sleep(4)
        
#         env.privilege_escalate('user5')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on user5")
#         sleep(4)
        
#         subnet = '10.0.2.0/24'
#         env.discover_remote_systems(subnet)
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Remote Systems on subnet: 10.0.2.0/24")
        
#         env.discover_network('10.0.2.3')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Discover Network on op_server")
 
#         env.exploit('op')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Exploit on op_server")
#         sleep(4)
        
#         env.privilege_escalate('op')
#         print("Updated Observation:")
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Privilege Escalate on op_server")
#         sleep(4)
        
#         env.impact('op')
#         pprint(env.get_observation())
#         print("\n\n")
#         env.update_graph("Performed Impact on op_server")
#         sleep(4)
    
#     except Exception as e:
#         print(f"[!] Error: {e}")
    
#     finally:
#         # Clean up the network
#         topo.net.stop()

def main():
    setLogLevel('info')
    
    try:
        topo = ACO('scenarios/scenario2.yml')
        env = RedTeamEnv(topo)
        
        # Launch for ploting the graph
        threading.Thread(target=env.start_plot_loop, daemon=True).start()
        env.update_graph()
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Initial Observation")
        
        subnet = '10.0.0.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Remote Systems on subnet: 10.0.0.0/24")
        
        ip_addr = '10.0.0.3'
        env.discover_network(ip_addr)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on user1")
        
        env.exploit('user1')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.update_graph("Performed Exploit on user1")
        
        env.privilege_escalate('user1')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on user1")
        
        
        env.discover_network('10.0.0.4')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on user2")
        
        env.exploit('user2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Exploit on user2")
        
        env.privilege_escalate('user2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on user2")
        
        env.discover_network('10.0.1.2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on user3")
        
        env.exploit('user3')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Exploit on user3")
        
        env.privilege_escalate('user3')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on user3")
        
        subnet = '10.0.1.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Remote Systems on subnet: 10.0.1.0/24")
        
        env.discover_network('10.0.1.3')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on user4")
        
        env.exploit('user4')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Exploit on user4")
        
        env.privilege_escalate('user4')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on user4")
        
        env.discover_network('10.0.2.2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on user5")
        
        env.exploit('user5')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Exploit on user5")
        
        env.privilege_escalate('user5')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on user5")
        
        subnet = '10.0.2.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Remote Systems on subnet: 10.0.2.0/24")
        
        env.discover_network('10.0.2.3')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Discover Network on op_server")
 
        env.exploit('op')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Exploit on op_server")
        
        env.privilege_escalate('op')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Privilege Escalate on op_server")
        
        env.impact('op')
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph("Performed Impact on op_server")
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        topo.net.stop()
        
if __name__ == '__main__':
    # blue_test()
    main()
    # test()