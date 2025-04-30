from pprint import pprint
import threading
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from mininet.log import setLogLevel
from aco import ACO

def main():
    setLogLevel('info')
    
    try:
        topo = ACO('scenario2.yml')
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
        
def test():
    setLogLevel('info')
    
    try:
        # topo = ACO('scenario1.yml')
        topo = ACOEmulator()
        
        env = RedTeamEnv(topo)
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        # print("sleep 10")
        # result = topo.net.get('user0').cmd('ls / ; sleep 10')
        # print(result)
        
        # return
        
        subnet = '10.0.0.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        ip_addr = '10.0.0.3'
        env.discover_network(ip_addr)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        env.drop_reverse_shell('user0', 'user2', 'hacker', '1234')
 
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.update_graph()
        # env.plot_graph()
        
        env.privilege_escalate('user2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        
    
        env.discover_network('10.0.1.2')
        # env.drop_reverse_shell('user2', 'op', 'root', 'root')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        # return
        env.drop_reverse_shell('user2', 'op', 'hacker', '1234')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.update_graph()
        # env.plot_graph()
        
        
        env.privilege_escalate('op')
        
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.update_graph()
        # env.plot_graph()
        
        env.discover_remote_systems('10.0.1.0/24')
        
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.update_graph()
        # env.plot_graph()
        
        env.impact('op')
        
        env.update_graph()
        # env.plot_graph()
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        env.net.stop()
        # topo.net.stop()
    
if __name__ == '__main__':
    main()
    # test()