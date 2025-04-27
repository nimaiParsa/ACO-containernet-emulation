from pprint import pprint
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from mininet.log import setLogLevel
from aco import ACO

def main():
    setLogLevel('info')
    
    try:
        topo = ACO('scenario1.yml')
        
        env = RedTeamEnv(topo)
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        print(topo.net.get('user0').cmd('ls'))
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        env.net.stop()
        
def test():
    setLogLevel('info')
    
    try:
        topo = ACO('scenario1.yml')
        # topo = ACOEmulator()
        
        env = RedTeamEnv(topo)
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        
        subnet = '10.0.0.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        ip_addr = '10.0.0.3'
        env.discover_network(ip_addr)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        env.drop_reverse_shell('user0', 'user2', 'hacker', '1234')
 
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
        
        env.privilege_escalate('user2')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        
    
        env.discover_network('10.0.1.2')
        # env.drop_reverse_shell('user2', 'op', 'root', 'root')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        # return
        env.drop_reverse_shell('user2', 'op', 'hacker', '1234')
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        env.plot_graph()
        
        
        env.privilege_escalate('op')
        
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
        
        env.discover_remote_systems('10.0.1.0/24')
        
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
        
        env.impact('op')
        
        env.plot_graph()
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        env.net.stop()
        # topo.net.stop()
    
if __name__ == '__main__':
    # main()
    test()