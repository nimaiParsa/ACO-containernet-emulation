from pprint import pprint
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator
from mininet.log import setLogLevel

def main():
    setLogLevel('info')
    
    try:
        topo = ACOEmulator()
        
        env = RedTeamEnv(topo)
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
        
        subnet = input("Enter subnet to discover (e.g., 10.0.0.0/24): ")
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
        
        ip_addr = input("Enter a an IP Address to discover network services (e.g., 10.0.0.3): ")
        env.discover_network(ip_addr)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.plot_graph()
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        env.net.stop()
        
def test():
    setLogLevel('info')
    
    try:
        topo = ACOEmulator()
        
        env = RedTeamEnv(topo)
        
        print("\n\n")
        print("Initial Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        
        subnet = '10.0.0.0/24'
        env.discover_remote_systems(subnet)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        ip_addr = '10.0.0.3'
        env.discover_network(ip_addr)
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.drop_reverse_shell('user0', 'user2', 4444, 'hacker', '1234')
 
        print("Updated Observation:")
        pprint(env.get_observation())
        print("\n\n")
        
        env.execute_command_on('user2', command='cat /home/hacker/secret.txt')
        print("\n\n")
        
        env.plot_graph()
        
        
    
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        # Clean up the network
        env.net.stop()
    
if __name__ == '__main__':
    # main()
    test()