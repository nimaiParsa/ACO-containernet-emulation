from pprint import pprint
import time
from Blue.blue_observation_manager import BlueObservationManager
from Blue.port_scan_detector import PortScanDetector
from Blue.connection_detector import ConnectionDetector
from red_agent_env import RedTeamEnv
from aco_emulator import ACOEmulator

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
            

        port_scan_detector.detect(topo.net.get('user0'))

        # pprint(blue_mgr.get_observations())

        ip_addr = '10.0.0.3'
        env_red.discover_remote_systems('10.0.0.1/24')
        env_red.discover_network(ip_addr)

        # pprint(env_red.observations)
        # print(topo.net.get('blue0').cmd('cd /home/captures && ls'))
        port_scan_detector.detect(topo.net.get('user0'))

        # pprint(blue_mgr.get_observations())

        # connection_detector.detect(topo.net.get('user0'))

        # pprint(blue_mgr.get_observations())

    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        topo.net.stop()
        print("[INFO] Network stopped.")