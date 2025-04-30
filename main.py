from aco import ACO
# from aco_emulator import ACOEmulator
from mininet.log import setLogLevel

if __name__ == '__main__':
    setLogLevel('info')
    topo = ACO('scenario2.yml')
    topo.build(interactive=True)
    r = topo.net.get('r1')
    print(r.IP())
