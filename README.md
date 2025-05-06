# Autonomous Cyber Operations Emulator using Containernet

## Overview

This project simulates **Autonomous Cyber Operations (ACO)** using a red-blue team environmet in a **virtual network environment**. Offensive and defensive cyber operations are emulated using realistic tools and scripts. It uses **Containernet**, an extension of Mininet that allows using Docker containers as network hosts, enabling a more realistic and flexible simulation.

## Project Goals

- Emulate **offensive cyber actions** by a Red Agent (based on MITRE ATT&CK tactics).
- Simulate **defensive responses** by a Blue Agent (detection, analysis, and mitigation).
- Support **realistic network scenarios** with weak services, privilege escalation paths, and service disruption.

---

## Containernet

[Containernet](https://github.com/containernet/containernet) is a **Mininet fork** that allows the use of **Docker containers as hosts** in software-defined network simulations. This enables running full-featured OS-level services and tools (e.g., SSH, nmap, Python) inside each host.

Advantages:
- Run real-world tools (like `nmap`, `hydra`, `sshpass`) inside containers.
- Use isolated Docker containers for red and blue agents.
- Simulate dynamic network topologies and link failures.

---

## Containernet Setup

Setup containernet from their official [GitHub repository](https://github.com/containernet/containernet)

---

## Project Setup

 **Important**: Clone this repository **inside** the `containernet/` directory:

```bash
cd containernet
git clone <this-repo-url> aco-simulator
cd aco-simulator
```

---

## Project Structure

```plaintext
aco-simulator/
├── aco_emulator_test.py   # Containernet topology setup (hardcoded)
├── aco_emulator.py        # Containernet topology setup (Input from a .yaml file)
├── red_run_env.py         # Code to simulate red actions
├── blue_run_env.py        # Code to simulate blue actions
├── makefile               # Build/run automation
└── red_scripts/           # Red agent scripts
    ├── discover_remote.sh
    ├── discover_network.sh
    ├── exploit.sh
    ├── escalate.sh
    ├── file_processor.py
    └── impact.sh
└── blue_scripts/          # Blue agent scripts
    ├── discover_remote.sh
    ├── discover_network.sh
    ├── exploit.sh
    ├── escalate.sh
    └── impact.sh
└── op_scripts/            # Server scripts
    └── start_services.sh
└── Blue/                  # Blue agent Logic
    ├── action.py
    ├── block_ip.py
    ├── blue_observation_manager.py
    ├── connection_detector.py
    ├── density_detector.py
    ├── detector.py
    └── port_scan_detector.py
└── docker_setup/          # Blue agent scripts
    ├── Dockerfile.red
    ├── Dockerfile.blue
    └── Dockerfile.op
└── scenarios/            # different network topologies
    ├── scenario1.yml
    └── scenario2.yml
```

---

## Build and Run

### 1. Build Docker Images

```bash
make build
```

This will:
- Build Docker images for red, blue, and operational nodes.
- Set up weakly configured SSH access and required tools.

### 2. Start the Simulation

```bash
make red
```

This executes `run_red_env.py`, which:
- Sets up a network with:
  - Red agents (e.g., `user0`, `user1`, `user2`)
  - Blue agent (`blue`)
  - Operational node (`op`)
  - Router (`r1`) connecting the subnets
- Demonstrates the various red actions
---

```bash
make blue
```

This executes `run_blue_env.py`, which:
- Sets up a network with:
  - Red agents (e.g., `user0`, `user1`, `user2`)
  - Blue agent (`blue`)
  - Operational node (`op`)
  - Router (`r1`) connecting the subnets
- Demonstrates the various blue actions
---


## Red Agent Actions
- **Discover Remote Systems**: Find out the various hosts in your subnet
- **Discover Network Services**: Find out the open ports on of a hosts
- **Exploit**: Gain user level access on a remote host by establishing a reverse shell connection
- **Privelege Escalate**: Gain root level access on a remote host
- **Impact**: Disrupt the services provided by the server 

---

## Blue Agent Actions

TODO

---

## Network Topology Configuration File


This framework uses a YAML file to define the entire virtual network topology and host behavior. Each device (host, switch, or router) is declared with its type, neighbor links, and optional startup commands.


### Node Definition Format

Each node is defined in the following format:

```yaml
node_name:
  type: <Red | Blue | Op | Router | Switch>
  neighbors: [<neighbor1>, <neighbor2>, ...]
  cmds: [<command1>, <command2>, ...]  # Optional
```

#### 🔹 Fields Explained

| Field       | Description                                                              |
| ----------- | ------------------------------------------------------------------------ |
| `type`      | Specifies the type of device: `Red`, `Blue`, `Op`, `Router`, or `Switch` |
| `neighbors` | List of other nodes directly connected to this node                      |
| `cmds`      | (Optional) Shell commands to execute after the node starts               |


### Example Topology

```yaml
r1:
  type: Router
  neighbors: [user0, user1, user2, blue, op]

user0:
  type: Red
  neighbors: [r1]
  cmds: ["service ssh start"]

user1:
  type: Red
  neighbors: [r1]
  cmds: []

user2:
  type: Red
  neighbors: [r1]
  cmds: []

blue:
  type: Blue
  neighbors: [r1]
  cmds: ["tcpdump -i any -w blue.pcap &"]

op:
  type: Op
  neighbors: [r1]
  cmds: ["python3 -m http.server 80 &"]
```

### cmds
`cmds` are the initial commands run on every host. It can be used for many things such as:
- Setup routing in the containernet hosts
- Setup any firewall rules for some of the hosts using iptables
- Setup some packet logging in blue hosts for packet based analysis  

### IP Address Referencing

* IP addresses for each endpoint of a link are deterministically assigned and can be **referenced in shell commands** using **`${node_name}`** syntax.
* If a host has multiple interfaces, the IP address of each host can be referenced by **`${node_name[1]}`**

#### Example

```yaml
cmds: ["ping -c 1 ${op}", "nmap -sS ${user1}"]
```

> This will resolve `${op}` and `${user1}` to their respective IP addresses based on topology.


This format allows easy prototyping and reproducibility of network scenarios for autonomous cyber operations.

---

sudo -E env PATH=$PATH python3 blue_agent_tester.py