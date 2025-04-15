# Autonomous Cyber Operations Emulator using Containernet

## Overview

This project simulates **Autonomous Cyber Operations (ACO)** using a red-blue team environmet in a **virtual networked environment**. Offensive and defensive cyber operations are emulated using realistic tools and scripts. It uses **Containernet**, an extension of Mininet that allows using Docker containers as network hosts, enabling a more realistic and flexible simulation.

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

1. **Clone Containernet and build dependencies**:

   ```bash
   git clone https://github.com/containernet/containernet.git
   cd containernet
   ```

2. **Install dependencies** (run from `containernet/`):

   ```bash
   sudo apt update
   sudo apt install -y ansible aptitude net-tools \
       iproute2 iputils-ping sshpass \
       openvswitch-switch openvswitch-common \
       python3-pip python3-setuptools \
       python3-dev libffi-dev libssl-dev \
       docker.io

   sudo pip3 install -U pip
   sudo pip3 install networkx mininet

   sudo ansible-playbook -i "localhost," -c local install.yml
   ```

3. **Test Containernet installation**:

   ```bash
   sudo python3 examples/containernet_test.py
   ```

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
├── Dockerfile.red         # Docker image for red agent
├── Dockerfile.blue        # Docker image for blue agent
├── Dockerfile.op          # Docker image for operational (target) node
├── main.py                # Containernet topology setup
├── makefile               # Build/run automation
└── red_scripts/           # Red agent scripts
    ├── discover_remote.sh
    ├── discover_network.sh
    ├── exploit.sh
    ├── escalate.sh
    └── impact.sh
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
make run
```

This executes `main.py`, which:
- Sets up a network with:
  - Red agents (e.g., `user0`, `user1`, `user2`)
  - Blue agent (`blue`)
  - Operational node (`op`)
  - Router (`r1`) connecting the subnets
- Launches terminals for each host.

---

## Red Agent Actions

### `discover_remote.sh`
Discover active IPs in a subnet via `ping` sweep:

```bash
./red_scripts/discover_remote.sh 10.0.0.0/24
```

### `discover_network.sh`
Scan open ports on reachable hosts using `nmap`:

```bash
./red_scripts/discover_network.sh 10.0.0.0/24
```

### `exploit.sh`
Perform SSH brute-force login using `sshpass`:

```bash
./red_scripts/exploit.sh <target-ip> hacker
```

### `escalate.sh` *(placeholder)*
Intended for privilege escalation post-exploit.

### `impact.sh`
Disable SSH or shutdown compromised machine.

---

## Blue Agent Capabilities

- **Monitor**: Watch for red agent actions like login attempts.
- **Analyze**: Check host logs, user sessions, services.
- **Remove**: Kill red agent shells or malicious services.
- **Restore**: Reset compromised machines (at score cost).
- **Misinform**: Set honeypots to deceive red agents (planned).

---

## Automation with Makefile

```bash
make build   # Build all Docker images
make run     # Start the simulation
make clean   # Stop simulation and remove containers
```

---

<!-- ## License -->

<!-- MIT License — use freely for research, education, and development. -->

<!-- --- -->
