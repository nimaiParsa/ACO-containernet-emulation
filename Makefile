# Variables
PYTHON = python3
MAIN = main.py

# Docker image tags
RED_IMAGE = red_node
BLUE_IMAGE = blue_node
OP_IMAGE = op_node

# Dockerfiles
RED_DOCKERFILE = Dockerfile.red
BLUE_DOCKERFILE = Dockerfile.blue
OP_DOCKERFILE = Dockerfile.op

# Default target
.PHONY: all
all: build run

# Build all Docker images
.PHONY: build
build:
	@echo "[+] Building Docker images..."
	docker build -f $(RED_DOCKERFILE) -t $(RED_IMAGE) .
	docker build -f $(BLUE_DOCKERFILE) -t $(BLUE_IMAGE) .
	docker build -f $(OP_DOCKERFILE) -t $(OP_IMAGE) .

# Run the emulator
.PHONY: run
run:
	@echo "[+] Running Containernet network..."
	sudo -E env PATH=$$PATH $(PYTHON) $(MAIN)

# Clean up Docker containers and Mininet state
.PHONY: clean
clean:
	@echo "[+] Cleaning up Mininet..."
	sudo mn -c
	@echo "[+] Removing Docker containers..."
	sudo docker rm -f $$(sudo docker ps -a -q --filter "name=mn.") || true
	@echo "[+] Done."

# Clean only Docker images if needed
.PHONY: clean-images
clean-images:
	@echo "[+] Removing Docker images..."
	sudo docker rmi -f $(RED_IMAGE) $(BLUE_IMAGE) $(OP_IMAGE) || true
