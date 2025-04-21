FROM ubuntu:22.04

# Set noninteractive frontend
ENV DEBIAN_FRONTEND=noninteractive

# Install essential tools and SSH server
RUN apt-get update && apt-get install -y \
    openssh-server \
    iputils-ping \
    traceroute \
    net-tools \
    iproute2 \
    curl \
    sshpass \
    hydra \
    netcat \
    nmap \
    vim \
    python3 \
    binutils \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create user with weak password
RUN useradd -ms /bin/bash hacker && \
    echo "hacker:1234" | chpasswd && \
    adduser hacker sudo

# Enable root SSH login with password
RUN echo "root:root" | chpasswd && passwd -u root && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

# Configure SSH to allow password authentication
RUN mkdir /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

COPY red_scripts /home/hacker/red_scripts
COPY blue_scripts /home/hacker/blue_scripts
RUN chown -R hacker:hacker /home/hacker/red_scripts && chmod +x /home/hacker/red_scripts/*.sh
RUN chown -R hacker:hacker /home/hacker/blue_scripts && chmod +x /home/hacker/blue_scripts/*.sh
    
# Expose SSH
EXPOSE 22

# Start SSH service by default
CMD ["/usr/sbin/sshd", "-D"]
