# Base Containerfile for Node.js development environments
ARG BASE_IMAGE=node:22-alpine

FROM ${BASE_IMAGE}

# Install essential tools and SSH server
RUN apk add --no-cache \
    openssh-server \
    git \
    curl \
    bash \
    sudo \
    && mkdir -p /run/sshd \
    && ssh-keygen -A

# Create dev user with sudo access
ARG DEV_USER=developer
ARG DEV_UID=1000
ARG DEV_GID=1000

RUN addgroup -g ${DEV_GID} ${DEV_USER} \
    && adduser -D -u ${DEV_UID} -G ${DEV_USER} -s /bin/bash ${DEV_USER} \
    && echo "${DEV_USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${DEV_USER}

# Setup SSH for the dev user
RUN mkdir -p /home/${DEV_USER}/.ssh \
    && chmod 700 /home/${DEV_USER}/.ssh \
    && chown -R ${DEV_USER}:${DEV_USER} /home/${DEV_USER}/.ssh

# Configure SSH
RUN sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
    && echo "AllowUsers ${DEV_USER}" >> /etc/ssh/sshd_config

# Set working directory
WORKDIR /home/${DEV_USER}/workspace

# Switch to dev user
USER ${DEV_USER}

# Expose SSH port
EXPOSE 22

# Default command: start SSH daemon
CMD ["sudo", "/usr/sbin/sshd", "-D", "-e"]
