# Docker Test Environment for HSTS Compliance Tools

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    git \
    sudo \
    xmlstarlet \
    libxml2-utils \
    openjdk-11-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Create test user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Set up test directory structure simulating a Tomcat server
RUN mkdir -p /opt/tomcat/conf && \
    mkdir -p /opt/tomcat/logs && \
    mkdir -p /opt/tomcat/temp && \
    mkdir -p /opt/tomcat/webapps && \
    chown -R testuser:testuser /opt/tomcat

# Create a dummy web.xml
COPY examples/test_web.xml /opt/tomcat/conf/web.xml

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Grant execution permissions
# Grant execution permissions
RUN chmod +x src/unix/*.sh && \
    chmod +x tests/unix/*.sh

# Switch to test user
USER testuser

# Default command runs the Unix test suite
CMD ["./tests/unix/test_hsts_unix.sh"]
