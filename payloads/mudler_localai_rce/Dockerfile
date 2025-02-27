# Use Ubuntu 18.04 with AMD64 architecture as the base image (which has glibc 2.27)
FROM --platform=linux/amd64 ubuntu:18.04

# Set environment variables to non-interactive (this prevents some prompts)
ENV DEBIAN_FRONTEND=noninteractive

# Update and install basic utilities
RUN apt-get update && apt-get install -y \
  software-properties-common \
  apt-utils \
  wget \
  curl \
  build-essential \
  git \
  net-tools \
  libx11-dev \          
  libxext-dev \        
  pkg-config \         
  libssl-dev           

# Install GCC, Python, Go, and other dependencies
RUN apt-get install -y \
  gcc \
  python3 \
  python3-pip \
  python3-dev \
  golang-go

# Upgrade pip and install pyinstaller
RUN python3 -m pip install --upgrade pip && \
  python3 -m pip install pyinstaller

# Set the working directory
WORKDIR /src

# Your build or run commands here
# For example, to build a Rust project:
# COPY . .
# RUN cargo build --release

# Start Bash
CMD  /bin/bash
