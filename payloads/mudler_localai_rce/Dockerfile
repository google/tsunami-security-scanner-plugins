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

# Set the working directory
WORKDIR /opt

# Install pyinstaller
COPY requirements.txt requirements.txt
RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install --require-hashes -r requirements.txt

COPY app_bin_compile.py app_bin_compile.py

# Start Bash
CMD  /bin/bash
