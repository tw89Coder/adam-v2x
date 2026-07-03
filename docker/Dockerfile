# Use official Ubuntu 22.04 LTS as base
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    g++ \
    git \
    wget \
    curl \
    pkg-config \
    libboost-all-dev \
    libgeographic-dev \
    libcrypto++-dev \
    libssl-dev \
    openssl \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set up the working directory inside the container
WORKDIR /workspace

# Download and install ONNX Runtime C++ prebuilt library (matching setup.sh)
RUN mkdir -p /workspace/third_party && \
    cd /tmp && \
    wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.16.3/onnxruntime-linux-x64-1.16.3.tgz && \
    tar -xzf onnxruntime-linux-x64-1.16.3.tgz && \
    mv onnxruntime-linux-x64-1.16.3 /workspace/third_party/onnxruntime && \
    rm onnxruntime-linux-x64-1.16.3.tgz

# Copy requirements.txt to install Python dependencies
COPY tools/rl_bridge/requirements.txt /tmp/requirements.txt

# Create Python virtual environment and install Python dependencies.
# Optimizations applied:
# 1. Uses a fast PyPI mirror (Tuna) to resolve packages rapidly.
# 2. Instructs pip to fetch the lightweight CPU-only version of PyTorch,
#    reducing the download payload size from ~2.5GB (CUDA default) down to ~150MB.
RUN python3 -m venv /workspace/tools/rl_bridge/venv && \
    /workspace/tools/rl_bridge/venv/bin/pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple && \
    /workspace/tools/rl_bridge/venv/bin/pip install -r /tmp/requirements.txt \
        -i https://pypi.tuna.tsinghua.edu.cn/simple \
        --extra-index-url https://download.pytorch.org/whl/cpu

# Copy the entire workspace into the container (respects .dockerignore)
COPY . /workspace

# Pre-compile C++ binaries (both unpatched and patched workspaces) to speed up container launch
RUN ./manage_build.sh unpatched && ./manage_build.sh patched

# Set default execution command
CMD ["bash"]
