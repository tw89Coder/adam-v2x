# V2X QoS Research: Dockerized Sandbox Environment

This directory contains the containerization configurations designed to streamline building and executing the C++ co-simulation environment without manually configuring libraries (CMake, Conan, GTest, ONNX Runtime) on different host architectures.

---

## Directory Structure

```text
docker/
├── Dockerfile             # Core image configuration (GCC/Python/ONNX Runtime stack)
└── docker-compose.yml     # Service configuration and mount coordinates (located in root)
```

---

## Prerequisites

Ensure you have Docker and Docker Compose installed on your host system:
* **Docker Engine**: Version 20.10.0 or higher.
* **Docker Compose**: Version 1.29.0 or higher.

---

## Usage Instructions

To launch the sandbox environment and mount the source code directory, execute the following commands from the project root:

```bash
# 1. Build and boot up the sandbox container in detached mode
docker compose up -d --build

# 2. Access the container's interactive shell interface
docker compose exec qos-sandbox bash
```

Once inside the container shell, you can execute the normal build script and run experiments:
```bash
# Compile unpatched and patched target harnesses inside container
bash manage_build.sh all clean

# Execute in-container RL training or static simulation matrices
bash run_experiments.sh unpatched --simulate-all -r "10.0 5.0"
```

---

## Volume Mapping Configuration

The `docker-compose.yml` mounts the following host directories:

```mermaid
graph LR
    H[Host Directory] -->|Mounted via docker-compose| C[Container Directory]
    H_Src[Workspace Source] -->|/V2X/home/yhl/term-project/CSE625_QoS| C_Src[/workspace]
    H_Checkpoints[checkpoints/] -->|checkpoints/| C_Checkpoints[/workspace/checkpoints]
    H_Outputs[outputs/] -->|outputs/| C_Outputs[/workspace/outputs]
```

This volume layout guarantees that any trained weights (`.pth` / `.onnx`) or evaluation statistics CSVs and plots generated inside the container are automatically written back to your host filesystem.
