# Containerized co-simulation

The root `docker-compose.yml` provides an optional development environment for
online Python/C++ co-simulation. It is not required for the Raspberry Pi
deployment path or for plotting existing paper outputs.

From the repository root:

```bash
docker compose up -d --build
docker compose logs -f rl-bridge qos-simulation
```

The services are:

- `rl-bridge`: runs the Python online learner on port 8080.
- `qos-simulation`: builds/runs the unpatched C++ harness with `--train-rl` and
  shares the learner's network namespace.

The repository is mounted at `/workspace`. Checkpoints and outputs therefore
remain visible on the host. Anonymous volumes protect the container-built
virtual environment, third-party runtime, and C++ build directories from
incompatible host artifacts.

Stop the services without deleting repository data:

```bash
docker compose down
```

The paper's policy was trained through the online C++/Python loop. The final
Raspberry Pi evaluation instead uses in-process C++ ONNX inference and a
separate Python UDP sender.
