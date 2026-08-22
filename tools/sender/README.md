# Physical-testbed UDP sender

`udp_sender.py` is the Python traffic generator used for Raspberry Pi
deployment experiments. It sends nominal and recursive attack payloads to the
C++ UDP receiver; packet filtering and ONNX inference remain on the receiver.

Run commands from the repository root:

```bash
python tools/sender/udp_sender.py --dest-ip raspberrypi.local \
  -F -o -m "0 1 2" -r "1.0 5.0 10.0" \
  -N 1000000 -l 3000 -I "1 20"
```

The principal options are documented by:

```bash
python tools/sender/udp_sender.py --help
```

Modes `0`, `1`, and `2` select continuous, single-pulse, and periodic attack
schedules. Every value passed through `-r` is the target malicious-payload
percentage over the complete session. The pulse and periodic schedules
concentrate that global budget into their active windows. `-I "1 20"` produces the 20-run layout consumed by
`python tools/plot_engine.py -M --runs 1-20`.

The predefined control suite runs Mode-2 FSM and static-100% comparisons at
0.1% and 10%, plus a Mode-0 clean baseline. Odd and even trial IDs reverse the
profile order to counterbalance temperature and CPU-frequency drift:

```bash
python tools/sender/udp_sender.py --dest-ip raspberrypi.local \
  --suite controls -N 1000000 -l 3000 -I "1 20"
```

Use `--dry-run` to inspect the complete session order without loading payloads
or opening a socket.
