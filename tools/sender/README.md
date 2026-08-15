# UDP hardware sender

The preferred entry point is `tools/sender/udp_sender.py`. The historical
`tools/engine/udp_sender.py` path remains as a compatibility wrapper.

Run the paper control groups while keeping one Raspberry Pi receiver daemon
alive:

```powershell
python \\wsl.localhost\V2X\home\yhl\term-project\CSE625_QoS\tools\sender\udp_sender.py --dest-ip raspberrypi.local -P 9999 --suite controls -N 1000000 -l 3000 -I "1 20"
```

Each run contains Mode-2 FSM at 0.1% and 10%, Mode-2 static 100% at 0.1% and
10%, and the Mode-0 0% baseline. Odd and even runs use opposite profile order
to counterbalance temperature and CPU-frequency drift. Use `--dry-run` to
inspect the resolved order without opening a socket.
