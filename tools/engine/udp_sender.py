#!/usr/bin/env python3
"""
Cross-Platform UDP Traffic Generator Transmitter (Windows PowerShell & Linux)
Streams V2X packet matrices over native OS sockets to Raspberry Pi / Edge Node Receiver.
"""

import os
import sys
import time
import socket
import struct
import argparse
import random

MAGIC_SESSION_START = 0x56325853
MAGIC_SESSION_ACK   = 0x56325841
MAGIC_SESSION_END   = 0x56325845
MAGIC_BATCH_END     = 0x56325842

HEADER_FORMAT = "<IIfIfII"  # 28-byte packed struct matching C++ UDPControlHeader

def load_packets_from_dir(folder_path):
    packets = []
    if not os.path.exists(folder_path):
        return packets
    for fname in sorted(os.listdir(folder_path)):
        fpath = os.path.join(folder_path, fname)
        if os.path.isfile(fpath) and not fname.startswith("."):
            with open(fpath, "rb") as f:
                content = f.read()
                if len(content) > 0:
                    packets.append(content)
    return packets

def main():
    parser = argparse.ArgumentParser(description="V2X Hardware Testbed UDP Traffic Sender")
    parser.add_argument("--dest-ip", type=str, default="192.168.137.120", help="Target Raspberry Pi IP Address")
    parser.add_argument("-P", "--port", type=int, default=9999, help="Target UDP Port")
    parser.add_argument("-m", "--modes", type=str, default="0", help="Space-separated attack modes (e.g. '0 1 2')")
    parser.add_argument("-r", "--rates", type=str, default="0.0", help="Space-separated pollution rates (e.g. '0.0 5.0')")
    parser.add_argument("-N", "--packets", type=int, default=1000000, help="Total packets per session")
    parser.add_argument("-l", "--lambda-pps", type=float, default=3000.0, help="Arrival rate lambda (pps)")
    parser.add_argument("-B", "--baseline", action="store_true", help="Baseline mode (Filter OFF)")
    parser.add_argument("-F", "--filter", action="store_true", help="Adaptive FSM Filter Mode")
    parser.add_argument("-S", "--static-100", action="store_true", help="Static 100% Full Inspection Mode")
    parser.add_argument("-o", "--onnx", action="store_true", help="ONNX DRL Neural Model Inference Mode")
    parser.add_argument("--patched", action="store_true", help="Target kernel is patched")

    args = parser.parse_args()

    # Determine filter mode: 0=OFF, 1=ADAPTIVE FSM, 2=STATIC 100%, 3=ONNX DRL
    filter_mode = 0  # OFF
    if args.onnx:
        filter_mode = 3
    elif args.static_100:
        filter_mode = 2
    elif args.filter:
        filter_mode = 1

    modes = [int(x) for x in args.modes.split()]
    rates = [float(x) for x in args.rates.split()]

    # Resolve inputs folder relative to repository root
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    normal_dir = os.path.join(repo_root, "inputs", "base_packets")
    attack_dir = os.path.join(repo_root, "inputs", "attack_vectors", "malware")

    normals = load_packets_from_dir(normal_dir)
    attacks = load_packets_from_dir(attack_dir)

    if not normals or not attacks:
        print(f"\033[31m[-] Error: Base packet datasets missing in inputs/ folder ({repo_root})\033[0m")
        sys.exit(1)

    print("======================================================================")
    print(f"\033[1;36m[UDP WINDOWS TRANSMITTER] Native OS Sender Active\033[0m")
    print(f"  ├── Target Receiver    : \033[33m{args.dest_ip}:{args.port}\033[0m")
    print(f"  ├── Matrix Sweep Scope : {len(modes)} modes x {len(rates)} rates")
    print(f"  └── Total Packets/Sess : {args.packets:,} | Pacing: {args.lambda_pps:.0f} pps")
    print("======================================================================")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)  # 500ms timeout for ACK validation

    dest_tuple = (args.dest_ip, args.port)

    interval_sec = (1.0 / args.lambda_pps) if args.lambda_pps > 0 else 0.0

    for mode in modes:
        for rate in rates:
            print(f"\n\033[34m[UDP SESSION INIT]\033[0m Mode: \033[36m{mode}\033[0m | Rate: \033[33m{rate:.1f}%\033[0m | Filter Mode: {filter_mode}")
            print(f"  [*] Connecting & sending START_SESSION handshake to Pi ({args.dest_ip}:{args.port})...")

            start_header = struct.pack(
                HEADER_FORMAT,
                MAGIC_SESSION_START,
                mode,
                float(rate),
                args.packets,
                float(args.lambda_pps),
                filter_mode,
                1 if args.patched else 0
            )

            ack_received = False
            for attempt in range(1, 21):
                try:
                    sock.sendto(start_header, dest_tuple)
                    resp, _ = sock.recvfrom(28)
                    if len(resp) == 28:
                        magic, = struct.unpack("<I", resp[:4])
                        if magic == MAGIC_SESSION_ACK:
                            ack_received = True
                            print(f"\033[32m  [+] Handshake ACK confirmed from Pi! Starting packet stream...\033[0m")
                            break
                except socket.timeout:
                    print(f"\033[33m  [!] Handshake Attempt {attempt}/20 timeout. Retrying...\r\033[0m", end="")
                    sys.stdout.flush()

            if not ack_received:
                print(f"\n\033[31m[-] [UDP ERROR] Unable to reach Pi at {args.dest_ip}:{args.port}!\033[0m")
                print(f"[-] Check if receiver daemon is running on Pi.")
                sock.close()
                sys.exit(1)

            start_time = time.perf_counter()
            print_interval = max(1, args.packets // 100)
            malware_count = 0

            for i in range(args.packets):
                # Determine malware injection
                is_malware = False
                p_rnd = random.uniform(0.0, 100.0)

                if mode == 0:
                    is_malware = (p_rnd < rate)
                elif mode == 1:
                    if args.packets * 0.3 <= i <= args.packets * 0.5:
                        is_malware = (p_rnd < rate * 2.0)
                elif mode == 2:
                    cycle = (i // (args.packets // 10)) % 2
                    if cycle == 1:
                        is_malware = (p_rnd < rate * 1.5)

                if is_malware:
                    malware_count += 1
                    pkt_data = attacks[i % len(attacks)]
                else:
                    pkt_data = normals[i % len(normals)]

                sock.sendto(pkt_data, dest_tuple)

                # Real-time progress update
                if (i + 1) % print_interval == 0 or i == args.packets - 1:
                    pct = (i + 1) * 100.0 / args.packets
                    print(f"\r  \033[36m[*] Stream Progress:\033[0m {i+1:7d}/{args.packets:7d} | \033[31mMal: {malware_count:5d}\033[0m | {pct:5.1f}%", end="")
                    sys.stdout.flush()

                # Pacing
                if interval_sec > 0:
                    target_t = start_time + (i + 1) * interval_sec
                    sleep_t = target_t - time.perf_counter()
                    if sleep_t > 0:
                        time.sleep(sleep_t)

            print(f"\n\033[32m  [+] Streamed {args.packets:,} packets for Session (Mode={mode}, Rate={rate}%).\033[0m")

            # Send End Session Control
            end_header = struct.pack(
                HEADER_FORMAT,
                MAGIC_SESSION_END,
                mode,
                float(rate),
                args.packets,
                float(args.lambda_pps),
                filter_mode,
                1 if args.patched else 0
            )
            for _ in range(3):
                sock.sendto(end_header, dest_tuple)
                time.sleep(0.005)
            time.sleep(0.2)

    # Batch completed
    batch_header = struct.pack(HEADER_FORMAT, MAGIC_BATCH_END, 0, 0.0, 0, 0.0, 0, 0)
    for _ in range(3):
        sock.sendto(batch_header, dest_tuple)
        time.sleep(0.005)

    print(f"\n\033[1;32m[UDP SENDER COMPLETE] All batch sessions streamed successfully to {args.dest_ip}:{args.port}!\033[0m")
    sock.close()

if __name__ == "__main__":
    main()
