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
import tarfile

MAGIC_SESSION_START = 0x56325853
MAGIC_SESSION_ACK   = 0x56325841
MAGIC_SESSION_END   = 0x56325845
MAGIC_BATCH_END     = 0x56325842

HEADER_FORMAT = "<IIfIfIIII"  # 36-byte packed struct matching C++ UDPControlHeader

def load_packets_from_dir(folder_path, is_malware_header=0):
    packets = []
    repo_root = os.path.abspath(os.path.join(folder_path, ".."))
    tar_path = os.path.join(repo_root, "base_packets_full.tar.gz")
    header_bytes = struct.pack("<I", is_malware_header)
    
    # 1. Fast Path: Read directly from pre-sorted base_packets_full.tar.gz (0.2s instant read)
    if is_malware_header == 0 and os.path.exists(tar_path):
        print(f"[*] Fast Loading dataset directly from archive: {os.path.basename(tar_path)} ...")
        t0 = time.time()
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.isfile()]
                total_m = len(members)
                print(f"  └── Found {total_m:,} pre-sorted packets in archive. Extracting ALL {total_m:,} packets to RAM...")
                sys.stdout.flush()
                
                for idx, member in enumerate(members, 1):
                    f = tar.extractfile(member)
                    if f:
                        content = f.read()
                        if len(content) > 0:
                            packets.append(header_bytes + content)
                    if idx % 50000 == 0 or idx == total_m:
                        print(f"  ├── RAM Load Progress: {idx:,} / {total_m:,} packets loaded ({idx*100//total_m}%)...")
                        sys.stdout.flush()
            print(f"\033[32m[SUCCESS] Loaded ALL {len(packets):,} pre-sorted V2X baseline packets into RAM!\033[0m")
            return packets
        except Exception as e:
            print(f"\033[33m[!] Tar fast loading failed ({e}). Falling back to directory scan...\033[0m")
            packets = []

    # 2. Fallback Path: File system directory enumeration
    if not os.path.exists(folder_path):
        return packets
    
    print(f"[*] Enumerating files in {folder_path} ...")
    files = sorted(os.listdir(folder_path))
    print(f"  └── Directory contains {len(files):,} files. Reading to RAM...")
    
    for f in files:
        full_path = os.path.join(folder_path, f)
        if os.path.isfile(full_path):
            with open(full_path, "rb") as fp:
                content = fp.read()
                if len(content) > 0:
                    packets.append(header_bytes + content)
    print(f"\033[32m[SUCCESS] Loaded {len(packets):,} packets into RAM!\033[0m")
    return packets

def main():
    parser = argparse.ArgumentParser(description="V2X Hardware Testbed UDP Traffic Sender")
    parser.add_argument("--dest-ip", type=str, default="127.0.0.1", help="Target Receiver IP Address")
    parser.add_argument("-P", "--port", type=int, default=9999, help="Target UDP Port")
    parser.add_argument("-m", "--modes", type=str, default="0", help="Space-separated attack modes (e.g. '0 1 2')")
    parser.add_argument("-r", "--rates", type=str, default="0.0", help="Space-separated pollution rates (e.g. '0.0 5.0')")
    parser.add_argument("-N", "--packets", type=int, default=1000000, help="Total packets per session")
    parser.add_argument("-l", "--lambda-pps", type=float, default=3000.0, help="Arrival rate lambda (pps)")
    parser.add_argument("-B", "--baseline", action="store_true", help="Baseline mode (Filter OFF)")
    parser.add_argument("-F", "--filter", action="store_true", help="Adaptive FSM Filter Mode")
    parser.add_argument("-S", "--static-100", action="store_true", help="Static 100% Full Inspection Mode")
    parser.add_argument("-C", "--codel", action="store_true", help="CoDel AQM Queue Protection Baseline Mode")
    parser.add_argument("-o", "--onnx", action="store_true", help="Enable ONNX DRL Agent Filter Mode")
    parser.add_argument("-I", "--run-range", type=str, default="0 0", help="Space-separated trial run ID range (e.g. '1 20' or '1 1')")
    parser.add_argument("--patched", action="store_true", help="Target kernel is patched")

    args = parser.parse_args()

    # Determine filter mode: 0=OFF, 1=ADAPTIVE FSM, 2=STATIC 100%, 3=ONNX DRL, 4=CODEL
    filter_mode = 0  # OFF
    if args.codel:
        filter_mode = 4  # CODEL
    elif args.onnx:
        filter_mode = 3
    elif args.static_100:
        filter_mode = 2
    elif args.filter:
        filter_mode = 1

    modes = [int(x) for x in args.modes.split()]
    rates = [float(x) for x in args.rates.split()]

    run_parts = [int(x) for x in args.run_range.split()]
    if len(run_parts) == 1:
        start_run, end_run = run_parts[0], run_parts[0]
    elif len(run_parts) >= 2:
        start_run, end_run = run_parts[0], run_parts[1]
    else:
        start_run, end_run = 0, 0

    # Resolve inputs folder relative to repository root
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    normal_dir = os.path.join(repo_root, "inputs", "base_packets")
    attack_dir = os.path.join(repo_root, "inputs", "attack_vectors", "malware")

    normals = load_packets_from_dir(normal_dir, is_malware_header=0)
    attacks = load_packets_from_dir(attack_dir, is_malware_header=1)

    if not normals or not attacks:
        print(f"\033[31m[-] Error: Base packet datasets missing in inputs/ folder ({repo_root})\033[0m")
        sys.exit(1)

    print("======================================================================")
    print(f"\033[1;36m[UDP WINDOWS TRANSMITTER] Native OS Sender Active\033[0m")
    print(f"  ├── Target Receiver    : \033[33m{args.dest_ip}:{args.port}\033[0m")
    print(f"  ├── Matrix Sweep Scope : {len(modes)} modes x {len(rates)} rates")
    print(f"  ├── Total Packets/Sess : {args.packets:,} | Pacing: {args.lambda_pps:.0f} pps")
    if start_run > 0:
        print(f"  └── Multi-Run Trial Range: \033[1;33mRun {start_run} to Run {end_run}\033[0m")
    else:
        print(f"  └── Multi-Run Mode     : Standard Single Run (Legacy csv_raw)")
    print("======================================================================")

    # Resolve IPv4/IPv6 address dynamically (supports fe80:: IPv6 link-local and IPv4)
    try:
        addr_info = socket.getaddrinfo(args.dest_ip, args.port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        family, socktype, proto, _, dest_tuple = addr_info[0]
        sock = socket.socket(family, socktype, proto)
    except Exception:
        family = socket.AF_INET
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dest_tuple = (args.dest_ip, args.port)

    sock.settimeout(0.5)  # 500ms timeout for ACK validation
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except Exception:
        pass

    # Explicitly bind to 0.0.0.0:0 or :::0 so socket receives ACK across IPv4/IPv6 interfaces
    try:
        sock.bind(('::' if family == socket.AF_INET6 else '0.0.0.0', 0))
    except Exception:
        pass

    interval_sec = (1.0 / args.lambda_pps) if args.lambda_pps > 0 else 0.0

    run_list = range(start_run, end_run + 1) if start_run > 0 else [0]
    is_first_session = 1

    try:
        for run_id in run_list:
            if start_run > 0:
                print(f"\n======================================================================")
                print(f"\033[1;35m[MULTI-RUN TRIAL IN PROGRESS]\033[0m Iteration: \033[1;33mRun {run_id} / {end_run}\033[0m")
                print(f"======================================================================")

            for mode in modes:
                for rate in rates:
                    print(f"\n\033[34m[UDP SESSION INIT]\033[0m Mode: \033[36m{mode}\033[0m | Rate: \033[33m{rate:.1f}%\033[0m | Filter Mode: {filter_mode} | Run ID: {run_id}")
                    print(f"  [*] Connecting & sending START_SESSION handshake to Pi ({args.dest_ip}:{args.port})...")

                    # Drain any stale ACKs in local socket buffer before initiating new session handshake
                    sock.setblocking(False)
                    try:
                        while True:
                            sock.recv(4096)
                    except OSError:
                        pass

                    # Restore blocking socket mode with timeout for reliable handshake ACK exchange
                    sock.setblocking(True)
                    sock.settimeout(0.5)

                    start_header = struct.pack(
                        HEADER_FORMAT,
                        MAGIC_SESSION_START,
                        mode,
                        float(rate),
                        args.packets,
                        float(args.lambda_pps),
                        filter_mode,
                        1 if args.patched else 0,
                        run_id,
                        is_first_session
                    )
                    is_first_session = 0

                    ack_received = False
                    for attempt in range(1, 21):
                        try:
                            sock.sendto(start_header, dest_tuple)
                            resp, _ = sock.recvfrom(36)
                            if len(resp) >= 32:
                                magic = struct.unpack("<I", resp[:4])[0]
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
                    spinner_chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
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
                            wire_pkt = attacks[i % len(attacks)]
                        else:
                            wire_pkt = normals[i % len(normals)]

                        # Native UDP best-effort transport: non-blocking send without infinite retry stalls
                        try:
                            sock.sendto(wire_pkt, dest_tuple)
                        except OSError:
                            pass

                        # Real-time dynamic heartbeat UI update (updates every 1,000 packets / 0.33s)
                        if (i + 1) % 1000 == 0 or i == args.packets - 1:
                            now_t = time.perf_counter()
                            elapsed_s = now_t - start_time
                            inst_pps = (i + 1) / elapsed_s if elapsed_s > 0 else args.lambda_pps
                            est_total_s = args.packets / args.lambda_pps if args.lambda_pps > 0 else 0
                            
                            elapsed_str = f"{int(elapsed_s)//60:02d}:{int(elapsed_s)%60:02d}"
                            est_str = f"{int(est_total_s)//60:02d}:{int(est_total_s)%60:02d}"
                            spin_char = spinner_chars[(i // 1000) % len(spinner_chars)]
                            pct = (i + 1) * 100.0 / args.packets

                            print(f"\r  \033[36m[*] Stream Progress [{spin_char} ALIVE]:\033[0m {i+1:7d}/{args.packets:7d} | \033[31mMal: {malware_count:5d}\033[0m | {pct:5.1f}% | [{elapsed_str}/{est_str}] | {inst_pps:,.0f} pps", end="")
                            sys.stdout.flush()

                        # Pacing
                        if interval_sec > 0:
                            target_t = start_time + (i + 1) * interval_sec
                            sleep_t = target_t - time.perf_counter()
                            if sleep_t > 0:
                                time.sleep(sleep_t)

                    print(f"\n\033[32m  [+] Streamed {args.packets:,} packets for Session (Mode={mode}, Rate={rate}%).\033[0m")
                    time.sleep(0.5)  # Pause 0.5s to allow RPi receiver socket re-bind & cleanup

                    # Send End Session Control
                    end_header = struct.pack(
                        HEADER_FORMAT,
                        MAGIC_SESSION_END,
                        mode,
                        float(rate),
                        args.packets,
                        float(args.lambda_pps),
                        filter_mode,
                        1 if args.patched else 0,
                        run_id
                    )
                    for _ in range(3):
                        sock.sendto(end_header, dest_tuple)
                        time.sleep(0.005)
                    time.sleep(0.2)

    except KeyboardInterrupt:
        print(f"\n\033[31m[!] Aborted instantly by user (KeyboardInterrupt). Closing socket.\033[0m")
        sock.close()
        sys.exit(0)

    # Batch completed
    batch_end_header = struct.pack(
        HEADER_FORMAT,
        MAGIC_BATCH_END,
        0, 0.0, 0, 0.0, 0, 0, 0
    )
    for _ in range(3):
        sock.sendto(batch_end_header, dest_tuple)
        time.sleep(0.005)

    sock.close()
    print(f"\n\033[32m[SUCCESS] UDP Transmitter stream matrix finished successfully.\033[0m")

if __name__ == "__main__":
    main()
