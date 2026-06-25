import socket
import random
import time

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', 8080))
server.listen(1)
print("[*] Mock AI Agent listening on port 8080... Ready for C++ Handshake.")

try:
    while True:
        conn, addr = server.accept()
        data = conn.recv(1024).decode('utf-8').strip()
        if data:
            print(f"[<- C++] Received Telemetry (Avg_SQ, Avg_Budget, Anomaly_Rate): {data}")
            
            # Simulate AI decision: generate dummy policy parameters
            rec = round(random.uniform(0.01, 0.5), 3)       # Dynamic RECOVERY_RATE
            pen = round(random.uniform(10.0, 100.0), 1)     # Dynamic PENALTY_MULTIPLIER
            sq = random.randint(500, 700)                   # Dynamic SQ_THRESHOLD
            
            response = f"{rec},{pen},{sq}"
            conn.send(response.encode('utf-8'))
            print(f"[-> C++] Injected Optimized Policy: {response}\n")
        conn.close()
except KeyboardInterrupt:
    print("\n[*] Shutting down Mock Agent.")
    server.close()