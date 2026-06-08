import collections
import os

def calculate_max_sq_from_file(filepath: str, window_size: int = 64) -> int:
    """
    Reads a binary file and calculates the maximum SQ (F2 moment) under a given sliding window.
    """
    if not os.path.exists(filepath):
        return f"Error: File not found {filepath}"

    # Read the entire payload in binary mode
    with open(filepath, 'rb') as f:
        payload = f.read()

    # If payload length is smaller than the window size, calculate SQ for the entire payload directly
    if len(payload) < window_size:
        counts = collections.Counter(payload)
        return sum(count ** 2 for count in counts.values())

    max_sq = 0
    
    # Simulate a 64-byte sliding window
    for i in range(len(payload) - window_size + 1):
        window = payload[i : i + window_size]
        
        # Count the occurrences of each byte within the window
        counts = collections.Counter(window)
        
        # Calculate SQ (sum of squares of counts)
        current_sq = sum(count ** 2 for count in counts.values())
        
        if current_sq > max_sq:
            max_sq = current_sq
            
    return max_sq

if __name__ == "__main__":
    # Using the actual file paths used in your previous xxd command
    cam_path = "vanetza_unpatched/tools/qos-harness/input/cam_v3_certificate.dat"
    poc_path = "vanetza_unpatched/tools/qos-harness/input-malware/poc_mtu_limit.bin"

    print("=== Parser Structure Signal (SQ) Calculation ===")
    
    print(f"\n[1] Scanning legitimate packet: {cam_path}")
    cam_sq = calculate_max_sq_from_file(cam_path)
    print(f" -> Max SQ of legitimate CAM: {cam_sq}")

    print(f"\n[2] Scanning malicious packet: {poc_path}")
    poc_sq = calculate_max_sq_from_file(poc_path)
    print(f" -> Max SQ of malicious PoC: {poc_sq}")