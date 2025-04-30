# run_density_scan.py

import os
import sys
import math

def shannon_entropy(data):
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8.0

def compute_file_density(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        return shannon_entropy(data)
    except Exception as e:
        print(f"[!] Could not read {path}: {e}", file=sys.stderr)
        return 0.0

def main():
    directory = "/home/tmp/drops/"
    total_density = 0.0
    file_count = 0

    for root, _, files in os.walk(directory):
        for name in files:
            filepath = os.path.join(root, name)
            if os.path.islink(filepath):
                continue
            density = compute_file_density(filepath)
            print(f"[+] {filepath}: density = {density:.4f}", file=sys.stderr)
            total_density += density
            file_count += 1

    print(f"Density:{total_density:.4f}")  # Final output is just the total

if __name__ == "__main__":

    main()
