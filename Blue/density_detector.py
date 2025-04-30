import os 
from Blue.detector import Detector
import math


class DensityDetector(Detector):
    def __init__(self, blue_mgr, topo, threshold=10, time_window=5.0):
        """
        blue_mgr: instance of BlueObservationManager
        pcap_directory: directory where the pcap files are stored
        threshold: number of distinct ports in time window to trigger scan detection
        time_window: seconds within which connections must occur
        """
        self.blue_mgr = blue_mgr
        self.pcap_directory = "/home/captures/"
        self.threshold = threshold
        self.time_window = time_window
        self.topo = topo

    def shannon_entropy(self,data):
        """Compute Shannon entropy of the byte data."""
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

    def compute_file_density(self,path):
        """Compute normalized entropy (density) of a file."""
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if not data:
                return 0.0
            return self.shannon_entropy(data)
        except Exception as e:
            print(f"[!] Could not read {path}: {e}")
            return 0.0

    def detect(self,host,directory):
        """Compute sum of density (entropy) for all files in the directory tree."""
        total_density = 0.0
        file_count = 0

        for root, dirs, files in os.walk(directory):
            for name in files:
                filepath = os.path.join(root, name)
                if os.path.islink(filepath):
                    continue  # Skip symlinks
                density = self.compute_file_density(filepath)
                print(f"[+] {filepath}: density = {density:.4f}")
                total_density += density
                file_count += 1

        print(f"\n[✓] Total density: {total_density:.4f} over {file_count} files")
        self.blue_mgr.get_observations()["hosts"][host.name]["density"] = total_density
        return False
    



