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

    def detect(self,host):
        """Compute sum of density (entropy) for all files in the directory tree."""
        total_density = self.blue_mgr.get_observations()["hosts"][host.name]["density"]
        file_count = 0

        resulst = host.cmd(f"python3 /home/hacker/red_scripts/file_processor.py {self.pcap_directory}")
        for line in resulst.splitlines():
            if "Density:" in line:
                try:
                    density_value = float(line.split("Density:")[1].strip())
                    total_density += density_value
                    file_count += 1
                except ValueError:
                    print(f"Warning: Could not parse density value from line: {line}")
        print(f"\n[✓] Total density: {total_density:.4f} over {file_count} files")
        self.blue_mgr.get_observations()["hosts"][host.name]["density"] = total_density
        return False
    



