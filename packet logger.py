from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import csv

OUTPUT_FILE = "packet_log.csv"

def packet_callback(packet):
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"

        row = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "source": packet[IP].src,
            "destination": packet[IP].dst,
            "protocol": protocol,
            "length": len(packet)
        }

        print(row)

        with open(OUTPUT_FILE, "a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=row.keys())
            if file.tell() == 0:
                writer.writeheader()
            writer.writerow(row)

print("Starting packet metadata logger...")
sniff(prn=packet_callback, store=False, timeout=30)