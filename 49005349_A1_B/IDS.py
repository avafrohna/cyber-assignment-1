import sys
import os
import scapy.all as scapy
from datetime import datetime

def log_alert(message):
    with open("IDS_log.txt", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"{timestamp} - Alert: {message}\n")

def process_pcap(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    for packet in packets:
        # Task 1
        if packet.haslayer(scapy.TCP):
            log_alert("receive a tcp packet")
        
        # Task 2
        if packet.haslayer(scapy.ICMP):
            if packet[scapy.IP].src == "192.168.0.33":
                log_alert("Detect an ICMP packet from IP address 192.168.0.33")

        # Task 3
        if packet.haslayer(scapy.IP):
            if packet[scapy.IP].src == "192.168.0.44" and packet[scapy.IP].dst == "192.168.0.55":
                log_alert("Detect an ip packets from IP address 192.168.0.44 towards IP address 192.168.0.55")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 IDS.py <path_to_the_pcap_file> <path_to_the_IDS_rules>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]

    if not os.path.isfile(pcap_file):
        print(f"Error: The pcap file '{pcap_file}' does not exist.")
        sys.exit(1)
    
    if not os.path.isfile(rules_file):
        print(f"Error: The IDS rules file '{rules_file}' does not exist.")
        sys.exit(1)
    
    process_pcap(pcap_file)

if __name__ == "__main__":
    main()