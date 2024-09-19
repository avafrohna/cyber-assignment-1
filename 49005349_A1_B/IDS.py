import sys
import os
import scapy.all as scapy
from datetime import datetime

def log_alert(log_file, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write(f"{timestamp} - Alert: {message}\n")

def parse_pcap(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    return packets

def parse_rules(rules_file):
    rules = []
    with open(rules_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("#") or not line: 
                continue
            
            parts = line.split(" ", 7) 
            action = parts[0]
            protocol = parts[1]
            src_ip = parts[2]
            src_port = parts[3]
            dst_ip = parts[5]
            dst_port = parts[6]
            options = parts[7]

            msg_start = options.find('msg: "') + len('msg: "')
            msg_end = options.find('";', msg_start)
            msg = options[msg_start:msg_end]

            content = None
            content_start = options.find('content: "')
            if content_start != -1:
                content_start += len('content: "')
                content_end = options.find('";', content_start)
                content = options[content_start:content_end]

            rules.append({
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'msg': msg,
                'content': content
            })
    return rules

def apply_rules(packets, rules):
    with open("IDS_log.txt", "w") as log_file:
        for packet in packets:
            for rule in rules:
                if rule['protocol'] == "tcp" and packet.haslayer(scapy.TCP):
                    if rule.get('content'):
                        if packet[scapy.IP].src == rule['src_ip'] and packet[scapy.IP].dst == rule['dst_ip']:
                            if packet.haslayer(scapy.Raw) and rule['content'] in packet[scapy.Raw].load.decode(errors='ignore'):
                                log_alert(log_file, rule['msg'])
                        elif packet[scapy.IP].src == rule['src_ip'] and rule['dst_ip'] == "any":
                            if packet.haslayer(scapy.Raw) and rule['content'] in packet[scapy.Raw].load.decode(errors='ignore'):
                                log_alert(log_file, rule['msg'])
                    else:
                        if rule['src_ip'] == "any" and rule['dst_ip'] == "any":
                            log_alert(log_file, rule['msg'])
                        elif packet[scapy.IP].src == rule['src_ip']:
                            log_alert(log_file, rule['msg'])

                elif rule['protocol'] == "icmp" and packet.haslayer(scapy.ICMP):
                    if rule['src_ip'] == "192.168.0.33" and packet[scapy.IP].src == "192.168.0.33":
                        log_alert(log_file, rule['msg'])
                    elif rule['src_ip'] == "any":
                        log_alert(log_file, rule['msg'])

                elif rule['protocol'] == "ip" and packet.haslayer(scapy.IP):
                    if (packet[scapy.IP].src == rule['src_ip'] and packet[scapy.IP].dst == rule['dst_ip']):
                        log_alert(log_file, rule['msg'])
                    elif (packet[scapy.IP].dst == rule['dst_ip'] and packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport == 6666):
                        log_alert(log_file, rule['msg'])

                elif rule['protocol'] == "udp" and packet.haslayer(scapy.UDP):
                    if packet[scapy.IP].src == rule['src_ip'] and packet[scapy.IP].dst == rule['dst_ip']:
                        if rule.get('content'):
                            if packet.haslayer(scapy.Raw) and rule['content'] in packet[scapy.Raw].load.decode(errors='ignore'):
                                log_alert(log_file, rule['msg'])
                        else:
                            if (packet[scapy.IP].src == rule['src_ip'] and
                                packet[scapy.UDP].sport == int(rule['src_port']) and
                                packet[scapy.IP].dst == rule['dst_ip'] and
                                packet[scapy.UDP].dport == int(rule['dst_port'])):
                                log_alert(log_file, rule['msg'])

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
    
    packets = parse_pcap(pcap_file)
    rules = parse_rules(rules_file)
    apply_rules(packets, rules)

if __name__ == "__main__":
    main()
