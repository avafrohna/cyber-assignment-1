import sys
import scapy.all as scapy
from datetime import datetime

timestamp = {}
alert_count = {}

def alert(log_file, message):
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

            flags = None
            flags_start = options.find('flags: ')
            if flags_start != -1:
                flags_start += len('flags: ')
                flags_end = options.find(';', flags_start)
                flags = options[flags_start:flags_end]

            detection_filter = None
            filter_start = options.find('detection_filter:')
            if filter_start != -1:
                filter_start += len('detection_filter: ')
                filter_end = options.find(';', filter_start)
                detection_filter = options[filter_start:filter_end].strip().split(',')
                detection_filter = [item.strip() for item in detection_filter]

            rules.append({
                'protocol': protocol,
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'msg': msg,
                'content': content,
                'flags': flags,
                'detection_filter': detection_filter
            })
    return rules

def apply_rules(packets, rules):
    with open("IDS_log.txt", "w") as log_file:
        for packet in packets:
            for rule in rules:
                if rule['protocol'] == "tcp" and packet.haslayer(scapy.TCP):
                    if ((packet[scapy.IP].src == rule['src_ip'] or rule['src_ip'] == "any") and (packet[scapy.IP].dst == rule['dst_ip'] or rule['dst_ip'] == "any")):
                        ruleIsTrue = True
                        if rule.get('flags'):
                            tcp_flags = packet[scapy.TCP].flags
                            if rule['flags'] not in tcp_flags:
                                ruleIsTrue = False
                        
                        if rule.get('content'):
                            if not packet.haslayer(scapy.Raw) or rule['content'] not in packet[scapy.Raw].load.decode(errors='ignore'):
                                ruleIsTrue = False
                        
                        if ruleIsTrue and rule.get('detection_filter'):
                            count = int(rule['detection_filter'][0].split()[1])
                            seconds = int(rule['detection_filter'][1].split()[1])
                            rule_id = f"{rule['src_ip']}_{rule['dst_ip']}_{rule['flags']}_{rule['content']}"
                            if rule_id not in timestamp:
                                timestamp[rule_id] = []
                                alert_count[rule_id] = 0

                            timestamp[rule_id].append(packet.time)
                            timestamp[rule_id] = [t for t in timestamp[rule_id] if packet.time - t <= seconds]
                            
                            if len(timestamp[rule_id]) > count:
                                if alert_count[rule_id] < len(timestamp[rule_id]) - count:
                                    alert_count[rule_id] += 1
                                    alert(log_file, rule['msg'])
                            else:
                                alert_count[rule_id] = 0
                        elif ruleIsTrue:
                            alert(log_file, rule['msg'])
                
                elif rule['protocol'] == "icmp" and packet.haslayer(scapy.ICMP):
                    if (rule['src_ip'] == packet[scapy.IP].src) or rule['src_ip'] == "any":
                        alert(log_file, rule['msg'])
                
                elif rule['protocol'] == "ip" and packet.haslayer(scapy.IP):
                    if ((packet[scapy.IP].src == rule['src_ip'] or rule['src_ip'] == "any") and (packet[scapy.IP].dst == rule['dst_ip'] or rule['dst_ip'] == "any")):
                        alert(log_file, rule['msg'])
                
                elif rule['protocol'] == "udp" and packet.haslayer(scapy.UDP):
                    if ((packet[scapy.IP].src == rule['src_ip'] or rule['src_ip'] == "any") and (packet[scapy.IP].dst == rule['dst_ip'] or rule['dst_ip'] == "any")):
                        if rule.get('content'):
                            if packet.haslayer(scapy.Raw) and rule['content'] in packet[scapy.Raw].load.decode(errors='ignore'):
                                alert(log_file, rule['msg'])
                        elif ((packet[scapy.UDP].sport == int(rule['src_port']) or rule['src_port'] == "any") and (packet[scapy.UDP].dport == int(rule['dst_port']) or rule['dst_port'] == "any")):
                            alert(log_file, rule['msg'])

def main():
    pcap_file = sys.argv[1]
    rules_file = sys.argv[2]
    
    packets = parse_pcap(pcap_file)
    rules = parse_rules(rules_file)
    apply_rules(packets, rules)

if __name__ == "__main__":
    main()
