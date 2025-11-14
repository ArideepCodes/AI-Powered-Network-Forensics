import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import os

def parse_pcap_file(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        return parse_packets(packets)
    except Exception as e:
        raise Exception(f"Error parsing PCAP file: {str(e)}")

def parse_packets(packets):
    packet_data = []
    
    for i, packet in enumerate(packets):
        packet_info = {
            'packet_num': i + 1,
            'timestamp': datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S.%f'),
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'length': len(packet),
            'flags': None,
            'payload_size': 0,
            'info': ''
        }
        
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = packet[IP].proto
            
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
        
        if Raw in packet:
            packet_info['payload_size'] = len(packet[Raw].load)
        
        packet_data.append(packet_info)
    
    return pd.DataFrame(packet_data)

def extract_packet_features(packet_row):
    features = []
    
    features.append(packet_row.get('length', 0))
    features.append(packet_row.get('payload_size', 0))
    features.append(1 if packet_row.get('protocol') == 'TCP' else 0)
    features.append(1 if packet_row.get('protocol') == 'UDP' else 0)
    features.append(1 if packet_row.get('protocol') == 'ICMP' else 0)
    
    src_port = packet_row.get('src_port', 0)
    dst_port = packet_row.get('dst_port', 0)
    features.append(src_port if src_port else 0)
    features.append(dst_port if dst_port else 0)
    
    well_known_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080]
    features.append(1 if dst_port in well_known_ports else 0)
    
    flags_str = str(packet_row.get('flags', ''))
    features.append(1 if 'S' in flags_str else 0)
    features.append(1 if 'F' in flags_str else 0)
    
    return features
