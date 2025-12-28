"""
PCAP Ingestion Module
Responsibility: Read PCAP files, parse packets, and extract flows in the operational format.
"""

import numpy as np
from typing import Dict, Tuple, List, Optional
from scapy.all import rdpcap, IP, TCP, UDP
import logging

logger = logging.getLogger(__name__)

def extract_flows_from_pcap(pcap_path: str, min_packets: int = 5) -> Dict[str, np.ndarray]:
    """
    Reads a PCAP file and extracts TCP flows.
    
    Args:
        pcap_path: Path to the .pcap file.
        min_packets: Minimum number of packets to consider a valid flow.
        
    Returns:
        Dict[flow_id, np.ndarray]:
            Keys are flow IDs (e.g., "192.168.1.5:443-10.0.0.1:5678-tcp").
            Values are NumPy arrays of shape (N, 3).
            Columns:
                0: Packet Size (signed: + for outgoing, - for incoming)
                1: Relative Timestamp (seconds from first packet)
                2: Direction (+1 for outgoing, -1 for incoming)
    """
    logger.info(f"Ingesting PCAP: {pcap_path}")
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        logger.error(f"Failed to read PCAP {pcap_path}: {e}")
        return {}

    flows_data: Dict[str, List[Tuple[float, int, int]]] = {}
    
    count = 0
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
            
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        timestamp = float(pkt.time)
        size = len(pkt)
        
        if pkt.haslayer(TCP):
            proto = 'tcp'
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP): # Optional support, though strictly we focus on TCP/TOR
            proto = 'udp'
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue
            
        
        
        
        forward_key = f"{src_ip}:{sport}-{dst_ip}:{dport}-{proto}"
        reverse_key = f"{dst_ip}:{dport}-{src_ip}:{sport}-{proto}"
        
        if forward_key in flows_data:
            flow_key = forward_key
            direction = 1 # Matches Originator -> Responder
            signed_size = size
        elif reverse_key in flows_data:
            flow_key = reverse_key
            direction = -1 # Matches Responder -> Originator
            signed_size = -size
        else:
            flow_key = forward_key
            flows_data[flow_key] = []
            direction = 1
            signed_size = size

        flows_data[flow_key].append((timestamp, signed_size, direction))
        count += 1

    logger.info(f"Parsed {count} packets into {len(flows_data)} raw flows.")

    valid_flows: Dict[str, np.ndarray] = {}
    
    for fid, pkt_list in flows_data.items():
        if len(pkt_list) < min_packets:
            continue
            
        pkt_list.sort(key=lambda x: x[0])
        
        
        data = np.zeros((len(pkt_list), 3), dtype=np.float32)
        base_time = pkt_list[0][0]
        
        for i, (ts, s_size, direct) in enumerate(pkt_list):
            data[i, 0] = s_size       # Signed Size
            data[i, 1] = ts - base_time # Relative Timestamp
            data[i, 2] = direct       # Direction (+1/-1)
            
        valid_flows[fid] = data

    logger.info(f"Retained {len(valid_flows)} flows after filtering (min_packets={min_packets}).")
    return valid_flows
