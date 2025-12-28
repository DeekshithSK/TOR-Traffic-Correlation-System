"""
Flow ID Parser Utility

Extracts IP addresses from flow ID strings.
Supports multiple formats used in the codebase.
"""

import re


def extract_ips_from_flow_id(flow_id: str):
    """
    Extract source and destination IPs from flow ID string.
    
    Supported formats:
    1. src_ip:src_port-dst_ip:dst_port-protocol (e.g., 192.168.1.5:443-10.0.0.1:5678-tcp)
    2. src_ip_src_port_dst_ip_dst_port_protocol (e.g., 192.168.1.2_62133_51.159.211.57_9001_tcp)
    3. Plain IP address (e.g., 51.159.211.57)
    
    Returns:
        Tuple of (src_ip, dst_ip) or (ip, None) for single IP, or (None, None) if parsing fails
    """
    if not flow_id or not isinstance(flow_id, str):
        return None, None
    
    try:
        if ':' in flow_id and '-' in flow_id:
            parts = flow_id.split('-')
            if len(parts) >= 2:
                src_ip = parts[0].split(':')[0]
                dst_ip = parts[1].split(':')[0]
                return src_ip, dst_ip
        
        if '_' in flow_id:
            parts = flow_id.replace('_tcp', '').replace('_udp', '').split('_')
            ips = [p for p in parts if p.count('.') == 3]
            if len(ips) >= 2:
                return ips[0], ips[1]
            elif len(ips) == 1:
                return ips[0], None
        
        if flow_id.count('.') == 3 and all(p.isdigit() for p in flow_id.split('.')):
            return flow_id, None
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, flow_id)
        if len(ips) >= 2:
            return ips[0], ips[1]
        elif len(ips) == 1:
            return ips[0], None
        
        return None, None
        
    except Exception:
        return None, None


def extract_public_ip(flow_id: str) -> str:
    """
    Extract the most likely public (non-private) IP from a flow ID.
    Falls back to any available IP if all are private.
    
    Returns:
        Public IP string or None
    """
    src_ip, dst_ip = extract_ips_from_flow_id(flow_id)
    
    private_prefixes = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                        '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
                        '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', 
                        '172.29.', '172.30.', '172.31.')
    
    for ip in [dst_ip, src_ip]:
        if ip and not ip.startswith(private_prefixes):
            return ip
    
    return dst_ip or src_ip
