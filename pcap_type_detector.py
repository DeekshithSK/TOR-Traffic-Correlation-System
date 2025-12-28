"""
PCAP Type Detector Module

Analyzes PCAP flows to determine if the capture is from:
- Entry-side (Client → Tor Guard)
- Exit-side (Tor Exit → Destination)

Detection is PURELY flow-based - NO filename heuristics.

FORENSIC RATIONALE:
- Entry-side PCAPs contain traffic to Tor Guard relays (port 9001, Tor cell sizes)
- Exit-side PCAPs contain traffic to arbitrary destinations (port 80/443, varied sizes)
"""

import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from pcap_processor import PCAPParser

logger = logging.getLogger(__name__)


class PCAPTypeDetector:
    """
    Flow-based PCAP type detection.
    
    Uses multiple heuristics to classify PCAPs:
    1. Tor relay role lookup (Guard vs Exit) from consensus
    2. Port patterns (9001 = Tor OR port)
    3. Packet size distribution (Tor cells ~512 bytes)
    4. Traffic directionality
    """
    
    TOR_OR_PORTS = {9001, 9030, 9051}  # Standard Tor ports
    TOR_CELL_SIZE_MIN = 500
    TOR_CELL_SIZE_MAX = 600
    
    APPLICATION_PORTS = {80, 443, 8080, 8443}
    
    PRIVATE_IP_PREFIXES = (
        '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.', 'localhost'
    )
    
    def __init__(self):
        """Initialize detector with optional Tor consensus."""
        self.consensus = None
        self.consensus_available = False
        self._load_tor_consensus()
    
    def _load_tor_consensus(self):
        """Attempt to load Tor consensus for relay lookups."""
        try:
            from tor_path_inference import TorConsensusClient
            self.consensus = TorConsensusClient()
            self.consensus.fetch_consensus()
            self.consensus_available = self.consensus.relay_count > 0
            if self.consensus_available:
                logger.info(f"✓ Tor consensus loaded: {self.consensus.relay_count} relays")
        except Exception as e:
            logger.warning(f"Tor consensus not available: {e}")
            self.consensus = None
            self.consensus_available = False
    
    def detect(self, pcap_path: str) -> Dict:
        """
        Analyze PCAP and determine type.
        
        Args:
            pcap_path: Path to PCAP file
            
        Returns:
            {
                'type': 'entry' | 'exit' | 'unknown',
                'confidence': float (0.0 - 1.0),
                'evidence': {
                    'guard_ips': int,
                    'exit_ips': int,
                    'tor_port_flows': int,
                    'app_port_flows': int,
                    'tor_cell_packets': int,
                    'total_flows': int,
                    'unique_ips': int
                }
            }
        """
        logger.info(f"📊 Detecting PCAP type: {pcap_path}")
        
        parser = PCAPParser(min_packets=2)
        try:
            flows = parser.parse_pcap(pcap_path)
        except Exception as e:
            logger.error(f"Failed to parse PCAP: {e}")
            return {
                'type': 'unknown',
                'confidence': 0.0,
                'evidence': {'error': str(e)}
            }
        
        if not flows:
            return {
                'type': 'unknown',
                'confidence': 0.0,
                'evidence': {'error': 'No flows extracted'}
            }
        
        evidence = self._collect_evidence(flows)
        
        entry_score, exit_score = self._calculate_scores(evidence)
        
        if entry_score > exit_score and entry_score > 0.3:
            pcap_type = 'entry'
            confidence = min(entry_score, 1.0)
        elif exit_score > entry_score and exit_score > 0.3:
            pcap_type = 'exit'
            confidence = min(exit_score, 1.0)
        else:
            pcap_type = 'unknown'
            confidence = max(entry_score, exit_score)
        
        logger.info(f"  Detection result: {pcap_type.upper()} (confidence: {confidence:.0%})")
        logger.info(f"  Evidence: Guards={evidence['guard_ips']}, Exits={evidence['exit_ips']}, "
                   f"TorPorts={evidence['tor_port_flows']}, AppPorts={evidence['app_port_flows']}")
        
        return {
            'type': pcap_type,
            'confidence': confidence,
            'evidence': evidence,
            'scores': {'entry': entry_score, 'exit': exit_score}
        }
    
    def _collect_evidence(self, flows: Dict) -> Dict:
        """Collect detection evidence from flows."""
        evidence = {
            'guard_ips': 0,
            'exit_ips': 0,
            'tor_port_flows': 0,
            'app_port_flows': 0,
            'tor_cell_packets': 0,
            'total_packets': 0,
            'total_flows': len(flows),
            'unique_ips': set(),
            'private_ip_as_src': 0,
            'private_ip_as_dst': 0,
            'non_tor_destinations': 0
        }
        
        for flow_id, flow_session in flows.items():
            src_ip, src_port, dst_ip, dst_port = self._parse_flow_id(flow_id)
            
            if not src_ip or not dst_ip:
                continue
            
            for ip in [src_ip, dst_ip]:
                if not ip.startswith(self.PRIVATE_IP_PREFIXES):
                    evidence['unique_ips'].add(ip)
            
            if src_port in self.TOR_OR_PORTS or dst_port in self.TOR_OR_PORTS:
                evidence['tor_port_flows'] += 1
            
            if src_port in self.APPLICATION_PORTS or dst_port in self.APPLICATION_PORTS:
                evidence['app_port_flows'] += 1
            
            if src_ip.startswith(self.PRIVATE_IP_PREFIXES):
                evidence['private_ip_as_src'] += 1
            if dst_ip.startswith(self.PRIVATE_IP_PREFIXES):
                evidence['private_ip_as_dst'] += 1
            
            if hasattr(flow_session, 'ingress_packets'):
                for ts, size in flow_session.ingress_packets:
                    evidence['total_packets'] += 1
                    if self.TOR_CELL_SIZE_MIN <= size <= self.TOR_CELL_SIZE_MAX:
                        evidence['tor_cell_packets'] += 1
            
            if hasattr(flow_session, 'egress_packets'):
                for ts, size in flow_session.egress_packets:
                    evidence['total_packets'] += 1
                    if self.TOR_CELL_SIZE_MIN <= size <= self.TOR_CELL_SIZE_MAX:
                        evidence['tor_cell_packets'] += 1
            
            if self.consensus_available:
                for ip in [src_ip, dst_ip]:
                    if ip.startswith(self.PRIVATE_IP_PREFIXES):
                        continue
                    
                    relay = self._lookup_relay(ip)
                    if relay:
                        flags = self._get_relay_flags(relay)
                        if 'Guard' in flags:
                            evidence['guard_ips'] += 1
                        if 'Exit' in flags:
                            evidence['exit_ips'] += 1
                    else:
                        evidence['non_tor_destinations'] += 1
        
        evidence['unique_ips'] = len(evidence['unique_ips'])
        
        return evidence
    
    def _calculate_scores(self, evidence: Dict) -> Tuple[float, float]:
        """
        Calculate entry and exit scores from evidence.
        
        CRITICAL: Consensus-verified IPs (guards/exits) are the PRIMARY signal.
        Port patterns are SECONDARY and only significant when IPs are present.
        
        Entry-side indicators:
        - Guard IPs present (STRONG - from consensus)
        - Tor OR ports (9001)
        - Tor cell-sized packets
        - Private IP as source (client → guard)
        
        Exit-side indicators:
        - Exit IPs present (STRONG - from consensus)
        - Application ports (80, 443) - only if exits present
        - Private IP as destination (exit → local server)
        """
        entry_score = 0.0
        exit_score = 0.0
        
        total_flows = max(evidence['total_flows'], 1)
        total_packets = max(evidence['total_packets'], 1)
        unique_ips = max(evidence['unique_ips'], 1)
        
        guard_ips = evidence.get('guard_ips', 0)
        exit_ips = evidence.get('exit_ips', 0)
        
        
        if guard_ips > 0:
            entry_score += 0.50 * min(guard_ips / unique_ips + 0.5, 1.0)
        
        if exit_ips > 0:
            exit_score += 0.50 * min(exit_ips / unique_ips + 0.5, 1.0)
        
        if guard_ips > 0 and exit_ips == 0:
            entry_score += 0.30  # Strong boost for entry
            exit_score *= 0.3   # Penalize exit score
        
        if exit_ips > 0 and guard_ips == 0:
            exit_score += 0.30  # Strong boost for exit
            entry_score *= 0.3  # Penalize entry score
        
        
        if evidence['tor_port_flows'] > 0:
            tor_port_ratio = evidence['tor_port_flows'] / total_flows
            entry_score += 0.15 * min(tor_port_ratio * 2, 1.0)
        
        if evidence['app_port_flows'] > 0 and exit_ips > 0:
            app_port_ratio = evidence['app_port_flows'] / total_flows
            exit_score += 0.15 * min(app_port_ratio * 2, 1.0)
        
        
        if evidence['tor_cell_packets'] > 0:
            cell_ratio = evidence['tor_cell_packets'] / total_packets
            entry_score += 0.10 * min(cell_ratio * 2, 1.0)
        
        if evidence['private_ip_as_src'] > evidence['private_ip_as_dst']:
            entry_score += 0.10
        elif evidence['private_ip_as_dst'] > evidence['private_ip_as_src']:
            exit_score += 0.10
        
        entry_score = min(entry_score, 1.0)
        exit_score = min(exit_score, 1.0)
        
        return entry_score, exit_score
    
    def _parse_flow_id(self, flow_id: str) -> Tuple[Optional[str], int, Optional[str], int]:
        """Parse flow ID into components."""
        try:
            parts = flow_id.split('-')
            if len(parts) < 2:
                return None, 0, None, 0
            
            src_part = parts[0]
            dst_part = parts[1]
            
            if ':' in src_part:
                src_ip = src_part.rsplit(':', 1)[0]
                src_port = int(src_part.rsplit(':', 1)[1])
            else:
                src_ip = src_part
                src_port = 0
            
            if ':' in dst_part:
                dst_ip = dst_part.rsplit(':', 1)[0]
                dst_port = int(dst_part.rsplit(':', 1)[1])
            else:
                dst_ip = dst_part
                dst_port = 0
            
            return src_ip, src_port, dst_ip, dst_port
        except Exception:
            return None, 0, None, 0
    
    def _lookup_relay(self, ip: str):
        """Lookup relay in Tor consensus."""
        if not self.consensus_available or not self.consensus:
            return None
        
        try:
            relays = self.consensus.get_relays_by_ip(ip)
            if relays:
                return relays[0] if isinstance(relays, list) else relays
        except Exception:
            pass
        
        return None
    
    def _get_relay_flags(self, relay) -> List[str]:
        """Extract flags from relay object."""
        if hasattr(relay, 'flags'):
            return relay.flags if isinstance(relay.flags, list) else list(relay.flags)
        return []


def detect_pcap_type(pcap_path: str) -> str:
    """
    Quick detection function.
    
    Returns: 'entry', 'exit', or 'unknown'
    """
    detector = PCAPTypeDetector()
    result = detector.detect(pcap_path)
    return result['type']


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python pcap_type_detector.py <pcap_file>")
        sys.exit(1)
    
    logging.basicConfig(level=logging.INFO)
    
    detector = PCAPTypeDetector()
    result = detector.detect(sys.argv[1])
    
    print(f"\n{'='*60}")
    print(f"PCAP Type Detection Result")
    print(f"{'='*60}")
    print(f"  Type:       {result['type'].upper()}")
    print(f"  Confidence: {result['confidence']:.0%}")
    print(f"  Evidence:")
    for key, value in result['evidence'].items():
        print(f"    {key}: {value}")
    print(f"{'='*60}")
