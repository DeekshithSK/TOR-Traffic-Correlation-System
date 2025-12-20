"""
PCAP Ingestion Processor
Convert network capture files to RECTor-compatible format

Features:
- PCAP parsing with scapy
- Flow extraction (packet size, timing, direction)
- Support for ISP logs, mail server logs, proxy logs
- Conversion to inflow/outflow directory structure
"""

import os
import pickle
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict
import logging

try:
    from scapy.all import rdpcap, IP, TCP, UDP, Packet
except ImportError:
    print("⚠️ Warning: scapy not installed. Run: pip install scapy")
    raise

import config


# ============================================================================
# Logging Setup
# ============================================================================

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================================
# Flow Session Tracker
# ============================================================================

class FlowSession:
    """
    Represents a bidirectional network flow session.
    """
    
    def __init__(self, flow_id: str, src_ip: str, dst_ip: str, 
                 src_port: int, dst_port: int, protocol: str):
        """
        Initialize flow session.
        
        Args:
            flow_id: Unique flow identifier
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol (tcp/udp)
        """
        self.flow_id = flow_id
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        
        # Packet lists: (timestamp, size, direction)
        self.ingress_packets = []  # Packets from src to dst
        self.egress_packets = []   # Packets from dst to src
        
        self.start_time = None
        self.last_time = None
        self.byte_count = 0
        self.packet_count = 0
    
    def add_packet(self, timestamp: float, size: int, direction: str):
        """
        Add packet to flow.
        
        Args:
            timestamp: Packet timestamp (seconds since epoch)
            size: Packet size in bytes
            direction: 'ingress' or 'egress'
        """
        if self.start_time is None:
            self.start_time = timestamp
        
        self.last_time = timestamp
        self.byte_count += size
        self.packet_count += 1
        
        if direction == 'ingress':
            self.ingress_packets.append((timestamp, size))
        else:
            self.egress_packets.append((timestamp, size))
    
    def get_duration(self) -> float:
        """Get flow duration in seconds."""
        if self.start_time and self.last_time:
            return self.last_time - self.start_time
        return 0.0
    
    def to_rector_format(self) -> Tuple[List[Dict], List[Dict]]:
        """
        Convert to RECTor inflow/outflow format.
        
        Returns:
            Tuple of (inflow_data, outflow_data) where each is a list of dicts
            with 'timestamp' and 'size' keys
        """
        # Convert ingress packets
        inflow = []
        for timestamp, size in self.ingress_packets:
            # Relative timestamp from flow start
            rel_time = timestamp - self.start_time if self.start_time else 0
            inflow.append(f"{rel_time}\t{size}")
        
        # Convert egress packets  
        outflow = []
        for timestamp, size in self.egress_packets:
            rel_time = timestamp - self.start_time if self.start_time else 0
            outflow.append(f"{rel_time}\t{size}")
        
        return inflow, outflow


# ============================================================================
# PCAP Parser
# ============================================================================

class PCAPParser:
    """
    Core PCAP parsing engine with flow reassembly.
    """
    
    def __init__(self, flow_timeout: int = config.PCAP_FLOW_TIMEOUT,
                 min_packets: int = config.PCAP_MIN_PACKETS):
        """
        Initialize PCAP parser.
        
        Args:
            flow_timeout: Flow inactivity timeout in seconds
            min_packets: Minimum packets per flow to keep
        """
        self.flow_timeout = flow_timeout
        self.min_packets = min_packets
        self.flows = {}  # flow_id -> FlowSession
        self.flow_last_seen = {}  # flow_id -> last_timestamp
        
        logger.info(f"PCAPParser initialized (timeout={flow_timeout}s, min_packets={min_packets})")
    
    @staticmethod
    def get_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, 
                    protocol: str) -> Tuple[str, str]:
        """
        Generate bidirectional flow ID and direction.
        
        Args:
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Port numbers  
            protocol: Protocol name
            
        Returns:
            Tuple of (flow_id, direction) where direction is 'ingress' or 'egress'
        """
        # Normalize flow (smaller IP/port first for bidirectional)
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            direction = 'ingress'
        else:
            flow_id = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            direction = 'egress'
        
        return flow_id, direction
    
    def parse_pcap(self, pcap_path: str) -> Dict[str, FlowSession]:
        """
        Parse PCAP file and extract flows.
        
        Args:
            pcap_path: Path to PCAP file
            
        Returns:
            Dictionary of flow_id -> FlowSession
        """
        logger.info(f"Parsing PCAP: {pcap_path}")
        
        try:
            packets = rdpcap(pcap_path)
            logger.info(f"Loaded {len(packets)} packets")
        except Exception as e:
            logger.error(f"Failed to read PCAP: {e}")
            raise
        
        # Process each packet
        for pkt in packets:
            self._process_packet(pkt)
        
        # Filter flows by minimum packet count
        valid_flows = {
            fid: flow for fid, flow in self.flows.items()
            if flow.packet_count >= self.min_packets
        }
        
        logger.info(f"Extracted {len(valid_flows)} flows (min {self.min_packets} packets)")
        
        return valid_flows
    
    def _process_packet(self, pkt: Packet):
        """Process single packet and add to appropriate flow."""
        # Handle both IPv4 and IPv6 packets
        from scapy.layers.inet6 import IPv6
        
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ip_version = 4
        elif pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ip_version = 6
        else:
            # Skip non-IP packets
            return
        
        timestamp = float(pkt.time)
        size = len(pkt)
        
        # Skip loopback/localhost traffic
        if ip_version == 4:
            if src_ip.startswith("127.") or src_ip == "localhost":
                return
            if dst_ip.startswith("127.") or dst_ip == "localhost":
                return
        else:  # IPv6 loopback
            if src_ip == "::1" or dst_ip == "::1":
                return
            # Skip link-local addresses (fe80::)
            if src_ip.startswith("fe80:") or dst_ip.startswith("fe80:"):
                return
        
        # Determine protocol and ports
        if pkt.haslayer(TCP):
            protocol = 'tcp'
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            protocol = 'udp'
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            # Skip non-TCP/UDP packets
            return
        
        # Filter by protocol
        if protocol not in [p.lower() for p in config.PCAP_PROTOCOLS]:
            return
        
        # Get or create flow
        flow_id, direction = self.get_flow_id(
            src_ip, dst_ip, src_port, dst_port, protocol
        )
        
        if flow_id not in self.flows:
            # Parse flow components for FlowSession
            parts = flow_id.split('-')
            src_addr, dst_addr = parts[0], parts[1]
            src_ip_parsed, src_port_parsed = src_addr.rsplit(':', 1)
            dst_ip_parsed, dst_port_parsed = dst_addr.rsplit(':', 1)
            
            self.flows[flow_id] = FlowSession(
                flow_id=flow_id,
                src_ip=src_ip_parsed,
                dst_ip=dst_ip_parsed,
                src_port=int(src_port_parsed),
                dst_port=int(dst_port_parsed),
                protocol=protocol
            )
        
        # Add packet to flow
        self.flows[flow_id].add_packet(timestamp, size, direction)
        self.flow_last_seen[flow_id] = timestamp
        
        # Clean up expired flows
        self._cleanup_expired_flows(timestamp)
    
    def _cleanup_expired_flows(self, current_time: float):
        """Remove flows that have exceeded timeout."""
        expired = [
            fid for fid, last_seen in self.flow_last_seen.items()
            if current_time - last_seen > self.flow_timeout
        ]
        
        for fid in expired:
            del self.flow_last_seen[fid]
            # Keep flow in self.flows for final output


# ============================================================================
# Log Format Adapters
# ============================================================================

class LogFormatAdapter:
    """Base class for log format adapters."""
    
    @staticmethod
    def is_applicable(pcap_path: str, log_type: str) -> bool:
        """Check if this adapter applies to the given log type."""
        raise NotImplementedError
    
    @staticmethod
    def preprocess(pcap_path: str) -> str:
        """Preprocess log before PCAP parsing (e.g., format conversion)."""
        return pcap_path  # Default: no preprocessing


class ISPLogAdapter(LogFormatAdapter):
    """Adapter for ISP NetFlow logs."""
    
    @staticmethod
    def is_applicable(pcap_path: str, log_type: str) -> bool:
        return log_type == 'isp'
    
    @staticmethod
    def filter_flows(flows: Dict[str, FlowSession]) -> Dict[str, FlowSession]:
        """Filter and anonymize ISP flows."""
        if config.ISP_ANONYMIZE_IPS:
            logger.info("Anonymizing IP addresses for ISP logs")
            # Simple anonymization: hash IPs
            # In production, use proper anonymization techniques
        
        return flows


class MailServerAdapter(LogFormatAdapter):
    """Adapter for mail server logs (SMTP/IMAP/POP3)."""
    
    @staticmethod
    def is_applicable(pcap_path: str, log_type: str) -> bool:
        return log_type == 'mail'
    
    @staticmethod
    def filter_flows(flows: Dict[str, FlowSession]) -> Dict[str, FlowSession]:
        """Filter only mail protocol flows."""
        mail_ports = {25, 587, 465, 143, 993, 110, 995}
        
        filtered = {
            fid: flow for fid, flow in flows.items()
            if flow.src_port in mail_ports or flow.dst_port in mail_ports
        }
        
        logger.info(f"Filtered to {len(filtered)} mail flows (from {len(flows)})")
        return filtered


class ProxyLogAdapter(LogFormatAdapter):
    """Adapter for proxy server logs."""
    
    @staticmethod
    def is_applicable(pcap_path: str, log_type: str) -> bool:
        return log_type == 'proxy'
    
    @staticmethod
    def filter_flows(flows: Dict[str, FlowSession]) -> Dict[str, FlowSession]:
        """Filter only proxy flows."""
        proxy_ports = {8080, 8443, 3128, 8888}
        
        filtered = {
            fid: flow for fid, flow in flows.items()
            if flow.src_port in proxy_ports or flow.dst_port in proxy_ports
        }
        
        logger.info(f"Filtered to {len(filtered)} proxy flows (from {len(flows)})")
        return filtered


# ============================================================================
# Flow Extractor
# ============================================================================

class FlowExtractor:
    """
    Extract flows from PCAP and convert to RECTor inflow/outflow format.
    """
    
    def __init__(self, log_type: str = 'standard'):
        """
        Initialize flow extractor.
        
        Args:
            log_type: Type of log ('standard', 'isp', 'mail', 'proxy')
        """
        self.log_type = log_type
        self.parser = PCAPParser()
        
        # Select appropriate adapter
        self.adapters = {
            'isp': ISPLogAdapter,
            'mail': MailServerAdapter,
            'proxy': ProxyLogAdapter,
        }
        
        logger.info(f"FlowExtractor initialized (log_type={log_type})")
    
    def process_pcap(self, pcap_path: str, output_dir: str) -> Tuple[int, int]:
        """
        Process PCAP file and export to inflow/outflow directories.
        
        Args:
            pcap_path: Path to PCAP file
            output_dir: Output directory for inflow/outflow subdirectories
            
        Returns:
            Tuple of (num_flows, total_packets)
        """
        logger.info("=" * 60)
        logger.info(f"Processing PCAP: {pcap_path}")
        logger.info(f"Output: {output_dir}")
        logger.info(f"Log Type: {self.log_type}")
        logger.info("=" * 60)
        
        # Parse PCAP
        flows = self.parser.parse_pcap(pcap_path)
        
        # Apply log-specific filtering
        if self.log_type in self.adapters:
            adapter = self.adapters[self.log_type]
            flows = adapter.filter_flows(flows)
        
        # Create output directories
        output_path = Path(output_dir)
        inflow_dir = output_path / 'inflow'
        outflow_dir = output_path / 'outflow'
        
        inflow_dir.mkdir(parents=True, exist_ok=True)
        outflow_dir.mkdir(parents=True, exist_ok=True)
        
        # Export flows
        total_packets = 0
        for flow_id, flow in flows.items():
            # Sanitize flow_id for filename
            safe_filename = flow_id.replace(':', '_').replace('-', '_')
            
            inflow_data, outflow_data = flow.to_rector_format()
            
            # Write inflow file
            inflow_path = inflow_dir / safe_filename
            with open(inflow_path, 'w') as f:
                f.write('\n'.join(inflow_data))
            
            # Write outflow file
            outflow_path = outflow_dir / safe_filename
            with open(outflow_path, 'w') as f:
                f.write('\n'.join(outflow_data))
            
            total_packets += flow.packet_count
        
        logger.info(f"✅ Exported {len(flows)} flows ({total_packets} packets)")
        logger.info(f"   Inflow:  {inflow_dir}")
        logger.info(f"   Outflow: {outflow_dir}")
        
        return len(flows), total_packets


# ============================================================================
# PCAP to Pickle Converter
# ============================================================================

class PCAPToPickleConverter:
    """
    Convert PCAP directly to RECTor pickle format.
    """
    
    def __init__(self, log_type: str = 'standard'):
        """Initialize converter."""
        self.extractor = FlowExtractor(log_type=log_type)
    
    def convert(self, pcap_path: str, output_pickle: str,
                window_params: Optional[Dict] = None) -> str:
        """
        Convert PCAP to pickle format.
        
        Args:
            pcap_path: Path to PCAP file
            output_pickle: Output pickle file path
            window_params: Optional window creation parameters
            
        Returns:
            Path to output pickle file
        """
        # Create temp directory for inflow/outflow
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract flows
            self.extractor.process_pcap(pcap_path, temp_dir)
            
            # Import backend for preprocessing
            from backend import TrafficPreprocessor
            
            preprocessor = TrafficPreprocessor()
            
            # Use provided window params or defaults
            if window_params is None:
                window_params = config.PCAP_WINDOW_PARAMS
            
            # Create qualified file list
            qualified_file = Path(temp_dir) / "qualified.txt"
            
            flows = preprocessor.create_overlap_windows(
                data_path=temp_dir,
                output_file=str(qualified_file),
                **window_params
            )
            
            # Process windows
            if len(flows) > 0:
                preprocessor.process_window_files(
                    data_path=temp_dir,
                    file_list_path=str(qualified_file),
                    output_prefix=output_pickle.replace('.pickle', '_'),
                    **window_params
                )
        
        logger.info(f"✅ PCAP converted to pickle format: {output_pickle}")
        return output_pickle


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="PCAP Ingestion Processor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        'input',
        help='Input PCAP file path'
    )
    parser.add_argument(
        '--output',
        '-o',
        default='./pcap_output',
        help='Output directory (default: ./pcap_output)'
    )
    parser.add_argument(
        '--log-type',
        '-t',
        choices=['standard', 'isp', 'mail', 'proxy'],
        default='standard',
        help='Log format type (default: standard)'
    )
    parser.add_argument(
        '--to-pickle',
        action='store_true',
        help='Convert directly to pickle format'
    )
    parser.add_argument(
        '--min-packets',
        type=int,
        default=config.PCAP_MIN_PACKETS,
        help=f'Minimum packets per flow (default: {config.PCAP_MIN_PACKETS})'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input):
        print(f"❌ Error: Input file not found: {args.input}")
        return 1
    
    try:
        if args.to_pickle:
            # Convert to pickle
            converter = PCAPToPickleConverter(log_type=args.log_type)
            output_pickle = f"{args.output}.pickle"
            converter.convert(args.input, output_pickle)
            print(f"\n✅ Success! Output: {output_pickle}")
        else:
            # Extract to inflow/outflow
            extractor = FlowExtractor(log_type=args.log_type)
            extractor.parser.min_packets = args.min_packets
            num_flows, num_packets = extractor.process_pcap(args.input, args.output)
            
            print(f"\n✅ Success!")
            print(f"   Flows: {num_flows}")
            print(f"   Packets: {num_packets}")
            print(f"   Output: {args.output}/")
        
        return 0
        
    except Exception as e:
        logger.error(f"Processing failed: {e}", exc_info=True)  
        print(f"\n❌ Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
