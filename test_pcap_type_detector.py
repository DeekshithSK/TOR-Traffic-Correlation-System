#!/usr/bin/env python3
"""
Test Suite for PCAP Type Detector

Tests flow-based PCAP type detection (entry vs exit side).
Verifies NO filename heuristics are used.
"""

import unittest
import os
import shutil
import tempfile
from scapy.all import wrpcap, Ether, IP, TCP


class TestPCAPTypeDetector(unittest.TestCase):
    """Test cases for PCAPTypeDetector."""
    
    def setUp(self):
        """Create temporary directory for test PCAPs."""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up temporary directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def _create_pcap(self, filename: str, packets: list) -> str:
        """Helper to create PCAP file."""
        pcap_path = os.path.join(self.test_dir, filename)
        wrpcap(pcap_path, packets)
        return pcap_path
    
    def _create_entry_side_packets(self) -> list:
        """Create packets typical of entry-side (client → guard) traffic."""
        packets = []
        base_time = 1000.0
        
        # Traffic to Tor OR port 9001 (typical guard connection)
        for i in range(20):
            # Client → Guard (Tor cell-sized packets ~512 bytes)
            pkt = Ether()/IP(src="192.168.1.100", dst="185.220.101.42")/TCP(sport=45678, dport=9001)/("A"*500)
            pkt.time = base_time + i * 0.1
            packets.append(pkt)
            
            # Guard → Client response
            pkt2 = Ether()/IP(src="185.220.101.42", dst="192.168.1.100")/TCP(sport=9001, dport=45678)/("B"*512)
            pkt2.time = base_time + i * 0.1 + 0.05
            packets.append(pkt2)
        
        return packets
    
    def _create_exit_side_packets(self) -> list:
        """Create packets typical of exit-side (exit → destination) traffic."""
        packets = []
        base_time = 1000.0
        
        # Use consistent port for flow aggregation
        ephemeral_port = 54321
        
        # Traffic to standard web ports (typical exit connection)
        for i in range(20):
            # Exit → Web server (varied sizes)
            pkt = Ether()/IP(src="45.33.32.156", dst="93.184.216.34")/TCP(sport=ephemeral_port, dport=443)/("A"*(100 + i*50))
            pkt.time = base_time + i * 0.1
            packets.append(pkt)
            
            # Web server → Exit response
            pkt2 = Ether()/IP(src="93.184.216.34", dst="45.33.32.156")/TCP(sport=443, dport=ephemeral_port)/("B"*(200 + i*100))
            pkt2.time = base_time + i * 0.1 + 0.05
            packets.append(pkt2)
        
        return packets
    
    def test_entry_side_detection_by_tor_port(self):
        """Test detection of entry-side PCAP using Tor OR port."""
        from pcap_type_detector import PCAPTypeDetector
        
        pcap_path = self._create_pcap("test.pcap", self._create_entry_side_packets())
        
        detector = PCAPTypeDetector()
        result = detector.detect(pcap_path)
        
        self.assertIn(result['type'], ['entry', 'unknown'])
        self.assertGreater(result['evidence']['tor_port_flows'], 0)
        print(f"Entry detection: type={result['type']}, confidence={result['confidence']:.0%}")
    
    def test_exit_side_detection_by_app_port(self):
        """Test detection of exit-side PCAP using application ports."""
        from pcap_type_detector import PCAPTypeDetector
        
        pcap_path = self._create_pcap("test.pcap", self._create_exit_side_packets())
        
        detector = PCAPTypeDetector()
        result = detector.detect(pcap_path)
        
        self.assertIn(result['type'], ['exit', 'unknown'])
        self.assertGreater(result['evidence']['app_port_flows'], 0)
        print(f"Exit detection: type={result['type']}, confidence={result['confidence']:.0%}")
    
    def test_no_filename_fallback(self):
        """
        CRITICAL TEST: Filename should NOT influence detection.
        
        A file named 'exit_capture.pcap' with entry-side traffic
        should STILL be detected as 'entry', not 'exit'.
        """
        from pcap_type_detector import PCAPTypeDetector
        
        # Create entry-side traffic but name file as "exit"
        pcap_path = self._create_pcap("exit_capture.pcap", self._create_entry_side_packets())
        
        detector = PCAPTypeDetector()
        result = detector.detect(pcap_path)
        
        # Should detect based on traffic, not filename
        # With Tor port 9001 traffic, should lean toward 'entry'
        self.assertNotEqual(
            result['type'], 
            'exit',
            "Detector incorrectly used filename 'exit_capture.pcap' instead of flow analysis"
        )
        print(f"Filename fallback test: type={result['type']} (expected: NOT 'exit')")
    
    def test_empty_pcap_returns_unknown(self):
        """Test that empty PCAP returns unknown type."""
        from pcap_type_detector import PCAPTypeDetector
        
        pcap_path = self._create_pcap("empty.pcap", [])
        
        detector = PCAPTypeDetector()
        result = detector.detect(pcap_path)
        
        self.assertEqual(result['type'], 'unknown')
        self.assertEqual(result['confidence'], 0.0)
    
    def test_evidence_collection(self):
        """Test that evidence is properly collected."""
        from pcap_type_detector import PCAPTypeDetector
        
        pcap_path = self._create_pcap("test.pcap", self._create_entry_side_packets())
        
        detector = PCAPTypeDetector()
        result = detector.detect(pcap_path)
        
        evidence = result['evidence']
        
        # Check required evidence fields exist
        self.assertIn('guard_ips', evidence)
        self.assertIn('exit_ips', evidence)
        self.assertIn('tor_port_flows', evidence)
        self.assertIn('app_port_flows', evidence)
        self.assertIn('total_flows', evidence)
        self.assertIn('unique_ips', evidence)
        
        # Verify at least one flow was detected
        self.assertGreater(evidence['total_flows'], 0)


def random_port():
    """Generate random ephemeral port."""
    import random
    return random.randint(32768, 65535)


if __name__ == "__main__":
    unittest.main(verbosity=2)
