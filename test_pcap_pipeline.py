
import unittest
import os
import shutil
import numpy as np
from scapy.all import wrpcap, Ether, IP, TCP
from pcap_ingest.pcap_to_flows import extract_flows_from_pcap
from flow_store.raw_flows import FlowStore

class TestPCAPPipeline(unittest.TestCase):
    def setUp(self):
        self.test_dir = "test_pcap_output"
        os.makedirs(self.test_dir, exist_ok=True)
        self.pcap_path = os.path.join(self.test_dir, "test.pcap")
        
        # Create synthetic PCAP
        # Flow 1: Client (10.0.0.1:12345) -> Guard (1.2.3.4:443)
        pkts = []
        base_time = 1000.0
        
        # 10 packets
        for i in range(10):
            # Client -> Server (Outgoing)
            pkt = Ether()/IP(src="10.0.0.1", dst="1.2.3.4")/TCP(sport=12345, dport=443)/("A"*100)
            pkt.time = base_time + i * 0.1
            pkts.append(pkt)
            
            # Server -> Client (Incoming)
            pkt2 = Ether()/IP(src="1.2.3.4", dst="10.0.0.1")/TCP(sport=443, dport=12345)/("B"*200)
            pkt2.time = base_time + i * 0.1 + 0.05
            pkts.append(pkt2)
            
        wrpcap(self.pcap_path, pkts)
        
    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_pcap_ingestion(self):
        """Test extraction of flows from PCAP."""
        flows = extract_flows_from_pcap(self.pcap_path, min_packets=2)
        
        self.assertTrue(len(flows) > 0)
        
        # Verify Flow ID structure
        # Expected: 10.0.0.1:12345-1.2.3.4:443-tcp
        self.assertIn("10.0.0.1:12345-1.2.3.4:443-tcp", flows)
        
        data = flows["10.0.0.1:12345-1.2.3.4:443-tcp"]
        self.assertEqual(data.shape[0], 20) # 10 out + 10 in
        self.assertEqual(data.shape[1], 3)  # size, ts, dir
        
        # Verify values
        # Outgoing: + size (header + 100 payload approx 154)
        # Incoming: - size (header + 200 payload approx 254)
        
        # Index 0 is Size
        self.assertTrue(data[0, 0] > 0) # First packet was outgoing
        
        # Index 2 is Direction
        self.assertEqual(data[0, 2], 1.0) 

    def test_flow_store(self):
        """Test simple FlowStore operations."""
        flows = extract_flows_from_pcap(self.pcap_path)
        store = FlowStore()
        store.clear()
        store.save_flows(flows)
        
        self.assertEqual(len(store.get_all_flow_ids()), 1)
        self.assertIsNotNone(store.get_flow("10.0.0.1:12345-1.2.3.4:443-tcp"))

if __name__ == "__main__":
    unittest.main()
