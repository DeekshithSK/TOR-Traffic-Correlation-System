"""
Test Suite for Police-Ready Extensions
Covers:
- Entry Node Aggregation
- TOR Directory Integration
- Forensic Report Generation
- Dashboard Data Loading
"""

import unittest
import os
import shutil
import json
from pathlib import Path
from analysis.entry_node_aggregator import EntryNodeAggregator
from tor_intel.tor_directory import TorDirectory
from reporting.forensic_report import ForensicReportGenerator
from viz.dashboard import load_evidence

class TestPoliceExtensions(unittest.TestCase):
    
    def setUp(self):
        self.test_dir = Path("test_extensions_tmp")
        self.test_dir.mkdir(exist_ok=True)
        self.evidence_path = self.test_dir / "evidence.json"
        self.cache_path = self.test_dir / "tor_cache.json"
        self.report_dir = self.test_dir / "reports"
        
    def tearDown(self):
        shutil.rmtree(self.test_dir)
        
    def test_entry_node_aggregation_logic(self):
        """Verify that more observations = higher score."""
        agg = EntryNodeAggregator(str(self.evidence_path))
        agg.clear_evidence()
        
        # Single observation
        agg.update_evidence("node_A", 0.8)
        initial_score = agg.get_ranked_guards()[0]['score']
        
        # Second observation
        agg.update_evidence("node_A", 0.8)
        new_score = agg.get_ranked_guards()[0]['score']
        
        print(f"\nAggregation: {initial_score} -> {new_score}")
        self.assertGreater(new_score, initial_score, "Score should increase with more evidence")
        
        # Verify persistence
        agg2 = EntryNodeAggregator(str(self.evidence_path))
        ranked = agg2.get_ranked_guards()
        self.assertEqual(len(ranked), 1)
        self.assertEqual(ranked[0]['guard_id'], "node_A")
        
    def test_tor_directory_enrichment(self):
        """Verify mock logic for TOR directory (since no internet in some envs)."""
        td = TorDirectory(str(self.cache_path))
        
        # Inject mock data directly related to what might fail in offline test
        mock_relay = {
            'fingerprint': '1234' * 10,
            'nickname': 'TestGuard',
            'or_addresses': ['192.168.1.1:9001'],
            'flags': ['Guard'],
            'observed_bandwidth': 500
        }
        td._index_relays([mock_relay])
        
        # Test Search
        result = td.search_relay("192.168.1.1")
        self.assertIsNotNone(result)
        self.assertEqual(result['nickname'], 'TestGuard')
        self.assertEqual(result['role'], 'Guard')
        
    def test_forensic_report_generation(self):
        """Verify report creation."""
        gen = ForensicReportGenerator(str(self.report_dir))
        
        dummy_result = {
            'target_flow_id': 'target_1',
            'metadata': {},
            'ranked_candidates': [
                {
                    'flow_id': 'flow_1',
                    'final': 0.9,
                    'guard_identifier': 'node_A'
                }
            ]
        }
        
        path = gen.generate_report(dummy_result, "TEST-CASE")
        self.assertTrue(os.path.exists(path))
        
        with open(path, 'r') as f:
            content = f.read()
            self.assertIn("Forensic Report", content)
            self.assertIn("node_A", content)
            
    def test_dashboard_data_loading(self):
        """Verify dashboard can load evidence file."""
        # Create dummy evidence
        data = {'guard_1': {'count': 1, 'total_confidence': 0.9, 'last_seen': '2023-01-01', 'timestamps': []}}
        with open(self.evidence_path, 'w') as f:
            json.dump(data, f)
            
        # Mock the path in dashboard module for this test
        # (A bit hacky, but avoids modifying dashboard just for test)
        import viz.dashboard
        viz.dashboard.EVIDENCE_FILE = self.evidence_path
        
        loaded = load_evidence()
        self.assertIn('guard_1', loaded)

if __name__ == '__main__':
    unittest.main()
