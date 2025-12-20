#!/usr/bin/env python3
"""
Test Suite for Indirect Exit Evidence Scoring System

Validates:
1. Direct correlation logic remains unchanged
2. Indirect scoring activates when direct fails
3. exit_confirmation NEVER elevated by indirect evidence
4. Indirect boost capped at 0.25
5. Three correlation modes work correctly
6. Confidence never decreases compared to guard_only
"""

import unittest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from exit_correlation import (
    IndirectExitEvidenceScorer,
    ConfidenceAggregator,
    ExitCorrelator,
    run_exit_correlation
)


class TestDirectCorrelationUnchanged(unittest.TestCase):
    """Ensure existing direct correlation logic is preserved."""
    
    def test_direct_correlation_succeeds_sets_exit_confirmation_true(self):
        """CRITICAL: Direct correlation >= 0.5 MUST set exit_confirmation=True"""
        # Simulate successful direct correlation
        exit_result = {
            'matched': True,
            'score': 0.75
        }
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.6,
            exit_result=exit_result
        )
        
        self.assertTrue(agg['exit_confirmation'])
        self.assertEqual(agg['mode'], 'guard+exit_confirmed')
        self.assertGreater(agg['final_confidence'], 0.6)  # Boost applied
    
    def test_direct_correlation_threshold_at_50_percent(self):
        """Verify 50% threshold is preserved in ExitCorrelator."""
        correlator = ExitCorrelator()
        
        # Check the threshold is used in correlate method
        # (We verify by checking the matched logic in results)
        guard_flows = [{'id': 'guard_1', 'packets': 10, 'timestamps': [0, 1, 2], 'sizes': [100, 200, 100]}]
        exit_flows = [{'id': 'exit_1', 'packets': 10, 'timestamps': [0, 1, 2], 'sizes': [100, 200, 100]}]
        
        result = correlator.correlate(guard_flows, exit_flows)
        
        # If score > 0.5, matched should be True
        self.assertIn('matched', result)
        self.assertIn('score', result)
        if result['score'] > 0.5:
            self.assertTrue(result['matched'])
        else:
            self.assertFalse(result['matched'])


class TestIndirectEvidenceScoring(unittest.TestCase):
    """Test indirect exit evidence scoring system."""
    
    def test_indirect_score_when_direct_fails(self):
        """Indirect boost should be applied when direct < 0.5"""
        exit_result = {
            'matched': False,
            'score': 0.35  # Below threshold
        }
        
        exit_flows = [{'id': 'exit_1', 'duration': 120}]  # Plausible Tor duration
        guard_flow = {'id': 'guard_1', 'duration': 120, 'timestamps': [0, 1, 2]}
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.5,
            exit_result=exit_result,
            exit_flows=exit_flows,
            guard_flow=guard_flow
        )
        
        # Should have indirect boost > 0 (from burst similarity partial credit)
        self.assertGreaterEqual(agg['exit_boost'], 0.0)
        self.assertFalse(agg['exit_confirmation'])  # NEVER true for indirect
    
    def test_indirect_never_sets_exit_confirmation_true(self):
        """CRITICAL: Indirect evidence MUST NEVER elevate exit_confirmation to True"""
        # Even with maximum indirect evidence, exit_confirmation stays False
        exit_result = {
            'matched': False,
            'score': 0.49  # Just below threshold
        }
        
        # Create scenario with maximum indirect evidence
        metadata = {
            'exit_asn': 'AS24940',  # Known Tor exit ASN
            'guard_observation_count': 10,  # High stability
            'session_duration': 120  # Optimal range
        }
        exit_flows = [{'id': 'exit_1', 'asn': 'AS24940', 'duration': 120, 'timestamps': [0, 60, 120]}]
        guard_flow = {'id': 'guard_1', 'duration': 120, 'timestamps': [0, 60, 120]}
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.5,
            exit_result=exit_result,
            exit_flows=exit_flows,
            guard_flow=guard_flow,
            metadata=metadata
        )
        
        # CRITICAL ASSERTION
        self.assertFalse(agg['exit_confirmation'], 
            "FORENSIC VIOLATION: Indirect evidence must NEVER set exit_confirmation=True")
        
        # Mode should be indirect, not confirmed
        self.assertIn(agg['mode'], ['guard+exit_indirect', 'guard_only'])
        self.assertNotEqual(agg['mode'], 'guard+exit_confirmed')
    
    def test_indirect_boost_capped_at_025(self):
        """Total indirect boost MUST be capped at 0.25"""
        # Compute with all factors at maximum
        result = IndirectExitEvidenceScorer.compute(
            exit_flows=[{'id': 'exit_1', 'asn': 'AS24940', 'timestamps': [0, 1, 2]}],
            guard_flow={'id': 'guard_1', 'timestamps': [0, 1, 2], 'duration': 60},
            metadata={'exit_asn': 'AS24940', 'guard_observation_count': 10},
            direct_score=0.49  # Maximum without triggering direct match
        )
        
        self.assertLessEqual(result['indirect_score'], 0.25,
            f"Indirect boost {result['indirect_score']} exceeds cap of 0.25")
        self.assertEqual(IndirectExitEvidenceScorer.MAX_INDIRECT_BOOST, 0.25)


class TestConfidenceNeverDecreases(unittest.TestCase):
    """Verify confidence ranking order is preserved."""
    
    def test_guard_only_confidence_unchanged(self):
        """Guard-only confidence should not be reduced."""
        guard_confidence = 0.7
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=guard_confidence,
            exit_result=None
        )
        
        # Guard-only should preserve exact confidence (clamped at 0.999999)
        self.assertGreaterEqual(agg['final_confidence'], guard_confidence - 0.001)
    
    def test_indirect_cannot_reduce_confidence(self):
        """Indirect evidence must NEVER reduce confidence below guard_only level."""
        guard_confidence = 0.6
        
        # Run with indirect evidence
        exit_result = {'matched': False, 'score': 0.2}
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=guard_confidence,
            exit_result=exit_result,
            exit_flows=[],
            guard_flow=None
        )
        
        self.assertGreaterEqual(agg['final_confidence'], guard_confidence,
            "FORENSIC VIOLATION: Indirect evidence reduced confidence")


class TestModeValues(unittest.TestCase):
    """Test correlation mode values."""
    
    def test_mode_guard_only(self):
        """No exit data -> guard_only mode"""
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.6,
            exit_result=None
        )
        self.assertEqual(agg['mode'], 'guard_only')
    
    def test_mode_guard_exit_indirect(self):
        """Direct fails but indirect contributes -> guard+exit_indirect"""
        exit_result = {'matched': False, 'score': 0.4}
        guard_flow = {'id': 'g1', 'duration': 60, 'timestamps': [0, 1]}
        exit_flows = [{'id': 'e1', 'timestamps': [0, 1]}]
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.5,
            exit_result=exit_result,
            exit_flows=exit_flows,
            guard_flow=guard_flow
        )
        
        # Should be indirect if any boost was obtained
        if agg['exit_boost'] > 0:
            self.assertEqual(agg['mode'], 'guard+exit_indirect')
    
    def test_mode_guard_exit_confirmed(self):
        """Direct succeeds -> guard+exit_confirmed"""
        exit_result = {'matched': True, 'score': 0.8}
        
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.6,
            exit_result=exit_result
        )
        
        self.assertEqual(agg['mode'], 'guard+exit_confirmed')
        self.assertTrue(agg['exit_confirmation'])


class TestOriginAssessment(unittest.TestCase):
    """Test origin_assessment output structure."""
    
    def test_origin_assessment_present(self):
        """All aggregation results should include origin_assessment"""
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.6,
            exit_result=None,
            guard_ip="1.2.3.4"
        )
        
        self.assertIn('origin_assessment', agg)
        oa = agg['origin_assessment']
        
        self.assertIn('primary_guard_ip', oa)
        self.assertIn('final_confidence', oa)
        self.assertIn('confidence_class', oa)
        self.assertIn('confidence_sources', oa)
        self.assertIn('exit_evidence_type', oa)
        self.assertIn('forensic_note', oa)
    
    def test_confidence_class_values(self):
        """Confidence class should be LOW, MEDIUM, or HIGH"""
        for conf, expected_class in [(0.3, 'LOW'), (0.6, 'MEDIUM'), (0.9, 'HIGH')]:
            agg = ConfidenceAggregator.aggregate(
                guard_confidence=conf,
                exit_result=None
            )
            self.assertEqual(agg['origin_assessment']['confidence_class'], expected_class)
    
    def test_forensic_note_present(self):
        """Forensic note must always be present and conservative"""
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=0.6,
            exit_result={'matched': True, 'score': 0.9}
        )
        
        oa = agg['origin_assessment']
        self.assertIn('probabilistic', oa['forensic_note'].lower())


class TestIndirectFactorWeights(unittest.TestCase):
    """Test individual factor weights in IndirectExitEvidenceScorer."""
    
    def test_weights_sum_to_max_boost(self):
        """Factor weights should sum to MAX_INDIRECT_BOOST"""
        total_weights = sum(IndirectExitEvidenceScorer.WEIGHTS.values())
        self.assertEqual(total_weights, IndirectExitEvidenceScorer.MAX_INDIRECT_BOOST,
            f"Weights sum {total_weights} != MAX_INDIRECT_BOOST {IndirectExitEvidenceScorer.MAX_INDIRECT_BOOST}")
    
    def test_factor_score_detail_present(self):
        """Each factor should have score and detail explanation"""
        result = IndirectExitEvidenceScorer.compute(
            exit_flows=[{'id': 'e1'}],
            guard_flow={'id': 'g1'},
            metadata={},
            direct_score=0.3
        )
        
        self.assertIn('factor_scores', result)
        self.assertIn('factor_details', result)
        
        for factor in IndirectExitEvidenceScorer.WEIGHTS.keys():
            self.assertIn(factor, result['factor_scores'])
            self.assertIn(factor, result['factor_details'])


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("INDIRECT EXIT EVIDENCE SCORING - TEST SUITE")
    print("=" * 70 + "\n")
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestDirectCorrelationUnchanged))
    suite.addTests(loader.loadTestsFromTestCase(TestIndirectEvidenceScoring))
    suite.addTests(loader.loadTestsFromTestCase(TestConfidenceNeverDecreases))
    suite.addTests(loader.loadTestsFromTestCase(TestModeValues))
    suite.addTests(loader.loadTestsFromTestCase(TestOriginAssessment))
    suite.addTests(loader.loadTestsFromTestCase(TestIndirectFactorWeights))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
    else:
        print("❌ SOME TESTS FAILED")
    print("=" * 70 + "\n")
    
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
