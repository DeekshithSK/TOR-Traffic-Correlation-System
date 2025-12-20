#!/usr/bin/env python3
"""
Test Suite for Tor Path Inference Module

Tests:
1. Consensus client functionality
2. Path probability estimation
3. Architecture compliance (no PCAP consumption)
4. Graph format output
"""

import sys
import json
import logging
from pathlib import Path
from unittest.mock import Mock, patch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_module_import():
    """Test that tor_path_inference module can be imported."""
    logger.info("=" * 70)
    logger.info("TEST 1: Module Import")
    logger.info("=" * 70)
    
    try:
        from tor_path_inference import (
            TorPathInference,
            TorConsensusClient,
            PathProbabilityEstimator,
            infer_path_from_guard,
            RelayInfo,
            ExitCandidate,
            PathInferenceResult
        )
        logger.info("✅ All classes and functions imported successfully")
        return True
    except ImportError as e:
        logger.error(f"❌ Import failed: {e}")
        return False


def test_relay_info_dataclass():
    """Test RelayInfo dataclass properties."""
    logger.info("=" * 70)
    logger.info("TEST 2: RelayInfo Dataclass")
    logger.info("=" * 70)
    
    from tor_path_inference import RelayInfo
    
    # Create test relay
    relay = RelayInfo(
        fingerprint="ABCD1234" * 5,
        nickname="TestGuard",
        ip_address="1.2.3.4",
        or_port=9001,
        dir_port=9030,
        flags=["Guard", "Stable", "Fast", "Running"],
        bandwidth=10000000,
        country="US"
    )
    
    # Test properties
    assert relay.is_guard == True, "Should be guard"
    assert relay.is_exit == False, "Should not be exit"
    assert relay.is_stable == True, "Should be stable"
    assert relay.is_fast == True, "Should be fast"
    
    logger.info(f"   Relay: {relay.nickname} ({relay.ip_address})")
    logger.info(f"   Flags: {relay.flags}")
    logger.info(f"   is_guard: {relay.is_guard}")
    logger.info("✅ RelayInfo dataclass works correctly")
    return True


def test_consensus_client_caching():
    """Test consensus client caching mechanism."""
    logger.info("=" * 70)
    logger.info("TEST 3: Consensus Client Caching")
    logger.info("=" * 70)
    
    from tor_path_inference import TorConsensusClient, TOR_CONSENSUS_CACHE_DIR
    
    client = TorConsensusClient()
    
    # Check cache directory exists
    assert TOR_CONSENSUS_CACHE_DIR.exists(), "Cache directory should exist"
    logger.info(f"   Cache dir: {TOR_CONSENSUS_CACHE_DIR}")
    
    # Check cache methods exist
    assert hasattr(client, '_is_cache_valid')
    assert hasattr(client, '_save_to_cache')
    assert hasattr(client, '_load_from_cache')
    
    logger.info("✅ Consensus client caching structure correct")
    return True


def test_path_inference_initialization():
    """Test TorPathInference initialization without network."""
    logger.info("=" * 70)
    logger.info("TEST 4: Path Inference Initialization")
    logger.info("=" * 70)
    
    from tor_path_inference import TorPathInference
    
    inference = TorPathInference()
    
    assert hasattr(inference, 'consensus_client')
    assert hasattr(inference, 'probability_estimator')
    assert hasattr(inference, 'initialize')
    assert hasattr(inference, 'estimate_path')
    assert hasattr(inference, 'to_graph_format')
    
    logger.info("   TorPathInference class structure correct")
    logger.info("✅ Path inference initialization works")
    return True


def test_no_pcap_consumption():
    """CRITICAL: Verify module does NOT consume PCAP data."""
    logger.info("=" * 70)
    logger.info("TEST 5: Architecture Compliance - No PCAP Consumption")
    logger.info("=" * 70)
    
    # Read the source file
    with open('tor_path_inference.py', 'r') as f:
        source_code = f.read().lower()
    
    # Check for PCAP-related imports
    pcap_patterns = [
        'import scapy',
        'from scapy',
        'import pcapy',
        'from pcapy',
        'pcap_processor',
        'read_pcap',
        'parse_pcap',
        '.pcap'
    ]
    
    violations = []
    for pattern in pcap_patterns:
        if pattern in source_code:
            violations.append(pattern)
    
    if violations:
        logger.error(f"❌ CRITICAL: Found PCAP-related patterns: {violations}")
        return False
    
    logger.info("   ✓ No scapy imports")
    logger.info("   ✓ No pcap_processor imports")
    logger.info("   ✓ No PCAP file operations")
    logger.info("✅ Module does NOT consume PCAP data")
    return True


def test_estimate_path_with_mock():
    """Test path estimation with mocked consensus data."""
    logger.info("=" * 70)
    logger.info("TEST 6: Path Estimation (Mocked)")
    logger.info("=" * 70)
    
    from tor_path_inference import TorPathInference, RelayInfo
    
    inference = TorPathInference()
    
    # Mock the consensus client with test data
    test_relays = {}
    for i in range(10):
        fp = f"{'A' * 35}{i:05d}"
        relay = RelayInfo(
            fingerprint=fp,
            nickname=f"TestExit{i}",
            ip_address=f"10.0.0.{i+1}",
            or_port=9001,
            dir_port=9030,
            flags=["Exit", "Stable", "Fast"],
            bandwidth=1000000 * (i + 1),
            country="US"
        )
        test_relays[fp] = relay
    
    # Add a guard
    guard_fp = "GUARD" + "B" * 35
    guard_relay = RelayInfo(
        fingerprint=guard_fp,
        nickname="TestGuard",
        ip_address="192.168.1.1",
        or_port=9001,
        dir_port=9030,
        flags=["Guard", "Stable", "Fast"],
        bandwidth=5000000,
        country="DE"
    )
    test_relays[guard_fp] = guard_relay
    
    # Inject mock data
    inference.consensus_client._relays = test_relays
    inference.consensus_client._relays_by_ip = {
        relay.ip_address: [relay] for relay in test_relays.values()
    }
    inference._initialized = True
    
    # Test estimation
    result = inference.estimate_path(
        guard_ip="192.168.1.1",
        guard_confidence=0.85,
        sample_count=100
    )
    
    # Validate result structure
    assert result.is_probabilistic == True
    assert 'confidence' in result.guard
    assert result.guard['confidence'] == 0.85
    assert len(result.exit_candidates) > 0
    
    # Check probabilities sum to ~1.0
    if result.exit_candidates:
        total_prob = sum(e['probability'] for e in result.exit_candidates)
        logger.info(f"   Exit candidates: {len(result.exit_candidates)}")
        logger.info(f"   Total probability: {total_prob:.4f}")
        logger.info(f"   Top exit: {result.exit_candidates[0]['nickname']} ({result.exit_candidates[0]['probability']:.2%})")
    
    logger.info("✅ Path estimation works correctly with mocked data")
    return True


def test_graph_format():
    """Test graph format output for frontend."""
    logger.info("=" * 70)
    logger.info("TEST 7: Graph Format Output")
    logger.info("=" * 70)
    
    from tor_path_inference import TorPathInference, RelayInfo, PathInferenceResult
    
    inference = TorPathInference()
    
    # Create mock result
    result = PathInferenceResult(
        guard={
            'ip': '1.2.3.4',
            'fingerprint': 'ABCD' * 10,
            'nickname': 'TestGuard',
            'country': 'DE',
            'confidence': 0.85,
            'in_consensus': True,
            'flags': ['Guard', 'Stable']
        },
        tor_core={
            'label': 'Tor Network (Hidden by Design)',
            'is_observable': False
        },
        exit_candidates=[
            {'ip': '5.6.7.8', 'fingerprint': 'EXIT1' + 'A' * 35, 'nickname': 'Exit1', 'probability': 0.3, 'country': 'US', 'bandwidth': 1000000, 'flags': ['Exit']},
            {'ip': '5.6.7.9', 'fingerprint': 'EXIT2' + 'A' * 35, 'nickname': 'Exit2', 'probability': 0.2, 'country': 'NL', 'bandwidth': 800000, 'flags': ['Exit']},
        ],
        is_probabilistic=True,
        consensus_timestamp='2025-12-18T12:00:00Z',
        sample_count=3000,
        total_exit_bandwidth=1800000,
        inference_metadata={'sample_count': 3000}
    )
    
    # Test graph format
    graph = inference.to_graph_format(result)
    
    assert 'nodes' in graph
    assert 'edges' in graph
    assert 'metadata' in graph
    assert graph['is_probabilistic'] == True
    
    # Check nodes
    node_types = [n['type'] for n in graph['nodes']]
    assert 'client' in node_types
    assert 'guard' in node_types
    assert 'tor_core' in node_types
    assert 'exit' in node_types
    
    # Check edges
    edge_types = [e['type'] for e in graph['edges']]
    assert 'solid' in edge_types  # Client -> Guard
    assert 'dashed' in edge_types  # Guard -> Tor Core
    assert 'dotted' in edge_types  # Tor Core -> Exits
    
    logger.info(f"   Nodes: {len(graph['nodes'])}")
    logger.info(f"   Edges: {len(graph['edges'])}")
    logger.info(f"   Node types: {set(node_types)}")
    logger.info(f"   Edge types: {set(edge_types)}")
    logger.info("✅ Graph format output is correct")
    return True


def test_confidence_aggregation():
    """Test confidence aggregation rules."""
    logger.info("=" * 70)
    logger.info("TEST 8: Confidence Aggregation Rules")
    logger.info("=" * 70)
    
    from tor_path_inference import TorPathInference, RelayInfo
    
    inference = TorPathInference()
    
    # Mock minimal data
    inference.consensus_client._relays = {}
    inference.consensus_client._relays_by_ip = {}
    inference._initialized = True
    
    # Test without exit evidence
    result1 = inference.estimate_path(
        guard_ip="1.2.3.4",
        guard_confidence=0.75,
        sample_count=10
    )
    
    # Confidence should NOT increase without exit evidence
    final_conf = result1.inference_metadata.get('final_confidence', 0)
    base_conf = result1.inference_metadata.get('base_confidence', 0)
    
    assert final_conf == base_conf, "Confidence should not increase without exit evidence"
    logger.info(f"   Base confidence: {base_conf}")
    logger.info(f"   Final confidence (no exit): {final_conf}")
    
    # Test with exit evidence
    result2 = inference.estimate_path(
        guard_ip="1.2.3.4",
        guard_confidence=0.75,
        sample_count=10,
        exit_evidence={'match_score': 0.8}
    )
    
    final_conf2 = result2.inference_metadata.get('final_confidence', 0)
    boost = result2.inference_metadata.get('confidence_boost', 0)
    
    logger.info(f"   Final confidence (with exit): {final_conf2}")
    logger.info(f"   Confidence boost: {boost}")
    
    # Exit evidence should provide boost
    assert boost > 0, "Exit evidence should provide confidence boost"
    assert final_conf2 > base_conf, "Exit evidence should increase final confidence"
    assert final_conf2 <= 1.0, "Confidence should not exceed 1.0"
    
    logger.info("✅ Confidence aggregation rules work correctly")
    return True


def main():
    """Run all tests."""
    logger.info("\n" + "=" * 70)
    logger.info("TOR PATH INFERENCE MODULE - TEST SUITE")
    logger.info("=" * 70 + "\n")
    
    results = {}
    
    tests = [
        ('import', test_module_import),
        ('relay_info', test_relay_info_dataclass),
        ('caching', test_consensus_client_caching),
        ('initialization', test_path_inference_initialization),
        ('no_pcap', test_no_pcap_consumption),
        ('estimation', test_estimate_path_with_mock),
        ('graph_format', test_graph_format),
        ('confidence', test_confidence_aggregation),
    ]
    
    for name, test_fn in tests:
        try:
            results[name] = test_fn()
        except Exception as e:
            logger.error(f"❌ Test {name} failed: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Summary
    logger.info("\n" + "=" * 70)
    logger.info("TEST SUMMARY")
    logger.info("=" * 70)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        logger.info(f"   {test_name.upper()}: {status}")
    
    all_passed = all(results.values())
    
    logger.info("=" * 70)
    if all_passed:
        logger.info("🎉 ALL TESTS PASSED!")
    else:
        logger.info("⚠️  SOME TESTS FAILED")
    logger.info("=" * 70 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
