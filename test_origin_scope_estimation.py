#!/usr/bin/env python3
"""
Test Suite for Origin Scope Estimation Module

Tests:
1. Module import and structure
2. Hosting profile classification
3. Origin region estimation
4. Confidence does NOT override guard confidence
5. No PCAP consumption
6. Disclaimer presence
"""

import sys
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_module_import():
    """Test that origin_scope_estimation module can be imported."""
    logger.info("=" * 70)
    logger.info("TEST 1: Module Import")
    logger.info("=" * 70)
    
    try:
        from origin_scope_estimation import (
            OriginScopeEstimator,
            HostingProfileClassifier,
            OriginRegionEstimator,
            OriginScopeResult,
            HostingProfile,
            OriginConfidence,
            estimate_origin_scope
        )
        logger.info("✅ All classes and functions imported successfully")
        return True
    except ImportError as e:
        logger.error(f"❌ Import failed: {e}")
        return False


def test_hosting_profile_classification():
    """Test hosting profile classification logic."""
    logger.info("=" * 70)
    logger.info("TEST 2: Hosting Profile Classification")
    logger.info("=" * 70)
    
    from origin_scope_estimation import HostingProfileClassifier, HostingProfile
    
    classifier = HostingProfileClassifier()
    
    # Test VPS detection
    profile, desc = classifier.classify("DigitalOcean, LLC", None)
    assert profile == HostingProfile.VPS_COMMERCIAL, f"Expected VPS, got {profile}"
    logger.info(f"   DigitalOcean → {profile.value}")
    
    profile, desc = classifier.classify("Amazon Web Services", None)
    assert profile == HostingProfile.VPS_COMMERCIAL
    logger.info(f"   AWS → {profile.value}")
    
    # Test residential ISP
    profile, desc = classifier.classify("Comcast Cable Communications", None)
    assert profile == HostingProfile.RESIDENTIAL_ISP
    logger.info(f"   Comcast → {profile.value}")
    
    # Test academic
    profile, desc = classifier.classify("Stanford University Network", None)
    assert profile == HostingProfile.ACADEMIC
    logger.info(f"   Stanford → {profile.value}")
    
    # Test unknown
    profile, desc = classifier.classify("Random Corp Inc", None)
    assert profile == HostingProfile.ENTERPRISE
    logger.info(f"   Unknown Corp → {profile.value}")
    
    logger.info("✅ Hosting profile classification works correctly")
    return True


def test_origin_region_estimation():
    """Test origin region estimation logic."""
    logger.info("=" * 70)
    logger.info("TEST 3: Origin Region Estimation")
    logger.info("=" * 70)
    
    from origin_scope_estimation import OriginRegionEstimator, HostingProfile, OriginConfidence
    
    estimator = OriginRegionEstimator()
    
    # Test VPS - should be global/low confidence
    region, countries, radius, confidence = estimator.estimate("DE", HostingProfile.VPS_COMMERCIAL)
    assert "Global" in region, f"VPS should be global, got {region}"
    assert confidence == OriginConfidence.LOW
    logger.info(f"   VPS (DE) → {region}, Confidence: {confidence.value}")
    
    # Test residential - should be local/high confidence
    region, countries, radius, confidence = estimator.estimate("US", HostingProfile.RESIDENTIAL_ISP)
    assert confidence == OriginConfidence.HIGH
    logger.info(f"   Residential (US) → {region}, Confidence: {confidence.value}")
    
    # Test academic - medium confidence
    region, countries, radius, confidence = estimator.estimate("NL", HostingProfile.ACADEMIC)
    assert confidence == OriginConfidence.MEDIUM
    logger.info(f"   Academic (NL) → {region}, Confidence: {confidence.value}")
    
    logger.info("✅ Origin region estimation works correctly")
    return True


def test_full_estimation_flow():
    """Test complete estimation flow."""
    logger.info("=" * 70)
    logger.info("TEST 4: Full Estimation Flow")
    logger.info("=" * 70)
    
    from origin_scope_estimation import estimate_origin_scope
    
    result = estimate_origin_scope(
        guard_country="Germany",
        guard_country_code="DE",
        guard_isp="Hetzner Online GmbH"
    )
    
    # Verify structure
    assert 'guard_country' in result
    assert 'hosting_profile' in result
    assert 'probable_origin_region' in result
    assert 'confidence_level' in result
    assert 'disclaimer' in result
    assert 'is_supplementary' in result
    
    logger.info(f"   Guard: {result['guard_country']}")
    logger.info(f"   Hosting: {result['hosting_profile']}")
    logger.info(f"   Region: {result['probable_origin_region']}")
    logger.info(f"   Confidence: {result['confidence_level']}")
    
    logger.info("✅ Full estimation flow works correctly")
    return True


def test_no_confidence_override():
    """CRITICAL: Verify origin scope does NOT produce numeric confidence that could override guard."""
    logger.info("=" * 70)
    logger.info("TEST 5: No Confidence Override")
    logger.info("=" * 70)
    
    from origin_scope_estimation import estimate_origin_scope
    
    result = estimate_origin_scope(
        guard_country="United States",
        guard_country_code="US",
        guard_isp="DigitalOcean"
    )
    
    # Confidence must be QUALITATIVE (string), not numeric
    assert isinstance(result['confidence_level'], str), "Confidence must be string, not numeric"
    assert result['confidence_level'] in ['Low', 'Medium', 'High'], "Confidence must be qualitative"
    
    # Ensure no numeric confidence score
    assert 'confidence_score' not in result, "Should not have numeric confidence_score"
    
    # Verify is_supplementary flag
    assert result['is_supplementary'] == True, "Must be marked as supplementary"
    
    logger.info(f"   Confidence type: {type(result['confidence_level']).__name__}")
    logger.info(f"   Confidence value: {result['confidence_level']}")
    logger.info(f"   Is supplementary: {result['is_supplementary']}")
    
    logger.info("✅ No confidence override - origin scope is qualitative only")
    return True


def test_no_pcap_consumption():
    """CRITICAL: Verify module does NOT consume PCAP data."""
    logger.info("=" * 70)
    logger.info("TEST 6: No PCAP Consumption")
    logger.info("=" * 70)
    
    # Read the source file
    with open('origin_scope_estimation.py', 'r') as f:
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
        'flowextractor'
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


def test_disclaimer_presence():
    """Test that disclaimer is present and correct."""
    logger.info("=" * 70)
    logger.info("TEST 7: Disclaimer Presence")
    logger.info("=" * 70)
    
    from origin_scope_estimation import estimate_origin_scope
    
    result = estimate_origin_scope(
        guard_country="France",
        guard_country_code="FR",
        guard_isp="OVH SAS"
    )
    
    disclaimer = result.get('disclaimer', '')
    
    # Verify disclaimer contains key phrases
    assert 'contextual intelligence' in disclaimer.lower()
    assert 'does not identify' in disclaimer.lower()
    assert 'exact IP' in disclaimer.lower() or 'exact ip' in disclaimer.lower()
    
    logger.info(f"   Disclaimer: {disclaimer[:80]}...")
    logger.info("✅ Disclaimer is present and correct")
    return True


def test_no_ip_output():
    """Verify no IP addresses or ranges are output."""
    logger.info("=" * 70)
    logger.info("TEST 8: No IP/Range Output")
    logger.info("=" * 70)
    
    from origin_scope_estimation import estimate_origin_scope
    import re
    
    result = estimate_origin_scope(
        guard_country="Germany",
        guard_country_code="DE",
        guard_isp="Hetzner Online GmbH"
    )
    
    # Convert result to string for inspection
    result_str = str(result)
    
    # IP address pattern
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    
    # Check for IP addresses in output (except in field names)
    found_ips = re.findall(ip_pattern, result_str)
    
    if found_ips:
        logger.error(f"❌ Found IP addresses in output: {found_ips}")
        return False
    
    # Verify no IP range fields
    assert 'ip_range' not in result
    assert 'client_ip' not in result
    assert 'user_ip' not in result
    
    logger.info("   ✓ No IP addresses in output")
    logger.info("   ✓ No IP ranges in output")
    logger.info("✅ No IP/Range output - compliant")
    return True


def main():
    """Run all tests."""
    logger.info("\n" + "=" * 70)
    logger.info("ORIGIN SCOPE ESTIMATION MODULE - TEST SUITE")
    logger.info("=" * 70 + "\n")
    
    results = {}
    
    tests = [
        ('import', test_module_import),
        ('hosting_profile', test_hosting_profile_classification),
        ('region_estimation', test_origin_region_estimation),
        ('full_flow', test_full_estimation_flow),
        ('no_confidence_override', test_no_confidence_override),
        ('no_pcap', test_no_pcap_consumption),
        ('disclaimer', test_disclaimer_presence),
        ('no_ip_output', test_no_ip_output),
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
