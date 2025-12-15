#!/usr/bin/env python3
"""
Test Suite for Statistical Similarity and Siamese Model Integration

Tests all individual components and their integration:
1. Statistical similarity metrics
2. Siamese model loading and inference
3. Correlation pipeline
4. Architecture compliance
"""

import sys
import numpy as np
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_statistical_similarity():
    """Test statistical similarity module."""
    logger.info("=" * 70)
    logger.info("TEST 1: Statistical Similarity Module")
    logger.info("=" * 70)
    
    from statistical_similarity import (
        process_flow,
        cross_correlation_similarity,
        mad_similarity,
        burst_similarity,
        statistical_similarity,
        batch_statistical_similarity
    )
    
    # Create test flows
    logger.info("Creating test flows...")
    flow1 = np.random.randn(150, 3) * 100 + 500
    flow2 = flow1 + np.random.randn(150, 3) * 10  # Similar
    flow3 = np.random.randn(150, 3) * 100 + 1000  # Different
    
    # Test processing
    logger.info("\\nTesting process_flow()...")
    p1 = process_flow(flow1)
    p2 = process_flow(flow2)
    p3 = process_flow(flow3)
    
    assert p1.shape == (300,), f"Expected shape (300,), got {p1.shape}"
    assert p2.shape == (300,), f"Expected shape (300,), got {p2.shape}"
    assert p3.shape == (300,), f"Expected shape (300,), got {p3.shape}"
    logger.info("✅ process_flow() works correctly")
    
    # Test individual metrics
    logger.info("\\nTesting cross-correlation...")
    cc_12 = cross_correlation_similarity(p1, p2)
    cc_13 = cross_correlation_similarity(p1, p3)
    logger.info(f"   Similar flows: {cc_12:.4f}")
    logger.info(f"   Different flows: {cc_13:.4f}")
    assert 0 <= cc_12 <= 1 and 0 <= cc_13 <= 1
    logger.info("✅ Cross-correlation works")
    
    logger.info("\\nTesting MAD similarity...")
    mad_12 = mad_similarity(p1, p2)
    mad_13 = mad_similarity(p1, p3)
    logger.info(f"   Similar flows: {mad_12:.4f}")
    logger.info(f"   Different flows: {mad_13:.4f}")
    assert 0 <= mad_12 <= 1 and 0 <= mad_13 <= 1
    logger.info("✅ MAD similarity works")
    
    logger.info("\\nTesting burst similarity...")
    burst_12 = burst_similarity(p1, p2)
    burst_13 = burst_similarity(p1, p3)
    logger.info(f"   Similar flows: {burst_12:.4f}")
    logger.info(f"   Different flows: {burst_13:.4f}")
    assert 0 <= burst_12 <= 1 and 0 <= burst_13 <= 1
    logger.info("✅ Burst similarity works")
    
    # Test combined metric
    logger.info("\\nTesting statistical similarity (combined)...")
    stat_12 = statistical_similarity(p1, p2)
    stat_13 = statistical_similarity(p1, p3)
    logger.info(f"   Similar flows: {stat_12:.4f}")
    logger.info(f"   Different flows: {stat_13:.4f}")
    assert 0 <= stat_12 <= 1 and 0 <= stat_13 <= 1
    logger.info("✅ Statistical similarity works")
    
    # Test batch processing
    logger.info("\\nTesting batch processing...")
    candidates = {f'flow_{i}': process_flow(np.random.randn(150, 3) * 100 + 500) 
                  for i in range(10)}
    batch_scores = batch_statistical_similarity(candidates, p1, metric='statistical')
    assert len(batch_scores) == 10
    logger.info(f"✅ Batch processing works ({len(batch_scores)} flows)")
    
    logger.info("\\n✅ Statistical similarity module: ALL TESTS PASSED\\n")
    return True


def test_siamese_model():
    """Test Siamese model module."""
    logger.info("=" * 70)
    logger.info("TEST 2: Siamese Model Module")
    logger.info("=" * 70)
    
    from siamese_model import (
        load_siamese_model,
        siamese_similarity,
        batch_similarity_with_target,
        get_model_info
    )
    
    model_path = "./lightweight_siamese.pth"
    
    if not Path(model_path).exists():
        logger.warning(f"⚠️  Model file not found: {model_path}")
        logger.warning("   Skipping Siamese model tests")
        return False
    
    # Test model loading
    logger.info(f"\\nLoading model from {model_path}...")
    model = load_siamese_model(model_path)
    logger.info("✅ Model loaded successfully")
    
    # Get model info
    info = get_model_info(model)
    logger.info(f"\\nModel information:")
    logger.info(f"   Parameters: {info['total_parameters']:,}")
    logger.info(f"   Device: {info['device']}")
    logger.info(f"   Architecture: {info['architecture']}")
    
    # Test single inference
    logger.info("\\nTesting single inference...")
    flow1 = np.random.randn(300).astype(np.float32) * 100 + 500
    flow2 = flow1 + np.random.randn(300).astype(np.float32) * 10
    flow3 = np.random.randn(300).astype(np.float32) * 100 + 1000
    
    sim_12 = siamese_similarity(model, flow1, flow2)
    sim_13 = siamese_similarity(model, flow1, flow3)
    
    logger.info(f"   Similar flows: {sim_12:.4f}")
    logger.info(f"   Different flows: {sim_13:.4f}")
    
    assert 0 <= sim_12 <= 1 and 0 <= sim_13 <= 1
    logger.info("✅ Single inference works")
    
    # Test batch inference
    logger.info("\\nTesting batch inference...")
    candidates = {f'flow_{i}': np.random.randn(300).astype(np.float32) * 100 + 500 
                  for i in range(20)}
    
    batch_scores = batch_similarity_with_target(model, flow1, candidates, batch_size=8)
    assert len(batch_scores) == 20
    logger.info(f"✅ Batch inference works ({len(batch_scores)} flows)")
    
    logger.info("\\n✅ Siamese model module: ALL TESTS PASSED\\n")
    return True


def test_correlation_pipeline():
    """Test correlation pipeline."""
    logger.info("=" * 70)
    logger.info("TEST 3: Correlation Pipeline")
    logger.info("=" * 70)
    
    from correlation_pipeline import CorrelationPipeline
    
    model_path = "./lightweight_siamese.pth"
    
    if not Path(model_path).exists():
        logger.warning(f"⚠️  Model file not found: {model_path}")
        logger.warning("   Skipping correlation pipeline tests")
        return False
    
    # Create dummy flow store
    logger.info("\\nCreating dummy flow store...")
    flow_store = {}
    for i in range(50):
        sizes = np.random.randn(200) * 100 + 500
        flow_store[f'flow_{i}'] = {
            'sizes': sizes.tolist(),
            'timestamps': np.linspace(0, 10, len(sizes)).tolist(),
            'directions': ['in' if j % 2 == 0 else 'out' for j in range(len(sizes))]
        }
    logger.info(f"   Created {len(flow_store)} flows")
    
    # Initialize pipeline
    logger.info("\\nInitializing correlation pipeline...")
    pipeline = CorrelationPipeline(
        siamese_model_path=model_path,
        statistical_weight=0.7,
        siamese_weight=0.3,
        top_k_for_siamese=10
    )
    logger.info("✅ Pipeline initialized")
    
    # Test flow loading
    logger.info("\\nTesting flow loading...")
    flow_ids = [f'flow_{i}' for i in range(50)]
    loaded_flows = pipeline.load_raw_flows(flow_ids, flow_store)
    assert len(loaded_flows) == 50
    logger.info(f"✅ Loaded {len(loaded_flows)} flows")
    
    # Test statistical scores
    logger.info("\\nTesting statistical scores...")
    target = loaded_flows['flow_0']
    candidates = {k: v for k, v in loaded_flows.items() if k != 'flow_0'}
    stat_scores = pipeline.compute_statistical_scores(target, candidates)
    assert len(stat_scores) == 49
    logger.info(f"✅ Computed {len(stat_scores)} statistical scores")
    
    # Test top-K selection
    logger.info("\\nTesting top-K selection...")
    top_k_ids = pipeline.select_top_k(stat_scores, k=10)
    assert len(top_k_ids) == 10
    logger.info(f"✅ Selected top-{len(top_k_ids)} candidates")
    
    # Test Siamese refinement
    logger.info("\\nTesting Siamese refinement...")
    top_k_flows = {fid: loaded_flows[fid] for fid in top_k_ids}
    siamese_scores = pipeline.refine_with_siamese(target, top_k_flows)
    assert len(siamese_scores) == 10
    logger.info(f"✅ Computed {len(siamese_scores)} Siamese scores")
    
    # Test score fusion
    logger.info("\\nTesting score fusion...")
    fused = pipeline.fuse_scores(stat_scores, siamese_scores)
    assert len(fused) == 49
    
    # Check that top-K have Siamese scores, others don't
    has_siamese = sum(1 for v in fused.values() if v['siamese'] is not None)
    assert has_siamese == 10
    logger.info(f"✅ Fused scores: {has_siamese} with Siamese, {len(fused) - has_siamese} without")
    
    # Test ranking
    logger.info("\\nTesting ranking generation...")
    ranked = pipeline.generate_ranking(fused)
    assert len(ranked) == 49
    assert ranked[0]['rank'] == 1
    logger.info(f"✅ Generated ranking of {len(ranked)} candidates")
    
    # Test full pipeline run
    logger.info("\\nTesting full pipeline run...")
    results = pipeline.run(
        target_flow_id='flow_0',
        filtered_flow_ids=[f'flow_{i}' for i in range(1, 50)],
        flow_store=flow_store,
        top_k=10
    )
    
    assert 'ranked_candidates' in results
    assert 'metadata' in results
    assert results['metadata']['total_candidates'] == 49
    assert results['metadata']['top_k_for_siamese'] == 10
    
    logger.info(f"\n   Top 5 candidates:")
    for i in range(5):
        cand = results['ranked_candidates'][i]
        siamese_str = f"{cand['siamese']:.4f}" if cand['siamese'] is not None else 'N/A'
        logger.info(f"   {i+1}. {cand['flow_id']}: {cand['final']:.4f} | "
                   f"Statistical: {cand['statistical']:.4f} | "
                   f"Siamese: {siamese_str}")
    
    logger.info("\n✅ Correlation pipeline: ALL TESTS PASSED\n")
    return True


def test_architecture_compliance():
    """Test architecture compliance (no SUMo feature mixing)."""
    logger.info("=" * 70)
    logger.info("TEST 4: Architecture Compliance")
    logger.info("=" * 70)
    
    logger.info("\\nVerifying NO SUMo feature mixing...")
    
    # Check that statistical module doesn't import SUMo
    logger.info("   Checking statistical_similarity.py...")
    with open('statistical_similarity.py', 'r') as f:
        stat_code = f.read()
        assert 'sumo' not in stat_code.lower() or 'sumo_adapter' not in stat_code
        logger.info("   ✅ No SUMo imports in statistical_similarity.py")
    
    # Check that siamese module doesn't import SUMo
    logger.info("   Checking siamese_model.py...")
    with open('siamese_model.py', 'r') as f:
        siamese_code = f.read()
        assert 'sumo' not in siamese_code.lower() or 'sumo_adapter' not in siamese_code
        logger.info("   ✅ No SUMo imports in siamese_model.py")
    
    # Check that correlation pipeline doesn't import SUMo
    logger.info("   Checking correlation_pipeline.py...")
    with open('correlation_pipeline.py', 'r') as f:
        corr_code = f.read()
        assert 'sumo_adapter' not in corr_code and 'sumo_filter' not in corr_code
        logger.info("   ✅ No SUMo imports in correlation_pipeline.py")
    
    # Verify fusion weights
    logger.info("\\nVerifying fusion weights (0.7 statistical, 0.3 Siamese)...")
    from correlation_pipeline import CorrelationPipeline
    
    # Check default weights
    assert CorrelationPipeline.__init__.__defaults__[0] == 0.7  # statistical_weight
    assert CorrelationPipeline.__init__.__defaults__[1] == 0.3  # siamese_weight
    logger.info("   ✅ Fusion weights correct: 70% statistical, 30% Siamese")
    
    logger.info("\\n✅ Architecture compliance: ALL TESTS PASSED\\n")
    return True


def main():
    """Run all tests."""
    logger.info("\\n" + "=" * 70)
    logger.info("COMPREHENSIVE TEST SUITE")
    logger.info("Statistical Similarity + Siamese Model Integration")
    logger.info("=" * 70 + "\\n")
    
    results = {}
    
    # Test 1: Statistical Similarity
    try:
        results['statistical'] = test_statistical_similarity()
    except Exception as e:
        logger.error(f"❌ Statistical similarity tests failed: {e}")
        import traceback
        traceback.print_exc()
        results['statistical'] = False
    
    # Test 2: Siamese Model
    try:
        results['siamese'] = test_siamese_model()
    except Exception as e:
        logger.error(f"❌ Siamese model tests failed: {e}")
        import traceback
        traceback.print_exc()
        results['siamese'] = False
    
    # Test 3: Correlation Pipeline
    try:
        results['correlation'] = test_correlation_pipeline()
    except Exception as e:
        logger.error(f"❌ Correlation pipeline tests failed: {e}")
        import traceback
        traceback.print_exc()
        results['correlation'] = False
    
    # Test 4: Architecture Compliance
    try:
        results['architecture'] = test_architecture_compliance()
    except Exception as e:
        logger.error(f"❌ Architecture compliance tests failed: {e}")
        import traceback
        traceback.print_exc()
        results['architecture'] = False
    
    # Summary
    logger.info("=" * 70)
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
    logger.info("=" * 70 + "\\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
