"""
Statistical Similarity Module

Implements correlation metrics for TOR traffic flow analysis using raw packet size data.
All metrics operate ONLY on raw flow arrays (NOT SUMo features).

Flow Format:
    - Input: np.ndarray of shape (N, 3) where column 0 = packet size
    - Processed: Fixed-length 1D array of length 300 (standardized)

Similarity Metrics:
    1. Cross-Correlation: Normalized correlation coefficient
    2. MAD: Mean Absolute Difference mapped to [0,1]
    3. Burst: Packet burst pattern similarity
    4. Statistical: Weighted fusion (0.5, 0.3, 0.2)
"""

import numpy as np
from scipy import signal, stats
from typing import Tuple, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Configuration
FIXED_LENGTH = 300
BURST_THRESHOLD = 1000  # Packet size threshold for burst detection (bytes)
MIN_BURST_SIZE = 3      # Minimum consecutive packets to count as burst


def process_flow(flow_array: np.ndarray) -> np.ndarray:
    """
    Convert variable-length flow to fixed-length array.
    
    Uses ONLY column 0 (packet size) from raw flow data.
    Truncates or zero-pads to achieve fixed length of 300.
    
    Args:
        flow_array: np.ndarray of shape (N, 3) with columns:
                    [packet_size, timestamp, direction]
                    
    Returns:
        np.ndarray of shape (300,) containing packet sizes
        
    Example:
        >>> flow = np.array([[100, 0.1, 1], [200, 0.2, -1], [150, 0.3, 1]])
        >>> processed = process_flow(flow)
        >>> processed.shape
        (300,)
    """
    if len(flow_array.shape) == 1:
        # Already 1D, assume it's packet sizes
        sizes = flow_array
    else:
        # Extract packet sizes from column 0
        sizes = flow_array[:, 0]
    
    # Handle empty flows
    if len(sizes) == 0:
        logger.warning("Empty flow received, returning zeros")
        return np.zeros(FIXED_LENGTH)
    
    # Truncate or pad to fixed length
    if len(sizes) >= FIXED_LENGTH:
        # Truncate to first FIXED_LENGTH packets
        result = sizes[:FIXED_LENGTH]
    else:
        # Zero-pad to FIXED_LENGTH
        result = np.zeros(FIXED_LENGTH)
        result[:len(sizes)] = sizes
    
    return result.astype(np.float32)


def normalize_flow(flow: np.ndarray) -> np.ndarray:
    """
    Z-score normalization (zero mean, unit variance).
    
    Args:
        flow: 1D array of packet sizes
        
    Returns:
        Normalized flow array
    """
    mean = np.mean(flow)
    std = np.std(flow)
    
    # Avoid division by zero for constant flows
    if std < 1e-6:
        return flow - mean
    
    return (flow - mean) / std


def cross_correlation_similarity(flow_a: np.ndarray, flow_b: np.ndarray) -> float:
    """
    Compute normalized cross-correlation similarity.
    
    Process:
    1. Z-score normalize both flows
    2. Compute cross-correlation
    3. Take maximum absolute correlation value
    4. Return as similarity in [0, 1]
    
    Args:
        flow_a: Processed flow array (300,)
        flow_b: Processed flow array (300,)
        
    Returns:
        Similarity score in [0, 1]
    """
    # Normalize flows
    norm_a = normalize_flow(flow_a)
    norm_b = normalize_flow(flow_b)
    
    # Compute cross-correlation
    correlation = signal.correlate(norm_a, norm_b, mode='valid')
    
    # Normalize by length
    max_corr = np.max(np.abs(correlation)) / len(flow_a)
    
    # Clip to [0, 1] range
    similarity = np.clip(max_corr, 0.0, 1.0)
    
    return float(similarity)


def mad_similarity(flow_a: np.ndarray, flow_b: np.ndarray) -> float:
    """
    Mean Absolute Difference similarity.
    
    Computes MAD between flows and maps to similarity using:
        similarity = 1 / (1 + normalized_MAD)
    
    Args:
        flow_a: Processed flow array (300,)
        flow_b: Processed flow array (300,)
        
    Returns:
        Similarity score in [0, 1]
    """
    # Compute mean absolute difference
    mad = np.mean(np.abs(flow_a - flow_b))
    
    # Normalize by average flow magnitude to make scale-independent
    avg_magnitude = (np.mean(np.abs(flow_a)) + np.mean(np.abs(flow_b))) / 2
    
    if avg_magnitude < 1e-6:
        # Both flows are near zero
        return 1.0 if mad < 1e-6 else 0.0
    
    normalized_mad = mad / (avg_magnitude + 1e-6)
    
    # Map to similarity: lower MAD = higher similarity
    similarity = 1.0 / (1.0 + normalized_mad)
    
    return float(similarity)


def detect_bursts(flow: np.ndarray, 
                  threshold: float = BURST_THRESHOLD,
                  min_burst_size: int = MIN_BURST_SIZE) -> int:
    """
    Detect packet bursts in flow.
    
    A burst is defined as consecutive packets above the threshold.
    
    Args:
        flow: 1D array of packet sizes
        threshold: Packet size threshold for burst detection
        min_burst_size: Minimum consecutive packets to count as burst
        
    Returns:
        Number of bursts detected
    """
    # Find packets above threshold
    above_threshold = flow > threshold
    
    # Count consecutive sequences
    burst_count = 0
    current_burst_length = 0
    
    for is_large in above_threshold:
        if is_large:
            current_burst_length += 1
        else:
            if current_burst_length >= min_burst_size:
                burst_count += 1
            current_burst_length = 0
    
    # Check final burst
    if current_burst_length >= min_burst_size:
        burst_count += 1
    
    return burst_count


def burst_similarity(flow_a: np.ndarray, flow_b: np.ndarray) -> float:
    """
    Compare packet burst patterns between flows.
    
    Computes burst counts for both flows and returns similarity based on
    the difference in burst counts.
    
    Args:
        flow_a: Processed flow array (300,)
        flow_b: Processed flow array (300,)
        
    Returns:
        Similarity score in [0, 1]
    """
    bursts_a = detect_bursts(flow_a)
    bursts_b = detect_bursts(flow_b)
    
    # If both have no bursts, they're similar
    if bursts_a == 0 and bursts_b == 0:
        return 1.0
    
    # Compute similarity based on burst count difference
    max_bursts = max(bursts_a, bursts_b)
    burst_diff = abs(bursts_a - bursts_b)
    
    if max_bursts == 0:
        return 1.0
    
    # Normalize difference
    similarity = 1.0 - (burst_diff / (max_bursts + bursts_a + bursts_b))
    
    return float(np.clip(similarity, 0.0, 1.0))


def statistical_similarity(flow_a: np.ndarray, flow_b: np.ndarray,
                           weights: Optional[Tuple[float, float, float]] = None) -> float:
    """
    Combined statistical similarity using weighted fusion.
    
    Default weights:
        - Cross-correlation: 0.5 (PRIMARY signal)
        - MAD: 0.3
        - Burst: 0.2
        
    This is the AUTHORITATIVE correlation metric.
    
    Args:
        flow_a: Processed flow array (300,)
        flow_b: Processed flow array (300,)
        weights: Optional custom weights (cross_corr, mad, burst)
        
    Returns:
        Combined similarity score in [0, 1]
    """
    if weights is None:
        weights = (0.5, 0.3, 0.2)
    
    w_corr, w_mad, w_burst = weights
    
    # Compute individual metrics
    corr_sim = cross_correlation_similarity(flow_a, flow_b)
    mad_sim = mad_similarity(flow_a, flow_b)
    burst_sim = burst_similarity(flow_a, flow_b)
    
    # Weighted fusion
    combined = w_corr * corr_sim + w_mad * mad_sim + w_burst * burst_sim
    
    return float(combined)


def batch_statistical_similarity(flows: dict, 
                                 target_flow: np.ndarray,
                                 metric: str = 'statistical') -> dict:
    """
    Compute similarity between target flow and multiple candidate flows.
    
    Args:
        flows: Dictionary of {flow_id: flow_array}
        target_flow: Target flow to compare against
        metric: Similarity metric to use ('statistical', 'cross_corr', 'mad', 'burst')
        
    Returns:
        Dictionary of {flow_id: similarity_score}
    """
    metric_functions = {
        'statistical': statistical_similarity,
        'cross_corr': cross_correlation_similarity,
        'mad': mad_similarity,
        'burst': burst_similarity
    }
    
    if metric not in metric_functions:
        raise ValueError(f"Unknown metric: {metric}. Choose from {list(metric_functions.keys())}")
    
    similarity_func = metric_functions[metric]
    
    results = {}
    for flow_id, flow_array in flows.items():
        try:
            score = similarity_func(target_flow, flow_array)
            results[flow_id] = score
        except Exception as e:
            logger.warning(f"Failed to compute similarity for {flow_id}: {e}")
            results[flow_id] = 0.0
    
    return results


# ============================================================================
# StatisticalCorrelator Class (for exit_correlation.py compatibility)
# ============================================================================

class StatisticalCorrelator:
    """
    Class wrapper for statistical similarity functions.
    Used by exit_correlation.py for consistent API.
    """
    
    def __init__(self, weights: Optional[Tuple[float, float, float]] = None):
        """
        Args:
            weights: Optional custom weights (cross_corr, mad, burst)
        """
        self.weights = weights or (0.5, 0.3, 0.2)
    
    def compute_similarity(self, flow_a: np.ndarray, flow_b: np.ndarray) -> float:
        """Compute statistical similarity between two flows."""
        return statistical_similarity(flow_a, flow_b, self.weights)
    
    def process_flow(self, flow_array: np.ndarray) -> np.ndarray:
        """Process raw flow to fixed-length array."""
        return process_flow(flow_array)
    
    def batch_similarity(self, flows: dict, target_flow: np.ndarray) -> dict:
        """Compute similarity between target and multiple flows."""
        return batch_statistical_similarity(flows, target_flow, metric='statistical')


# ============================================================================
# Testing and Validation
# ============================================================================

def test_process_flow():
    """Test flow preprocessing."""
    print("Testing process_flow()...")
    
    # Test truncation
    long_flow = np.random.randn(500, 3) * 100
    processed = process_flow(long_flow)
    assert processed.shape == (FIXED_LENGTH,), f"Expected shape (300,), got {processed.shape}"
    
    # Test padding
    short_flow = np.random.randn(50, 3) * 100
    processed = process_flow(short_flow)
    assert processed.shape == (FIXED_LENGTH,), f"Expected shape (300,), got {processed.shape}"
    assert np.sum(processed == 0) >= FIXED_LENGTH - 50, "Padding failed"
    
    # Test empty flow
    empty_flow = np.array([]).reshape(0, 3)
    processed = process_flow(empty_flow)
    assert np.all(processed == 0), "Empty flow should return zeros"
    
    print("✅ process_flow() tests passed")


def test_similarity_metrics():
    """Test similarity metrics."""
    print("\nTesting similarity metrics...")
    
    # Create test flows
    flow1 = np.random.randn(FIXED_LENGTH) * 100 + 500
    flow2 = flow1 + np.random.randn(FIXED_LENGTH) * 10  # Similar to flow1
    flow3 = np.random.randn(FIXED_LENGTH) * 100 + 1000  # Different
    
    # Test cross-correlation
    sim_12 = cross_correlation_similarity(flow1, flow2)
    sim_13 = cross_correlation_similarity(flow1, flow3)
    print(f"Cross-correlation: flow1-flow2={sim_12:.3f}, flow1-flow3={sim_13:.3f}")
    assert 0 <= sim_12 <= 1, "Similarity out of range"
    assert 0 <= sim_13 <= 1, "Similarity out of range"
    
    # Test MAD
    mad_12 = mad_similarity(flow1, flow2)
    mad_13 = mad_similarity(flow1, flow3)
    print(f"MAD similarity: flow1-flow2={mad_12:.3f}, flow1-flow3={mad_13:.3f}")
    assert 0 <= mad_12 <= 1, "Similarity out of range"
    assert 0 <= mad_13 <= 1, "Similarity out of range"
    
    # Test burst
    burst_12 = burst_similarity(flow1, flow2)
    burst_13 = burst_similarity(flow1, flow3)
    print(f"Burst similarity: flow1-flow2={burst_12:.3f}, flow1-flow3={burst_13:.3f}")
    assert 0 <= burst_12 <= 1, "Similarity out of range"
    assert 0 <= burst_13 <= 1, "Similarity out of range"
    
    # Test combined
    stat_12 = statistical_similarity(flow1, flow2)
    stat_13 = statistical_similarity(flow1, flow3)
    print(f"Statistical similarity: flow1-flow2={stat_12:.3f}, flow1-flow3={stat_13:.3f}")
    assert 0 <= stat_12 <= 1, "Similarity out of range"
    assert 0 <= stat_13 <= 1, "Similarity out of range"
    
    print("✅ Similarity metrics tests passed")


def test_batch_processing():
    """Test batch similarity computation."""
    print("\nTesting batch processing...")
    
    target = np.random.randn(FIXED_LENGTH) * 100 + 500
    flows = {
        f'flow_{i}': np.random.randn(FIXED_LENGTH) * 100 + 500
        for i in range(10)
    }
    
    results = batch_statistical_similarity(flows, target, metric='statistical')
    
    assert len(results) == 10, f"Expected 10 results, got {len(results)}"
    for flow_id, score in results.items():
        assert 0 <= score <= 1, f"Score out of range for {flow_id}: {score}"
    
    print(f"✅ Batch processing test passed: {len(results)} flows processed")


if __name__ == "__main__":
    print("=" * 70)
    print("Statistical Similarity Module - Tests")
    print("=" * 70)
    
    test_process_flow()
    test_similarity_metrics()
    test_batch_processing()
    
    print("\n" + "=" * 70)
    print("✅ All tests passed!")
    print("=" * 70)
