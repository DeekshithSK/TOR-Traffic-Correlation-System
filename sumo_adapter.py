"""
SUMo Feature Adapter
Converts inflow/outflow flow format to SUMo-compatible feature vectors.

This module replicates SUMo's feature extraction logic to generate the exact
166 features required by the pretrained source/target separation models.
"""

import os
import sys
import numpy as np
import pandas as pd
from scipy.stats import kurtosis, skew
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FlowFeatureExtractor:
    """
    Extracts SUMo-compatible features from inflow/outflow files.
    
    Our Format (tab-separated):
        timestamp\tpacket_size
        
    SUMo Features (166 total):
        - Packet size statistics (total, in, out)
        - Inter-packet time statistics (total, in, out) 
        - Burst statistics (in, out)
    """
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = self._get_feature_headers()
    
    @staticmethod
    def _get_feature_headers() -> List[str]:
        """
        Get exact SUMo feature names (166 features).
        Must match the order used during model training.
        """
        headers = []
        
        headers.extend(['TotalPackets', 'totalPacketsIn', 'totalPacketsOut'])
        
        headers.extend(['totalBytes', 'totalBytesIn', 'totalBytesOut'])
        
        headers.extend([
            'minPacketSize', 'maxPacketSize', 'meanPacketSizes',
            'stdevPacketSizes', 'variancePacketSizes', 
            'kurtosisPacketSizes', 'skewPacketSizes',
            'p10PacketSizes', 'p20PacketSizes', 'p30PacketSizes',
            'p40PacketSizes', 'p50PacketSizes', 'p60PacketSizes',
            'p70PacketSizes', 'p80PacketSizes', 'p90PacketSizes'
        ])
        
        headers.extend([
            'minPacketSizeIn', 'maxPacketSizeIn', 'meanPacketSizesIn',
            'stdevPacketSizesIn', 'variancePacketSizesIn',
            'skewPacketSizesIn', 'kurtosisPacketSizesIn',
            'p10PacketSizesIn', 'p20PacketSizesIn', 'p30PacketSizesIn',
            'p40PacketSizesIn', 'p50PacketSizesIn', 'p60PacketSizesIn',
            'p70PacketSizesIn', 'p80PacketSizesIn', 'p90PacketSizesIn'
        ])
        
        headers.extend([
            'minPacketSizeOut', 'maxPacketSizeOut', 'meanPacketSizesOut',
            'stdevPacketSizesOut', 'variancePacketSizesOut',
            'skewPacketSizesOut', 'kurtosisPacketSizesOut',
            'p10PacketSizesOut', 'p20PacketSizesOut', 'p30PacketSizesOut',
            'p40PacketSizesOut', 'p50PacketSizesOut', 'p60PacketSizesOut',
            'p70PacketSizesOut', 'p80PacketSizesOut', 'p90PacketSizesOut'
        ])
        
        headers.extend([
            'maxIPT', 'minIPT', 'meanPacketTimes',
            'stdevPacketTimes', 'variancePacketTimes',
            'kurtosisPacketTimes', 'skewPacketTimes',
            'p10PacketTimes', 'p20PacketTimes', 'p30PacketTimes',
            'p40PacketTimes', 'p50PacketTimes', 'p60PacketTimes',
            'p70PacketTimes', 'p80PacketTimes', 'p90PacketTimes'
        ])
        
        headers.extend([
            'minPacketTimesIn', 'maxPacketTimesIn', 'meanPacketTimesIn',
            'stdevPacketTimesIn', 'variancePacketTimesIn',
            'skewPacketTimesIn', 'kurtosisPacketTimesIn',
            'p10PacketTimesIn', 'p20PacketTimesIn', 'p30PacketTimesIn',
            'p40PacketTimesIn', 'p50PacketTimesIn', 'p60PacketTimesIn',
            'p70PacketTimesIn', 'p80PacketTimesIn', 'p90PacketTimesIn'
        ])
        
        headers.extend([
            'minPacketTimesOut', 'maxPacketTimesOut', 'meanPacketTimesOut',
            'stdevPacketTimesOut', 'variancePacketTimesOut',
            'skewPacketTimesOut', 'kurtosisPacketTimesOut',
            'p10PacketTimesOut', 'p20PacketTimesOut', 'p30PacketTimesOut',
            'p40PacketTimesOut', 'p50PacketTimesOut', 'p60PacketTimesOut',
            'p70PacketTimesOut', 'p80PacketTimesOut', 'p90PacketTimesOut'
        ])
        
        headers.extend([
            'out_totalBursts', 'out_maxBurst', 'out_meanBurst',
            'out_stdevBurst', 'out_varianceBurst', 'out_kurtosisBurst',
            'out_skewBurst', 'out_p10Burst', 'out_p20Burst',
            'out_p30Burst', 'out_p40Burst', 'out_p50Burst',
            'out_p60Burst', 'out_p70Burst', 'out_p80Burst', 'out_p90Burst'
        ])
        
        headers.extend([
            'out_maxBurstBytes', 'out_minBurstBytes', 'out_meanBurstBytes',
            'out_stdevBurstBytes', 'out_varianceBurstBytes',
            'out_kurtosisBurstBytes', 'out_skewBurstBytes',
            'out_p10BurstBytes', 'out_p20BurstBytes', 'out_p30BurstBytes',
            'out_p40BurstBytes', 'out_p50BurstBytes', 'out_p60BurstBytes',
            'out_p70BurstBytes', 'out_p80BurstBytes', 'out_p90BurstBytes'
        ])
        
        headers.extend([
            'in_totalBursts', 'in_maxBurst', 'in_meanBurst',
            'in_stdevBurst', 'in_varianceBurst', 'in_kurtosisBurst',
            'in_skewBurst', 'in_p10Burst', 'in_p20Burst',
            'in_p30Burst', 'in_p40Burst', 'in_p50Burst',
            'in_p60Burst', 'in_p70Burst', 'in_p80Burst', 'in_p90Burst'
        ])
        
        headers.extend([
            'in_maxBurstBytes', 'in_minBurstBytes', 'in_meanBurstBytes',
            'in_stdevBurstBytes', 'in_varianceBurstBytes',
            'in_kurtosisBurstBytes', 'in_skewBurstBytes',
            'in_p10BurstBytes', 'in_p20BurstBytes', 'in_p30BurstBytes',
            'in_p40BurstBytes', 'in_p50BurstBytes', 'in_p60BurstBytes',
            'in_p70BurstBytes', 'in_p80BurstBytes', 'in_p90BurstBytes'
        ])
        
        headers.extend(['Class', 'Capture'])
        
        return headers
    
    def read_flow_file(self, flow_path: str) -> Tuple[np.ndarray, np.ndarray]:
        """
        Read a flow file in our format (timestamp	size).
        
        Returns:
            timestamps: Array of timestamps (relative to first packet)
            sizes: Array of packet sizes
        """
        try:
            data = np.loadtxt(flow_path, delimiter='	')
            if len(data.shape) == 1:  # Single packet
                data = data.reshape(1, -1)
            
            timestamps = data[:, 0]
            sizes = data[:, 1].astype(int)
            
            timestamps = timestamps - timestamps[0]
            
            return timestamps, sizes
        except Exception as e:
            logger.warning(f"Error reading {flow_path}: {e}")
            return np.array([0.0]), np.array([0])
    
    def compute_iat(self, timestamps: np.ndarray) -> np.ndarray:
        """Compute inter-arrival times (in milliseconds, like SUMo)."""
        if len(timestamps) <= 1:
            return np.array([0.0])
        iat = np.diff(timestamps) * 1000  # Convert to ms
        return np.maximum(iat, 0)  # Ensure non-negative
    
    def compute_bursts(self, timestamps: np.ndarray, sizes: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute burst statistics.
        A burst = consecutive packets in same direction.
        
        Returns:
            burst_counts: Number of packets per burst
            burst_sizes: Total bytes per burst
        """
        if len(timestamps) == 0:
            return np.array([0]), np.array([0])
        
        bursts_counts = []
        bursts_sizes = []
        
        current_burst_count = 1
        current_burst_size = sizes[0]
        
        for i in range(1, len(timestamps)):
            if (timestamps[i] - timestamps[i-1]) * 1000 < 10:
                current_burst_count += 1
                current_burst_size += sizes[i]
            else:
                if current_burst_count > 1:  # Only count bursts > 1 packet
                    bursts_counts.append(current_burst_count)
                    bursts_sizes.append(current_burst_size)
                current_burst_count = 1
                current_burst_size = sizes[i]
        
        if current_burst_count > 1:
            bursts_counts.append(current_burst_count)
            bursts_sizes.append(current_burst_size)
        
        if len(bursts_counts) == 0:
            return np.array([0]), np.array([0])
        
        return np.array(bursts_counts), np.array(bursts_sizes)
    
    def compute_statistics(self, values: np.ndarray) -> Dict[str, float]:
        """Compute statistical features for an array."""
        if len(values) == 0 or np.all(values == 0):
            return {
                'min': 0, 'max': 0, 'mean': 0, 'std': 0, 'var': 0,
                'kurtosis': 0, 'skew': 0,
                'p10': 0, 'p20': 0, 'p30': 0, 'p40': 0, 'p50': 0,
                'p60': 0, 'p70': 0, 'p80': 0, 'p90': 0
            }
        
        try:
            return {
                'min': np.min(values),
                'max': np.max(values),
                'mean': np.mean(values),
                'std': np.std(values),
                'var': np.var(values),
                'kurtosis': float(kurtosis(values)),
                'skew': float(skew(values)),
                'p10': np.percentile(values, 10),
                'p20': np.percentile(values, 20),
                'p30': np.percentile(values, 30),
                'p40': np.percentile(values, 40),
                'p50': np.percentile(values, 50),
                'p60': np.percentile(values, 60),
                'p70': np.percentile(values, 70),
                'p80': np.percentile(values, 80),
                'p90': np.percentile(values, 90),
            }
        except:
            return {k: 0 for k in ['min', 'max', 'mean', 'std', 'var', 'kurtosis', 'skew',
                                    'p10', 'p20', 'p30', 'p40', 'p50', 'p60', 'p70', 'p80', 'p90']}
    
    def extract_features(self, inflow_path: str, outflow_path: str, flow_id: str) -> Dict[str, float]:
        """
        Extract all SUMo features from a bidirectional flow.
        
        Args:
            inflow_path: Path to inflow file (packets TO the monitored host)
            outflow_path: Path to outflow file (packets FROM the monitored host)
            flow_id: Unique identifier for this flow
            
        Returns:
            Dictionary with all 166 features + metadata
        """
        features = {}
        
        ts_in, sizes_in = self.read_flow_file(inflow_path)
        ts_out, sizes_out = self.read_flow_file(outflow_path)
        
        all_sizes = np.concatenate([sizes_in, sizes_out])
        
        iat_in = self.compute_iat(ts_in)
        iat_out = self.compute_iat(ts_out)
        all_iat = np.concatenate([iat_in, iat_out])
        
        features['TotalPackets'] = len(all_sizes)
        features['totalPacketsIn'] = len(sizes_in)
        features['totalPacketsOut'] = len(sizes_out)
        
        features['totalBytes'] = int(np.sum(all_sizes))
        features['totalBytesIn'] = int(np.sum(sizes_in))
        features['totalBytesOut'] = int(np.sum(sizes_out))
        
        size_stats = self.compute_statistics(all_sizes)
        features['minPacketSize'] = size_stats['min']
        features['maxPacketSize'] = size_stats['max']
        features['meanPacketSizes'] = size_stats['mean']
        features['stdevPacketSizes'] = size_stats['std']
        features['variancePacketSizes'] = size_stats['var']
        features['kurtosisPacketSizes'] = size_stats['kurtosis']
        features['skewPacketSizes'] = size_stats['skew']
        features['p10PacketSizes'] = size_stats['p10']
        features['p20PacketSizes'] = size_stats['p20']
        features['p30PacketSizes'] = size_stats['p30']
        features['p40PacketSizes'] = size_stats['p40']
        features['p50PacketSizes'] = size_stats['p50']
        features['p60PacketSizes'] = size_stats['p60']
        features['p70PacketSizes'] = size_stats['p70']
        features['p80PacketSizes'] = size_stats['p80']
        features['p90PacketSizes'] = size_stats['p90']
        
        size_stats_in = self.compute_statistics(sizes_in)
        features['minPacketSizeIn'] = size_stats_in['min']
        features['maxPacketSizeIn'] = size_stats_in['max']
        features['meanPacketSizesIn'] = size_stats_in['mean']
        features['stdevPacketSizesIn'] = size_stats_in['std']
        features['variancePacketSizesIn'] = size_stats_in['var']
        features['skewPacketSizesIn'] = size_stats_in['skew']
        features['kurtosisPacketSizesIn'] = size_stats_in['kurtosis']
        features['p10PacketSizesIn'] = size_stats_in['p10']
        features['p20PacketSizesIn'] = size_stats_in['p20']
        features['p30PacketSizesIn'] = size_stats_in['p30']
        features['p40PacketSizesIn'] = size_stats_in['p40']
        features['p50PacketSizesIn'] = size_stats_in['p50']
        features['p60PacketSizesIn'] = size_stats_in['p60']
        features['p70PacketSizesIn'] = size_stats_in['p70']
        features['p80PacketSizesIn'] = size_stats_in['p80']
        features['p90PacketSizesIn'] = size_stats_in['p90']
        
        size_stats_out = self.compute_statistics(sizes_out)
        features['minPacketSizeOut'] = size_stats_out['min']
        features['maxPacketSizeOut'] = size_stats_out['max']
        features['meanPacketSizesOut'] = size_stats_out['mean']
        features['stdevPacketSizesOut'] = size_stats_out['std']
        features['variancePacketSizesOut'] = size_stats_out['var']
        features['skewPacketSizesOut'] = size_stats_out['skew']
        features['kurtosisPacketSizesOut'] = size_stats_out['kurtosis']
        features['p10PacketSizesOut'] = size_stats_out['p10']
        features['p20PacketSizesOut'] = size_stats_out['p20']
        features['p30PacketSizesOut'] = size_stats_out['p30']
        features['p40PacketSizesOut'] = size_stats_out['p40']
        features['p50PacketSizesOut'] = size_stats_out['p50']
        features['p60PacketSizesOut'] = size_stats_out['p60']
        features['p70PacketSizesOut'] = size_stats_out['p70']
        features['p80PacketSizesOut'] = size_stats_out['p80']
        features['p90PacketSizesOut'] = size_stats_out['p90']
        
        iat_stats = self.compute_statistics(all_iat)
        features['maxIPT'] = iat_stats['max']
        features['minIPT'] = iat_stats['min']
        features['meanPacketTimes'] = iat_stats['mean']
        features['stdevPacketTimes'] = iat_stats['std']
        features['variancePacketTimes'] = iat_stats['var']
        features['kurtosisPacketTimes'] = iat_stats['kurtosis']
        features['skewPacketTimes'] = iat_stats['skew']
        features['p10PacketTimes'] = iat_stats['p10']
        features['p20PacketTimes'] = iat_stats['p20']
        features['p30PacketTimes'] = iat_stats['p30']
        features['p40PacketTimes'] = iat_stats['p40']
        features['p50PacketTimes'] = iat_stats['p50']
        features['p60PacketTimes'] = iat_stats['p60']
        features['p70PacketTimes'] = iat_stats['p70']
        features['p80PacketTimes'] = iat_stats['p80']
        features['p90PacketTimes'] = iat_stats['p90']
        
        iat_stats_in = self.compute_statistics(iat_in)
        features['minPacketTimesIn'] = iat_stats_in['min']
        features['maxPacketTimesIn'] = iat_stats_in['max']
        features['meanPacketTimesIn'] = iat_stats_in['mean']
        features['stdevPacketTimesIn'] = iat_stats_in['std']
        features['variancePacketTimesIn'] = iat_stats_in['var']
        features['skewPacketTimesIn'] = iat_stats_in['skew']
        features['kurtosisPacketTimesIn'] = iat_stats_in['kurtosis']
        features['p10PacketTimesIn'] = iat_stats_in['p10']
        features['p20PacketTimesIn'] = iat_stats_in['p20']
        features['p30PacketTimesIn'] = iat_stats_in['p30']
        features['p40PacketTimesIn'] = iat_stats_in['p40']
        features['p50PacketTimesIn'] = iat_stats_in['p50']
        features['p60PacketTimesIn'] = iat_stats_in['p60']
        features['p70PacketTimesIn'] = iat_stats_in['p70']
        features['p80PacketTimesIn'] = iat_stats_in['p80']
        features['p90PacketTimesIn'] = iat_stats_in['p90']
        
        iat_stats_out = self.compute_statistics(iat_out)
        features['minPacketTimesOut'] = iat_stats_out['min']
        features['maxPacketTimesOut'] = iat_stats_out['max']
        features['meanPacketTimesOut'] = iat_stats_out['mean']
        features['stdevPacketTimesOut'] = iat_stats_out['std']
        features['variancePacketTimesOut'] = iat_stats_out['var']
        features['skewPacketTimesOut'] = iat_stats_out['skew']
        features['kurtosisPacketTimesOut'] = iat_stats_out['kurtosis']
        features['p10PacketTimesOut'] = iat_stats_out['p10']
        features['p20PacketTimesOut'] = iat_stats_out['p20']
        features['p30PacketTimesOut'] = iat_stats_out['p30']
        features['p40PacketTimesOut'] = iat_stats_out['p40']
        features['p50PacketTimesOut'] = iat_stats_out['p50']
        features['p60PacketTimesOut'] = iat_stats_out['p60']
        features['p70PacketTimesOut'] = iat_stats_out['p70']
        features['p80PacketTimesOut'] = iat_stats_out['p80']
        features['p90PacketTimesOut'] = iat_stats_out['p90']
        
        burst_counts_out, burst_sizes_out = self.compute_bursts(ts_out, sizes_out)
        
        features['out_totalBursts'] = len(burst_counts_out)
        burst_stats_out = self.compute_statistics(burst_counts_out)
        features['out_maxBurst'] = burst_stats_out['max']
        features['out_meanBurst'] = burst_stats_out['mean']
        features['out_stdevBurst'] = burst_stats_out['std']
        features['out_varianceBurst'] = burst_stats_out['var']
        features['out_kurtosisBurst'] = burst_stats_out['kurtosis']
        features['out_skewBurst'] = burst_stats_out['skew']
        features['out_p10Burst'] = burst_stats_out['p10']
        features['out_p20Burst'] = burst_stats_out['p20']
        features['out_p30Burst'] = burst_stats_out['p30']
        features['out_p40Burst'] = burst_stats_out['p40']
        features['out_p50Burst'] = burst_stats_out['p50']
        features['out_p60Burst'] = burst_stats_out['p60']
        features['out_p70Burst'] = burst_stats_out['p70']
        features['out_p80Burst'] = burst_stats_out['p80']
        features['out_p90Burst'] = burst_stats_out['p90']
        
        burst_size_stats_out = self.compute_statistics(burst_sizes_out)
        features['out_maxBurstBytes'] = burst_size_stats_out['max']
        features['out_minBurstBytes'] = burst_size_stats_out['min']
        features['out_meanBurstBytes'] = burst_size_stats_out['mean']
        features['out_stdevBurstBytes'] = burst_size_stats_out['std']
        features['out_varianceBurstBytes'] = burst_size_stats_out['var']
        features['out_kurtosisBurstBytes'] = burst_size_stats_out['kurtosis']
        features['out_skewBurstBytes'] = burst_size_stats_out['skew']
        features['out_p10BurstBytes'] = burst_size_stats_out['p10']
        features['out_p20BurstBytes'] = burst_size_stats_out['p20']
        features['out_p30BurstBytes'] = burst_size_stats_out['p30']
        features['out_p40BurstBytes'] = burst_size_stats_out['p40']
        features['out_p50BurstBytes'] = burst_size_stats_out['p50']
        features['out_p60BurstBytes'] = burst_size_stats_out['p60']
        features['out_p70BurstBytes'] = burst_size_stats_out['p70']
        features['out_p80BurstBytes'] = burst_size_stats_out['p80']
        features['out_p90BurstBytes'] = burst_size_stats_out['p90']
        
        burst_counts_in, burst_sizes_in = self.compute_bursts(ts_in, sizes_in)
        
        features['in_totalBursts'] = len(burst_counts_in)
        burst_stats_in = self.compute_statistics(burst_counts_in)
        features['in_maxBurst'] = burst_stats_in['max']
        features['in_meanBurst'] = burst_stats_in['mean']
        features['in_stdevBurst'] = burst_stats_in['std']
        features['in_varianceBurst'] = burst_stats_in['var']
        features['in_kurtosisBurst'] = burst_stats_in['kurtosis']
        features['in_skewBurst'] = burst_stats_in['skew']
        features['in_p10Burst'] = burst_stats_in['p10']
        features['in_p20Burst'] = burst_stats_in['p20']
        features['in_p30Burst'] = burst_stats_in['p30']
        features['in_p40Burst'] = burst_stats_in['p40']
        features['in_p50Burst'] = burst_stats_in['p50']
        features['in_p60Burst'] = burst_stats_in['p60']
        features['in_p70Burst'] = burst_stats_in['p70']
        features['in_p80Burst'] = burst_stats_in['p80']
        features['in_p90Burst'] = burst_stats_in['p90']
        
        burst_size_stats_in = self.compute_statistics(burst_sizes_in)
        features['in_maxBurstBytes'] = burst_size_stats_in['max']
        features['in_minBurstBytes'] = burst_size_stats_in['min']
        features['in_meanBurstBytes'] = burst_size_stats_in['mean']
        features['in_stdevBurstBytes'] = burst_size_stats_in['std']
        features['in_varianceBurstBytes'] = burst_size_stats_in['var']
        features['in_kurtosisBurstBytes'] = burst_size_stats_in['kurtosis']
        features['in_skewBurstBytes'] = burst_size_stats_in['skew']
        features['in_p10BurstBytes'] = burst_size_stats_in['p10']
        features['in_p20BurstBytes'] = burst_size_stats_in['p20']
        features['in_p30BurstBytes'] = burst_size_stats_in['p30']
        features['in_p40BurstBytes'] = burst_size_stats_in['p40']
        features['in_p50BurstBytes'] = burst_size_stats_in['p50']
        features['in_p60BurstBytes'] = burst_size_stats_in['p60']
        features['in_p70BurstBytes'] = burst_size_stats_in['p70']
        features['in_p80BurstBytes'] = burst_size_stats_in['p80']
        features['in_p90BurstBytes'] = burst_size_stats_in['p90']
        
        features['Class'] = 0  # Placeholder (not used in inference)
        features['Capture'] = flow_id
        
        return features
    
    def process_flow_directory(self, flows_dir: str) -> pd.DataFrame:
        """
        Process all flows in a directory (inflow/ and outflow subdirectories).
        
        Args:
            flows_dir: Path to directory containing inflow/ and outflow/ subdirectories
            
        Returns:
            DataFrame with SUMo features for all flows
        """
        inflow_dir = Path(flows_dir) / 'inflow'
        outflow_dir = Path(flows_dir) / 'outflow'
        
        if not inflow_dir.exists() or not outflow_dir.exists():
            raise ValueError(f"Missing inflow or outflow directory in {flows_dir}")
        
        inflow_files = {f.stem: f for f in inflow_dir.glob('*') if f.is_file()}
        outflow_files = {f.stem: f for f in outflow_dir.glob('*') if f.is_file()}
        
        common_flows = set(inflow_files.keys()) & set(outflow_files.keys())
        
        if len(common_flows) == 0:
            raise ValueError(f"No matching inflow/outflow pairs found in {flows_dir}")
        
        logger.info(f"Processing {len(common_flows)} flows from {flows_dir}")
        
        all_features = []
        for flow_id in sorted(common_flows):
            try:
                features = self.extract_features(
                    str(inflow_files[flow_id]),
                    str(outflow_files[flow_id]),
                    flow_id
                )
                all_features.append(features)
            except Exception as e:
                logger.warning(f"Failed to extract features for {flow_id}: {e}")
                continue
        
        df = pd.DataFrame(all_features, columns=self.feature_names)
        
        df = self.normalize_features(df)
        
        logger.info(f"Extracted features: {df.shape[0]} flows x {df.shape[1]} features")
        
        return df
    
    def normalize_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply SUMo's feature normalization (replicates gather_dataset logic).
        
        This must match the preprocessing done during model training.
        """
        feature_cols = df.columns[:-2]  # Exclude 'Class' and 'Capture'
        for col in feature_cols:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], downcast='float', errors='coerce')
        
        df = df.fillna(0)
        
        non_zero_cols = (df[feature_cols] != 0).any(axis=0)
        cols_to_keep = list(df[feature_cols].columns[non_zero_cols]) + ['Class', 'Capture']
        df = df[cols_to_keep]
        
        
        return df


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python sumo_adapter.py <flows_directory>")
        print("  flows_directory should contain inflow/ and outflow/ subdirectories")
        sys.exit(1)
    
    flows_dir = sys.argv[1]
    
    extractor = FlowFeatureExtractor()
    features_df = extractor.process_flow_directory(flows_dir)
    
    output_file = f"{flows_dir}_sumo_features.csv"
    features_df.to_csv(output_file, index=False)
    
    print(f"✅ Extracted features saved to: {output_file}")
    print(f"   Shape: {features_df.shape}")
    print(f"   Columns: {list(features_df.columns[:10])}... (showing first 10)")
