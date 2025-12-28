"""
SUMo Filtering Wrapper
Provides a clean API for using pretrained SUMo models for flow filtering.

This module wraps the SUMo source and target separation models to:
1. Filter flows based on client/OS separation (source separation)
2. Identify sessions to onion services (target separation)
3. Return filtered flow IDs with confidence scores
4. Implement fallback mechanism when all flows are filtered out
"""

import os
import sys
import numpy as np
import pandas as pd
import joblib
from typing import Dict, List, Tuple, Optional
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SUMoSourceSeparationFilter:
    """
    Source Separation Filter
    
    Separates client-side flows from onion-service-side flows.
    Uses pretrained XGBoost model to classify flows based on network characteristics.
    
    Classification Logic:
    - Probability < threshold → Client-side flow
    - Probability >= threshold → Onion-service-side flow
    """
    
    def __init__(self, model_path: str):
        """
        Initialize source separation filter.
        
        Args:
            model_path: Path to pretrained source separation model (.joblib)
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Source separation model not found: {model_path}")
        
        logger.info(f"Loading source separation model from {model_path}")
        self.model = joblib.load(model_path)
        self.model_features = self.model.feature_names
        logger.info(f"Model loaded with {len(self.model_features)} features")
    
    def filter(self, 
               features_df: pd.DataFrame,
               threshold: float = 0.001,
               fallback_top_k: int = 100) -> Dict:
        """
        Separate client-side from onion-service-side flows.
        
        Args:
            features_df: DataFrame with SUMo features (from sumo_adapter)
            threshold: Confidence threshold for classification (default: 0.001)
            fallback_top_k: If all filtered, return top-K by confidence
            
        Returns:
            {
                'client_flow_ids': [...],       # Flow IDs classified as client
                'os_flow_ids': [...],            # Flow IDs classified as OS
                'probabilities': [...],          # Confidence scores per flow
                'filtered_count': int,           # Number of flows passing threshold
                'fallback_used': bool            # True if fallback triggered
            }
        """
        X = features_df[features_df.columns[:-2]]  # Exclude Class and Capture
        flow_ids = features_df['Capture'].tolist()
        
        X = self._align_features(X)
        
        logger.info(f"Running source separation inference on {len(X)} flows")
        probabilities = self.model.predict_proba(X)
        
        os_probabilities = probabilities[:, 1]
        
        client_mask = os_probabilities < threshold
        
        client_flow_ids = [flow_ids[i] for i in range(len(flow_ids)) if client_mask[i]]
        os_flow_ids = [flow_ids[i] for i in range(len(flow_ids)) if not client_mask[i]]
        
        fallback_used = False
        if len(client_flow_ids) == 0 and fallback_top_k > 0:
            logger.warning(f"All flows classified as OS-side. Using fallback: top-{fallback_top_k} lowest confidence")
            top_k_indices = np.argsort(os_probabilities)[:fallback_top_k]
            client_flow_ids = [flow_ids[i] for i in top_k_indices]
            os_flow_ids = [flow_ids[i] for i in range(len(flow_ids)) if i not in top_k_indices]
            fallback_used = True
        
        logger.info(f"Source separation results: {len(client_flow_ids)} client, {len(os_flow_ids)} OS")
        
        return {
            'client_flow_ids': client_flow_ids,
            'os_flow_ids': os_flow_ids,
            'probabilities': os_probabilities.tolist(),
            'filtered_count': len(client_flow_ids),
            'fallback_used': fallback_used,
            'threshold': threshold
        }
    
    def _align_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Align input features with model's expected features."""
        for feat in self.model_features:
            if feat not in X.columns:
                X[feat] = 0
        
        return X[self.model_features]


class SUMoTargetSeparationFilter:
    """
    Target Separation Filter
    
    Filters client flows to identify sessions to onion services.
    Applied after source separation to refine the candidate set.
    
    Classification Logic:
    - Probability >= threshold → Session to onion service
    - Probability < threshold → Other session
    """
    
    def __init__(self, model_path: str):
        """
        Initialize target separation filter.
        
        Args:
            model_path: Path to pretrained target separation model (.joblib)
        """
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Target separation model not found: {model_path}")
        
        logger.info(f"Loading target separation model from {model_path}")
        self.model = joblib.load(model_path)
        self.model_features = self.model.feature_names
        logger.info(f"Model loaded with {len(self.model_features)} features")
    
    def filter(self,
               client_flow_ids: List[str],
               features_df: pd.DataFrame,
               threshold: float = 0.9,
               fallback_top_k: int = 50) -> Dict:
        """
        Filter client flows to identify sessions to onion services.
        
        Args:
            client_flow_ids: Flow IDs from source separation (client-side only)
            features_df: DataFrame with SUMo features
            threshold: Confidence threshold (default: 0.9)
            fallback_top_k: If all filtered, return top-K by confidence
            
        Returns:
            {
                'filtered_flow_ids': [...],   # Flow IDs likely to be OS sessions
                'probabilities': [...],        # Confidence scores
                'filtered_count': int,
                'fallback_used': bool
            }
        """
        if len(client_flow_ids) == 0:
            logger.warning("No client flows to filter in target separation")
            return {
                'filtered_flow_ids': [],
                'probabilities': [],
                'filtered_count': 0,
                'fallback_used': False,
                'threshold': threshold
            }
        
        client_mask = features_df['Capture'].isin(client_flow_ids)
        client_features_df = features_df[client_mask]
        
        X = client_features_df[client_features_df.columns[:-2]]
        flow_ids = client_features_df['Capture'].tolist()
        
        X = self._align_features(X)
        
        logger.info(f"Running target separation inference on {len(X)} client flows")
        probabilities = self.model.predict_proba(X)
        
        os_session_probabilities = probabilities[:, 1]
        
        filtered_mask = os_session_probabilities >= threshold
        filtered_flow_ids = [flow_ids[i] for i in range(len(flow_ids)) if filtered_mask[i]]
        
        fallback_used = False
        if len(filtered_flow_ids) == 0 and fallback_top_k > 0:
            logger.warning(f"All flows filtered out. Using fallback: top-{fallback_top_k} highest confidence")
            top_k_indices = np.argsort(os_session_probabilities)[::-1][:fallback_top_k]
            filtered_flow_ids = [flow_ids[i] for i in top_k_indices]
            fallback_used = True
        
        logger.info(f"Target separation results: {len(filtered_flow_ids)} flows identified as OS sessions")
        
        return {
            'filtered_flow_ids': filtered_flow_ids,
            'probabilities': os_session_probabilities.tolist(),
            'filtered_count': len(filtered_flow_ids),
            'fallback_used': fallback_used,
            'threshold': threshold
        }
    
    def _align_features(self, X: pd.DataFrame) -> pd.DataFrame:
        """Align input features with model's expected features."""
        for feat in self.model_features:
            if feat not in X.columns:
                X[feat] = 0
        return X[self.model_features]


class SUMoPipeline:
    """
    SUMo Two-Stage Filtering Pipeline
    
    Orchestrates the full SUMo filtering process:
    1. Source Separation: Client vs OS-side flows
    2. Target Separation: Identify sessions to onion services
    3. Retrieve original raw flows (NOT SUMo features)
    4. Format for ESPRESSO input
    
    CRITICAL: SUMo features are used ONLY for filtering decisions.
    Original raw flow data is retrieved and passed to ESPRESSO.
    """
    
    def __init__(self, 
                 source_model_path: str,
                 target_model_path: str):
        """
        Initialize SUMo pipeline with both models.
        
        Args:
            source_model_path: Path to source separation model
            target_model_path: Path to target separation model
        """
        self.source_filter = SUMoSourceSeparationFilter(source_model_path)
        self.target_filter = SUMoTargetSeparationFilter(target_model_path)
        logger.info("SUMo pipeline initialized with both models")
    
    def run_filtering(self,
                     features_df: pd.DataFrame,
                     flow_store: Dict[str, Dict],
                     source_threshold: float = 0.001,
                     target_threshold: float = 0.9,
                     fallback_top_k: int = 50) -> Dict:
        """
        Execute full two-stage filtering and retrieve original flows.
        
        Args:
            features_df: SUMo-engineered features (for filtering only)
            flow_store: Mapping of flow_id -> original raw flow data
                       {flow_id: {'timestamps': [...], 'sizes': [...], 
                                  'directions': [...], 'inflow_path': ..., 'outflow_path': ...}}
            source_threshold: Threshold for source separation (default: 0.001)
            target_threshold: Threshold for target separation (default: 0.9)
            fallback_top_k: Fallback count if all filtered
            
        Returns:
            {
                'filtered_flow_ids': [...],        # Final filtered flow IDs
                'filtered_raw_flows': {...},       # flow_id -> original time-series
                'espresso_ready_flows': [...],     # Formatted for ESPRESSO input
                'source_separation': {...},        # Stage 1 details
                'target_separation': {...},        # Stage 2 details
                'reduction_ratio': float,          # Reduction percentage
                'sumo_features_discarded': True    # Confirm SUMo features not passed
            }
        """
        total_flows = len(features_df)
        logger.info(f"Starting SUMo pipeline on {total_flows} flows")
        
        logger.info("=== Stage 1: Source Separation ===")
        source_results = self.source_filter.filter(
            features_df,
            threshold=source_threshold,
            fallback_top_k=fallback_top_k * 2  # More lenient for first stage
        )
        
        logger.info("=== Stage 2: Target Separation ===")
        target_results = self.target_filter.filter(
            source_results['client_flow_ids'],
            features_df,
            threshold=target_threshold,
            fallback_top_k=fallback_top_k
        )
        
        filtered_flow_ids = target_results['filtered_flow_ids']
        
        logger.info("=== Retrieving Original Raw Flows ===")
        filtered_raw_flows = {}
        espresso_ready_flows = []
        
        for flow_id in filtered_flow_ids:
            if flow_id in flow_store:
                flow_data = flow_store[flow_id]
                filtered_raw_flows[flow_id] = flow_data
                
                espresso_ready_flows.append({
                    'flow_id': flow_id,
                    'inflow_path': flow_data.get('inflow_path'),
                    'outflow_path': flow_data.get('outflow_path'),
                    'timestamps': flow_data.get('timestamps'),
                    'sizes': flow_data.get('sizes'),
                    'directions': flow_data.get('directions')
                })
            else:
                logger.warning(f"Flow {flow_id} not found in flow store")
        
        reduction_ratio = 1.0 - (len(filtered_flow_ids) / total_flows) if total_flows > 0 else 0.0
        
        logger.info(f"=== Filtering Complete ===")
        logger.info(f"Total flows: {total_flows}")
        logger.info(f"Filtered to: {len(filtered_flow_ids)}")
        logger.info(f"Reduction: {reduction_ratio * 100:.1f}%")
        
        return {
            'filtered_flow_ids': filtered_flow_ids,
            'filtered_raw_flows': filtered_raw_flows,
            'espresso_ready_flows': espresso_ready_flows,
            'source_separation': source_results,
            'target_separation': target_results,
            'reduction_ratio': reduction_ratio,
            'total_flows': total_flows,
            'filtered_count': len(filtered_flow_ids),
            'sumo_features_discarded': True,  # Critical: confirm SUMo features not passed
            'thresholds': {
                'source': source_threshold,
                'target': target_threshold
            }
        }


def load_default_pipeline(sumo_base_path: str = './sumo') -> SUMoPipeline:
    """
    Convenience function to load SUMo pipeline with default model paths.
    
    Args:
        sumo_base_path: Base path to SUMo directory
        
    Returns:
        Initialized SUMoPipeline
    """
    source_model = os.path.join(
        sumo_base_path,
        'sumo_pipeline/source_separation/models/source_separation_model_bayesian_optimization.joblib'
    )
    target_model = os.path.join(
        sumo_base_path,
        'sumo_pipeline/target_separation/models/target_separation_model_bayesian_optimization.joblib'
    )
    
    return SUMoPipeline(source_model, target_model)


if __name__ == "__main__":
    print("SUMo Filtering Wrapper")
    print("=" * 60)
    print("\nUsage example:")
    print("""
    from sumo_filter import load_default_pipeline
    from sumo_adapter import FlowFeatureExtractor
    
    extractor = FlowFeatureExtractor()
    features_df = extractor.process_flow_directory('./data/flows/')
    
    flow_store = {
        'flow_001': {
            'inflow_path': './data/flows/inflow/flow_001',
            'outflow_path': './data/flows/outflow/flow_001',
            'timestamps': [...],
            'sizes': [...],
            'directions': [...]
        },
        ...
    }
    
    pipeline = load_default_pipeline()
    results = pipeline.run_filtering(features_df, flow_store)
    
    for flow in results['espresso_ready_flows']:
        print(f"Flow {flow['flow_id']}: {flow['inflow_path']}")
    """)
    
    print("\nDefault model paths:")
    print(f"  Source: sumo/sumo_pipeline/source_separation/models/source_separation_model_bayesian_optimization.joblib")
    print(f"  Target: sumo/sumo_pipeline/target_separation/models/target_separation_model_bayesian_optimization.joblib")
