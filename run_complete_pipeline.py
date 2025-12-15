#!/usr/bin/env python3
"""
Complete TOR Traffic Analysis Pipeline

Integrates SUMo filtering with statistical and Siamese correlation.

Pipeline Flow:
    1. PCAP Processing → Extract flows
    2. Feature Extraction → SUMo features (filtering only)
    3. SUMo Filtering → Two-stage filtering (BLACK BOX)
    4. Flow Retrieval → Get original raw flows
    5. Correlation → Statistical (70%) + Siamese (30%)
    6. Output Generation → Ranked candidates + metrics

CRITICAL ARCHITECTURE:
    - SUMo features used ONLY for filtering
    - Correlation operates ONLY on raw flow data
    - No feature space mixing
    - Statistical similarity is PRIMARY (70%)
    - Siamese model is SECONDARY refinement (30%)
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import shutil

# Import pipeline components
from pcap_processor import PCAPParser
from sumo_adapter import FlowFeatureExtractor
from sumo_filter import load_default_pipeline
from correlation_pipeline import CorrelationPipeline, save_correlation_results

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CompletePipeline:
    """
    End-to-end TOR traffic analysis pipeline.
    
    SUMo Filtering → Statistical Correlation → Siamese Refinement
    """
    
    def __init__(self,
                 output_dir: str,
                 log_type: str = 'standard',
                 sumo_base_path: str = './sumo',
                 siamese_model_path: str = './lightweight_siamese.pth',
                 correlation_top_k: int = 50):
        """
        Initialize complete pipeline.
        
        Args:
            output_dir: Directory for all outputs
            log_type: PCAP log type (standard, isp, mail, proxy)
            sumo_base_path: Path to SUMo directory
            siamese_model_path: Path to Siamese model
            correlation_top_k: Top-K for Siamese refinement
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_type = log_type
        
        # Create subdirectories
        self.flows_dir = self.output_dir / 'flows'
        self.filtered_dir = self.output_dir / 'filtered_flows'
        self.correlation_dir = self.output_dir / 'correlation'
        self.metrics_dir = self.output_dir / 'metrics'
        
        for d in [self.flows_dir, self.filtered_dir, self.correlation_dir, self.metrics_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        logger.info("Initializing pipeline components...")
        self.feature_extractor = FlowFeatureExtractor()
        self.sumo_pipeline = load_default_pipeline(sumo_base_path)
        self.correlation_pipeline = CorrelationPipeline(
            siamese_model_path=siamese_model_path,
            statistical_weight=0.7,
            siamese_weight=0.3,
            top_k_for_siamese=correlation_top_k
        )
        
        # Metrics storage
        self.metrics = {
            'pipeline_start': datetime.now().isoformat(),
            'stages': {}
        }
    
    def process_pcap(self, pcap_path: str) -> Dict:
        """Stage 1: Extract flows from PCAP."""
        logger.info("=" * 70)
        logger.info("STAGE 1: PCAP Processing")
        logger.info("=" * 70)
        
        stage_start = datetime.now()
        
        parser = PCAPParser(pcap_path, log_type=self.log_type)
        flows = parser.extract_flows()
        
        # Save flows
        inflow_dir = self.flows_dir / 'inflow'
        outflow_dir = self.flows_dir / 'outflow'
        inflow_dir.mkdir(parents=True, exist_ok=True)
        outflow_dir.mkdir(parents=True, exist_ok=True)
        
        flow_ids = []
        for flow in flows:
            flow_id = flow.get_flow_id()
            flow_ids.append(flow_id)
            
            inflow_data = flow.get_inflow_data()
            with open(inflow_dir / flow_id, 'w') as f:
                for ts, size in inflow_data:
                    f.write(f"{ts}\\t{size}\\n")
            
            outflow_data = flow.get_outflow_data()
            with open(outflow_dir / flow_id, 'w') as f:
                for ts, size in outflow_data:
                    f.write(f"{ts}\\t{size}\\n")
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        
        result = {
            'flow_count': len(flow_ids),
            'flows_dir': str(self.flows_dir),
            'flow_ids': flow_ids,
            'duration_seconds': stage_duration
        }
        
        self.metrics['stages']['pcap_processing'] = result
        logger.info(f"✅ Extracted {len(flow_ids)} flows ({stage_duration:.2f}s)")
        
        return result
    
    def extract_sumo_features(self) -> Dict:
        """Stage 2: Extract SUMo features (filtering only)."""
        logger.info("\\n" + "=" * 70)
        logger.info("STAGE 2: SUMo Feature Extraction")
        logger.info("=" * 70)
        logger.info("⚠️  Features used ONLY for filtering - discarded after")
        
        stage_start = datetime.now()
        
        features_df = self.feature_extractor.process_flow_directory(str(self.flows_dir))
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        
        result = {
            'features_df': features_df,
            'feature_count': features_df.shape[1],
            'flow_count': features_df.shape[0],
            'duration_seconds': stage_duration
        }
        
        self.metrics['stages']['feature_extraction'] = {
            'feature_count': result['feature_count'],
            'flow_count': result['flow_count'],
            'duration_seconds': result['duration_seconds']
        }
        
        logger.info(f"✅ Extracted {result['feature_count']} features for {result['flow_count']} flows")
        
        return result
    
    def create_flow_store(self, flow_ids: List[str]) -> Dict[str, Dict]:
        """Create flow store with original raw flow data."""
        import numpy as np
        
        logger.info("Creating flow store (original raw flows)...")
        
        flow_store = {}
        inflow_dir = self.flows_dir / 'inflow'
        outflow_dir = self.flows_dir / 'outflow'
        
        for flow_id in flow_ids:
            try:
                inflow_path = str(inflow_dir / flow_id)
                outflow_path = str(outflow_dir / flow_id)
                
                inflow_data = np.loadtxt(inflow_path, delimiter='\\t')
                outflow_data = np.loadtxt(outflow_path, delimiter='\\t')
                
                if len(inflow_data.shape) == 1:
                    inflow_data = inflow_data.reshape(1, -1)
                if len(outflow_data.shape) == 1:
                    outflow_data = outflow_data.reshape(1, -1)
                
                flow_store[flow_id] = {
                    'inflow_path': inflow_path,
                    'outflow_path': outflow_path,
                    'timestamps': np.concatenate([inflow_data[:, 0], outflow_data[:, 0]]).tolist(),
                    'sizes': np.concatenate([inflow_data[:, 1], outflow_data[:, 1]]).tolist(),
                    'directions': ['in'] * len(inflow_data) + ['out'] * len(outflow_data)
                }
            except Exception as e:
                logger.warning(f"Failed to load flow {flow_id}: {e}")
                continue
        
        logger.info(f"✅ Flow store created: {len(flow_store)} flows")
        return flow_store
    
    def run_sumo_filtering(self, features_df, flow_store: Dict,
                          source_threshold: float = 0.001,
                          target_threshold: float = 0.9,
                          fallback_top_k: int = 100) -> Dict:
        """Stage 3: SUMo filtering (BLACK BOX)."""
        logger.info("\\n" + "=" * 70)
        logger.info("STAGE 3: SUMo Filtering (BLACK BOX)")
        logger.info("=" * 70)
        
        stage_start = datetime.now()
        
        results = self.sumo_pipeline.run_filtering(
            features_df,
            flow_store,
            source_threshold=source_threshold,
            target_threshold=target_threshold,
            fallback_top_k=fallback_top_k
        )
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        results['duration_seconds'] = stage_duration
        
        logger.info(f"\\n📊 FILTERING METRICS:")
        logger.info(f"   Total flows:    {results['total_flows']}")
        logger.info(f"   Filtered flows: {results['filtered_count']}")
        logger.info(f"   Reduction:      {results['reduction_ratio']*100:.1f}%")
        logger.info(f"   Duration:       {stage_duration:.2f}s")
        
        self.metrics['stages']['sumo_filtering'] = {
            'total_flows': results['total_flows'],
            'filtered_flows': results['filtered_count'],
            'reduction_ratio': results['reduction_ratio'],
            'duration_seconds': stage_duration
        }
        
        # Save filtered flows
        filtered_flow_ids = results['filtered_flow_ids']
        if len(filtered_flow_ids) > 0:
            filtered_inflow_dir = self.filtered_dir / 'inflow'
            filtered_outflow_dir = self.filtered_dir / 'outflow'
            filtered_inflow_dir.mkdir(parents=True, exist_ok=True)
            filtered_outflow_dir.mkdir(parents=True, exist_ok=True)
            
            for flow_id in filtered_flow_ids:
                src_inflow = self.flows_dir / 'inflow' / flow_id
                src_outflow = self.flows_dir / 'outflow' / flow_id
                
                if src_inflow.exists():
                    shutil.copy2(src_inflow, filtered_inflow_dir / flow_id)
                if src_outflow.exists():
                    shutil.copy2(src_outflow, filtered_outflow_dir / flow_id)
        
        logger.info(f"✅ SUMo filtering complete")
        
        return results
    
    def run_correlation(self,
                       target_flow_id: str,
                       filtering_results: Dict,
                       flow_store: Dict) -> Dict:
        """Stage 4: Statistical + Siamese Correlation."""
        logger.info("\\n" + "=" * 70)
        logger.info("STAGE 4: Correlation Analysis")
        logger.info("=" * 70)
        logger.info("⚠️  Operating ONLY on raw flow data (NOT SUMo features)")
        
        stage_start = datetime.now()
        
        filtered_flow_ids = filtering_results['filtered_flow_ids']
        
        # Remove target from candidates
        candidate_ids = [fid for fid in filtered_flow_ids if fid != target_flow_id]
        
        if len(candidate_ids) == 0:
            logger.warning("No candidates for correlation")
            return {
                'target_flow_id': target_flow_id,
                'ranked_candidates': [],
                'metadata': {'note': 'No candidates available'}
            }
        
        # Run correlation pipeline
        results = self.correlation_pipeline.run(
            target_flow_id=target_flow_id,
            filtered_flow_ids=candidate_ids,
            flow_store=flow_store
        )
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        
        logger.info(f"\\n📊 CORRELATION METRICS:")
        logger.info(f"   Candidates:     {len(candidate_ids)}")
        logger.info(f"   Top-K Siamese:  {results['metadata']['top_k_for_siamese']}")
        logger.info(f"   Top candidate:  {results['ranked_candidates'][0]['flow_id']}")
        logger.info(f"   Top score:      {results['ranked_candidates'][0]['final']:.4f}")
        logger.info(f"   Duration:       {stage_duration:.2f}s")
        
        self.metrics['stages']['correlation'] = {
            'total_candidates': len(candidate_ids),
            'top_k_for_siamese': results['metadata']['top_k_for_siamese'],
            'statistical_weight': results['metadata']['statistical_weight'],
            'siamese_weight': results['metadata']['siamese_weight'],
            'duration_seconds': stage_duration
        }
        
        # Save correlation results
        save_correlation_results(results, self.correlation_dir)
        
        logger.info(f"✅ Correlation complete")
        
        return results
    
    def save_final_metrics(self):
        """Save complete pipeline metrics."""
        self.metrics['pipeline_end'] = datetime.now().isoformat()
        
        # Calculate total reduction
        if 'sumo_filtering' in self.metrics['stages']:
            sumo_reduction = self.metrics['stages']['sumo_filtering']['reduction_ratio']
            self.metrics['total_candidate_reduction'] = sumo_reduction
        
        metrics_path = self.metrics_dir / 'pipeline_metrics.json'
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        logger.info(f"\\n📊 Complete pipeline metrics saved: {metrics_path}")
        return str(metrics_path)
    
    def run(self,
            pcap_path: str,
            target_flow_id: Optional[str] = None,
            source_threshold: float = 0.001,
            target_threshold: float = 0.9,
            sumo_fallback_k: int = 100) -> Dict:
        """
        Run complete pipeline.
        
        Args:
            pcap_path: Input PCAP file
            target_flow_id: Target flow for correlation (uses first flow if None)
            source_threshold: SUMo source separation threshold
            target_threshold: SUMo target separation threshold
            sumo_fallback_k: SUMo fallback top-K
            
        Returns:
            Complete pipeline results
        """
        logger.info("\\n" + "=" * 70)
        logger.info("COMPLETE TOR TRAFFIC ANALYSIS PIPELINE")
        logger.info("=" * 70)
        logger.info(f"Input PCAP: {pcap_path}")
        logger.info(f"Output directory: {self.output_dir}")
        
        try:
            # Stage 1: PCAP Processing
            pcap_results = self.process_pcap(pcap_path)
            
            # Stage 2: Feature Extraction
            feature_results = self.extract_sumo_features()
            
            # Create flow store
            flow_store = self.create_flow_store(pcap_results['flow_ids'])
            
            # Stage 3: SUMo Filtering
            filtering_results = self.run_sumo_filtering(
                feature_results['features_df'],
                flow_store,
                source_threshold=source_threshold,
                target_threshold=target_threshold,
                fallback_top_k=sumo_fallback_k
            )
            
            # Determine target flow
            if target_flow_id is None:
                # Use first filtered flow as target
                if len(filtering_results['filtered_flow_ids']) > 0:
                    target_flow_id = filtering_results['filtered_flow_ids'][0]
                else:
                    logger.warning("No filtered flows available")
                    return {
                        'success': False,
                        'error': 'No flows passed filtering'
                    }
            
            # Stage 4: Correlation
            correlation_results = self.run_correlation(
                target_flow_id,
                filtering_results,
                flow_store
            )
            
            # Save metrics
            metrics_path = self.save_final_metrics()
            
            # Final summary
            logger.info("\\n" + "=" * 70)
            logger.info("PIPELINE COMPLETE ✅")
            logger.info("=" * 70)
            logger.info(f"Total input flows:      {filtering_results['total_flows']}")
            logger.info(f"SUMo filtered flows:    {filtering_results['filtered_count']}")
            logger.info(f"Reduction ratio:        {filtering_results['reduction_ratio']*100:.1f}%")
            logger.info(f"Target flow:            {target_flow_id}")
            logger.info(f"Top ranked candidate:   {correlation_results['ranked_candidates'][0]['flow_id']}")
            logger.info(f"Top candidate score:    {correlation_results['ranked_candidates'][0]['final']:.4f}")
            logger.info(f"\\nOutputs:")
            logger.info(f"  Filtered flows:  {self.filtered_dir}")
            logger.info(f"  Correlation:     {self.correlation_dir}")
            logger.info(f"  Metrics:         {metrics_path}")
            
            return {
                'success': True,
                'metrics_path': metrics_path,
                'filtered_dir': str(self.filtered_dir),
                'correlation_dir': str(self.correlation_dir),
                'sumo_reduction_ratio': filtering_results['reduction_ratio'],
                'target_flow_id': target_flow_id,
                'top_candidate': correlation_results['ranked_candidates'][0]
            }
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }


def main():
    parser = argparse.ArgumentParser(
        description='Complete TOR Traffic Analysis Pipeline - SUMo Filtering + Correlation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--pcap', required=True, help='Input PCAP file')
    parser.add_argument('--output', required=True, help='Output directory')
    parser.add_argument('--target-flow', default=None, help='Target flow ID for correlation')
    parser.add_argument('--log-type', default='standard',
                       choices=['standard', 'isp', 'mail', 'proxy'],
                       help='PCAP log format type')
    parser.add_argument('--source-threshold', type=float, default=0.001,
                       help='SUMo source separation threshold')
    parser.add_argument('--target-threshold', type=float, default=0.9,
                       help='SUMo target separation threshold')
    parser.add_argument('--sumo-fallback-k', type=int, default=100,
                       help='SUMo fallback top-K')
    parser.add_argument('--correlation-top-k', type=int, default=50,
                       help='Top-K for Siamese refinement')
    parser.add_argument('--sumo-path', default='./sumo',
                       help='Path to SUMo directory')
    parser.add_argument('--siamese-model', default='./lightweight_siamese.pth',
                       help='Path to Siamese model')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    if not os.path.exists(args.siamese_model):
        print(f"Error: Siamese model not found: {args.siamese_model}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = CompletePipeline(
        output_dir=args.output,
        log_type=args.log_type,
        sumo_base_path=args.sumo_path,
        siamese_model_path=args.siamese_model,
        correlation_top_k=args.correlation_top_k
    )
    
    results = pipeline.run(
        pcap_path=args.pcap,
        target_flow_id=args.target_flow,
        source_threshold=args.source_threshold,
        target_threshold=args.target_threshold,
        sumo_fallback_k=args.sumo_fallback_k
    )
    
    sys.exit(0 if results['success'] else 1)


if __name__ == "__main__":
    main()
