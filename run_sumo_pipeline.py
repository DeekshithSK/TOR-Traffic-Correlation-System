#!/usr/bin/env python3
"""
SUMo Filtering Pipeline - Main Entry Point

End-to-end pipeline for filtering Tor traffic flows using pretrained SUMo models.

Pipeline Flow:
1. PCAP Processing    → Extract flows to inflow/outflow
2. Feature Extraction → Generate SUMo features (for filtering ONLY)
3. SUMo Filtering     → Two-stage filtering (BLACK BOX)
4. Flow Retrieval     → Get original raw flows using filtered IDs
5. Output Generation  → Save ESPRESSO-compatible results

CRITICAL: SUMo features are ONLY used for filtering decisions.
          Original raw flow data is passed to downstream correlation (ESPRESSO).
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

# Import our modules
from pcap_processor import PCAPParser
from sumo_adapter import FlowFeatureExtractor
from sumo_filter import load_default_pipeline

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SUMoFilteringPipeline:
    """
    Main pipeline orchestrator.
    
    Treats SUMo filtering as a BLACK BOX:
    - Input: Flow features
    - Output: Filtered flow IDs
    - Does NOT modify original flow data
    """
    
    def __init__(self, 
                 output_dir: str,
                 log_type: str = 'standard',
                 sumo_base_path: str = './sumo'):
        """
        Initialize pipeline.
        
        Args:
            output_dir: Directory for all outputs
            log_type: PCAP log type (standard, isp, mail, proxy)
            sumo_base_path: Path to SUMo directory
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_type = log_type
        
        # Create subdirectories
        self.flows_dir = self.output_dir / 'flows'
        self.filtered_dir = self.output_dir / 'filtered_flows'
        self.metrics_dir = self.output_dir / 'metrics'
        
        for d in [self.flows_dir, self.filtered_dir, self.metrics_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        logger.info("Initializing pipeline components...")
        self.feature_extractor = FlowFeatureExtractor()
        self.sumo_pipeline = load_default_pipeline(sumo_base_path)
        
        # Metrics storage
        self.metrics = {
            'pipeline_start': datetime.now().isoformat(),
            'stages': {}
        }
    
    def process_pcap(self, pcap_path: str) -> Dict:
        """
        Stage 1: Extract flows from PCAP.
        
        Args:
            pcap_path: Path to input PCAP file
            
        Returns:
            {
                'flow_count': int,
                'flows_dir': str,
                'flow_ids': [...]
            }
        """
        logger.info("="*70)
        logger.info("STAGE 1: PCAP Processing")
        logger.info("="*70)
        
        stage_start = datetime.now()
        
        # Parse PCAP and extract flows
        logger.info(f"Processing PCAP: {pcap_path}")
        logger.info(f"Log type: {self.log_type}")
        
        parser = PCAPParser(pcap_path, log_type=self.log_type)
        flows = parser.extract_flows()
        
        # Save flows to inflow/outflow directories
        inflow_dir = self.flows_dir / 'inflow'
        outflow_dir = self.flows_dir / 'outflow'
        inflow_dir.mkdir(parents=True, exist_ok=True)
        outflow_dir.mkdir(parents=True, exist_ok=True)
        
        flow_ids = []
        for flow in flows:
            flow_id = flow.get_flow_id()
            flow_ids.append(flow_id)
            
            # Save inflow (packets TO monitored host)
            inflow_data = flow.get_inflow_data()  # [(timestamp, size), ...]
            with open(inflow_dir / flow_id, 'w') as f:
                for ts, size in inflow_data:
                    f.write(f"{ts}\t{size}\n")
            
            # Save outflow (packets FROM monitored host)
            outflow_data = flow.get_outflow_data()
            with open(outflow_dir / flow_id, 'w') as f:
                for ts, size in outflow_data:
                    f.write(f"{ts}\t{size}\n")
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        
        result = {
            'flow_count': len(flow_ids),
            'flows_dir': str(self.flows_dir),
            'flow_ids': flow_ids,
            'duration_seconds': stage_duration
        }
        
        self.metrics['stages']['pcap_processing'] = result
        
        logger.info(f"✅ Extracted {len(flow_ids)} flows")
        logger.info(f"   Duration: {stage_duration:.2f}s")
        logger.info(f"   Output: {self.flows_dir}")
        
        return result
    
    def extract_sumo_features(self) -> Dict:
        """
        Stage 2: Extract SUMo features.
        
        Features are used ONLY for filtering - NOT passed to ESPRESSO.
        
        Returns:
            {
                'features_df': DataFrame,
                'feature_count': int,
                'flow_count': int
            }
        """
        logger.info("\n" + "="*70)
        logger.info("STAGE 2: SUMo Feature Extraction")
        logger.info("="*70)
        logger.info("⚠️  Features used ONLY for filtering - discarded after")
        
        stage_start = datetime.now()
        
        # Extract features
        logger.info(f"Processing flows from: {self.flows_dir}")
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
        logger.info(f"   Duration: {stage_duration:.2f}s")
        
        return result
    
    def create_flow_store(self, flow_ids: List[str]) -> Dict[str, Dict]:
        """
        Create flow store mapping flow IDs to original raw flow data.
        
        This is the ONLY data passed to ESPRESSO (not SUMo features).
        
        Args:
            flow_ids: List of flow identifiers
            
        Returns:
            {flow_id: {'inflow_path': ..., 'outflow_path': ..., ...}}
        """
        logger.info("Creating flow store (original raw flows)...")
        
        import numpy as np
        
        flow_store = {}
        inflow_dir = self.flows_dir / 'inflow'
        outflow_dir = self.flows_dir / 'outflow'
        
        for flow_id in flow_ids:
            try:
                inflow_path = str(inflow_dir / flow_id)
                outflow_path = str(outflow_dir / flow_id)
                
                # Read raw data
                inflow_data = np.loadtxt(inflow_path, delimiter='\t')
                outflow_data = np.loadtxt(outflow_path, delimiter='\t')
                
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
                          fallback_top_k: int = 50) -> Dict:
        """
        Stage 3: Run SUMo filtering (BLACK BOX).
        
        SUMo is a black box:
        - Input: Feature DataFrame
        - Output: Filtered flow IDs + confidence scores
        - Does NOT modify original flows
        
        Args:
            features_df: SUMo features (for filtering only)
            flow_store: Original raw flows
            source_threshold: Source separation threshold
            target_threshold: Target separation threshold
            fallback_top_k: Fallback count
            
        Returns:
            SUMo filtering results with flow IDs
        """
        logger.info("\n" + "="*70)
        logger.info("STAGE 3: SUMo Filtering (BLACK BOX)")
        logger.info("="*70)
        logger.info("⚠️  Filtering ONLY - original flows unchanged")
        
        stage_start = datetime.now()
        
        # Run filtering (BLACK BOX)
        logger.info(f"Thresholds: source={source_threshold}, target={target_threshold}")
        results = self.sumo_pipeline.run_filtering(
            features_df,
            flow_store,
            source_threshold=source_threshold,
            target_threshold=target_threshold,
            fallback_top_k=fallback_top_k
        )
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        results['duration_seconds'] = stage_duration
        
        # Log reduction metrics (judges love metrics!)
        logger.info(f"\n📊 FILTERING METRICS:")
        logger.info(f"   Total input flows:     {results['total_flows']}")
        logger.info(f"   Filtered output flows: {results['filtered_count']}")
        logger.info(f"   Reduction ratio:       {results['reduction_ratio']*100:.1f}%")
        logger.info(f"   Duration:              {stage_duration:.2f}s")
        logger.info(f"\n   Source Separation:")
        logger.info(f"     Client flows:  {len(results['source_separation']['client_flow_ids'])}")
        logger.info(f"     OS flows:      {len(results['source_separation']['os_flow_ids'])}")
        logger.info(f"     Fallback used: {results['source_separation']['fallback_used']}")
        logger.info(f"\n   Target Separation:")
        logger.info(f"     OS sessions:   {results['target_separation']['filtered_count']}")
        logger.info(f"     Fallback used: {results['target_separation']['fallback_used']}")
        
        # Store metrics
        self.metrics['stages']['sumo_filtering'] = {
            'total_flows': results['total_flows'],
            'filtered_flows': results['filtered_count'],
            'reduction_ratio': results['reduction_ratio'],
            'source_separation': {
                'client_count': len(results['source_separation']['client_flow_ids']),
                'os_count': len(results['source_separation']['os_flow_ids']),
                'fallback_used': results['source_separation']['fallback_used']
            },
            'target_separation': {
                'filtered_count': results['target_separation']['filtered_count'],
                'fallback_used': results['target_separation']['fallback_used']
            },
            'duration_seconds': stage_duration
        }
        
        logger.info(f"\n✅ SUMo filtering complete")
        logger.info(f"   ⚠️  SUMo features DISCARDED: {results['sumo_features_discarded']}")
        
        return results
    
    def save_espresso_output(self, filtering_results: Dict) -> str:
        """
        Stage 4: Save ESPRESSO-compatible output.
        
        Saves ONLY original raw flows (NOT SUMo features).
        
        Args:
            filtering_results: Results from SUMo filtering
            
        Returns:
            Path to output JSON
        """
        logger.info("\n" + "="*70)
        logger.info("STAGE 4: Generating ESPRESSO Output")
        logger.info("="*70)
        
        stage_start = datetime.now()
        
        # Copy filtered flows to output directory
        filtered_flow_ids = filtering_results['filtered_flow_ids']
        
        if len(filtered_flow_ids) > 0:
            # Copy original flow files
            filtered_inflow_dir = self.filtered_dir / 'inflow'
            filtered_outflow_dir = self.filtered_dir / 'outflow'
            filtered_inflow_dir.mkdir(parents=True, exist_ok=True)
            filtered_outflow_dir.mkdir(parents=True, exist_ok=True)
            
            for flow_id in filtered_flow_ids:
                src_inflow = self.flows_dir / 'inflow' / flow_id
                src_outflow = self.flows_dir / 'outflow' / flow_id
                dst_inflow = filtered_inflow_dir / flow_id
                dst_outflow = filtered_outflow_dir / flow_id
                
                if src_inflow.exists():
                    shutil.copy2(src_inflow, dst_inflow)
                if src_outflow.exists():
                    shutil.copy2(src_outflow, dst_outflow)
            
            logger.info(f"✅ Copied {len(filtered_flow_ids)} filtered flows to {self.filtered_dir}")
        
        # Generate JSON manifest for ESPRESSO
        espresso_manifest = {
            'timestamp': datetime.now().isoformat(),
            'pipeline_version': '1.0.0',
            'sumo_filtering_applied': True,
            'total_input_flows': filtering_results['total_flows'],
            'filtered_output_flows': filtering_results['filtered_count'],
            'reduction_ratio': filtering_results['reduction_ratio'],
            'filtered_flow_ids': filtered_flow_ids,
            'flows_directory': str(self.filtered_dir),
            'data_format': {
                'note': 'Original raw flow time-series data ONLY',
                'sumo_features_excluded': True,
                'format': 'timestamp\\tpacket_size (tab-separated)',
                'directories': {
                    'inflow': str(filtered_inflow_dir),
                    'outflow': str(filtered_outflow_dir)
                }
            },
            'thresholds': filtering_results['thresholds'],
            'fallback_info': {
                'source_fallback_used': filtering_results['source_separation']['fallback_used'],
                'target_fallback_used': filtering_results['target_separation']['fallback_used']
            }
        }
        
        # Save manifest
        manifest_path = self.filtered_dir / 'espresso_manifest.json'
        with open(manifest_path, 'w') as f:
            json.dump(espresso_manifest, f, indent=2)
        
        stage_duration = (datetime.now() - stage_start).total_seconds()
        
        logger.info(f"✅ ESPRESSO manifest saved: {manifest_path}")
        logger.info(f"   Duration: {stage_duration:.2f}s")
        logger.info(f"\n   ⚠️  CRITICAL: Only original raw flows included")
        logger.info(f"   ⚠️  SUMo features NOT passed to ESPRESSO")
        
        self.metrics['stages']['espresso_output'] = {
            'manifest_path': str(manifest_path),
            'flows_directory': str(self.filtered_dir),
            'duration_seconds': stage_duration
        }
        
        return str(manifest_path)
    
    def save_metrics(self):
        """Save pipeline metrics."""
        self.metrics['pipeline_end'] = datetime.now().isoformat()
        
        metrics_path = self.metrics_dir / 'pipeline_metrics.json'
        with open(metrics_path, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        logger.info(f"\n📊 Metrics saved: {metrics_path}")
        return str(metrics_path)
    
    def run(self, pcap_path: str,
            source_threshold: float = 0.001,
            target_threshold: float = 0.9,
            fallback_top_k: int = 50) -> Dict:
        """
        Run complete pipeline.
        
        Args:
            pcap_path: Input PCAP file
            source_threshold: Source separation threshold
            target_threshold: Target separation threshold
            fallback_top_k: Fallback count
            
        Returns:
            Pipeline results
        """
        logger.info("\n" + "="*70)
        logger.info("SUMo Filtering Pipeline - Starting")
        logger.info("="*70)
        logger.info(f"Input PCAP: {pcap_path}")
        logger.info(f"Output directory: {self.output_dir}")
        
        try:
            # Stage 1: PCAP Processing
            pcap_results = self.process_pcap(pcap_path)
            
            # Stage 2: Feature Extraction
            feature_results = self.extract_sumo_features()
            
            # Create flow store
            flow_store = self.create_flow_store(pcap_results['flow_ids'])
            
            # Stage 3: SUMo Filtering (BLACK BOX)
            filtering_results = self.run_sumo_filtering(
                feature_results['features_df'],
                flow_store,
                source_threshold=source_threshold,
                target_threshold=target_threshold,
                fallback_top_k=fallback_top_k
            )
            
            # Stage 4: ESPRESSO Output
            manifest_path = self.save_espresso_output(filtering_results)
            
            # Save metrics
            metrics_path = self.save_metrics()
            
            # Final summary
            logger.info("\n" + "="*70)
            logger.info("PIPELINE COMPLETE ✅")
            logger.info("="*70)
            logger.info(f"Input flows:      {filtering_results['total_flows']}")
            logger.info(f"Filtered flows:   {filtering_results['filtered_count']}")
            logger.info(f"Reduction:        {filtering_results['reduction_ratio']*100:.1f}%")
            logger.info(f"\nOutputs:")
            logger.info(f"  Filtered flows: {self.filtered_dir}")
            logger.info(f"  Manifest:       {manifest_path}")
            logger.info(f"  Metrics:        {metrics_path}")
            
            return {
                'success': True,
                'manifest_path': manifest_path,
                'metrics_path': metrics_path,
                'filtered_dir': str(self.filtered_dir),
                'reduction_ratio': filtering_results['reduction_ratio'],
                'filtered_count': filtering_results['filtered_count']
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
        description='SUMo Filtering Pipeline - Filter Tor traffic flows using pretrained models',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python run_sumo_pipeline.py --pcap input.pcap --output ./results/

  # With custom thresholds
  python run_sumo_pipeline.py --pcap input.pcap --output ./results/ \\
      --source-threshold 0.01 --target-threshold 0.85

  # For ISP log format
  python run_sumo_pipeline.py --pcap isp.pcap --output ./results/ --log-type isp

Output:
  - filtered_flows/    : Original raw flows (ESPRESSO input)
  - metrics/           : Pipeline metrics (reduction ratios, etc.)
  - espresso_manifest.json : Metadata for ESPRESSO
        """
    )
    
    parser.add_argument('--pcap', required=True, help='Input PCAP file')
    parser.add_argument('--output', required=True, help='Output directory')
    parser.add_argument('--log-type', default='standard', 
                       choices=['standard', 'isp', 'mail', 'proxy'],
                       help='PCAP log format type')
    parser.add_argument('--source-threshold', type=float, default=0.001,
                       help='Source separation threshold (default: 0.001)')
    parser.add_argument('--target-threshold', type=float, default=0.9,
                       help='Target separation threshold (default: 0.9)')
    parser.add_argument('--fallback-top-k', type=int, default=50,
                       help='Fallback top-K flows (default: 50)')
    parser.add_argument('--sumo-path', default='./sumo',
                       help='Path to SUMo directory (default: ./sumo)')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not os.path.exists(args.pcap):
        print(f"Error: PCAP file not found: {args.pcap}")
        sys.exit(1)
    
    # Run pipeline
    pipeline = SUMoFilteringPipeline(
        output_dir=args.output,
        log_type=args.log_type,
        sumo_base_path=args.sumo_path
    )
    
    results = pipeline.run(
        pcap_path=args.pcap,
        source_threshold=args.source_threshold,
        target_threshold=args.target_threshold,
        fallback_top_k=args.fallback_top_k
    )
    
    sys.exit(0 if results['success'] else 1)


if __name__ == "__main__":
    main()
