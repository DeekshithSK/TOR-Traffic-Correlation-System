"""
Tor Traffic Correlation System - Official Processing Pipeline
Supports: PCAP Ingestion -> SUMo Filtering -> Correlation -> Forensic Reporting
"""

import argparse
import sys
import os
import shutil
import logging
import numpy as np
from pathlib import Path
from tempfile import TemporaryDirectory

from pcap_ingest.pcap_to_flows import extract_flows_from_pcap
from flow_store.raw_flows import FlowStore
from run_sumo_pipeline import SUMoFilteringPipeline
from correlation_pipeline import CorrelationPipeline
from analysis.entry_node_aggregator import EntryNodeAggregator
from tor_intel.tor_directory import TorDirectory
from reporting.forensic_report import ForensicReportGenerator, ForensicCaseParams

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Tor Traffic Correlation - Complete Pipeline")
    parser.add_argument("--pcap", required=True, help="Path to input PCAP file")
    parser.add_argument("--target-flow", help="Target Flow ID (optional, auto-detected if singular)")
    parser.add_argument("--output", default="./pipeline_output", help="Output directory")
    parser.add_argument("--case-ref", default="AUTO-CASE", help="Case Reference ID")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap):
        logger.error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)
        
    out_path = Path(args.output)
    out_path.mkdir(parents=True, exist_ok=True)
    
    logger.info("=" * 60)
    logger.info("STEP 1: PCAP Ingestion")
    logger.info("=" * 60)
    
    raw_flows = extract_flows_from_pcap(args.pcap)
    if not raw_flows:
        logger.error("No valid flows extracted from PCAP.")
        sys.exit(1)
        
    store = FlowStore()
    store.save_flows(raw_flows)
    
    logger.info(f"Loaded {len(raw_flows)} flows into memory.")
    
    logger.info("\n" + "=" * 60)
    logger.info("STEP 2: SUMo Filtering Preparation")
    logger.info("=" * 60)
    
    with TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        inflow_dir = temp_path / 'inflow'
        outflow_dir = temp_path / 'outflow'
        inflow_dir.mkdir()
        outflow_dir.mkdir()
        
        logger.info("Writing temporary flow files for SUMo analysis...")
        for flow_id, flow_data in raw_flows.items():
            
            
            mask_in = flow_data[:, 2] == -1
            mask_out = flow_data[:, 2] == 1
            
            in_data = flow_data[mask_in]
            out_data = flow_data[mask_out]
            
            safe_fname = flow_id.replace(':', '_').replace('-', '_')
            
            with open(inflow_dir / safe_fname, 'w') as f:
                for row in in_data:
                    f.write(f"{row[1]}\t{abs(row[0])}\n") # timestamp, abs(size)
                    
            with open(outflow_dir / safe_fname, 'w') as f:
                for row in out_data:
                    f.write(f"{row[1]}\t{abs(row[0])}\n")
                    
        
        sumo_pipeline = SUMoFilteringPipeline(
            output_dir=str(out_path / "sumo_stage"),
            log_type='standard'
        )
        
        sumo_pipeline.flows_dir = temp_path
        
        feature_results = sumo_pipeline.extract_sumo_features()
        
        sumo_flow_store = sumo_pipeline.create_flow_store([
            fid.replace(':', '_').replace('-', '_') for fid in raw_flows.keys()
        ])
        
        filtering_results = sumo_pipeline.run_sumo_filtering(
            feature_results['features_df'],
            sumo_flow_store
        )
        
        filtered_ids_sanitized = filtering_results['filtered_flow_ids']
        
        sanitized_to_original = {
            fid.replace(':', '_').replace('-', '_'): fid 
            for fid in raw_flows.keys()
        }
        
        filtered_original_ids = []
        for safe_id in filtered_ids_sanitized:
            if safe_id in sanitized_to_original:
                filtered_original_ids.append(sanitized_to_original[safe_id])
            else:
                match = next((orig for safe, orig in sanitized_to_original.items() if safe.startswith(safe_id)), None)
                if match:
                    logger.warning(f"Fuzzy mapped {safe_id} -> {match}")
                    filtered_original_ids.append(match)
                else:
                    logger.warning(f"Could not map sanitized ID {safe_id} back to original.")
                
        logger.info(f"SUMo Filtered Down to {len(filtered_original_ids)} candidates.")

    logger.info("\n" + "=" * 60)
    logger.info("STEP 3: Statistical & Siamese Correlation")
    logger.info("=" * 60)
    
    model_path = "./lightweight_siamese.pth"
    if not Path(model_path).exists():
        logger.warning(f"Siamese model not found at {model_path}. Using dummy path for specific environments or failing.")
    
    pipeline = CorrelationPipeline(siamese_model_path=model_path)
    
    target_id = None
    if args.target_flow:
        target_id = args.target_flow
    else:
        target_id = list(raw_flows.keys())[0]
        logger.warning(f"No target specified. Auto-selected: {target_id}")

    if target_id not in raw_flows:
        logger.error(f"Target flow {target_id} not found in PCAP.")
        sys.exit(1)
        
    flow_store_dict = {}
    for fid, data in raw_flows.items():
        
        sizes = np.abs(data[:, 0]) # Absolute sizes
        timestamps = data[:, 1]
        raw_dirs = data[:, 2] # 1.0 or -1.0
        
        dir_strs = ['in' if d < 0 else 'out' for d in raw_dirs]
        
        flow_store_dict[fid] = {
            'sizes': sizes.tolist(),
            'timestamps': timestamps.tolist(),
            'directions': dir_strs
        }
    
    candidates = [fid for fid in filtered_original_ids if fid != target_id]
    
    if len(candidates) < 5:
        logger.warning("SUMo returned very few candidates. Adding raw fallback.")
        all_others = [fid for fid in raw_flows.keys() if fid != target_id]
        candidates.extend(all_others[:50])
        candidates = list(set(candidates))
        
    results = pipeline.run(
        target_flow_id=target_id,
        filtered_flow_ids=candidates,
        flow_store=flow_store_dict
    )
    
    logger.info("\n" + "=" * 60)
    logger.info("STEP 4: Generation of Forensic Report")
    logger.info("=" * 60)
    
    rankings = results['ranked_candidates']
    
    report_gen = ForensicReportGenerator(output_dir=out_path / "reports")
    
    params = ForensicCaseParams(
        case_reference=args.case_ref,
        investigator_name="Auto-Analyst",
        target_description=f"Target Flow from {args.pcap}"
    )
    
    report_path = report_gen.generate_report(results, params.case_reference)
    logger.info(f"Report generated at: {report_path}")
    
    print("\n✅ PIPELINE COMPLETE")
    print(f"   Target: {target_id}")
    print(f"   Top Suspect: {rankings[0]['flow_id'] if rankings else 'None'}")
    print(f"   Report: {report_path}")

if __name__ == "__main__":
    main()
