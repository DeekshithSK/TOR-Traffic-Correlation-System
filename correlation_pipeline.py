"""
Correlation Pipeline

Orchestrates the correlation stage following SUMo filtering.
Combines statistical similarity (primary) and Siamese model (refinement).

Pipeline Flow:
    1. Load raw flows from SUMo-filtered IDs
    2. Compute statistical similarity for ALL candidates
    3. Select top-K candidates by statistical score
    4. Apply Siamese model to top-K only
    5. Fuse scores: 0.7 * statistical + 0.3 * siamese
    6. Generate final ranked output with confidence scores

CRITICAL: Operates ONLY on raw flow data, never on SUMo features.
"""

import numpy as np
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import logging

from statistical_similarity import (
    process_flow,
    statistical_similarity,
    batch_statistical_similarity
)
from siamese_model import (
    load_siamese_model,
    batch_similarity_with_target,
    get_model_info
)
from analysis.entry_node_aggregator import EntryNodeAggregator
from analysis.ip_lead_generation import generate_ip_leads
from tor_intel.tor_directory import TorDirectory
from utils.flow_id_parser import extract_ips_from_flow_id

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorrelationPipeline:
    """
    Flow correlation pipeline using statistical + Siamese similarity.
    
    Statistical similarity (70%) is the PRIMARY signal.
    Siamese model (30%) provides secondary refinement.
    """
    
    def __init__(self,
                 siamese_model_path: Optional[str] = None,
                 statistical_weight: float = 0.7,
                 siamese_weight: float = 0.3,
                 top_k_for_siamese: int = 50,
                 device: Optional[str] = None):
        """
        Initialize correlation pipeline with CERTIFIED ENGINE settings.
        
        Args:
            siamese_model_path: IGNORED. Hardcoded to 'lightweight_siamese.pth'.
            statistical_weight: Weight for statistical similarity (default: 0.7)
            siamese_weight: Weight for Siamese similarity (default: 0.3)
            top_k_for_siamese: Number of top candidates for Siamese refinement
            device: Device for Siamese model ('cpu', 'cuda', 'mps', or None)
        """
        CERTIFIED_MODEL_PATH = "lightweight_siamese.pth"
        
        if siamese_model_path is not None:
            logger.info(f"🔒 Security: Ignoring user path '{siamese_model_path}'. Using certified model.")
            
        self.statistical_weight = statistical_weight
        self.siamese_weight = siamese_weight
        self.top_k = top_k_for_siamese
        
        if not np.isclose(statistical_weight + siamese_weight, 1.0):
            logger.warning(
                f"Weights don't sum to 1.0: {statistical_weight} + {siamese_weight} = "
                f"{statistical_weight + siamese_weight}. Normalizing..."
            )
            total = statistical_weight + siamese_weight
            self.statistical_weight = statistical_weight / total
            self.siamese_weight = siamese_weight / total
        
        if not Path(CERTIFIED_MODEL_PATH).exists():
             raise FileNotFoundError(f"CRITICAL: Certified model '{CERTIFIED_MODEL_PATH}' missing!")
             
        logger.info(f"Loading Certified Engine from {CERTIFIED_MODEL_PATH}")
        self.siamese_model = load_siamese_model(CERTIFIED_MODEL_PATH, device=device)
        self.model_info = get_model_info(self.siamese_model)
        
        logger.info(f"✅ Correlation pipeline initialized (Forensic Mode)")
        logger.info(f"   Statistical weight: {self.statistical_weight:.1%}")
        logger.info(f"   Siamese weight: {self.siamese_weight:.1%}")
        logger.info(f"   Top-K for Siamese: {self.top_k}")
        logger.info(f"   Model parameters: {self.model_info['total_parameters']:,}")
        
        self.entry_aggregator = EntryNodeAggregator()
        self.tor_directory = TorDirectory()
    
    def load_raw_flows(self,
                       flow_ids: List[str],
                       flow_store: Dict[str, Dict]) -> Dict[str, np.ndarray]:
        """
        Load and preprocess raw flows from flow store.
        
        Args:
            flow_ids: List of flow IDs to load
            flow_store: Dict mapping flow_id -> raw flow data
                       {flow_id: {'timestamps': [...], 'sizes': [...], 'directions': [...]}}
        
        Returns:
            Dict of {flow_id: processed_flow_array}
        """
        logger.info(f"Loading {len(flow_ids)} raw flows...")
        
        processed_flows = {}
        
        for flow_id in flow_ids:
            if flow_id not in flow_store:
                logger.warning(f"Flow {flow_id} not in flow store, skipping")
                continue
            
            try:
                flow_data = flow_store[flow_id]
                
                sizes = np.array(flow_data['sizes'])
                
                if 'timestamps' in flow_data and 'directions' in flow_data:
                    timestamps = np.array(flow_data['timestamps'])
                    directions = np.array([1 if d == 'in' else -1 for d in flow_data['directions']])
                    
                    flow_array = np.column_stack([sizes, timestamps, directions])
                else:
                    flow_array = sizes
                
                processed = process_flow(flow_array)
                processed_flows[flow_id] = processed
                
            except Exception as e:
                logger.warning(f"Failed to process flow {flow_id}: {e}")
                continue
        
        logger.info(f"✅ Loaded {len(processed_flows)} flows")
        
        return processed_flows
    
    def compute_statistical_scores(self,
                                   target_flow: np.ndarray,
                                   candidate_flows: Dict[str, np.ndarray]) -> Dict[str, float]:
        """
        Compute statistical similarity for all candidates.
        
        This is the PRIMARY correlation signal (70% weight).
        
        Args:
            target_flow: Target flow array (300,)
            candidate_flows: Dict of {flow_id: flow_array}
            
        Returns:
            Dict of {flow_id: statistical_score}
        """
        logger.info(f"Computing statistical similarity for {len(candidate_flows)} candidates...")
        
        scores = batch_statistical_similarity(
            candidate_flows,
            target_flow,
            metric='statistical'
        )
        
        logger.info(f"✅ Statistical scores computed")
        
        return scores
    
    def select_top_k(self,
                    scores: Dict[str, float],
                    k: int) -> List[str]:
        """
        Select top-K flow IDs by score.
        
        Args:
            scores: Dict of {flow_id: score}
            k: Number of top candidates to select
            
        Returns:
            List of top-K flow IDs
        """
        sorted_items = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_k_items = sorted_items[:k]
        top_k_ids = [item[0] for item in top_k_items]
        
        logger.info(f"Selected top-{k} candidates")
        if len(top_k_items) > 0:
            logger.info(f"   Score range: {top_k_items[-1][1]:.4f} - {top_k_items[0][1]:.4f}")
        
        return top_k_ids
    
    def refine_with_siamese(self,
                           target_flow: np.ndarray,
                           top_k_flows: Dict[str, np.ndarray]) -> Dict[str, float]:
        """
        Apply Siamese model to top-K candidates for refinement.
        
        This is the SECONDARY signal (30% weight).
        Applied only to top-K to save computation.
        
        Args:
            target_flow: Target flow array (300,)
            top_k_flows: Dict of {flow_id: flow_array} for top-K
            
        Returns:
            Dict of {flow_id: siamese_score}
        """
        logger.info(f"Applying Siamese refinement to top-{len(top_k_flows)} candidates...")
        
        scores = batch_similarity_with_target(
            self.siamese_model,
            target_flow,
            top_k_flows,
            batch_size=32
        )
        
        logger.info(f"✅ Siamese scores computed")
        
        return scores
    
    def fuse_scores(self,
                   statistical_scores: Dict[str, float],
                   siamese_scores: Dict[str, float]) -> Dict[str, Dict]:
        """
        Combine statistical and Siamese scores with weighted fusion.
        
        Final score = 0.7 * statistical + 0.3 * siamese
        
        Args:
            statistical_scores: Statistical similarity scores (all candidates)
            siamese_scores: Siamese scores (top-K only)
            
        Returns:
            Dict of {flow_id: {'statistical': float, 'siamese': float, 'final': float}}
        """
        logger.info(f"Fusing scores with weights: stat={self.statistical_weight:.1%}, "
                   f"siamese={self.siamese_weight:.1%}")
        
        results = {}
        
        for flow_id, stat_score in statistical_scores.items():
            siamese_score = siamese_scores.get(flow_id, 0.0)
            
            if flow_id in siamese_scores:
                final_score = (self.statistical_weight * stat_score + 
                             self.siamese_weight * siamese_score)
            else:
                final_score = stat_score * self.statistical_weight
            
            results[flow_id] = {
                'statistical': float(stat_score),
                'siamese': float(siamese_score) if flow_id in siamese_scores else None,
                'final': float(final_score)
            }
        
        logger.info(f"✅ Scores fused for {len(results)} candidates")
        
        return results
    
    def generate_ranking(self,
                        fused_scores: Dict[str, Dict]) -> List[Dict]:
        """
        Generate final ranked candidate list.
        
        Args:
            fused_scores: Fused score dictionary
            
        Returns:
            Ranked list of candidates with scores
        """
        ranked = sorted(
            [
                {
                    'flow_id': flow_id,
                    **scores
                }
                for flow_id, scores in fused_scores.items()
            ],
            key=lambda x: x['final'],
            reverse=True
        )
        
        for i, item in enumerate(ranked, 1):
            item['rank'] = i
            src_ip, dst_ip = extract_ips_from_flow_id(item['flow_id'])
            item['client_ip'] = src_ip
        
        return ranked
    
    def run(self,
            target_flow_id: str,
            filtered_flow_ids: List[str],
            flow_store: Dict[str, Dict],
            top_k: Optional[int] = None) -> Dict:
        """
        Run complete correlation pipeline.
        
        Args:
            target_flow_id: Target flow to compare against
            filtered_flow_ids: SUMo-filtered candidate flow IDs
            flow_store: Raw flow data store
            top_k: Override default top-K (optional)
            
        Returns:
            {
                'target_flow_id': str,
                'ranked_candidates': [...],
                'statistical_scores': {...},
                'siamese_scores': {...},
                'fused_scores': {...},
                'metadata': {...}
            }
        """
        if top_k is None:
            top_k = self.top_k
        
        start_time = datetime.now()
        
        logger.info("=" * 70)
        logger.info("CORRELATION PIPELINE")
        logger.info("=" * 70)
        logger.info(f"Target flow: {target_flow_id}")
        logger.info(f"Candidates: {len(filtered_flow_ids)}")
        logger.info(f"Top-K for Siamese: {top_k}")
        
        all_flows = self.load_raw_flows(
            filtered_flow_ids + [target_flow_id],
            flow_store
        )
        
        if target_flow_id not in all_flows:
            raise ValueError(f"Target flow {target_flow_id} not found in flow store")
        
        target_flow = all_flows[target_flow_id]
        candidate_flows = {fid: flow for fid, flow in all_flows.items() 
                          if fid != target_flow_id}
        
        statistical_scores = self.compute_statistical_scores(
            target_flow,
            candidate_flows
        )
        
        top_k_ids = self.select_top_k(statistical_scores, top_k)
        top_k_flows = {fid: candidate_flows[fid] for fid in top_k_ids}
        
        siamese_scores = self.refine_with_siamese(target_flow, top_k_flows)
        
        fused_scores = self.fuse_scores(statistical_scores, siamese_scores)
        
        ranked_candidates = self.generate_ranking(fused_scores)
        
        logger.info("Enriching results with Entry Node Aggregation and TOR Topology...")
        for candidate in ranked_candidates:
            flow_id = candidate['flow_id']
            score = candidate['final']
            
            flow_meta = flow_store.get(flow_id, {})
            guard_identifier = flow_meta.get('src_ip') or flow_meta.get('client_ip') or flow_id
            
            self.entry_aggregator.update_evidence(guard_identifier, score)
            
            candidate['guard_identifier'] = guard_identifier
            evidence = self.entry_aggregator.get_ranked_guards()
            guard_evidence = next((e for e in evidence if e['guard_id'] == guard_identifier), None)
            candidate['aggregated_evidence'] = guard_evidence
            
            relay_info = self.tor_directory.search_relay(guard_identifier)
            candidate['tor_relay_info'] = relay_info
            
            if relay_info:
                 candidate['is_known_relay'] = True
                 candidate['relay_role'] = relay_info.get('role', 'Unknown')
            else:
                 candidate['is_known_relay'] = False
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 70)
        logger.info("CORRELATION COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Duration: {duration:.2f}s")
        if ranked_candidates:
            logger.info(f"Top candidate: {ranked_candidates[0]['flow_id']} "
                       f"(score: {ranked_candidates[0]['final']:.4f})")
        else:
            logger.warning("No candidates found.")
        
        ip_leads = generate_ip_leads(ranked_candidates)
        
        return {
            'target_flow_id': target_flow_id,
            'ranked_candidates': ranked_candidates,
            'ip_leads': ip_leads,
            'statistical_scores': statistical_scores,
            'siamese_scores': siamese_scores,
            'fused_scores': fused_scores,
            'metadata': {
                'total_candidates': len(filtered_flow_ids),
                'top_k_for_siamese': top_k,
                'statistical_weight': self.statistical_weight,
                'siamese_weight': self.siamese_weight,
                'duration_seconds': duration,
                'timestamp': datetime.now().isoformat(),
                'model_info': self.model_info
            }
        }


def save_correlation_results(results: Dict, output_dir: Path):
    """
    Save correlation results to output directory.
    
    Args:
        results: Correlation pipeline results
        output_dir: Output directory path
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    ranked_path = output_dir / 'ranked_candidates.json'
    with open(ranked_path, 'w') as f:
        json.dump(results['ranked_candidates'], f, indent=2)
    logger.info(f"✅ Ranked candidates saved: {ranked_path}")
    
    stat_path = output_dir / 'statistical_scores.json'
    with open(stat_path, 'w') as f:
        json.dump(results['statistical_scores'], f, indent=2)
    logger.info(f"✅ Statistical scores saved: {stat_path}")
    
    siamese_path = output_dir / 'siamese_scores.json'
    with open(siamese_path, 'w') as f:
        json.dump(results['siamese_scores'], f, indent=2)
    logger.info(f"✅ Siamese scores saved: {siamese_path}")
    
    manifest = {
        'target_flow_id': results['target_flow_id'],
        'metadata': results['metadata'],
        'top_10_candidates': results['ranked_candidates'][:10],
        'notes': {
            'statistical_weight': results['metadata']['statistical_weight'],
            'siamese_weight': results['metadata']['siamese_weight'],
            'description': 'Probabilistic similarity ranking - NOT classification',
            'sumo_features_excluded': True
        }
    }
    
    manifest_path = output_dir / 'correlation_manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"✅ Correlation manifest saved: {manifest_path}")



if __name__ == "__main__":
    print("=" * 70)
    print("Correlation Pipeline - Test")
    print("=" * 70)
    
    model_path = "./lightweight_siamese.pth"
    if not Path(model_path).exists():
        print(f"❌ Model file not found: {model_path}")
        print("   Please ensure lightweight_siamese.pth is in the current directory")
        exit(1)
    
    print("\nCreating dummy flow store...")
    flow_store = {}
    for i in range(100):
        sizes = np.random.randn(200) * 100 + 500
        flow_store[f'flow_{i}'] = {
            'sizes': sizes.tolist(),
            'timestamps': np.linspace(0, 10, len(sizes)).tolist(),
            'directions': ['in' if j % 2 == 0 else 'out' for j in range(len(sizes))]
        }
    
    print("\nInitializing correlation pipeline...")
    pipeline = CorrelationPipeline(
        siamese_model_path=model_path,
        statistical_weight=0.7,
        siamese_weight=0.3,
        top_k_for_siamese=20
    )
    
    print("\nRunning correlation...")
    results = pipeline.run(
        target_flow_id='flow_0',
        filtered_flow_ids=[f'flow_{i}' for i in range(1, 100)],
        flow_store=flow_store,
        top_k=20
    )
    
    print("\n" + "=" * 70)
    print("Top 10 Ranked Candidates:")
    print("=" * 70)
    for candidate in results['ranked_candidates'][:10]:
        print(f"Rank {candidate['rank']}: {candidate['flow_id']}")
        s_score = candidate.get('siamese')
        s_str = f"{s_score:.4f}" if s_score is not None else "N/A"
        print(f"  Final: {candidate['final']:.4f} | "
              f"Statistical: {candidate['statistical']:.4f} | "
              f"Siamese: {s_str}")
    
    print("\nSaving results...")
    save_correlation_results(results, Path('./test_correlation_output'))
    
    print("\n" + "=" * 70)
    print("✅ Test complete!")
    print("=" * 70)
