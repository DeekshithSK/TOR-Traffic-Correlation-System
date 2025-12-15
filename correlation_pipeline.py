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

# Import our modules
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorrelationPipeline:
    """
    Flow correlation pipeline using statistical + Siamese similarity.
    
    Statistical similarity (70%) is the PRIMARY signal.
    Siamese model (30%) provides secondary refinement.
    """
    
    def __init__(self,
                 siamese_model_path: str,
                 statistical_weight: float = 0.7,
                 siamese_weight: float = 0.3,
                 top_k_for_siamese: int = 50,
                 device: Optional[str] = None):
        """
        Initialize correlation pipeline.
        
        Args:
            siamese_model_path: Path to pretrained Siamese model (.pth)
            statistical_weight: Weight for statistical similarity (default: 0.7)
            siamese_weight: Weight for Siamese similarity (default: 0.3)
            top_k_for_siamese: Number of top candidates for Siamese refinement
            device: Device for Siamese model ('cpu', 'cuda', 'mps', or None)
        """
        self.statistical_weight = statistical_weight
        self.siamese_weight = siamese_weight
        self.top_k = top_k_for_siamese
        
        # Validate weights
        if not np.isclose(statistical_weight + siamese_weight, 1.0):
            logger.warning(
                f"Weights don't sum to 1.0: {statistical_weight} + {siamese_weight} = "
                f"{statistical_weight + siamese_weight}. Normalizing..."
            )
            total = statistical_weight + siamese_weight
            self.statistical_weight = statistical_weight / total
            self.siamese_weight = siamese_weight / total
        
        # Load Siamese model
        logger.info(f"Loading Siamese model from {siamese_model_path}")
        self.siamese_model = load_siamese_model(siamese_model_path, device=device)
        self.model_info = get_model_info(self.siamese_model)
        
        logger.info(f"✅ Correlation pipeline initialized")
        logger.info(f"   Statistical weight: {self.statistical_weight:.1%}")
        logger.info(f"   Siamese weight: {self.siamese_weight:.1%}")
        logger.info(f"   Top-K for Siamese: {self.top_k}")
        logger.info(f"   Model parameters: {self.model_info['total_parameters']:,}")
    
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
                
                # Extract packet sizes
                sizes = np.array(flow_data['sizes'])
                
                # Create flow array (N, 3) format: [size, timestamp, direction]
                # For simplicity, we'll just use sizes since process_flow uses column 0
                if 'timestamps' in flow_data and 'directions' in flow_data:
                    timestamps = np.array(flow_data['timestamps'])
                    directions = np.array([1 if d == 'in' else -1 for d in flow_data['directions']])
                    
                    # Create (N, 3) array
                    flow_array = np.column_stack([sizes, timestamps, directions])
                else:
                    # Just use sizes as 1D array
                    flow_array = sizes
                
                # Process to fixed length
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
            # Get Siamese score if available (only top-K have Siamese scores)
            siamese_score = siamese_scores.get(flow_id, 0.0)
            
            # Compute final score
            if flow_id in siamese_scores:
                # Top-K: use both scores
                final_score = (self.statistical_weight * stat_score + 
                             self.siamese_weight * siamese_score)
            else:
                # Outside top-K: use only statistical score
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
        # Sort by final score (descending)
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
        
        # Add rank
        for i, item in enumerate(ranked, 1):
            item['rank'] = i
        
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
        
        # Step 1: Load raw flows
        all_flows = self.load_raw_flows(
            filtered_flow_ids + [target_flow_id],
            flow_store
        )
        
        if target_flow_id not in all_flows:
            raise ValueError(f"Target flow {target_flow_id} not found in flow store")
        
        target_flow = all_flows[target_flow_id]
        candidate_flows = {fid: flow for fid, flow in all_flows.items() 
                          if fid != target_flow_id}
        
        # Step 2: Compute statistical similarity (ALL candidates)
        statistical_scores = self.compute_statistical_scores(
            target_flow,
            candidate_flows
        )
        
        # Step 3: Select top-K by statistical score
        top_k_ids = self.select_top_k(statistical_scores, top_k)
        top_k_flows = {fid: candidate_flows[fid] for fid in top_k_ids}
        
        # Step 4: Apply Siamese refinement (top-K only)
        siamese_scores = self.refine_with_siamese(target_flow, top_k_flows)
        
        # Step 5: Fuse scores
        fused_scores = self.fuse_scores(statistical_scores, siamese_scores)
        
        # Step 6: Generate final ranking
        ranked_candidates = self.generate_ranking(fused_scores)
        
        duration = (datetime.now() - start_time).total_seconds()
        
        logger.info("=" * 70)
        logger.info("CORRELATION COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Duration: {duration:.2f}s")
        logger.info(f"Top candidate: {ranked_candidates[0]['flow_id']} "
                   f"(score: {ranked_candidates[0]['final']:.4f})")
        
        return {
            'target_flow_id': target_flow_id,
            'ranked_candidates': ranked_candidates,
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
    
    # Save ranked candidates
    ranked_path = output_dir / 'ranked_candidates.json'
    with open(ranked_path, 'w') as f:
        json.dump(results['ranked_candidates'], f, indent=2)
    logger.info(f"✅ Ranked candidates saved: {ranked_path}")
    
    # Save statistical scores
    stat_path = output_dir / 'statistical_scores.json'
    with open(stat_path, 'w') as f:
        json.dump(results['statistical_scores'], f, indent=2)
    logger.info(f"✅ Statistical scores saved: {stat_path}")
    
    # Save Siamese scores
    siamese_path = output_dir / 'siamese_scores.json'
    with open(siamese_path, 'w') as f:
        json.dump(results['siamese_scores'], f, indent=2)
    logger.info(f"✅ Siamese scores saved: {siamese_path}")
    
    # Save correlation manifest
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


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Correlation Pipeline - Test")
    print("=" * 70)
    
    # Check if model exists
    model_path = "./lightweight_siamese.pth"
    if not Path(model_path).exists():
        print(f"❌ Model file not found: {model_path}")
        print("   Please ensure lightweight_siamese.pth is in the current directory")
        exit(1)
    
    # Create dummy flow store
    print("\nCreating dummy flow store...")
    flow_store = {}
    for i in range(100):
        sizes = np.random.randn(200) * 100 + 500
        flow_store[f'flow_{i}'] = {
            'sizes': sizes.tolist(),
            'timestamps': np.linspace(0, 10, len(sizes)).tolist(),
            'directions': ['in' if j % 2 == 0 else 'out' for j in range(len(sizes))]
        }
    
    # Initialize pipeline
    print("\nInitializing correlation pipeline...")
    pipeline = CorrelationPipeline(
        siamese_model_path=model_path,
        statistical_weight=0.7,
        siamese_weight=0.3,
        top_k_for_siamese=20
    )
    
    # Run correlation
    print("\nRunning correlation...")
    results = pipeline.run(
        target_flow_id='flow_0',
        filtered_flow_ids=[f'flow_{i}' for i in range(1, 100)],
        flow_store=flow_store,
        top_k=20
    )
    
    # Display results
    print("\n" + "=" * 70)
    print("Top 10 Ranked Candidates:")
    print("=" * 70)
    for candidate in results['ranked_candidates'][:10]:
        print(f"Rank {candidate['rank']}: {candidate['flow_id']}")
        print(f"  Final: {candidate['final']:.4f} | "
              f"Statistical: {candidate['statistical']:.4f} | "
              f"Siamese: {candidate['siamese']:.4f if candidate['siamese'] is not None else 'N/A'}")
    
    # Save results
    print("\nSaving results...")
    save_correlation_results(results, Path('./test_correlation_output'))
    
    print("\n" + "=" * 70)
    print("✅ Test complete!")
    print("=" * 70)
