"""
Correlation Aggregator

Responsibilities:
- Track entry-exit pair correlations across multiple sessions
- Accumulate matching evidence for specific guard-exit combinations
- Support confidence growth with repeated observations
- Provide ranked list of entry-exit pairs

Formula: Score = log(1 + pair_count) * avg_combined_confidence
"""

import numpy as np
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CorrelationAggregator:
    """
    Aggregates entry-exit pair correlation evidence over multiple sessions.
    """
    
    def __init__(self, storage_path: str = "data/correlation_evidence.json"):
        """
        Initialize the aggregator.
        
        Args:
            storage_path: Path to JSON file for persisting aggregated evidence.
        """
        self.storage_path = Path(storage_path)
        self.evidence = {}  # {pair_id: {entry_ip, exit_ip, count, scores...}}
        self._load_evidence()
        
    def _load_evidence(self):
        """Load accumulated evidence from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    self.evidence = json.load(f)
                logger.info(f"Loaded correlation evidence for {len(self.evidence)} entry-exit pairs.")
            except Exception as e:
                logger.error(f"Failed to load correlation evidence: {e}")
                self.evidence = {}
        else:
            logger.info("No existing correlation evidence found. Starting fresh.")
            self.evidence = {}

    def _save_evidence(self):
        """Save evidence to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(self.evidence, f, indent=2)
            logger.debug(f"Saved correlation evidence to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save correlation evidence: {e}")

    @staticmethod
    def _make_pair_id(entry_ip: str, exit_ip: str) -> str:
        """Create a unique pair identifier."""
        return f"{entry_ip}::{exit_ip}"

    def update_pair(
        self, 
        entry_ip: str,
        exit_ip: str,
        entry_confidence: float,
        exit_confidence: float,
        combined_confidence: float,
        mode: str = "guard_only",
        timestamp: Optional[str] = None
    ):
        """
        Update evidence for an entry-exit pair.
        
        Args:
            entry_ip: Entry/Guard node IP address.
            exit_ip: Exit node IP address (can be None for guard-only).
            entry_confidence: Guard correlation confidence [0.0, 1.0].
            exit_confidence: Exit correlation confidence [0.0, 1.0].
            combined_confidence: Final combined confidence [0.0, 1.0].
            mode: Correlation mode (guard_only, guard+exit_indirect, guard+exit_confirmed).
            timestamp: ISO format timestamp string.
        """
        if not entry_ip:
            return
            
        exit_ip = exit_ip or "none"
            
        if timestamp is None:
            timestamp = datetime.now().isoformat()
        
        pair_id = self._make_pair_id(entry_ip, exit_ip)
            
        if pair_id not in self.evidence:
            self.evidence[pair_id] = {
                'entry_ip': entry_ip,
                'exit_ip': exit_ip,
                'count': 0,
                'total_entry_confidence': 0.0,
                'total_exit_confidence': 0.0,
                'total_combined_confidence': 0.0,
                'confirmed_count': 0,
                'indirect_count': 0,
                'guard_only_count': 0,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'timestamps': []
            }
        
        record = self.evidence[pair_id]
        record['count'] += 1
        record['total_entry_confidence'] += float(entry_confidence)
        record['total_exit_confidence'] += float(exit_confidence)
        record['total_combined_confidence'] += float(combined_confidence)
        record['last_seen'] = timestamp
        
        if mode == 'guard+exit_confirmed':
            record['confirmed_count'] += 1
        elif mode == 'guard+exit_indirect':
            record['indirect_count'] += 1
        else:
            record['guard_only_count'] += 1
        
        record['timestamps'].append(timestamp)
        if len(record['timestamps']) > 50:
            record['timestamps'] = record['timestamps'][-50:]
              
        self._save_evidence()
        logger.info(f"Updated pair evidence for {pair_id}: count={record['count']}")

    def get_pair_count(self, entry_ip: str, exit_ip: str = None) -> int:
        """Get observation count for a specific entry-exit pair."""
        exit_ip = exit_ip or "none"
        pair_id = self._make_pair_id(entry_ip, exit_ip)
        if pair_id in self.evidence:
            return self.evidence[pair_id]['count']
        return 0
    
    def get_pair_score(self, entry_ip: str, exit_ip: str = None) -> float:
        """
        Get accumulated historical score for an entry-exit pair.
        
        Formula: log(1 + count) * avg_combined_confidence * (1 + confirm_ratio)
        """
        exit_ip = exit_ip or "none"
        pair_id = self._make_pair_id(entry_ip, exit_ip)
        
        if pair_id not in self.evidence:
            return 0.0
            
        record = self.evidence[pair_id]
        count = record['count']
        if count == 0:
            return 0.0
            
        avg_combined = record['total_combined_confidence'] / count
        confirm_ratio = record['confirmed_count'] / count
        
        score = np.log1p(count) * avg_combined * (1 + confirm_ratio)
        return float(score)

    def get_entry_stats(self, entry_ip: str) -> Dict:
        """Get aggregated stats for all pairs involving a specific entry IP."""
        total_count = 0
        total_confidence = 0.0
        exit_ips = []
        
        for pair_id, data in self.evidence.items():
            if data['entry_ip'] == entry_ip:
                total_count += data['count']
                total_confidence += data['total_combined_confidence']
                if data['exit_ip'] != "none":
                    exit_ips.append(data['exit_ip'])
        
        return {
            'entry_ip': entry_ip,
            'total_observations': total_count,
            'avg_confidence': total_confidence / total_count if total_count > 0 else 0.0,
            'associated_exits': list(set(exit_ips)),
            'historical_score': np.log1p(total_count) * (total_confidence / total_count if total_count > 0 else 0)
        }

    def get_ranked_pairs(self, min_count: int = 1) -> List[Dict]:
        """
        Get ranked list of entry-exit pairs.
        
        Args:
            min_count: Minimum observation count to include.
            
        Returns:
            List of dicts containing pair details and scores, sorted by score desc.
        """
        ranked = []
        
        for pair_id, data in self.evidence.items():
            count = data['count']
            if count < min_count:
                continue
            
            avg_entry = data['total_entry_confidence'] / count if count > 0 else 0
            avg_exit = data['total_exit_confidence'] / count if count > 0 else 0
            avg_combined = data['total_combined_confidence'] / count if count > 0 else 0
            confirm_ratio = data['confirmed_count'] / count if count > 0 else 0
            
            score = np.log1p(count) * avg_combined * (1 + confirm_ratio)
            
            ranked.append({
                'pair_id': pair_id,
                'entry_ip': data['entry_ip'],
                'exit_ip': data['exit_ip'],
                'score': float(score),
                'avg_entry_confidence': float(avg_entry),
                'avg_exit_confidence': float(avg_exit),
                'avg_combined_confidence': float(avg_combined),
                'confirm_ratio': float(confirm_ratio),
                'count': count,
                'confirmed_count': data['confirmed_count'],
                'indirect_count': data['indirect_count'],
                'guard_only_count': data['guard_only_count'],
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen']
            })
            
        ranked.sort(key=lambda x: x['score'], reverse=True)
        return ranked

    def clear_evidence(self):
        """Clear all accumulated evidence."""
        self.evidence = {}
        if self.storage_path.exists():
            self.storage_path.unlink()
        logger.info("Correlation evidence cleared.")


if __name__ == "__main__":
    aggregator = CorrelationAggregator("data/test_correlation_evidence.json")
    aggregator.clear_evidence()
    
    print("Updating pair evidence...")
    aggregator.update_pair("34.54.84.110", "185.220.101.15", 0.95, 0.33, 0.85, "guard+exit_indirect")
    aggregator.update_pair("34.54.84.110", "185.220.101.15", 0.92, 0.45, 0.88, "guard+exit_indirect")
    aggregator.update_pair("34.54.84.110", "185.220.101.15", 0.98, 0.72, 0.95, "guard+exit_confirmed")
    aggregator.update_pair("51.159.211.57", None, 0.85, 0.0, 0.85, "guard_only")
    
    ranked = aggregator.get_ranked_pairs()
    print(json.dumps(ranked, indent=2))
    
    assert ranked[0]['entry_ip'] == "34.54.84.110"
    assert ranked[0]['count'] == 3
    assert ranked[0]['confirmed_count'] == 1
    
    score = aggregator.get_pair_score("34.54.84.110", "185.220.101.15")
    print(f"Pair score: {score:.4f}")
    assert score > 0
    
    print("✅ CorrelationAggregator test passed!")
