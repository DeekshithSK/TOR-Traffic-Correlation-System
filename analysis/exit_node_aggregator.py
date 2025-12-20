"""
Exit Node Aggregator

Responsibilities:
- Aggregate exit correlation results across multiple sessions
- Track exit IPs and their observation counts
- Accumulate confidence scores with logarithmic dampening
- Provide ranked list of observed exit nodes

Formula: Score = log(1 + observation_count) * avg_confidence * match_ratio
"""

import numpy as np
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ExitNodeAggregator:
    """
    Aggregates evidence for Exit nodes over multiple correlation sessions.
    """
    
    def __init__(self, storage_path: str = "data/exit_evidence.json"):
        """
        Initialize the aggregator.
        
        Args:
            storage_path: Path to JSON file for persisting aggregated evidence.
        """
        self.storage_path = Path(storage_path)
        self.evidence = {}  # {exit_ip: {count, direct_matches, indirect_matches, total_direct_score, total_indirect_score, ...}}
        self._load_evidence()
        
    def _load_evidence(self):
        """Load accumulated evidence from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    self.evidence = json.load(f)
                logger.info(f"Loaded exit evidence for {len(self.evidence)} exit nodes.")
            except Exception as e:
                logger.error(f"Failed to load exit evidence: {e}")
                self.evidence = {}
        else:
            logger.info("No existing exit evidence found. Starting fresh.")
            self.evidence = {}

    def _save_evidence(self):
        """Save evidence to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(self.evidence, f, indent=2)
            logger.debug(f"Saved exit evidence to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save exit evidence: {e}")

    def update_evidence(
        self, 
        exit_ip: str, 
        direct_score: float,
        indirect_score: float = 0.0,
        matched: bool = False,
        timestamp: Optional[str] = None
    ):
        """
        Update evidence for a specific exit node.
        
        Args:
            exit_ip: Exit node IP address.
            direct_score: Direct correlation score [0.0, 1.0].
            indirect_score: Indirect evidence score [0.0, 0.25].
            matched: Whether direct correlation succeeded (>= 50%).
            timestamp: ISO format timestamp string.
        """
        if not exit_ip:
            return
            
        if timestamp is None:
            timestamp = datetime.now().isoformat()
            
        if exit_ip not in self.evidence:
            self.evidence[exit_ip] = {
                'count': 0,
                'direct_matches': 0,
                'indirect_matches': 0,
                'total_direct_score': 0.0,
                'total_indirect_score': 0.0,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'timestamps': []
            }
        
        record = self.evidence[exit_ip]
        record['count'] += 1
        record['total_direct_score'] += float(direct_score)
        record['total_indirect_score'] += float(indirect_score)
        record['last_seen'] = timestamp
        
        if matched:
            record['direct_matches'] += 1
        elif indirect_score > 0:
            record['indirect_matches'] += 1
        
        # Keep limited timestamp history
        record['timestamps'].append(timestamp)
        if len(record['timestamps']) > 50:
            record['timestamps'] = record['timestamps'][-50:]
              
        self._save_evidence()
        logger.info(f"Updated exit evidence for {exit_ip}: count={record['count']}, matches={record['direct_matches']}")

    def get_observation_count(self, exit_ip: str) -> int:
        """Get observation count for a specific exit IP."""
        if exit_ip in self.evidence:
            return self.evidence[exit_ip]['count']
        return 0
    
    def get_historical_score(self, exit_ip: str) -> float:
        """
        Get accumulated historical score for an exit IP.
        
        Formula: log(1 + count) * avg_direct_score * (1 + match_ratio)
        """
        if exit_ip not in self.evidence:
            return 0.0
            
        record = self.evidence[exit_ip]
        count = record['count']
        if count == 0:
            return 0.0
            
        avg_direct = record['total_direct_score'] / count
        match_ratio = record['direct_matches'] / count
        
        # Logarithmic boost + match ratio bonus
        score = np.log1p(count) * avg_direct * (1 + match_ratio)
        return float(score)

    def get_ranked_exits(self, min_count: int = 1) -> List[Dict]:
        """
        Get ranked list of observed exit nodes.
        
        Args:
            min_count: Minimum observation count to include.
            
        Returns:
            List of dicts containing exit details and scores, sorted by score desc.
        """
        ranked = []
        
        for exit_ip, data in self.evidence.items():
            count = data['count']
            if count < min_count:
                continue
            
            avg_direct = data['total_direct_score'] / count if count > 0 else 0
            avg_indirect = data['total_indirect_score'] / count if count > 0 else 0
            match_ratio = data['direct_matches'] / count if count > 0 else 0
            
            # Score with logarithmic dampening
            score = np.log1p(count) * avg_direct * (1 + match_ratio)
            
            ranked.append({
                'exit_ip': exit_ip,
                'score': float(score),
                'avg_direct_score': float(avg_direct),
                'avg_indirect_score': float(avg_indirect),
                'match_ratio': float(match_ratio),
                'count': count,
                'direct_matches': data['direct_matches'],
                'indirect_matches': data['indirect_matches'],
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
        logger.info("Exit evidence cleared.")


if __name__ == "__main__":
    # Test code
    aggregator = ExitNodeAggregator("data/test_exit_evidence.json")
    aggregator.clear_evidence()
    
    print("Updating exit evidence...")
    aggregator.update_evidence("185.220.101.15", direct_score=0.33, indirect_score=0.05, matched=False)
    aggregator.update_evidence("185.220.101.15", direct_score=0.45, indirect_score=0.08, matched=False)
    aggregator.update_evidence("185.220.101.15", direct_score=0.65, indirect_score=0.0, matched=True)
    aggregator.update_evidence("192.168.1.1", direct_score=0.20, indirect_score=0.02, matched=False)
    
    ranked = aggregator.get_ranked_exits()
    print(json.dumps(ranked, indent=2))
    
    assert ranked[0]['exit_ip'] == "185.220.101.15"
    assert ranked[0]['count'] == 3
    assert ranked[0]['direct_matches'] == 1
    print("✅ ExitNodeAggregator test passed!")
