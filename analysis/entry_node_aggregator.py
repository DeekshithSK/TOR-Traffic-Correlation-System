"""
Entry Node Aggregator

Responsibilities:
- Aggregate multiple correlation results across time
- Map entry-flow IDs → guard node identifiers
- Accumulate evidence over multiple flows
- Provide ranked list of suspected guard nodes with confidence scores

The aggregation logic uses a count-dampened confidence accumulation:
Final Score = log(1 + observation_count) * mean(confidence)
"""

import numpy as np
import logging
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EntryNodeAggregator:
    """
    Aggregates evidence for Entry/Guard nodes over multiple correlation sessions.
    """
    
    def __init__(self, storage_path: str = "data/guard_evidence.json"):
        """
        Initialize the aggregator.
        
        Args:
            storage_path: Path to JSON file for persisting aggregated evidence.
        """
        self.storage_path = Path(storage_path)
        self.evidence = {}  # {guard_id: {count: int, total_confidence: float, last_seen: str}}
        self._load_evidence()
        
    def _load_evidence(self):
        """Load accumulated evidence from disk."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    self.evidence = json.load(f)
                logger.info(f"Loaded evidence for {len(self.evidence)} potential guard nodes.")
            except Exception as e:
                logger.error(f"Failed to load evidence: {e}")
                self.evidence = {}
        else:
            logger.info("No existing evidence found. Starting fresh.")
            self.evidence = {}

    def _save_evidence(self):
        """Save evidence to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(self.evidence, f, indent=2)
            logger.info(f"Saved evidence to {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to save evidence: {e}")

    def update_evidence(self, guard_id: str, confidence: float, timestamp: Optional[str] = None):
        """
        Update evidence for a specific guard node.
        
        Args:
            guard_id: Identifier for the guard node (e.g., flow ID or IP if known).
            confidence: Correlation confidence score [0.0, 1.0].
            timestamp: ISO format timestamp string.
        """
        if timestamp is None:
            timestamp = datetime.now().isoformat()
            
        if guard_id not in self.evidence:
            self.evidence[guard_id] = {
                'count': 0,
                'total_confidence': 0.0,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'timestamps': [] 
            }
        
        record = self.evidence[guard_id]
        record['count'] += 1
        record['total_confidence'] += float(confidence)
        record['last_seen'] = timestamp
        record['timestamps'].append(timestamp)
        if len(record['timestamps']) > 50:
             record['timestamps'] = record['timestamps'][-50:]
             
        self._save_evidence()

    def get_ranked_guards(self, min_confidence: float = 0.0) -> List[Dict]:
        """
        Get ranked list of suspected guard nodes.
        
        Ranking Score = log(1 + count) * (total_confidence / count)
        
        Args:
            min_confidence: Minimum average confidence to include in results.
            
        Returns:
            List of dicts containing guard details and scores, sorted by score desc.
        """
        ranked = []
        
        for guard_id, data in self.evidence.items():
            count = data['count']
            if count == 0: continue
            
            avg_confidence = data['total_confidence'] / count
            
            if avg_confidence < min_confidence:
                continue
                
            score = np.log1p(count) * avg_confidence
            
            ranked.append({
                'guard_id': guard_id,
                'score': float(score),
                'confidence': float(avg_confidence),
                'count': count,
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'evidence_history': data['timestamps']
            })
            
        ranked.sort(key=lambda x: x['score'], reverse=True)
        
        return ranked

    def clear_evidence(self):
        """Clear all accumulated evidence."""
        self.evidence = {}
        if self.storage_path.exists():
            self.storage_path.unlink()
        logger.info("Evidence cleared.")

if __name__ == "__main__":
    aggregator = EntryNodeAggregator("data/test_evidence.json")
    aggregator.clear_evidence()
    
    print("Updating evidence...")
    aggregator.update_evidence("Guard_A", 0.8)
    aggregator.update_evidence("Guard_A", 0.9)
    aggregator.update_evidence("Guard_B", 0.6)
    
    ranked = aggregator.get_ranked_guards()
    print(json.dumps(ranked, indent=2))
    
    assert ranked[0]['guard_id'] == "Guard_A"
    assert ranked[0]['count'] == 2
    print("Test Complete")
