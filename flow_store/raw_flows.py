"""
Flow Store
Responsibility: Single Source of Truth for raw flow data.
"""

from typing import Dict, Optional
import numpy as np
import logging

logger = logging.getLogger(__name__)

class FlowStore:
    """
    In-memory storage for raw flows.
    """
    _instance = None
    
    def __init__(self):
        self._flows: Dict[str, np.ndarray] = {}
        
    def save_flows(self, flows: Dict[str, np.ndarray]):
        """
        Save a batch of flows to the store.
        """
        count_before = len(self._flows)
        self._flows.update(flows)
        count_after = len(self._flows)
        logger.info(f"FlowStore updated: {count_before} -> {count_after} flows stored.")
        
    def get_flow(self, flow_id: str) -> Optional[np.ndarray]:
        """
        Retrieve a single flow by ID.
        """
        return self._flows.get(flow_id)
        
    def get_all_flow_ids(self) -> list:
        """
        Get list of all stored flow IDs.
        """
        return list(self._flows.keys())

    def clear(self):
        """
        Clear all data.
        """
        self._flows.clear()
        logger.info("FlowStore cleared.")
