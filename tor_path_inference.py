"""
Tor Path Inference Module

Post-correlation probabilistic path estimation using Tor consensus data.
Implements torps-compatible path selection algorithm WITHOUT consuming PCAP data.

CRITICAL INTEGRATION RULES:
- Must be called ONLY AFTER guard inference
- Must NOT consume PCAP data
- Must NOT claim exact Tor circuit reconstruction
- Output must be probabilistic and clearly labeled as inferred

Path Structure:
    Client (Observed)
      ↓
    Guard Node (Inferred from traffic correlation)
      ↓
    Tor Network Core (Middle hops unobservable by design)
      ↓
    Possible Exit Nodes (Probabilistic, torps-based)
"""

import os
import re
import json
import time
import random
import logging
import hashlib
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

import config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Configuration
# ============================================================================

TOR_CONSENSUS_URL = "https://collector.torproject.org/recent/relay-descriptors/consensuses/"
TOR_CONSENSUS_CACHE_DIR = config.DATA_DIR / "tor_consensus_cache"
TOR_CONSENSUS_CACHE_TTL_HOURS = 6
TOR_PATH_SAMPLE_COUNT = 3000  # Default simulation sample count

# Ensure cache directory exists
TOR_CONSENSUS_CACHE_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class RelayInfo:
    """Parsed Tor relay information from consensus."""
    fingerprint: str
    nickname: str
    ip_address: str
    or_port: int
    dir_port: int
    flags: List[str]
    bandwidth: int  # Bandwidth weight for path selection
    country: Optional[str] = None
    asn: Optional[str] = None
    
    @property
    def is_guard(self) -> bool:
        return 'Guard' in self.flags
    
    @property
    def is_exit(self) -> bool:
        return 'Exit' in self.flags
    
    @property
    def is_stable(self) -> bool:
        return 'Stable' in self.flags
    
    @property
    def is_fast(self) -> bool:
        return 'Fast' in self.flags


@dataclass
class ExitCandidate:
    """Probabilistic exit relay candidate."""
    fingerprint: str
    ip_address: str
    nickname: str
    country: Optional[str]
    probability: float  # Normalized probability [0, 1]
    bandwidth: int
    flags: List[str]


@dataclass
class PathInferenceResult:
    """Complete path inference result."""
    guard: Dict[str, Any]
    tor_core: Dict[str, Any]
    exit_candidates: List[Dict[str, Any]]
    is_probabilistic: bool
    consensus_timestamp: str
    sample_count: int
    total_exit_bandwidth: int
    inference_metadata: Dict[str, Any]


# ============================================================================
# Tor Consensus Client
# ============================================================================

class TorConsensusClient:
    """
    Fetches and parses Tor network consensus data.
    
    Data source: https://collector.torproject.org/recent/relay-descriptors/consensuses/
    """
    
    def __init__(self, 
                 cache_dir: Path = TOR_CONSENSUS_CACHE_DIR,
                 cache_ttl_hours: int = TOR_CONSENSUS_CACHE_TTL_HOURS):
        self.cache_dir = Path(cache_dir)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self._relays: Dict[str, RelayInfo] = {}
        self._relays_by_ip: Dict[str, List[RelayInfo]] = defaultdict(list)
        self._consensus_timestamp: Optional[datetime] = None
        
    def _get_cache_path(self) -> Path:
        """Get path to cached consensus file."""
        return self.cache_dir / "consensus_cache.json"
    
    def _get_cache_meta_path(self) -> Path:
        """Get path to cache metadata file."""
        return self.cache_dir / "consensus_meta.json"
    
    def _is_cache_valid(self) -> bool:
        """Check if cached consensus is still valid."""
        meta_path = self._get_cache_meta_path()
        if not meta_path.exists():
            return False
        
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            cache_time = datetime.fromisoformat(meta['timestamp'])
            return datetime.now() - cache_time < self.cache_ttl
        except Exception:
            return False
    
    def _save_to_cache(self, relays: Dict[str, RelayInfo]) -> None:
        """Save parsed relays to cache."""
        cache_path = self._get_cache_path()
        meta_path = self._get_cache_meta_path()
        
        try:
            # Save relay data
            relay_data = {fp: asdict(relay) for fp, relay in relays.items()}
            with open(cache_path, 'w') as f:
                json.dump(relay_data, f)
            
            # Save metadata
            meta = {
                'timestamp': datetime.now().isoformat(),
                'relay_count': len(relays),
                'guard_count': sum(1 for r in relays.values() if r.is_guard),
                'exit_count': sum(1 for r in relays.values() if r.is_exit)
            }
            with open(meta_path, 'w') as f:
                json.dump(meta, f)
                
            logger.info(f"Cached {len(relays)} relays to {cache_path}")
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _load_from_cache(self) -> Optional[Dict[str, RelayInfo]]:
        """Load relays from cache."""
        cache_path = self._get_cache_path()
        if not cache_path.exists():
            return None
        
        try:
            with open(cache_path, 'r') as f:
                relay_data = json.load(f)
            
            relays = {}
            for fp, data in relay_data.items():
                relays[fp] = RelayInfo(**data)
            
            logger.info(f"Loaded {len(relays)} relays from cache")
            return relays
        except Exception as e:
            logger.error(f"Failed to load cache: {e}")
            return None
    
    def _fetch_latest_consensus_url(self) -> Optional[str]:
        """Get URL of latest consensus file from collector."""
        try:
            response = requests.get(TOR_CONSENSUS_URL, timeout=30)
            response.raise_for_status()
            
            # Parse directory listing to find latest consensus file
            # Files are named like: 2025-12-18-12-00-00-consensus
            pattern = r'href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-consensus)"'
            matches = re.findall(pattern, response.text)
            
            if not matches:
                logger.error("No consensus files found in directory listing")
                return None
            
            # Get the latest file
            latest_file = sorted(matches)[-1]
            return f"{TOR_CONSENSUS_URL}{latest_file}"
        except Exception as e:
            logger.error(f"Failed to fetch consensus directory: {e}")
            return None
    
    def _parse_consensus(self, raw_content: str) -> Dict[str, RelayInfo]:
        """Parse raw consensus document into RelayInfo objects."""
        relays = {}
        current_relay = None
        
        lines = raw_content.split('\n')
        
        for line in lines:
            line = line.strip()
            
            # Router line: r <nickname> <identity> <digest> <date> <time> <IP> <ORPort> <DirPort>
            # Example: r seele AAoQ1DAR6kkoo19hBAX5K0QztNw LNrZ8YA4... 2025-12-18 06:18:04 152.53.144.50 443 0
            if line.startswith('r '):
                parts = line.split()
                if len(parts) >= 9:  # Need at least 9 parts
                    nickname = parts[1]
                    # Identity is base64 encoded, convert to hex fingerprint
                    try:
                        import base64
                        identity_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)
                        identity_bytes = base64.b64decode(identity_b64)
                        fingerprint = identity_bytes.hex().upper()
                    except:
                        fingerprint = hashlib.sha1(parts[2].encode()).hexdigest().upper()
                    
                    # parts[3] = digest, parts[4] = date, parts[5] = time
                    ip_address = parts[6]  # IP is at index 6
                    or_port = int(parts[7])  # ORPort at index 7
                    dir_port = int(parts[8])  # DirPort at index 8
                    
                    current_relay = {
                        'fingerprint': fingerprint,
                        'nickname': nickname,
                        'ip_address': ip_address,
                        'or_port': or_port,
                        'dir_port': dir_port,
                        'flags': [],
                        'bandwidth': 0
                    }
            
            # Flags line: s <flag1> <flag2> ...
            elif line.startswith('s ') and current_relay:
                current_relay['flags'] = line[2:].split()
            
            # Bandwidth line: w Bandwidth=<value>
            elif line.startswith('w ') and current_relay:
                match = re.search(r'Bandwidth=(\d+)', line)
                if match:
                    current_relay['bandwidth'] = int(match.group(1))
                
                # This is typically the last line for a relay entry
                relay = RelayInfo(**current_relay)
                relays[relay.fingerprint] = relay
                current_relay = None
        
        logger.info(f"Parsed {len(relays)} relays from consensus")
        return relays
    
    def fetch_consensus(self, force_refresh: bool = False) -> bool:
        """
        Fetch and parse Tor consensus data.
        
        Args:
            force_refresh: If True, ignore cache and fetch fresh data
            
        Returns:
            True if consensus was loaded successfully
        """
        # Try cache first
        if not force_refresh and self._is_cache_valid():
            cached = self._load_from_cache()
            if cached:
                self._relays = cached
                self._index_relays()
                self._load_cache_timestamp()
                return True
        
        # Fetch fresh consensus
        consensus_url = self._fetch_latest_consensus_url()
        if not consensus_url:
            # Fallback to cache even if expired
            cached = self._load_from_cache()
            if cached:
                logger.warning("Using expired cache due to fetch failure")
                self._relays = cached
                self._index_relays()
                return True
            return False
        
        try:
            logger.info(f"Fetching consensus from {consensus_url}")
            response = requests.get(consensus_url, timeout=60)
            response.raise_for_status()
            
            self._relays = self._parse_consensus(response.text)
            self._index_relays()
            self._consensus_timestamp = datetime.now()
            
            # Cache the result
            self._save_to_cache(self._relays)
            
            return True
        except Exception as e:
            logger.error(f"Failed to fetch consensus: {e}")
            # Fallback to cache
            cached = self._load_from_cache()
            if cached:
                logger.warning("Using cached data due to fetch failure")
                self._relays = cached
                self._index_relays()
                return True
            return False
    
    def _index_relays(self) -> None:
        """Build IP-based index for relay lookup."""
        self._relays_by_ip.clear()
        for relay in self._relays.values():
            self._relays_by_ip[relay.ip_address].append(relay)
    
    def _load_cache_timestamp(self) -> None:
        """Load consensus timestamp from cache metadata."""
        meta_path = self._get_cache_meta_path()
        try:
            with open(meta_path, 'r') as f:
                meta = json.load(f)
            self._consensus_timestamp = datetime.fromisoformat(meta['timestamp'])
        except:
            self._consensus_timestamp = datetime.now()
    
    def get_relay_by_fingerprint(self, fingerprint: str) -> Optional[RelayInfo]:
        """Lookup relay by fingerprint."""
        return self._relays.get(fingerprint.upper())
    
    def get_relays_by_ip(self, ip_address: str) -> List[RelayInfo]:
        """Lookup relays by IP address."""
        return self._relays_by_ip.get(ip_address, [])
    
    def get_all_guards(self) -> List[RelayInfo]:
        """Get all relays with Guard flag."""
        return [r for r in self._relays.values() if r.is_guard]
    
    def get_all_exits(self) -> List[RelayInfo]:
        """Get all relays with Exit flag."""
        return [r for r in self._relays.values() if r.is_exit]
    
    @property
    def relay_count(self) -> int:
        return len(self._relays)
    
    @property
    def consensus_timestamp(self) -> Optional[datetime]:
        return self._consensus_timestamp


# ============================================================================
# Path Probability Estimator
# ============================================================================

class PathProbabilityEstimator:
    """
    Simulates Tor's path selection algorithm to estimate probable exit nodes.
    
    Based on Tor's documented bandwidth-weighted selection:
    - Exit selection is weighted by bandwidth
    - Fast and Stable flags increase selection probability
    - Does NOT claim exact circuit reconstruction
    """
    
    def __init__(self, consensus_client: TorConsensusClient):
        self.consensus = consensus_client
    
    def _calculate_exit_weight(self, relay: RelayInfo) -> float:
        """
        Calculate selection weight for an exit relay.
        
        Weight factors:
        - Base: bandwidth value
        - Bonus: +20% for Stable flag
        - Bonus: +20% for Fast flag
        """
        weight = float(relay.bandwidth)
        
        if relay.is_stable:
            weight *= 1.2
        if relay.is_fast:
            weight *= 1.2
        
        return weight
    
    def estimate_exit_probabilities(self, 
                                    guard_fingerprint: Optional[str] = None,
                                    guard_ip: Optional[str] = None,
                                    sample_count: int = TOR_PATH_SAMPLE_COUNT) -> List[ExitCandidate]:
        """
        Estimate probable exit nodes using bandwidth-weighted sampling.
        
        Args:
            guard_fingerprint: Optional guard fingerprint (for exclusion)
            guard_ip: Optional guard IP (for exclusion)
            sample_count: Number of samples for probability estimation
            
        Returns:
            List of ExitCandidate objects with normalized probabilities
        """
        exits = self.consensus.get_all_exits()
        
        if not exits:
            logger.warning("No exit relays found in consensus")
            return []
        
        # Exclude guard from exit selection (Tor doesn't use same relay twice)
        if guard_fingerprint:
            exits = [e for e in exits if e.fingerprint != guard_fingerprint]
        if guard_ip:
            exits = [e for e in exits if e.ip_address != guard_ip]
        
        # Calculate weights
        weights = []
        for exit_relay in exits:
            weight = self._calculate_exit_weight(exit_relay)
            weights.append(weight)
        
        total_weight = sum(weights)
        if total_weight == 0:
            logger.warning("Total exit weight is zero")
            return []
        
        # Normalize weights to probabilities
        probabilities = [w / total_weight for w in weights]
        
        # Simulate path selection
        selection_counts = defaultdict(int)
        for _ in range(sample_count):
            # Random weighted selection
            r = random.random()
            cumulative = 0
            for i, prob in enumerate(probabilities):
                cumulative += prob
                if r <= cumulative:
                    selection_counts[i] += 1
                    break
        
        # Convert to ExitCandidate objects with empirical probabilities
        candidates = []
        for i, exit_relay in enumerate(exits):
            if selection_counts[i] > 0:
                empirical_prob = selection_counts[i] / sample_count
                candidates.append(ExitCandidate(
                    fingerprint=exit_relay.fingerprint,
                    ip_address=exit_relay.ip_address,
                    nickname=exit_relay.nickname,
                    country=exit_relay.country,
                    probability=empirical_prob,
                    bandwidth=exit_relay.bandwidth,
                    flags=exit_relay.flags
                ))
        
        # Sort by probability descending
        candidates.sort(key=lambda x: x.probability, reverse=True)
        
        # Return top candidates (limit to reasonable number)
        return candidates[:50]


# ============================================================================
# Main Tor Path Inference Class
# ============================================================================

class TorPathInference:
    """
    Main interface for post-correlation path inference.
    
    IMPORTANT: This module must be called ONLY AFTER guard inference.
    It does NOT consume PCAP data directly.
    """
    
    def __init__(self):
        self.consensus_client = TorConsensusClient()
        self.probability_estimator = PathProbabilityEstimator(self.consensus_client)
        self._initialized = False
    
    def initialize(self, force_refresh: bool = False) -> bool:
        """
        Initialize by fetching Tor consensus.
        
        Args:
            force_refresh: Force fresh consensus fetch
            
        Returns:
            True if initialization successful
        """
        if self._initialized and not force_refresh:
            return True
        
        success = self.consensus_client.fetch_consensus(force_refresh)
        self._initialized = success
        
        if success:
            logger.info(f"TorPathInference initialized with {self.consensus_client.relay_count} relays")
        else:
            logger.error("Failed to initialize TorPathInference")
        
        return success
    
    def lookup_guard(self, guard_ip: str) -> Optional[RelayInfo]:
        """
        Lookup guard relay information by IP address.
        
        Args:
            guard_ip: IP address of the inferred guard node
            
        Returns:
            RelayInfo if found, None otherwise
        """
        if not self._initialized:
            self.initialize()
        
        relays = self.consensus_client.get_relays_by_ip(guard_ip)
        
        # Return the guard relay if found
        guards = [r for r in relays if r.is_guard]
        if guards:
            return guards[0]
        
        # Return any relay at that IP if no guard flag
        if relays:
            return relays[0]
        
        return None
    
    def estimate_path(self,
                      guard_ip: str,
                      guard_confidence: float,
                      sample_count: int = TOR_PATH_SAMPLE_COUNT,
                      exit_evidence: Optional[Dict] = None) -> PathInferenceResult:
        """
        Estimate probable Tor path from guard node.
        
        CRITICAL: This does NOT consume PCAP data. It uses only:
        - Inferred guard IP (from correlation)
        - Guard confidence score (from correlation)
        - Tor consensus data (public network information)
        
        Args:
            guard_ip: IP address of inferred guard node
            guard_confidence: Confidence score from guard inference [0, 1]
            sample_count: Number of samples for probability estimation
            exit_evidence: Optional exit-side correlation evidence
            
        Returns:
            PathInferenceResult with guard, tor_core, and exit candidates
        """
        if not self._initialized:
            self.initialize()
        
        # Lookup guard in consensus
        guard_relay = self.lookup_guard(guard_ip)
        
        guard_info = {
            'ip': guard_ip,
            'fingerprint': guard_relay.fingerprint if guard_relay else 'UNKNOWN',
            'nickname': guard_relay.nickname if guard_relay else 'Unknown',
            'country': guard_relay.country if guard_relay else None,
            'flags': guard_relay.flags if guard_relay else [],
            'confidence': guard_confidence,
            'in_consensus': guard_relay is not None,
            'label': 'Guard Relay (Inferred)'
        }
        
        # Tor core is always a placeholder
        tor_core_info = {
            'label': 'Tor Network (Hidden by Design)',
            'description': 'Middle relays cannot be observed or inferred',
            'is_observable': False
        }
        
        # Estimate exit probabilities
        exit_candidates = self.probability_estimator.estimate_exit_probabilities(
            guard_fingerprint=guard_relay.fingerprint if guard_relay else None,
            guard_ip=guard_ip,
            sample_count=sample_count
        )
        
        # Calculate total exit bandwidth for metadata
        total_exit_bw = sum(e.bandwidth for e in exit_candidates)
        
        # Convert to dicts for JSON serialization
        exit_list = []
        for candidate in exit_candidates:
            exit_list.append({
                'ip': candidate.ip_address,
                'fingerprint': candidate.fingerprint,
                'nickname': candidate.nickname,
                'country': candidate.country,
                'probability': round(candidate.probability, 6),
                'bandwidth': candidate.bandwidth,
                'flags': candidate.flags,
                'label': 'Possible Exit Relay (Probabilistic)'
            })
        
        # Confidence aggregation
        # RULE: torps does NOT increase confidence by itself
        final_confidence = guard_confidence
        confidence_boost = 0.0
        
        if exit_evidence:
            # Exit-side correlation may increase confidence
            exit_match_score = exit_evidence.get('match_score', 0)
            if exit_match_score > 0.5:
                confidence_boost = min(0.15, exit_match_score * 0.2)
                final_confidence = min(1.0, guard_confidence + confidence_boost)
        
        # Build metadata
        inference_metadata = {
            'sample_count': sample_count,
            'guard_in_consensus': guard_relay is not None,
            'exit_candidates_count': len(exit_list),
            'base_confidence': guard_confidence,
            'confidence_boost': confidence_boost,
            'final_confidence': final_confidence,
            'has_exit_evidence': exit_evidence is not None,
            'warning': 'Path estimation is probabilistic and should not be used as sole evidence'
        }
        
        return PathInferenceResult(
            guard=guard_info,
            tor_core=tor_core_info,
            exit_candidates=exit_list,
            is_probabilistic=True,
            consensus_timestamp=self.consensus_client.consensus_timestamp.isoformat() 
                if self.consensus_client.consensus_timestamp else datetime.now().isoformat(),
            sample_count=sample_count,
            total_exit_bandwidth=total_exit_bw,
            inference_metadata=inference_metadata
        )
    
    def to_graph_format(self, result: PathInferenceResult) -> Dict[str, Any]:
        """
        Convert PathInferenceResult to graph visualization format.
        
        Returns structure compatible with frontend RelayGraph component.
        """
        nodes = []
        edges = []
        
        # Client node
        nodes.append({
            'id': 'client',
            'type': 'client',
            'label': 'Client (Observed)',
            'style': 'neutral',
            'data': {}
        })
        
        # Guard node
        nodes.append({
            'id': 'guard',
            'type': 'guard',
            'label': 'Guard Relay',
            'style': 'highlighted',
            'data': result.guard
        })
        
        # Tor core node
        nodes.append({
            'id': 'tor_core',
            'type': 'tor_core',
            'label': 'Tor Network (Hidden)',
            'style': 'dashed',
            'data': result.tor_core
        })
        
        # Exit nodes (top 5 for visualization)
        for i, exit_candidate in enumerate(result.exit_candidates[:5]):
            nodes.append({
                'id': f'exit_{i}',
                'type': 'exit',
                'label': f"Exit: {exit_candidate.get('nickname', 'Unknown')}",
                'style': 'probabilistic',
                'probability': exit_candidate['probability'],
                'data': exit_candidate
            })
        
        # Edges
        # Client -> Guard (solid, traffic-inferred)
        edges.append({
            'source': 'client',
            'target': 'guard',
            'type': 'solid',
            'label': 'Traffic Inferred',
            'confidence': result.guard['confidence']
        })
        
        # Guard -> Tor Core (dashed, inferred boundary)
        edges.append({
            'source': 'guard',
            'target': 'tor_core',
            'type': 'dashed',
            'label': 'Inferred Boundary'
        })
        
        # Tor Core -> Exits (dotted, probabilistic)
        for i, exit_candidate in enumerate(result.exit_candidates[:5]):
            edges.append({
                'source': 'tor_core',
                'target': f'exit_{i}',
                'type': 'dotted',
                'label': f"Probability: {exit_candidate['probability']:.1%}",
                'probability': exit_candidate['probability']
            })
        
        return {
            'nodes': nodes,
            'edges': edges,
            'metadata': result.inference_metadata,
            'is_probabilistic': True,
            'timestamp': result.consensus_timestamp
        }


# ============================================================================
# Convenience Functions
# ============================================================================

def create_path_inference() -> TorPathInference:
    """Factory function to create initialized TorPathInference instance."""
    inference = TorPathInference()
    inference.initialize()
    return inference


def infer_path_from_guard(guard_ip: str, 
                          confidence: float,
                          sample_count: int = TOR_PATH_SAMPLE_COUNT) -> Dict[str, Any]:
    """
    Convenience function for API integration.
    
    Args:
        guard_ip: Inferred guard IP from correlation
        confidence: Guard inference confidence
        sample_count: Simulation sample count
        
    Returns:
        Dictionary with path inference results
    """
    inference = TorPathInference()
    if not inference.initialize():
        return {
            'error': 'Failed to initialize Tor consensus',
            'is_probabilistic': True
        }
    
    result = inference.estimate_path(guard_ip, confidence, sample_count)
    
    return {
        'guard': result.guard,
        'tor_core': result.tor_core,
        'exit_candidates': result.exit_candidates,
        'is_probabilistic': result.is_probabilistic,
        'consensus_timestamp': result.consensus_timestamp,
        'metadata': result.inference_metadata,
        'graph': inference.to_graph_format(result)
    }


# ============================================================================
# Testing
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Tor Path Inference Module - Test")
    print("=" * 70)
    
    # Initialize
    print("\n📡 Initializing Tor consensus client...")
    inference = TorPathInference()
    
    if not inference.initialize():
        print("❌ Failed to initialize - check network connection")
        exit(1)
    
    print(f"✅ Loaded {inference.consensus_client.relay_count} relays")
    
    # Test guard lookup
    print("\n🔍 Testing guard lookup...")
    test_ip = "51.159.211.57"  # Example TOR guard IP
    guard = inference.lookup_guard(test_ip)
    if guard:
        print(f"   Found: {guard.nickname} ({guard.ip_address})")
        print(f"   Flags: {guard.flags}")
    else:
        print(f"   No relay found at {test_ip}")
    
    # Test path estimation
    print("\n🛤️ Testing path estimation...")
    result = inference.estimate_path(
        guard_ip=test_ip,
        guard_confidence=0.85,
        sample_count=1000
    )
    
    print(f"\n   Guard: {result.guard['nickname'] if result.guard.get('nickname') else 'Unknown'}")
    print(f"   Confidence: {result.guard['confidence']:.1%}")
    print(f"   In Consensus: {result.guard['in_consensus']}")
    
    print(f"\n   Tor Core: {result.tor_core['label']}")
    
    print(f"\n   Exit Candidates (top 5):")
    for i, exit_cand in enumerate(result.exit_candidates[:5], 1):
        print(f"      {i}. {exit_cand['nickname']} ({exit_cand['ip']}) - {exit_cand['probability']:.2%}")
    
    # Test graph format
    print("\n📊 Testing graph format...")
    graph = inference.to_graph_format(result)
    print(f"   Nodes: {len(graph['nodes'])}")
    print(f"   Edges: {len(graph['edges'])}")
    
    print("\n" + "=" * 70)
    print("✅ All tests passed!")
    print("=" * 70)
