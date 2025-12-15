"""
TOR Network Data Collector
Automated scraping of TOR relay information using Onionoo API

Features:
- Guard, middle, and exit node classification
- Bandwidth, uptime, and flag tracking
- Hourly snapshot collection
- Time-indexed network graph storage
"""

import requests
import json
import pickle
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict

import config


# ============================================================================
# Logging Setup
# ============================================================================

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT,
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================================
# Onionoo API Client
# ============================================================================

class OnionooClient:
    """
    Client for TOR Project Onionoo API.
    Provides access to TOR relay and bridge descriptors.
    """
    
    def __init__(self, base_url: str = config.ONIONOO_BASE_URL,
                 timeout: int = config.TOR_TIMEOUT_SECONDS,
                 max_retries: int = config.TOR_MAX_RETRIES):
        """
        Initialize Onionoo API client.
        
        Args:
            base_url: Base URL for Onionoo API
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TrafficAnalysisDashboard/1.0'
        })
        
        logger.info(f"Initialized OnionooClient: {base_url}")
    
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make API request with retry logic.
        
        Args:
            endpoint: API endpoint (e.g., 'details', 'bandwidth')
            params: Query parameters
            
        Returns:
            JSON response as dictionary
        """
        url = f"{self.base_url}/{endpoint}"
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Request to {url} (attempt {attempt + 1}/{self.max_retries})")
                response = self.session.get(url, params=params, timeout=self.timeout)
                response.raise_for_status()
                
                # Rate limiting
                time.sleep(config.TOR_RATE_LIMIT_DELAY)
                
                return response.json()
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)  # Exponential backoff
        
        raise RuntimeError("Max retries exceeded")
    
    def get_all_relays(self, running: bool = True) -> List[Dict]:
        """
        Fetch all TOR relays.
        
        Args:
            running: Only return running relays
            
        Returns:
            List of relay dictionaries
        """
        params = {}
        if running:
            params['running'] = 'true'
        
        logger.info("Fetching all TOR relays...")
        response = self._make_request('details', params)
        
        relays = response.get('relays', [])
        logger.info(f"Retrieved {len(relays)} relays")
        
        return relays
    
    def get_relays_by_flag(self, flag: str) -> List[Dict]:
        """
        Fetch relays with specific flag (Guard, Exit, etc.).
        
        Args:
            flag: Flag name (e.g., 'Guard', 'Exit', 'Fast')
            
        Returns:
            List of relay dictionaries
        """
        params = {'flag': flag}
        
        logger.info(f"Fetching relays with flag: {flag}")
        response = self._make_request('details', params)
        
        relays = response.get('relays', [])
        logger.info(f"Retrieved {len(relays)} relays with flag '{flag}'")
        
        return relays
    
    def get_relay_bandwidth(self, fingerprint: str) -> Dict:
        """
        Get bandwidth history for specific relay.
        
        Args:
            fingerprint: Relay fingerprint
            
        Returns:
            Bandwidth data dictionary
        """
        params = {'lookup': fingerprint}
        response = self._make_request('bandwidth', params)
        
        relays = response.get('relays', [])
        return relays[0] if relays else {}
    
    def get_relay_uptime(self, fingerprint: str) -> Dict:
        """
        Get uptime history for specific relay.
        
        Args:
            fingerprint: Relay fingerprint
            
        Returns:
            Uptime data dictionary
        """
        params = {'lookup': fingerprint}
        response = self._make_request('uptime', params)
        
        relays = response.get('relays', [])
        return relays[0] if relays else {}


# ============================================================================
# Relay Classifier
# ============================================================================

class RelayClassifier:
    """
    Classify TOR relays by type and extract metadata.
    """
    
    @staticmethod
    def classify_relay(relay: Dict) -> str:
        """
        Classify relay as guard, middle, or exit node.
        
        Args:
            relay: Relay dictionary from Onionoo API
            
        Returns:
            Relay type: 'guard', 'exit', or 'middle'
        """
        flags = relay.get('flags', [])
        
        # Guard nodes
        if 'Guard' in flags:
            return 'guard'
        
        # Exit nodes
        if 'Exit' in flags and not 'BadExit' in flags:
            return 'exit'
        
        # Middle/relay nodes (default)
        return 'middle'
    
    @staticmethod
    def extract_metadata(relay: Dict) -> Dict:
        """
        Extract relevant metadata from relay.
        
        Args:
            relay: Relay dictionary
            
        Returns:
            Metadata dictionary
        """
        return {
            'fingerprint': relay.get('fingerprint', ''),
            'nickname': relay.get('nickname', ''),
            'address': relay.get('or_addresses', [])[0] if relay.get('or_addresses') else '',
            'flags': relay.get('flags', []),
            'running': relay.get('running', False),
            'bandwidth': {
                'observed': relay.get('observed_bandwidth', 0),
                'advertised': relay.get('advertised_bandwidth', 0),
                'consensus_weight': relay.get('consensus_weight', 0),
            },
            'uptime': {
                'first_seen': relay.get('first_seen', ''),
                'last_seen': relay.get('last_seen', ''),
                'last_changed_address': relay.get('last_changed_address_or_port', ''),
            },
            'geolocation': {
                'country': relay.get('country', ''),
                'country_name': relay.get('country_name', ''),
                'latitude': relay.get('latitude', None),
                'longitude': relay.get('longitude', None),
                'as_number': relay.get('as_number', ''),
                'as_name': relay.get('as_name', ''),
            },
            'contact': relay.get('contact', ''),
            'platform': relay.get('platform', ''),
            'version': relay.get('version', ''),
            'relay_type': RelayClassifier.classify_relay(relay),
        }


# ============================================================================
# TOR Network Graph
# ============================================================================

class TORNetworkGraph:
    """
    Time-indexed graph representation of TOR network.
    Stores relay snapshots with relationships and metadata.
    """
    
    def __init__(self):
        """Initialize empty network graph."""
        self.snapshots = []  # List of (timestamp, graph_data) tuples
        self.current_snapshot = None
        self.timestamp = None
        
    def add_snapshot(self, relays: List[Dict], timestamp: Optional[datetime] = None):
        """
        Add network snapshot at specific timestamp.
        
        Args:
            relays: List of relay dictionaries
            timestamp: Snapshot timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Build graph structure
        graph_data = {
            'timestamp': timestamp.isoformat(),
            'relay_count': len(relays),
            'relays_by_type': defaultdict(list),
            'relays': {},
            'statistics': {}
        }
        
        # Classify and store relays
        for relay in relays:
            metadata = RelayClassifier.extract_metadata(relay)
            relay_type = metadata['relay_type']
            fingerprint = metadata['fingerprint']
            
            graph_data['relays_by_type'][relay_type].append(fingerprint)
            graph_data['relays'][fingerprint] = metadata
        
        # Calculate statistics
        graph_data['statistics'] = self._calculate_statistics(graph_data)
        
        self.current_snapshot = graph_data
        self.timestamp = timestamp
        self.snapshots.append((timestamp, graph_data))
        
        logger.info(f"Added snapshot: {len(relays)} relays at {timestamp}")
        
    def _calculate_statistics(self, graph_data: Dict) -> Dict:
        """Calculate network statistics."""
        stats = {
            'total_relays': graph_data['relay_count'],
            'guard_nodes': len(graph_data['relays_by_type']['guard']),
            'exit_nodes': len(graph_data['relays_by_type']['exit']),
            'middle_relays': len(graph_data['relays_by_type']['middle']),
            'total_bandwidth': 0,
            'avg_bandwidth': 0,
            'countries': set(),
            'running_relays': 0,
        }
        
        bandwidths = []
        for relay_meta in graph_data['relays'].values():
            bw = relay_meta['bandwidth']['observed']
            bandwidths.append(bw)
            stats['total_bandwidth'] += bw
            
            if relay_meta['running']:
                stats['running_relays'] += 1
            
            country = relay_meta['geolocation']['country']
            if country:
                stats['countries'].add(country)
        
        if bandwidths:
            stats['avg_bandwidth'] = stats['total_bandwidth'] / len(bandwidths)
        
        stats['countries'] = len(stats['countries'])
        
        return stats
    
    def export_json(self, filepath: Path):
        """Export current snapshot to JSON."""
        if self.current_snapshot is None:
            raise ValueError("No snapshot available")
        
        # Convert sets to lists for JSON serialization
        export_data = json.loads(json.dumps(
            self.current_snapshot, 
            default=str
        ))
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported JSON snapshot: {filepath}")
    
    def export_pickle(self, filepath: Path):
        """Export current snapshot to pickle."""
        if self.current_snapshot is None:
            raise ValueError("No snapshot available")
        
        with open(filepath, 'wb') as f:
            pickle.dump(self.current_snapshot, f)
        
        logger.info(f"Exported pickle snapshot: {filepath}")
    
    def get_statistics_summary(self) -> str:
        """Get human-readable statistics summary."""
        if not self.current_snapshot:
            return "No snapshot available"
        
        stats = self.current_snapshot['statistics']
        
        summary = f"""
TOR Network Snapshot - {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
{'=' * 60}
Total Relays: {stats['total_relays']}
  - Guard Nodes:   {stats['guard_nodes']:,}
  - Exit Nodes:    {stats['exit_nodes']:,}
  - Middle Relays: {stats['middle_relays']:,}

Running Relays: {stats['running_relays']:,}
Countries: {stats['countries']}

Bandwidth:
  - Total: {stats['total_bandwidth'] / 1e9:.2f} GB/s
  - Average: {stats['avg_bandwidth'] / 1e6:.2f} MB/s per relay
{'=' * 60}
        """
        return summary.strip()


# ============================================================================
# TOR Collector Scheduler
# ============================================================================

class TORCollector:
    """
    Main TOR network data collector.
    Orchestrates API requests, classification, and storage.
    """
    
    def __init__(self, api_client: Optional[OnionooClient] = None):
        """
        Initialize TOR collector.
        
        Args:
            api_client: Optional OnionooClient instance (creates new if None)
        """
        self.api_client = api_client or OnionooClient()
        self.graph = TORNetworkGraph()
        
        logger.info("TORCollector initialized")
    
    def collect_snapshot(self) -> TORNetworkGraph:
        """
        Collect single network snapshot.
        
        Returns:
            Updated TORNetworkGraph
        """
        logger.info("=" * 60)
        logger.info("Starting TOR network snapshot collection")
        logger.info("=" * 60)
        
        # Fetch all relays
        relays = self.api_client.get_all_relays(running=config.TOR_RUNNING_ONLY)
        
        # Add to graph
        timestamp = datetime.now()
        self.graph.add_snapshot(relays, timestamp)
        
        # Export snapshots
        if 'json' in config.TOR_EXPORT_FORMATS:
            json_path = config.get_tor_snapshot_path(
                timestamp.strftime("%Y%m%d_%H%M%S")
            )
            self.graph.export_json(json_path)
        
        if 'pickle' in config.TOR_EXPORT_FORMATS:
            pickle_path = json_path.with_suffix('.pickle')
            self.graph.export_pickle(pickle_path)
        
        # Print summary
        print(self.graph.get_statistics_summary())
        
        logger.info("Snapshot collection complete")
        
        return self.graph
    
    def cleanup_old_snapshots(self):
        """Remove snapshots older than retention period."""
        cutoff_date = datetime.now() - timedelta(days=config.TOR_SNAPSHOT_RETENTION_DAYS)
        
        removed_count = 0
        for snapshot_file in config.TOR_DATA_DIR.glob("tor_snapshot_*"):
            # Parse timestamp from filename
            try:
                timestamp_str = snapshot_file.stem.replace("tor_snapshot_", "")
                file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                if file_date < cutoff_date:
                    snapshot_file.unlink()
                    removed_count += 1
                    logger.info(f"Removed old snapshot: {snapshot_file}")
            except (ValueError, OSError) as e:
                logger.warning(f"Error processing {snapshot_file}: {e}")
        
        logger.info(f"Cleanup complete: removed {removed_count} old snapshots")


# ============================================================================
# CLI Interface
# ============================================================================

def main():
    """Main entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="TOR Network Data Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--test', 
        action='store_true',
        help='Test API connectivity'
    )
    parser.add_argument(
        '--collect',
        action='store_true',
        help='Collect single snapshot'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up old snapshots'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show statistics from latest snapshot'
    )
    
    args = parser.parse_args()
    
    if args.test:
        print("🧪 Testing Onionoo API connectivity...")
        client = OnionooClient()
        try:
            relays = client.get_all_relays()
            print(f"✅ Success! Retrieved {len(relays)} relays")
        except Exception as e:
            print(f"❌ Error: {e}")
            return 1
    
    elif args.collect:
        collector = TORCollector()
        collector.collect_snapshot()
    
    elif args.cleanup:
        collector = TORCollector()
        collector.cleanup_old_snapshots()
    
    elif args.stats:
        latest_snapshot = config.get_latest_tor_snapshot()
        if latest_snapshot:
            with open(latest_snapshot, 'r') as f:
                data = json.load(f)
            
            stats = data['statistics']
            print(f"\nLatest Snapshot: {data['timestamp']}")
            print(f"Total Relays: {stats['total_relays']}")
            print(f"  Guard: {stats['guard_nodes']}")
            print(f"  Exit: {stats['exit_nodes']}")
            print(f"  Middle: {stats['middle_relays']}")
        else:
            print("No snapshots found")
    
    else:
        parser.print_help()
    
    return 0


if __name__ == "__main__":
    exit(main())
