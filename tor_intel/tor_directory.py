"""
TOR Directory Intelligence

Responsibilities:
- Fetch and cache TOR relay metadata (using Onionoo or consensus)
- Identify relay roles: Guard / Middle / Exit
- Expose relay metadata via fingerprint or IP lookup

This module uses a local cache to avoid excessive API calls.
"""

import requests
import json
import logging
import time
from pathlib import Path
from typing import Dict, Optional, List, Union

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TorDirectory:
    """
    Manages TOR relay metadata, fetching from Onionoo and caching locally.
    """
    
    ONIONOO_URL = "https://onionoo.torproject.org/details"
    
    def __init__(self, cache_path: str = "data/tor_cache.json", cache_expiry_hours: int = 24):
        """
        Initialize TOR Directory.
        
        Args:
            cache_path: Path to local JSON cache file.
            cache_expiry_hours: How long to keep cached data before refreshing.
        """
        self.cache_path = Path(cache_path)
        self.cache_expiry_seconds = cache_expiry_hours * 3600
        self.relays = {}     # Map by fingerprint -> details
        self.relays_by_ip = {} # Map by IP -> details (list, as IPs can be shared)
        
        self._load_data()
        
    def _load_data(self):
        """Load data from cache or fetch if expired/missing."""
        load_from_cache = False
        
        if self.cache_path.exists():
            mtime = self.cache_path.stat().st_mtime
            age = time.time() - mtime
            if age < self.cache_expiry_seconds:
                load_from_cache = True
            else:
                logger.info(f"Cache expired (age: {age/3600:.1f}h).")
        
        if load_from_cache:
            try:
                logger.info("Loading TOR data from cache...")
                with open(self.cache_path, 'r') as f:
                    data = json.load(f)
                    self._index_relays(data)
                return
            except Exception as e:
                logger.error(f"Failed to load cache: {e}")
        
        self._fetch_fresh_data()
        
    def _fetch_fresh_data(self):
        """Fetch fresh consensus data from Onionoo."""
        logger.info("Fetching fresh TOR relay data from Onionoo...")
        try:
            response = requests.get(self.ONIONOO_URL, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self._index_relays(data.get('relays', []))
                
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_path, 'w') as f:
                    json.dump(self.relays.values(), f)  # Save list of relays
                logger.info(f"Cached {len(self.relays)} relays to {self.cache_path}")
            else:
                logger.error(f"Failed to fetch TOR data: {response.status_code}")
                if self.cache_path.exists():
                    logger.warning("Using stale cache due to fetch failure.")
                    with open(self.cache_path, 'r') as f:
                        data = json.load(f)
                        self._index_relays(data)
        except Exception as e:
            logger.error(f"Exception fetching TOR data: {e}")
            if self.cache_path.exists():
                logger.warning("Using stale cache due to fetch exception.")
                try:
                    with open(self.cache_path, 'r') as f:
                        content = f.read().strip()
                        if content:
                            data = json.loads(content)
                            self._index_relays(data)
                        else:
                            logger.warning("Cache file is empty.")
                except Exception as cache_error:
                    logger.error(f"Failed to load stale cache: {cache_error}")

    def _index_relays(self, relays_list: Union[List, Dict]):
        """Index relay data by fingerprint and IP."""
        if isinstance(relays_list, dict):
             relays_list = list(relays_list.values())
        
        self.relays = {}
        self.relays_by_ip = {}
        
        count = 0 
        for relay in relays_list:
            fingerprint = relay.get('fingerprint')
            if not fingerprint: continue
            
            info = {
                'nickname': relay.get('nickname', 'Unnamed'),
                'fingerprint': fingerprint,
                'or_addresses': relay.get('or_addresses', []),
                'flags': relay.get('flags', []),
                'bandwidth': relay.get('observed_bandwidth', 0),
                'platform': relay.get('platform', 'Unknown'),
                'first_seen': relay.get('first_seen'),
                'last_seen': relay.get('last_seen'),
                'contact': relay.get('contact', 'None'),
                'role': self._determine_role(relay.get('flags', []))
            }
            
            self.relays[fingerprint] = info
            
            for addr in info['or_addresses']:
                ip = addr.split(':')[0]
                if ip not in self.relays_by_ip:
                    self.relays_by_ip[ip] = []
                self.relays_by_ip[ip].append(info)
            count += 1
            
        logger.info(f"Indexed {count} TOR relays.")

    def _determine_role(self, flags: List[str]) -> str:
        """Determine primary role from flags."""
        roles = []
        if 'Guard' in flags: roles.append('Guard')
        if 'Exit' in flags: roles.append('Exit')
        if 'Authority' in flags: roles.append('Authority')
        
        if not roles:
            return 'Middle'
        return '/'.join(roles)

    def get_relay_by_fingerprint(self, fingerprint: str) -> Optional[Dict]:
        """Lookup relay by fingerprint."""
        return self.relays.get(fingerprint)

    def get_relay_by_ip(self, ip_address: str) -> Optional[List[Dict]]:
        """Lookup relay by IP address (can return multiple)."""
        return self.relays_by_ip.get(ip_address)

    def search_relay(self, query: str) -> Optional[Dict]:
        """
        Smart search: try fingerprint, then IP.
        Returns best match or None.
        """
        if len(query) == 40 and query.isalnum(): # Likely fingerprint
             return self.get_relay_by_fingerprint(query)
        
        matches = self.get_relay_by_ip(query)
        if matches:
            return sorted(matches, key=lambda x: x['bandwidth'], reverse=True)[0]
            
        return None

if __name__ == "__main__":
    print("Initializing TOR Directory...")
    td = TorDirectory(cache_path="data/tor_cache_test.json")
    
    if not td.relays:
        print("Injecting mock data for test...")
        mock_relay = {
            'fingerprint': 'A'*40,
            'nickname': 'MockGuard',
            'or_addresses': ['1.2.3.4:9001'],
            'flags': ['Guard', 'Running', 'Stable'],
            'observed_bandwidth': 1000000
        }
        td._index_relays([mock_relay])
    
    print("Testing lookup...")
    relay = td.get_relay_by_ip('1.2.3.4')
    if relay:
        print(f"Found relay: {relay[0]['nickname']} ({relay[0]['role']})")
    else:
        if td.relays:
            fp = next(iter(td.relays))
            r = td.get_relay_by_fingerprint(fp)
            print(f"Found relay by fingerprint: {r['nickname']}")
