"""
Configuration settings for Traffic Analysis Dashboard
TOR Network Collection & PCAP Ingestion
"""

import os
from pathlib import Path


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
TOR_DATA_DIR = DATA_DIR / "tor_snapshots"
PCAP_DATA_DIR = DATA_DIR / "pcap_flows"

DATA_DIR.mkdir(exist_ok=True)
TOR_DATA_DIR.mkdir(exist_ok=True)
PCAP_DATA_DIR.mkdir(exist_ok=True)



ONIONOO_BASE_URL = "https://onionoo.torproject.org"
ONIONOO_ENDPOINTS = {
    "details": f"{ONIONOO_BASE_URL}/details",
    "bandwidth": f"{ONIONOO_BASE_URL}/bandwidth",
    "weights": f"{ONIONOO_BASE_URL}/weights",
    "clients": f"{ONIONOO_BASE_URL}/clients",
    "uptime": f"{ONIONOO_BASE_URL}/uptime",
}

TOR_METRICS_URL = "https://metrics.torproject.org"

TOR_COLLECTION_INTERVAL_HOURS = 1  # Hourly snapshots
TOR_MAX_RETRIES = 3
TOR_TIMEOUT_SECONDS = 30
TOR_RATE_LIMIT_DELAY = 2  # Seconds between API calls

TOR_RELAY_TYPES = ["guard", "middle", "exit"]
TOR_MIN_BANDWIDTH = 0  # Minimum bandwidth in bytes/s (0 = no filter)
TOR_RUNNING_ONLY = True  # Only collect running relays

TOR_SNAPSHOT_RETENTION_DAYS = 30  # Keep snapshots for 30 days
TOR_EXPORT_FORMATS = ["json", "pickle"]  # Export formats

TOR_GRAPH_BUILD_ENABLED = True
TOR_GRAPH_INCLUDE_RELATIONSHIPS = True  # Track relay connections



TOR_CONSENSUS_URL = "https://collector.torproject.org/recent/relay-descriptors/consensuses/"
TOR_CONSENSUS_CACHE_DIR = DATA_DIR / "tor_consensus_cache"
TOR_CONSENSUS_CACHE_DIR.mkdir(exist_ok=True)
TOR_CONSENSUS_CACHE_TTL_HOURS = 6  # Cache consensus for 6 hours
TOR_PATH_SAMPLE_COUNT = 3000  # Default simulation sample count for exit estimation


PCAP_SUPPORTED_FORMATS = [
    "standard",  # Standard PCAP files
    "isp",       # ISP NetFlow logs
    "mail",      # Mail server logs (SMTP/IMAP)
    "proxy",     # Proxy logs (HTTP/HTTPS CONNECT)
]

PCAP_FLOW_TIMEOUT = 60  # Flow timeout in seconds
PCAP_MIN_PACKETS = 5    # Minimum packets per flow
PCAP_MAX_PACKET_SIZE = 65535  # Maximum packet size to process

PCAP_PROTOCOLS = ["tcp", "udp"]  # Protocols to extract
PCAP_PORTS_OF_INTEREST = [
    80, 443,      # HTTP/HTTPS
    25, 587, 465, # SMTP
    143, 993,     # IMAP
    110, 995,     # POP3
    8080, 8443,   # Proxy ports
    9001, 9030,   # TOR ORPort and DirPort
]

ISP_LOG_FORMAT = "netflow"  # or "pcap", "csv"
ISP_ANONYMIZE_IPS = True    # Anonymize IP addresses

MAIL_EXTRACT_METADATA = True  # Extract email metadata
MAIL_PROTOCOLS = ["smtp", "imap", "pop3"]

PROXY_EXTRACT_CONNECT = True  # Extract CONNECT requests
PROXY_SSL_DECRYPT = False     # SSL decryption (requires keys)

PCAP_OUTPUT_FORMAT = "rector"  # Convert to RECTor inflow/outflow format
PCAP_CREATE_WINDOWS = True     # Auto-create overlapping windows
PCAP_WINDOW_PARAMS = {
    "threshold": 2,    # INVESTIGATIVE MODE: lowered from 10 for real Tor guard traffic
    "interval": 5,
    "num_windows": 10,
    "add_num": 2,
}

ANALYSIS_MODE = "investigative"



DASHBOARD_SHOW_TOR_TAB = True
DASHBOARD_SHOW_PCAP_TAB = True
DASHBOARD_MAX_UPLOAD_SIZE_MB = 500  # Max PCAP file size

VIZ_TOR_MAP_ENABLED = True
VIZ_MAX_RELAYS_DISPLAY = 1000  # Limit for performance
VIZ_REFRESH_INTERVAL_SECONDS = 300  # Auto-refresh interval



SCHEDULER_ENABLED = True
SCHEDULER_TOR_CRON = "0 * * * *"  # Hourly at minute 0
SCHEDULER_LOG_FILE = DATA_DIR / "scheduler.log"



LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = DATA_DIR / "traffic_analysis.log"



def get_latest_tor_snapshot():
    """Get path to most recent TOR snapshot."""
    snapshots = sorted(TOR_DATA_DIR.glob("tor_snapshot_*.json"))
    return snapshots[-1] if snapshots else None


def get_tor_snapshot_path(timestamp=None):
    """Generate path for TOR snapshot with optional timestamp."""
    from datetime import datetime
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return TOR_DATA_DIR / f"tor_snapshot_{timestamp}.json"


def get_pcap_output_dir(pcap_filename):
    """Generate output directory for processed PCAP."""
    base_name = Path(pcap_filename).stem
    return PCAP_DATA_DIR / base_name



def validate_config():
    """Validate configuration settings."""
    errors = []
    
    for dir_path in [DATA_DIR, TOR_DATA_DIR, PCAP_DATA_DIR]:
        if not os.access(dir_path, os.W_OK):
            errors.append(f"Directory not writable: {dir_path}")
    
    
    if errors:
        raise ValueError(f"Configuration errors: {'; '.join(errors)}")
    
    return True


if __name__ == "__main__":
    print("=" * 60)
    print("Traffic Analysis Dashboard - Configuration")
    print("=" * 60)
    print(f"\n📁 Base Directory: {BASE_DIR}")
    print(f"📁 Data Directory: {DATA_DIR}")
    print(f"📁 TOR Snapshots: {TOR_DATA_DIR}")
    print(f"📁 PCAP Flows: {PCAP_DATA_DIR}")
    print(f"\n🌐 Onionoo API: {ONIONOO_BASE_URL}")
    print(f"⏰ Collection Interval: {TOR_COLLECTION_INTERVAL_HOURS} hour(s)")
    print(f"📊 Supported PCAP Formats: {', '.join(PCAP_SUPPORTED_FORMATS)}")
    
    try:
        validate_config()
        print("\n✅ Configuration validated successfully!")
    except ValueError as e:
        print(f"\n❌ Configuration error: {e}")
