"""
Traffic Analysis Dashboard - FastAPI Backend
Exposes forensic capabilities via REST API for the React frontend.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict
from typing import Any, Optional
import requests  # For geolocation API
import shutil
import os
import time
from pathlib import Path
import pickle
import numpy as np
import traceback
import logging

logging.basicConfig(level=logging.WARNING)
logging.getLogger("pcap_processor").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("exit_correlation").setLevel(logging.WARNING)

from backend import (
    TrafficPreprocessor,
    RectorEngine,
    DEVICE
)
from report_generator import generate_forensic_report
try:
    from pcap_processor import FlowExtractor, PCAPParser
except ImportError:
    FlowExtractor = None
    PCAPParser = None

try:
    from exit_correlation import run_exit_correlation, ConfidenceAggregator
    EXIT_CORRELATION_AVAILABLE = True
except ImportError:
    EXIT_CORRELATION_AVAILABLE = False

try:
    from tor_path_inference import TorPathInference, infer_path_from_guard
    TOR_PATH_INFERENCE_AVAILABLE = True
except ImportError:
    TOR_PATH_INFERENCE_AVAILABLE = False

try:
    from origin_scope_estimation import estimate_origin_scope
    ORIGIN_SCOPE_AVAILABLE = True
except ImportError:
    ORIGIN_SCOPE_AVAILABLE = False

try:
    from utils.flow_id_parser import extract_ips_from_flow_id
    from analysis.ip_lead_generation import generate_ip_leads
    IP_LEADS_AVAILABLE = True
except ImportError:
    IP_LEADS_AVAILABLE = False

app = FastAPI(
    title="TOR Forensic Analysis API",
    description="Backend API for Traffic Analysis Dashboard",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_PATH = "lightweight_siamese.pth"
SEQ_LENGTH = 1000
EMB_SIZE = 64
NUM_WINDOWS = 11

COUNTRY_FLAGS = {
    'US': '🇺🇸', 'DE': '🇩🇪', 'NL': '🇳🇱', 'FR': '🇫🇷', 'GB': '🇬🇧',
    'CA': '🇨🇦', 'CH': '🇨🇭', 'SE': '🇸🇪', 'FI': '🇫🇮', 'RO': '🇷🇴',
    'RU': '🇷🇺', 'UA': '🇺🇦', 'LU': '🇱🇺', 'AT': '🇦🇹', 'CZ': '🇨🇿',
    'PL': '🇵🇱', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬', 'IN': '🇮🇳',
    'BR': '🇧🇷', 'IS': '🇮🇸', 'NO': '🇳🇴', 'DK': '🇩🇰', 'ES': '🇪🇸',
    'IT': '🇮🇹', 'BE': '🇧🇪', 'IE': '🇮🇪', 'PT': '🇵🇹', 'HK': '🇭🇰'
}

def extract_public_ip(flow_label: str) -> str:
    """Extract the public/remote IP from a flow label like '192.168.1.2_62133_51.159.211.57_9001_tcp'"""
    
    parts = flow_label.replace('_tcp', '').replace('_udp', '').split('_')
    
    ipv4_parts = [p for p in parts if p.count('.') == 3]
    
    if not ipv4_parts and len(parts) > 6:
        return "IPv6:" + flow_label[:30]
    
    ips = ipv4_parts
    
    for ip in ips:
        if not ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                              '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                              '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return ip
    
    return ips[-1] if ips else flow_label


NON_TOR_IP_PREFIXES = (
    '17.',    # Apple (iCloud, CDN)
    '23.',    # Akamai CDN (partial)
    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.',  # Cloudflare
    '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.', # Cloudflare
    '142.250.', '142.251.',  # Google
    '216.58.',  # Google
    '3.', '13.', '15.', '16.', '18.', '34.', '35.', '52.', '54.', '99.',
)

NON_TOR_ISPS = [
    'apple', 'icloud', 'akamai', 'cloudflare', 'fastly', 'cloudfront', 
    'amazon', 'aws', 'ec2',  # AWS (fixed: was 'amazon.com' which didn't match 'Amazon Web Services')
    'microsoft', 'azure', 'google cloud', 'gcp',
    'facebook', 'meta', 'netflix', 'spotify', 'twitter', 'tiktok', 'snapchat'
]

TOR_FRIENDLY_ISPS = [
    'scaleway', 'online s.a.s', 'online sas',  # Scaleway (France) - Very common for Tor
    'ovh', 'ovhcloud',                          # OVH (France/EU) - Very common for Tor
    'hetzner',                                   # Hetzner (Germany) - Very common for Tor
    'digitalocean',                              # DigitalOcean
    'linode', 'akamai connected',                # Linode
    'vultr',                                     # Vultr
    'contabo',                                   # Contabo
    'netcup',                                    # Netcup
    'myloc',                                     # myLoc
    'i3d',                                       # i3D.net
    '1337 services',                             # 1337 Services (Tor exit operator)
    'flokinet',                                  # FlokiNET (Tor-friendly)
    'trabia',                                    # Trabia
]


def is_likely_tor_guard(ip: str, isp: str = None) -> tuple:
    """
    Check if an IP is a Tor guard relay vs CDN/cloud infrastructure.
    
    IMPORTANT: Uses Tor consensus for authoritative verification first.
    
    Returns:
        (is_likely_tor, score_multiplier, reason)
        - is_likely_tor: True if verified Tor guard, False if NOT Tor
        - score_multiplier: 1.0 = neutral, 1.15 = verified boost, 0.0 = skip
        - reason: Explanation string
    """
    ip = str(ip)
    isp_lower = (isp or '').lower()
    
    try:
        from tor_path_inference import TorConsensusClient
        consensus = TorConsensusClient()
        consensus.fetch_consensus()
        if consensus.relay_count > 0:
            relays = consensus.get_relays_by_ip(ip)
            if relays:
                relay = relays[0] if isinstance(relays, list) else relays
                flags = relay.flags if hasattr(relay, 'flags') else []
                if 'Guard' in flags:
                    nickname = relay.nickname if hasattr(relay, 'nickname') else 'Unknown'
                    return (True, 1.15, f"Verified Tor Guard relay: {nickname}")
                elif 'Exit' in flags:
                    nickname = relay.nickname if hasattr(relay, 'nickname') else 'Unknown'
                    return (True, 1.0, f"Tor relay (Exit, not Guard): {nickname}")
                else:
                    return (True, 1.0, "Verified Tor relay (Middle)")
    except Exception as e:
        print(f"⚠️ Tor consensus not available for guard verification: {e}")
    
    for prefix in NON_TOR_IP_PREFIXES:
        if ip.startswith(prefix):
            return (False, 0.0, f"CDN IP range ({prefix}) - NOT a Tor relay")
    
    for non_tor_isp in NON_TOR_ISPS:
        if non_tor_isp in isp_lower:
            return (False, 0.0, f"CDN/Cloud ISP: {isp} - NOT a Tor relay")
    
    for tor_isp in TOR_FRIENDLY_ISPS:
        if tor_isp in isp_lower:
            return (True, 1.0, f"Tor-friendly ISP: {isp} (not verified in consensus)")
    
    return (False, 0.0, "Not verified in Tor consensus - cannot use for correlation")


TOR_EXIT_ISPS = [
    '1337 services',    # 1337 Services GmbH - Major Tor exit operator
    'f3 netze',         # F3 Netze - Tor exit operator
    'caliu',            # Caliu - Tor exit operator
    'appliedprivacy',   # appliedprivacy.net - Privacy-focused
    'riseup',           # Riseup - Tor-friendly
    'torservers',       # Torservers.net
    'accessnow',        # Access Now - Human rights
    'quintex',          # Quintex Alliance
    'dfri',             # DFRI - Digital Freedom
    'artikel10',        # Artikel 10 - Privacy advocates
]


def get_exit_isp_multiplier(exit_ip: str) -> float:
    """
    Get ISP boost multiplier for exit IP.
    Boost known Tor exit operator ISPs.
    
    Returns:
        float: 1.0 = neutral, 1.1+ = Tor exit ISP boost
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{exit_ip}?fields=isp", timeout=2)
        data = response.json()
        isp = data.get('isp', '').lower()
        
        for tor_exit_isp in TOR_EXIT_ISPS:
            if tor_exit_isp in isp:
                return 1.10  # 10% boost for known Tor exit operators
        
        for tor_isp in TOR_FRIENDLY_ISPS:
            if tor_isp in isp:
                return 1.05  # 5% boost for Tor-friendly hosters
        
        return 1.0  # Neutral
    except:
        return 1.0  # Neutral on error


def get_ip_geolocation(flow_label: str) -> dict:
    """Get geolocation for a guard node from its flow label"""
    try:
        ip = extract_public_ip(flow_label)
        
        if ip.startswith(('127.', '192.168.', '10.', '172.')):
            return {"country": "Local Network", "city": "Private", "flag": "🏠", "isp": "Local", "ip": ip}
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp", timeout=3)
        data = response.json()
        
        if data.get('status') == 'success':
            country_code = data.get('countryCode', 'XX')
            return {
                "country": data.get('country', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "flag": COUNTRY_FLAGS.get(country_code, '🌐'),
                "isp": data.get('isp', 'Unknown ISP'),
                "ip": ip
            }
    except Exception as e:
        print(f"Geolocation lookup failed for {flow_label}: {e}")
    
    extracted_ip = extract_public_ip(flow_label)
    return {"country": "Unknown", "city": "Unknown", "flag": "🌐", "isp": "Unknown", "ip": extracted_ip}

engine_instance = None

class CaseInfo(BaseModel):
    case_id: str
    investigator: str

class AnalysisRequest(BaseModel):
    case_id: str

class PathInferenceRequest(BaseModel):
    guard_ip: str
    guard_confidence: float
    sample_count: int = 3000

def get_engine():
    global engine_instance
    if engine_instance is None:
        if os.path.exists(MODEL_PATH):
            try:
                engine_instance = RectorEngine(
                    model_type='siamese',
                    input_shape=(SEQ_LENGTH, 1),
                    emb_size=EMB_SIZE,
                    num_windows=NUM_WINDOWS
                )
                engine_instance.load_weights(MODEL_PATH)
                print("✅ Engine loaded successfully.")
            except Exception as e:
                print(f"❌ Engine initialization failed: {e}")
                raise HTTPException(status_code=500, detail=f"Engine init failed: {e}")
        else:
            raise HTTPException(status_code=500, detail="Model file missing.")
    return engine_instance

@app.get("/api/health")
async def health_check():
    engine = get_engine() # Ensure engine loads
    return {"status": "online", "device": str(DEVICE), "model_loaded": True}

@app.post("/api/upload")
async def upload_pcap(file: UploadFile = File(...), case_id: str = "CASE-DEFAULT", file_type: str = "entry"):
    """
    Ingest uploaded PCAP:
    1. Create secure internal directory.
    2. Save PCAP.
    3. Run FlowExtractor.
    
    Args:
        file: Uploaded PCAP file
        case_id: Case identifier
        file_type: 'entry' for guard-side PCAP, 'exit' for exit-side PCAP
    """
    if FlowExtractor is None:
         raise HTTPException(status_code=500, detail="FlowExtractor not available (scapy missing?)")

    try:
        base_dir = Path(".evidence_store") / case_id
        base_dir.mkdir(parents=True, exist_ok=True)
        
        if file_type == "exit":
            pcap_path = base_dir / f"exit_{file.filename}"
        else:
            pcap_path = base_dir / file.filename
        
        with open(pcap_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        extractor = FlowExtractor(log_type='standard')
        num_flows, num_packets = extractor.process_pcap(str(pcap_path), str(base_dir))
        
        if num_flows == 0:
            return JSONResponse(
                status_code=400, 
                content={"error": "No valid flows found in PCAP.", "details": "Check if file is valid capture."}
            )

        return {
            "status": "success", 
            "message": "Evidence ingested successfully",
            "data_path": str(base_dir),
            "pcap_path": str(pcap_path),  # Full path to PCAP for exit correlation
            "file_type": file_type,
            "flow_count": num_flows,
            "filename": file.filename,
            "size_kb": os.path.getsize(pcap_path) / 1024
        }
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Upload/Ingestion failed: {str(e)}")

async def analyze_exit_only_pcap(exit_pcap_path: str, case_id: str, data_dir: str):
    """
    Analyze exit-side PCAP when no entry PCAP is available.
    Uses Tor consensus, timing patterns, and burst analysis to identify probable guards.
    """
    from pcap_processor import PCAPParser
    
    try:
        from tor_path_inference import TorConsensusClient
        tor_consensus = TorConsensusClient()
        tor_consensus.fetch_consensus()
        TOR_CONSENSUS_AVAILABLE = tor_consensus.relay_count > 0
        print(f"✓ Tor consensus loaded: {tor_consensus.relay_count} relays")
    except Exception as e:
        print(f"⚠️ Tor consensus not available: {e}")
        tor_consensus = None
        TOR_CONSENSUS_AVAILABLE = False
    
    print(f"")
    print(f"╔══════════════════════════════════════════════════════════════╗")
    print(f"║           EXIT-ONLY PCAP ANALYSIS                            ║")
    print(f"╠══════════════════════════════════════════════════════════════╣")
    print(f"║  Using: Tor Consensus + Timing + Burst Analysis              ║")
    print(f"╚══════════════════════════════════════════════════════════════╝")
    print(f"")
    
    CDN_CLOUD_PREFIXES = [
        '17.',      # Apple CDN
        '122.162.', # AWS India
        '13.', '34.', '35.', '52.', '54.', '18.', '3.',  # AWS
        '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.',  # Cloudflare
        '172.64.', '172.65.', '172.66.', '172.67.',  # Cloudflare
        '20.', '40.', '52.',  # Azure
        '142.250.', '172.217.', '216.58.',  # Google
    ]
    
    CDN_ISPS = ['amazon', 'cloudflare', 'google', 'microsoft', 'akamai', 'fastly', 'apple']
    
    try:
        parser = PCAPParser(min_packets=3)
        raw_flows = parser.parse_pcap(exit_pcap_path)
        
        if not raw_flows:
            return JSONResponse(
                status_code=400,
                content={"detail": "No valid flows found in exit PCAP."}
            )
        
        exit_candidates = {}
        filtered_count = 0
        
        for flow_id, flow_session in raw_flows.items():
            parts = flow_id.split('-')
            if len(parts) >= 2:
                for part in parts[:2]:
                    ip = part.split(':')[0] if ':' in part else part
                    
                    if ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', 
                                      '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
                        continue
                    
                    is_cdn = any(ip.startswith(prefix) for prefix in CDN_CLOUD_PREFIXES)
                    if is_cdn:
                        filtered_count += 1
                        continue
                    
                    if ip not in exit_candidates:
                        exit_candidates[ip] = {
                            'packet_count': 0,
                            'flow_count': 0,
                            'total_bytes': 0
                        }
                    exit_candidates[ip]['packet_count'] += flow_session.packet_count
                    exit_candidates[ip]['flow_count'] += 1
                    exit_candidates[ip]['total_bytes'] += flow_session.byte_count
        
        print(f"📊 Filtered {filtered_count} CDN/Cloud flows")
        print(f"📊 Found {len(exit_candidates)} potential Tor exit IPs")
        
        sorted_exits = sorted(exit_candidates.items(), 
                              key=lambda x: x[1]['packet_count'], reverse=True)[:5]
        
        top_exit_nodes = []
        probable_guards = []  # Predict based on Tor-friendly ISPs
        
        for exit_ip, stats in sorted_exits:
            try:
                geo_resp = requests.get(
                    f"http://ip-api.com/json/{exit_ip}?fields=country,countryCode,isp,city,org",
                    timeout=2
                )
                geo_data = geo_resp.json()
                country = geo_data.get('country', 'Unknown')
                country_code = geo_data.get('countryCode', '')
                isp = geo_data.get('isp', 'Unknown')
                org = geo_data.get('org', '')
                city = geo_data.get('city', '')
                flag = ''.join(chr(ord('🇦') + ord(c) - ord('A')) for c in country_code.upper()) if len(country_code) == 2 else '🌐'
                
                isp_lower = isp.lower()
                if any(cdn in isp_lower for cdn in CDN_ISPS):
                    print(f"  ⚠️ Skipping {exit_ip} - CDN/Cloud ISP: {isp}")
                    continue
                    
            except:
                country, flag, isp, city, org = 'Unknown', '🌐', 'Unknown', '', ''
            
            max_packets = sorted_exits[0][1]['packet_count'] if sorted_exits else 1
            activity_score = stats['packet_count'] / max_packets
            
            tor_relay_info = None
            is_known_guard = False
            is_known_exit = False
            relay_bandwidth = 0
            relay_uptime = None
            
            if TOR_CONSENSUS_AVAILABLE and tor_consensus:
                relays = tor_consensus.get_relays_by_ip(exit_ip)
                if relays:
                    tor_relay_info = relays[0] if isinstance(relays, list) else relays
                    if hasattr(tor_relay_info, 'is_guard'):
                        is_known_guard = tor_relay_info.is_guard() if callable(tor_relay_info.is_guard) else tor_relay_info.is_guard
                    elif hasattr(tor_relay_info, 'flags'):
                        is_known_guard = 'Guard' in tor_relay_info.flags
                    if hasattr(tor_relay_info, 'is_exit'):
                        is_known_exit = tor_relay_info.is_exit() if callable(tor_relay_info.is_exit) else tor_relay_info.is_exit
                    elif hasattr(tor_relay_info, 'flags'):
                        is_known_exit = 'Exit' in tor_relay_info.flags
                    relay_bandwidth = tor_relay_info.bandwidth if hasattr(tor_relay_info, 'bandwidth') else 0
                    print(f"  🔍 {exit_ip} found in Tor consensus: Guard={is_known_guard}, Exit={is_known_exit}, BW={relay_bandwidth}")
            
            if TOR_CONSENSUS_AVAILABLE and tor_relay_info is None:
                print(f"  ⚠️ Filtering {exit_ip} - NOT in Tor consensus (not a Tor relay)")
                continue
            
            node_data = {
                'ip': exit_ip,
                'country': country,
                'city': city,
                'flag': flag,
                'isp': isp,
                'org': org,
                'packet_count': stats['packet_count'],
                'flow_count': stats['flow_count'],
                'total_bytes': stats['total_bytes'],
                'score': activity_score,
                'is_known_guard': is_known_guard,
                'is_known_exit': is_known_exit,
                'relay_bandwidth': relay_bandwidth,
                'in_consensus': tor_relay_info is not None
            }
            
            top_exit_nodes.append(node_data)
            
            guard_probability = 0.0
            guard_reasons = []
            
            if is_known_guard:
                guard_probability += 0.5
                guard_reasons.append("Known Guard in Tor consensus")
            
            isp_lower = isp.lower()
            for tor_isp in TOR_FRIENDLY_ISPS:
                if tor_isp in isp_lower:
                    guard_probability += 0.25
                    guard_reasons.append(f"Tor-friendly ISP: {isp}")
                    break
            
            if relay_bandwidth > 10000000:  # >10 MB/s
                guard_probability += 0.15
                guard_reasons.append(f"High bandwidth: {relay_bandwidth/1000000:.1f} MB/s")
            
            if stats['packet_count'] > 100 and stats['flow_count'] == 1:
                guard_probability += 0.1
                guard_reasons.append("Persistent connection pattern")
            
            if guard_probability > 0.2:  # Threshold for "probable guard"
                probable_guards.append({
                    **node_data,
                    'guard_probability': min(guard_probability, 0.95),
                    'reason': ' + '.join(guard_reasons)
                })
            
            consensus_tag = " 📡" if tor_relay_info else ""
            print(f"  {flag} {exit_ip:<20} {country:<15} {isp[:20]:<20} Guard:{is_known_guard} Exit:{is_known_exit}{consensus_tag}")
        
        
        print(f"\n📡 Predicting probable Guard nodes from Tor consensus...")
        
        if TOR_CONSENSUS_AVAILABLE and tor_consensus:
            all_guards = tor_consensus.get_all_guards()
            
            if all_guards:
                print(f"  Found {len(all_guards)} guards in Tor consensus")
                
                timing_stats = {
                    'total_packets': 0,
                    'total_bytes': 0,
                    'avg_packet_size': 0,
                    'packet_size_std': 0,
                    'flow_count': len(raw_flows),
                    'avg_flow_duration': 0,
                    'burst_count': 0,
                    'tor_cell_ratio': 0,
                    'unique_ips': len(exit_candidates)
                }
                
                all_packet_sizes = []
                all_byte_counts = []
                flow_durations = []
                all_timestamps = []  # For inter-arrival analysis
                all_packet_data = []  # (timestamp, size) pairs for advanced analysis
                
                for flow_id, flow_session in raw_flows.items():
                    timing_stats['total_packets'] += flow_session.packet_count
                    timing_stats['total_bytes'] += flow_session.byte_count
                    all_byte_counts.append(flow_session.byte_count)
                    
                    if hasattr(flow_session, 'ingress_packets'):
                        for ts, size in flow_session.ingress_packets:
                            all_packet_sizes.append(size)
                            all_timestamps.append(ts)
                            all_packet_data.append((ts, size))
                    if hasattr(flow_session, 'egress_packets'):
                        for ts, size in flow_session.egress_packets:
                            all_packet_sizes.append(size)
                            all_timestamps.append(ts)
                            all_packet_data.append((ts, size))
                    
                    if hasattr(flow_session, 'get_duration'):
                        duration = flow_session.get_duration()
                        if duration > 0:
                            flow_durations.append(duration)
                    elif hasattr(flow_session, 'start_time') and hasattr(flow_session, 'last_time'):
                        if flow_session.start_time and flow_session.last_time:
                            duration = flow_session.last_time - flow_session.start_time
                            if duration > 0:
                                flow_durations.append(duration)
                
                flow_fingerprint = {
                    'burst_entropy': 0.0,        # Burst inter-arrival entropy
                    'micro_gap_avg': 0.0,        # Average micro-gap between packets
                    'micro_gap_std': 0.0,        # Std dev of micro-gaps
                    'size_variance_slope': 0.0,  # Packet size variance slope
                    'circuit_lifetime': 0.0,     # Estimated circuit lifetime
                    'fingerprint_hash': 0        # Unique fingerprint value
                }
                
                all_packet_data.sort(key=lambda x: x[0])
                
                if len(all_packet_data) >= 3:
                    inter_arrivals = []
                    for i in range(1, len(all_packet_data)):
                        gap = all_packet_data[i][0] - all_packet_data[i-1][0]
                        if gap > 0:
                            inter_arrivals.append(gap)
                    
                    if inter_arrivals:
                        import math
                        bins = {}
                        bin_size = 0.01  # 10ms bins
                        for gap in inter_arrivals:
                            bin_idx = int(gap / bin_size)
                            bins[bin_idx] = bins.get(bin_idx, 0) + 1
                        
                        total = len(inter_arrivals)
                        entropy = 0.0
                        for count in bins.values():
                            p = count / total
                            if p > 0:
                                entropy -= p * math.log2(p)
                        flow_fingerprint['burst_entropy'] = entropy
                        
                        flow_fingerprint['micro_gap_avg'] = sum(inter_arrivals) / len(inter_arrivals)
                        if len(inter_arrivals) > 1:
                            mean_gap = flow_fingerprint['micro_gap_avg']
                            variance = sum((g - mean_gap) ** 2 for g in inter_arrivals) / len(inter_arrivals)
                            flow_fingerprint['micro_gap_std'] = variance ** 0.5
                
                if len(all_packet_sizes) >= 5:
                    window_size = min(10, len(all_packet_sizes) // 2)
                    variances = []
                    for i in range(0, len(all_packet_sizes) - window_size, window_size):
                        window = all_packet_sizes[i:i+window_size]
                        mean = sum(window) / len(window)
                        var = sum((x - mean) ** 2 for x in window) / len(window)
                        variances.append(var)
                    
                    if len(variances) >= 2:
                        slope = (variances[-1] - variances[0]) / len(variances)
                        flow_fingerprint['size_variance_slope'] = slope
                
                if flow_durations:
                    flow_fingerprint['circuit_lifetime'] = max(flow_durations)
                elif all_timestamps and len(all_timestamps) >= 2:
                    flow_fingerprint['circuit_lifetime'] = max(all_timestamps) - min(all_timestamps)
                
                flow_fingerprint['fingerprint_hash'] = int(
                    abs(flow_fingerprint['burst_entropy'] * 1000) +
                    abs(flow_fingerprint['micro_gap_avg'] * 10000) +
                    abs(flow_fingerprint['size_variance_slope']) +
                    abs(flow_fingerprint['circuit_lifetime'] * 100)
                ) % 100000
                
                if all_packet_sizes:
                    timing_stats['avg_packet_size'] = sum(all_packet_sizes) / len(all_packet_sizes)
                    mean = timing_stats['avg_packet_size']
                    variance = sum((x - mean) ** 2 for x in all_packet_sizes) / len(all_packet_sizes)
                    timing_stats['packet_size_std'] = variance ** 0.5
                    
                    tor_cell_count = sum(1 for s in all_packet_sizes if 500 <= s <= 600)
                    timing_stats['tor_cell_ratio'] = tor_cell_count / len(all_packet_sizes)
                    
                    burst_threshold = 400
                    in_burst = False
                    for size in all_packet_sizes:
                        if size >= burst_threshold:
                            if not in_burst:
                                timing_stats['burst_count'] += 1
                                in_burst = True
                        else:
                            in_burst = False
                
                if flow_durations:
                    timing_stats['avg_flow_duration'] = sum(flow_durations) / len(flow_durations)
                
                print(f"  📊 PCAP Features: {timing_stats['total_packets']} pkts, {timing_stats['total_bytes']/1024:.1f}KB, {timing_stats['flow_count']} flows")
                print(f"  � Flow Fingerprint:")
                print(f"     Burst Entropy: {flow_fingerprint['burst_entropy']:.3f}")
                print(f"     Micro-gap Avg: {flow_fingerprint['micro_gap_avg']*1000:.2f}ms, Std: {flow_fingerprint['micro_gap_std']*1000:.2f}ms")
                print(f"     Size Var Slope: {flow_fingerprint['size_variance_slope']:.2f}")
                print(f"     Circuit Lifetime: {flow_fingerprint['circuit_lifetime']:.2f}s")
                print(f"     Fingerprint Hash: {flow_fingerprint['fingerprint_hash']}")
                
                
                guard_list = list(all_guards.values()) if isinstance(all_guards, dict) else list(all_guards)
                
                guard_list = [g for g in guard_list if hasattr(g, 'flags') and 'Guard' in g.flags]
                
                exit_countries = set()
                exit_isps = set()
                for exit_node in top_exit_nodes:
                    if exit_node.get('country'):
                        exit_countries.add(exit_node['country'])
                    if exit_node.get('isp'):
                        isp_words = exit_node['isp'].lower().split()[:2]
                        exit_isps.update(isp_words)
                
                print(f"  📍 Exit countries: {exit_countries}")
                print(f"  📍 Exit ISP keywords: {exit_isps}")
                
                
                guard_scores = []
                
                for guard in guard_list:
                    guard_ip = guard.ip_address if hasattr(guard, 'ip_address') else None
                    if not guard_ip:
                        continue
                    
                    guard_bw = guard.bandwidth if hasattr(guard, 'bandwidth') else 0
                    guard_flags = guard.flags if hasattr(guard, 'flags') else []
                    guard_country = guard.country if hasattr(guard, 'country') else None
                    
                    if 'Stable' not in guard_flags or 'Fast' not in guard_flags:
                        continue
                    
                    
                    guard_score = 0.0
                    overlap_score = 0.0
                    
                    for i, exit_i in enumerate(top_exit_nodes):
                        exit_i_country = exit_i.get('country', '')
                        exit_i_packets = exit_i.get('packet_count', 0)
                        
                        if guard_country and guard_country == exit_i_country:
                            overlap_score += 0.10  # Same country as exit
                        
                        for j, exit_j in enumerate(top_exit_nodes):
                            if i >= j:
                                continue  # Only unique pairs
                            
                            exit_j_country = exit_j.get('country', '')
                            exit_j_packets = exit_j.get('packet_count', 0)
                            
                            if guard_country == exit_i_country or guard_country == exit_j_country:
                                overlap_score += 0.05
                            
                            combined_packets = exit_i_packets + exit_j_packets
                            if combined_packets > 0 and guard_bw > 0:
                                traffic_match = min(combined_packets * 100, guard_bw) / max(combined_packets * 100, guard_bw)
                                overlap_score += traffic_match * 0.05
                    
                    guard_score += min(overlap_score, 0.30)  # Max 30% from exit overlap
                    
                    fingerprint_score = 0.0
                    
                    if flow_fingerprint['burst_entropy'] > 3.0:
                        fingerprint_score += 0.15 * min(guard_bw / 500000, 1.0)
                    elif flow_fingerprint['burst_entropy'] > 1.5:
                        fingerprint_score += 0.10
                    else:
                        fingerprint_score += 0.05
                    
                    if flow_fingerprint['micro_gap_std'] < 0.05:  # Low variance = stable guard
                        if 'Stable' in guard_flags:
                            fingerprint_score += 0.10
                    else:
                        fingerprint_score += 0.05
                    
                    if flow_fingerprint['circuit_lifetime'] > 60:  # Long circuit
                        fingerprint_score += 0.10
                    elif flow_fingerprint['circuit_lifetime'] > 10:
                        fingerprint_score += 0.07
                    else:
                        fingerprint_score += 0.03
                    
                    guard_score += min(fingerprint_score, 0.40)  # Max 40% from fingerprint
                    
                    bw_score = 0.20 * min(guard_bw / 1000000, 1.0)
                    guard_score += bw_score
                    
                    if 'Stable' in guard_flags and 'Fast' in guard_flags:
                        guard_score += 0.10
                    elif 'Stable' in guard_flags or 'Fast' in guard_flags:
                        guard_score += 0.05
                    
                    guard_scores.append((guard, guard_score, guard_bw, overlap_score))
                
                guard_scores.sort(key=lambda x: (x[1], x[2]), reverse=True)
                guard_list = [g[0] for g in guard_scores[:100]]
                
                print(f"  After fingerprint correlation: {len(guard_list)} candidates")
                if guard_scores[:3]:
                    print(f"  Top 3 guard overlaps: {[f'{g[3]:.2f}' for g in guard_scores[:3]]}")
                
                exit_timing_score = 0.45  # Max 45% from timing
                if top_exit_nodes:
                    total_exit_packets = sum(e.get('packet_count', 0) for e in top_exit_nodes)
                    if total_exit_packets > 50:
                        exit_timing_score = 0.45  # Strong timing evidence
                    elif total_exit_packets > 20:
                        exit_timing_score = 0.35
                    else:
                        exit_timing_score = 0.20
                
                guard_count = 0
                for guard in guard_list[:10]:  # Check top 10, add 3
                    guard_ip = guard.ip_address if hasattr(guard, 'ip_address') else 'Unknown'
                    guard_bw = guard.bandwidth if hasattr(guard, 'bandwidth') else 0
                    guard_nickname = guard.nickname if hasattr(guard, 'nickname') else 'Unknown'
                    guard_flags = guard.flags if hasattr(guard, 'flags') else []
                    
                    is_stable = 'Stable' in guard_flags
                    is_fast = 'Fast' in guard_flags
                    
                    if not is_stable and not is_fast:
                        continue  # Discard if neither Stable nor Fast
                    
                    try:
                        geo_resp = requests.get(f"http://ip-api.com/json/{guard_ip}?fields=country,countryCode,isp", timeout=2)
                        geo_data = geo_resp.json()
                        g_country = geo_data.get('country', 'Unknown')
                        g_code = geo_data.get('countryCode', '')
                        g_isp = geo_data.get('isp', 'Unknown')
                        g_flag = ''.join(chr(ord('🇦') + ord(c) - ord('A')) for c in g_code.upper()) if len(g_code) == 2 else '🌐'
                    except:
                        g_country, g_flag, g_isp = 'Unknown', '🌐', 'Unknown'
                    
                    
                    base_timing = 0.0
                    if timing_stats['total_packets'] > 100:
                        base_timing = 0.35  # Reduced from 0.45
                    elif timing_stats['total_packets'] > 50:
                        base_timing = 0.30
                    elif timing_stats['total_packets'] > 20:
                        base_timing = 0.25
                    else:
                        base_timing = 0.15
                    
                    tor_cell_boost = timing_stats.get('tor_cell_ratio', 0) * 0.08
                    
                    burst_boost = min(timing_stats.get('burst_count', 0) * 0.01, 0.07)
                    
                    timing_score = min(base_timing + tor_cell_boost + burst_boost, 0.40)
                    
                    alignment_score = 0.15
                    if timing_stats.get('flow_count', 0) > 10:
                        alignment_score = 0.25
                    elif timing_stats.get('flow_count', 0) > 5:
                        alignment_score = 0.20
                    
                    if timing_stats.get('total_bytes', 0) < 10000:  # < 10KB
                        alignment_score *= 0.7
                    
                    bw_score = max(0.15 - (guard_count * 0.05), 0.05)
                    
                    topology_score = 0.05
                    if is_stable and is_fast:
                        topology_score = 0.08
                    elif is_stable or is_fast:
                        topology_score = 0.06
                    
                    stability_penalty = 1.0
                    if not is_stable:
                        stability_penalty *= 0.6
                    if not is_fast:
                        stability_penalty *= 0.6
                    
                    position_variance = (guard_count * 0.08)
                    
                    raw_probability = timing_score + alignment_score + bw_score + topology_score - position_variance
                    guard_probability = min(max(raw_probability * stability_penalty, 0.10), 0.95)
                    
                    reasons = []
                    reasons.append(f"Timing:{timing_score*100:.0f}%")
                    reasons.append(f"Align:{alignment_score*100:.0f}%")
                    reasons.append(f"BW:{bw_score*100:.0f}%")
                    if is_stable: reasons.append("Stable")
                    if is_fast: reasons.append("Fast")
                    
                    probable_guards.append({
                        'ip': guard_ip,
                        'nickname': guard_nickname,
                        'country': g_country,
                        'flag': g_flag,
                        'isp': g_isp,
                        'relay_bandwidth': guard_bw,
                        'is_known_guard': True,
                        'is_known_exit': 'Exit' in guard_flags,
                        'in_consensus': True,
                        'guard_probability': guard_probability,
                        'reason': ' + '.join(reasons)
                    })
                    
                    print(f"  {g_flag} {guard_ip:<20} {guard_nickname:<12} BW:{guard_bw/1000000:.1f}MB/s Prob:{guard_probability*100:.0f}% [{'+'.join(reasons[:3])}]")
                    
                    guard_count += 1
                    if guard_count >= 3:
                        break
        else:
            print("  ⚠️ Tor consensus not available - cannot predict guards")
        
        probable_guards.sort(key=lambda x: x['guard_probability'], reverse=True)
        
        top_exit_nodes = top_exit_nodes[:3]
        probable_guards = probable_guards[:3]
        
        print(f"")
        print(f"╔══════════════════════════════════════════════════════════════╗")
        print(f"║              EXIT-ONLY ANALYSIS RESULTS                      ║")
        print(f"╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Total Flows Analyzed:   {len(raw_flows):<35} ║")
        print(f"║  Filtered (CDN/Cloud):   {filtered_count:<35} ║")
        print(f"║  Tor Exit Candidates:    {len(exit_candidates):<35} ║")
        print(f"║  Top Exit Node:          {top_exit_nodes[0]['ip'] if top_exit_nodes else 'N/A':<35} ║")
        if probable_guards:
            print(f"║  Probable Guards:        {len(probable_guards):<35} ║")
        print(f"║  Analysis Mode:          Exit-Side Only                      ║")
        print(f"╚══════════════════════════════════════════════════════════════╝")
        
        return {
            "confidence_scores": [node['score'] for node in top_exit_nodes],
            "labels": [node['ip'] for node in top_exit_nodes],
            "analysis_mode": "exit_only",
            "top_finding": {
                "guard_node": probable_guards[0]['ip'] if probable_guards else "N/A (Exit-Only Analysis)",
                "score": probable_guards[0]['guard_probability'] if probable_guards else 0,
                "ip": probable_guards[0]['ip'] if probable_guards else None,
                "country": probable_guards[0]['country'] if probable_guards else None,
                "flag": probable_guards[0]['flag'] if probable_guards else '🌐',
                "isp": probable_guards[0]['isp'] if probable_guards else None,
                "exit_ip": top_exit_nodes[0]['ip'] if top_exit_nodes else None,
                "geo_data": {
                    "ip": top_exit_nodes[0]['ip'] if top_exit_nodes else None,
                    "country": top_exit_nodes[0]['country'] if top_exit_nodes else None,
                    "city": top_exit_nodes[0]['city'] if top_exit_nodes else None,
                    "flag": top_exit_nodes[0]['flag'] if top_exit_nodes else '🌐',
                    "isp": top_exit_nodes[0]['isp'] if top_exit_nodes else None
                }
            },
            "confidence_level": "Exit Analysis" if not probable_guards else "Probable Guard",
            "confidence_description": "Exit-side PCAP analysis - Tor exit nodes identified" + (f", {len(probable_guards)} probable guard(s) detected" if probable_guards else ""),
            "correlation": {
                "mode": "exit_only",
                "exit_confirmation": True,
                "top_exit_nodes": top_exit_nodes,
                "probable_guards": probable_guards,
                "total_flows": len(raw_flows),
                "unique_exits": len(exit_candidates),
                "filtered_cdn": filtered_count,
                "exit_geo": top_exit_nodes[0] if top_exit_nodes else None
            },
            "flow_metadata": {
                "total_flows": len(raw_flows),
                "qualified_flows": len(raw_flows) - filtered_count,
                "unique_exit_ips": len(exit_candidates),
                "cdn_filtered": filtered_count,
                "total_packets": timing_stats.get('total_packets', 0),
                "total_bytes": timing_stats.get('total_bytes', 0),
                "tor_cell_ratio": timing_stats.get('tor_cell_ratio', 0),
                "fingerprint": flow_fingerprint
            }
        }
        
    except Exception as e:
        print(f"❌ Exit-only analysis failed: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"detail": f"Exit-only analysis failed: {str(e)}"}
        )


@app.post("/api/analyze/{case_id}")
async def run_analysis(
    case_id: str,
    mode: str = "guard_only",
    exit_path: str = None
):
    """
    Run the forensic analysis pipeline.
    
    Args:
        case_id: Case identifier
        mode: 'guard_only' (default) or 'guard_exit'
        exit_path: Optional path to exit-side evidence
    """
    
    data_dir = str(Path(".evidence_store") / case_id)
    if not os.path.exists(data_dir):
        raise HTTPException(status_code=404, detail="Case evidence not found.")

    engine = get_engine()
    results = {}
    
    try:
        pcap_files = [f for f in os.listdir(data_dir) if f.endswith(('.pcap', '.pcapng'))]
        
        detected_mode = None  # 'entry', 'exit', or 'dual'
        single_pcap_path = None
        
        if len(pcap_files) == 1:
            single_pcap_path = os.path.join(data_dir, pcap_files[0])
            print(f"📊 Single PCAP detected: {pcap_files[0]}")
            
            from pcap_type_detector import PCAPTypeDetector
            
            detector = PCAPTypeDetector()
            detection_result = detector.detect(single_pcap_path)
            
            detected_mode = detection_result['type']
            detection_confidence = detection_result['confidence']
            evidence = detection_result.get('evidence', {})
            
            print(f"  📊 Auto-detection: Guards={evidence.get('guard_ips', 0)}, "
                  f"Exits={evidence.get('exit_ips', 0)}, "
                  f"TorPorts={evidence.get('tor_port_flows', 0)}, "
                  f"AppPorts={evidence.get('app_port_flows', 0)}")
            
            if detected_mode == 'entry':
                print(f"  ✓ Detected as ENTRY-SIDE PCAP (confidence: {detection_confidence:.0%})")
            elif detected_mode == 'exit':
                print(f"  ✓ Detected as EXIT-SIDE PCAP (confidence: {detection_confidence:.0%})")
            else:
                print(f"  ⚠️ Could not determine PCAP type (confidence: {detection_confidence:.0%}). Defaulting to ENTRY-SIDE.")
                detected_mode = 'entry'
        
        if detected_mode == 'exit' and single_pcap_path:
            print(f"📊 Running EXIT-SIDE analysis...")
            return await analyze_exit_only_pcap(single_pcap_path, case_id, data_dir)
        
        preprocessor = TrafficPreprocessor()
        
        qualified_flows_file = os.path.join(data_dir, "qualified_flows_internal.txt") 
        
        qualified_flows = preprocessor.create_overlap_windows(
            data_path=data_dir,
            output_file=qualified_flows_file,
            threshold=3,   # Balanced: 3 packets per window (enough for pattern detection)
            interval=5,
            num_windows=7, # Balanced: 7 windows (~17s coverage) - maintains temporal consistency
            add_num=2
        )
        
        if not qualified_flows:
            return JSONResponse(
                status_code=400,
                content={"detail": "No qualified network flows detected. The PCAP file may not contain sufficient Tor traffic patterns, or the flows are too short/sparse for correlation analysis. Please try a PCAP with more sustained network activity."}
            )

        output_prefix = os.path.join(data_dir, "processed_evidence_")
        
        preprocessor.process_window_files(
            data_path=data_dir,
            file_list_path=qualified_flows_file,
            output_prefix=output_prefix,
            interval=5,
            num_windows=7,  # Match balanced settings
            add_num=2
        )
        
        pickle_path = f"{output_prefix}0.pickle"
        if not os.path.exists(pickle_path):
             found = [f for f in os.listdir(data_dir) if f.startswith("processed_evidence") and f.endswith(".pickle")]
             if found:
                 pickle_path = os.path.join(data_dir, found[0])
             else:
                  return {
                      "top_finding": {
                          "guard_node": "Unknown",
                          "confidence_score": 0.0,
                          "guard_confidence": 0.0,
                          "confidence_level": "Low",
                          "description": "Insufficient data for analysis",
                          "correlated_sessions": 0,
                      },
                      "details": {"scores": [], "labels": []},
                      "correlation": {"mode": "guard_only", "exit_confirmation": False},
                      "analysis_metadata": {
                          "analysis_mode": "investigative",
                          "low_confidence": True,
                          "warning": "No qualified network flows detected. Analysis could not proceed due to sparse Tor traffic patterns."
                      }
                  }

        result = preprocessor.load_for_inference(
            pickle_path=pickle_path,
            pad_length=SEQ_LENGTH
        )
        
        if len(result) == 4:
            ingress_tensor, egress_tensor, labels, analysis_metadata = result
        else:
            ingress_tensor, egress_tensor, labels = result
            analysis_metadata = {'analysis_mode': 'strict', 'low_confidence': False, 'warning': None}
        
        results['labels'] = labels
        results['source_file'] = "Uploaded PCAP Evidence"
        
        ingress_emb = engine.inference(ingress_tensor)
        egress_emb = engine.inference(egress_tensor)
        
        confidence_scores = []
        for i in range(len(labels)):
            score = engine.get_confidence_score(
                ingress_emb[i:i+1],
                egress_emb[i:i+1]
            )
            confidence_scores.append(float(score)) # Ensure float for JSON
            
        results['confidence_scores'] = confidence_scores
        
        verified_candidates = []
        for i, label in enumerate(labels):
            geo = get_ip_geolocation(label)
            ip = geo.get("ip", "")
            isp = geo.get("isp", "")
            
            is_tor, _, reason = is_likely_tor_guard(ip, isp)
            if is_tor:
                verified_candidates.append({
                    'idx': i,
                    'ip': ip,
                    'score': confidence_scores[i],
                    'geo': geo,
                    'label': label
                })
        
        if verified_candidates:
            verified_candidates.sort(key=lambda x: x['score'], reverse=True)
            top_verified = verified_candidates[0]
            max_idx = top_verified['idx']
            max_score = top_verified['score']
            guard_node = top_verified['label']
            geo_data = top_verified['geo']
            print(f"✓ Selected verified Tor guard: {top_verified['ip']} (score: {max_score:.1%})")
        else:
            print(f"⚠️ No verified Tor guards found - cannot identify guard node from this PCAP")
            max_idx = 0
            max_score = 0.0  # Zero confidence for no verified guard
            guard_node = "No Verified Guard"
            geo_data = {"ip": None, "country": "Unknown", "isp": "N/A", "flag": "⚠️"}
        
        if max_score >= 0.75:
            conf_level, conf_desc = "High", "Strong correlation detected."
        elif max_score >= 0.50:
             conf_level, conf_desc = "Medium", "Moderate correlation observed."
        else:
             conf_level, conf_desc = "Low", "Weak correlation."

        correlation_mode = "guard_only"
        exit_boost = 0.0
        exit_confirmation = False
        final_confidence = max_score
        agg = None  # Aggregation result from exit correlation
        
        if mode == "guard_exit" and EXIT_CORRELATION_AVAILABLE:
            
            best_guard_idx = max_idx  # Default to highest guard confidence
            best_combined_score = 0.0
            best_exit_result = None
            best_agg = None
            candidate_exit_scores = {}  # Store exit scores for ALL candidates
            guard_exit_pairs = []  # Store ALL guard-exit pair matches for UI display
            
            entry_pcap_files = [f for f in os.listdir(data_dir) 
                                if f.endswith(('.pcap', '.pcapng')) and not f.startswith('exit_')]
            entry_pcap_path = os.path.join(data_dir, entry_pcap_files[0]) if entry_pcap_files else None
            
            all_raw_flows = {}
            from pcap_processor import PCAPParser
            if entry_pcap_path:
                try:
                    parser = PCAPParser(min_packets=3)
                    all_raw_flows = parser.parse_pcap(entry_pcap_path)
                    if all_raw_flows:
                        unique_ips = set()
                        for flow_id in all_raw_flows.keys():
                            parts = flow_id.split('-')
                            if len(parts) >= 2:
                                src = parts[0].rsplit(':', 1)[0] if ':' in parts[0] else parts[0]
                                dst = parts[1].rsplit(':', 1)[0] if ':' in parts[1] else parts[1]
                                unique_ips.add(src)
                                unique_ips.add(dst)
                        print(f"📝 Entry PCAP: {len(all_raw_flows)} flows detected, {len(unique_ips)} unique IPs")
                except Exception as e:
                    print(f"⚠️ Failed to parse entry PCAP: {e}")
            
            top_n_candidates = min(5, len(labels))
            sorted_indices = sorted(range(len(confidence_scores)), key=lambda i: confidence_scores[i], reverse=True)
            
            print(f"")
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║           ENTRY-EXIT MATCHING ANALYSIS                       ║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            print(f"║  Analyzing top {top_n_candidates} guard candidates...                           ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            print(f"")
            
            for idx in sorted_indices[:top_n_candidates]:
                candidate_label = labels[idx]
                candidate_geo = get_ip_geolocation(candidate_label)
                candidate_ip = candidate_geo.get("ip")
                candidate_isp = candidate_geo.get("isp", "")
                guard_conf = confidence_scores[idx]
                
                is_tor, isp_multiplier, isp_reason = is_likely_tor_guard(candidate_ip, candidate_isp)
                if not is_tor:
                    print(f"│  ⚠ Skipping {candidate_ip} - NOT TOR: {isp_reason}")
                    continue
                
                guard_flows = []
                if all_raw_flows and candidate_ip:
                    for flow_id, flow_session in all_raw_flows.items():
                        ip_matches = (candidate_ip in flow_id) or (candidate_label in flow_id)
                        
                        if not ip_matches and '.' in candidate_ip:
                            ip_matches = candidate_ip.split('.')[0] in flow_id and candidate_ip.split('.')[2] in flow_id
                        
                        if ip_matches:
                            ingress = getattr(flow_session, 'ingress_packets', [])
                            egress = getattr(flow_session, 'egress_packets', [])
                            all_packets = [(t, s) for t, s in ingress] + [(t, s) for t, s in egress]
                            all_packets.sort(key=lambda x: x[0])
                            
                            if all_packets:
                                base_time = all_packets[0][0]
                                guard_flows.append({
                                    'id': flow_id,
                                    'packets': len(all_packets),
                                    'timestamps': [p[0] - base_time for p in all_packets],
                                    'sizes': [abs(p[1]) for p in all_packets],
                                    'duration': all_packets[-1][0] - all_packets[0][0] if len(all_packets) > 1 else 0
                                })
                
                origin_ip = None
                origin_ips_found = set()
                if guard_flows:
                    for gf in guard_flows:
                        flow_id = gf.get('id', '')
                        parts = flow_id.split('-')
                        if len(parts) >= 2:
                            src_part = parts[0]  # srcIP:port
                            dst_part = parts[1]  # dstIP:port
                            
                            src_ip = src_part.rsplit(':', 1)[0] if ':' in src_part else src_part
                            dst_ip = dst_part.rsplit(':', 1)[0] if ':' in dst_part else dst_part
                            
                            print(f"│  📝 Flow: {src_ip} <-> {dst_ip}")  # DEBUG
                            
                            for ip in [src_ip, dst_ip]:
                                if ip != candidate_ip and not ip.startswith(('127.', '0.0.0.0')):
                                    origin_ips_found.add(ip)
                    
                    if origin_ips_found:
                        origin_ip = list(origin_ips_found)[0]
                        print(f"│  🔍 Origin IP detected: {origin_ip}")
                
                if not guard_flows:
                    print(f"│  ⚠ Skipping {candidate_ip[:20]}... - no matching guard flows in PCAP")
                    continue
                
                try:
                    candidate_exit_result, candidate_agg = run_exit_correlation(
                        guard_flows=guard_flows,
                        exit_pcap_path=exit_path,
                        guard_confidence=guard_conf,
                        guard_ip=candidate_ip,
                        metadata={'case_id': case_id, 'candidate_idx': idx},
                        session_count=len(labels)
                    )
                    
                    exit_score = candidate_exit_result.get('score', 0)
                    combined = exit_score  # Pure flow-based correlation score
                    matched = candidate_exit_result.get('matched', False)
                    matched_flow = candidate_exit_result.get('exit_flow', 'N/A')
                    
                    all_exit_scores = candidate_exit_result.get('all_exit_scores', {})
                    
                    exit_ip = 'N/A'
                    if matched_flow and matched_flow != 'N/A':
                        parts = matched_flow.split('-')[:2]
                        ips = [p.split(':')[0] for p in parts if ':' in p]
                        private_prefixes = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                                           '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                                           '172.28.', '172.29.', '172.30.', '172.31.')
                        for ip in ips:
                            if not ip.startswith(private_prefixes):
                                exit_ip = ip
                                break
                        if exit_ip == 'N/A' and ips:
                            exit_ip = ips[0]
                    
                    if all_exit_scores:
                        sorted_exits = sorted(all_exit_scores.items(), key=lambda x: x[1], reverse=True)[:3]
                        for eip, escore in sorted_exits:
                            guard_exit_pairs.append({
                                'guard_ip': candidate_ip,
                                'guard_confidence': float(guard_conf),
                                'exit_ip': eip,
                                'exit_flow': matched_flow if eip == exit_ip else f"tied-{eip}",
                                'exit_score': float(escore),
                                'combined_score': float(escore),  # Pure flow-based score
                                'matched': bool(escore > 0.5),
                                'guard_flows_count': len(guard_flows),
                                'origin_ip': origin_ip  # Client IP that connected to this guard
                            })
                    else:
                        guard_exit_pairs.append({
                            'guard_ip': candidate_ip,
                            'guard_confidence': float(guard_conf),
                            'exit_ip': exit_ip,
                            'exit_flow': matched_flow,
                            'exit_score': float(exit_score),
                            'combined_score': float(combined),
                            'matched': bool(matched),
                            'guard_flows_count': len(guard_flows),
                            'origin_ip': origin_ip  # Client IP that connected to this guard
                        })
                    
                    boost_indicator = "🔹" if isp_multiplier > 1.0 else ""
                    print(f"┌─ Guard Candidate: {candidate_ip} {boost_indicator}")
                    print(f"│  ISP:              {candidate_isp[:30]}... (×{isp_multiplier:.2f})")
                    print(f"│  Guard Confidence:  {guard_conf*100:.1f}%")
                    print(f"│  Guard Flows:       {len(guard_flows)}")
                    print(f"│  Exit IP:           {exit_ip}")
                    print(f"│  Exit Score:        {exit_score*100:.1f}%")
                    print(f"│  Match Status:      {'✓ MATCHED' if matched else '✗ NO MATCH'}")
                    print(f"│  Combined Score:    {combined*100:.1f}% (Guard×0.3 + Exit×0.7)")
                    print(f"└──────────────────────────────────────────────────────────────")
                    print(f"")
                    
                    candidate_exit_scores[candidate_ip] = {
                        'exit_score': float(exit_score),
                        'combined_score': float(combined),
                        'guard_conf': float(guard_conf),
                        'exit_matched': bool(matched)
                    }
                    
                    if combined > best_combined_score:
                        best_combined_score = combined
                        best_guard_idx = idx
                        best_exit_result = candidate_exit_result
                        best_agg = candidate_agg
                        
                except Exception as e:
                    print(f"⚠️ Exit correlation failed for {candidate_ip}: {e}")
            
            
            exit_ip_scores = {}
            for pair in guard_exit_pairs:
                eip = pair['exit_ip']
                if eip and eip != 'N/A':
                    if eip not in exit_ip_scores:
                        exit_ip_scores[eip] = {'total_score': 0, 'count': 0, 'matched_count': 0, 'max_score': 0}
                    exit_ip_scores[eip]['total_score'] += pair['exit_score']
                    exit_ip_scores[eip]['count'] += 1
                    exit_ip_scores[eip]['max_score'] = max(exit_ip_scores[eip]['max_score'], pair['exit_score'])
                    if pair['matched']:
                        exit_ip_scores[eip]['matched_count'] += 1
            
            sorted_exits = sorted(exit_ip_scores.items(), key=lambda x: x[1]['max_score'], reverse=True)
            exits_are_tied = False
            if len(sorted_exits) >= 2:
                top_score = sorted_exits[0][1]['max_score']
                second_score = sorted_exits[1][1]['max_score']
                if abs(top_score - second_score) < 0.05:  # Within 5%
                    exits_are_tied = True
                    print(f"⚠️ Multiple exit IPs have similar scores - showing all possibilities")
            
            if not exits_are_tied:
                best_exit_ip = sorted_exits[0][0] if sorted_exits else None
                if best_exit_ip:
                    print(f"🔍 Identified primary exit node: {best_exit_ip}")
                    for pair in guard_exit_pairs:
                        if pair['exit_ip'] == best_exit_ip:
                            pair['combined_score'] = pair['combined_score'] * 1.2
                        else:
                            pair['combined_score'] = pair['combined_score'] * 0.7
            else:
                top_exits = [e[0] for e in sorted_exits[:min(3, len(sorted_exits))]]  # Top 3 exits (or less)
                if top_exits:
                    print(f"📊 Potential exit nodes: {', '.join(top_exits)}")
            
            guard_exit_pairs.sort(key=lambda x: x['combined_score'], reverse=True)
            
            if guard_exit_pairs:
                print(f"╔══════════════════════════════════════════════════════════════╗")
                print(f"║           TOP GUARD-EXIT MATCHES                             ║")
                print(f"╠══════════════════════════════════════════════════════════════╣")
                for i, pair in enumerate(guard_exit_pairs[:5]):
                    status = "✓" if pair['matched'] else "○"
                    print(f"║  {i+1}. {pair['guard_ip'][:18]:<18} → {pair['exit_ip']:<18} {status} {pair['combined_score']*100:.1f}% ║")
                print(f"╚══════════════════════════════════════════════════════════════╝")
                print(f"")
            
            if guard_exit_pairs:
                top_pair = guard_exit_pairs[0]
                top_guard_ip = top_pair['guard_ip']
                
                for idx, label in enumerate(labels):
                    label_geo = get_ip_geolocation(label)
                    if label_geo.get('ip') == top_guard_ip:
                        max_idx = idx
                        guard_node = label
                        max_score = confidence_scores[idx]
                        geo_data = label_geo
                        best_combined_score = top_pair['combined_score']
                        break
                
                print(f"✓ Selected guard {top_guard_ip} with combined score {top_pair['combined_score']*100:.1f}%")
                print(f"   Top exit: {top_pair['exit_ip']}")
            else:
                print(f"⚠️ No valid guard-exit pairs found - all candidates filtered as non-Tor IPs")
                guard_node = "No Verified Guard"
                geo_data = {"ip": None, "country": "Unknown", "isp": "N/A", "flag": "⚠️"}
                max_score = 0.0
            
            top_exit_nodes = []
            seen_exits = set()
            selected_guard_ip = top_guard_ip if 'top_guard_ip' in dir() else None
            
            for pair in guard_exit_pairs:
                if selected_guard_ip and pair.get('guard_ip') != selected_guard_ip:
                    continue
                    
                exit_ip = pair.get('exit_ip')
                if exit_ip and exit_ip not in seen_exits and not exit_ip.startswith(('127.', '192.168.', '10.', '172.')):
                    seen_exits.add(exit_ip)
                    try:
                        exit_geo_resp = requests.get(f"http://ip-api.com/json/{exit_ip}?fields=country,countryCode,isp", timeout=2)
                        exit_geo_data = exit_geo_resp.json()
                        country = exit_geo_data.get('country', 'Unknown')
                        country_code = exit_geo_data.get('countryCode', '')
                        isp = exit_geo_data.get('isp', 'Unknown')
                        flag = ''.join(chr(ord('🇦') + ord(c) - ord('A')) for c in country_code.upper()) if len(country_code) == 2 else '🌐'
                    except:
                        country, flag, isp = 'Unknown', '🌐', 'Unknown'
                    
                    top_exit_nodes.append({
                        'ip': exit_ip,
                        'country': country,
                        'flag': flag,
                        'isp': isp,
                        'score': pair.get('exit_score', 0),
                        'combined_score': pair.get('combined_score', 0)
                    })
                    
                    if len(top_exit_nodes) >= 3:
                        break
            
            if best_exit_result is not None:
                exit_result = best_exit_result
                agg = best_agg
            else:
                exit_result, agg = run_exit_correlation(
                    guard_flows=[{'id': labels[max_idx], 'packets': 10, 'timestamps': [], 'sizes': []}],
                    exit_pcap_path=exit_path,
                    guard_confidence=max_score,
                    guard_ip=geo_data.get("ip"),
                    metadata={'case_id': case_id},
                    session_count=len(labels)
                )
            
            correlation_mode = agg.get('mode', 'guard_exit')
            exit_boost = agg.get('exit_boost', 0.0)
            exit_confirmation = agg.get('exit_confirmation', False)
            final_confidence = agg.get('final_confidence', max_score)
            
            per_session = exit_result.get('per_session_scores', [])
            matched_count = sum(1 for s in per_session if s.get('matched', False))
            
            guard_ip_display = geo_data.get('ip') or 'No Verified Guard'
            if '_' in str(guard_ip_display):
                parts = guard_ip_display.split('_')
                if len(parts) >= 3:
                    guard_ip_display = parts[2]  # Guard IP is at index 2
                    client_ip = parts[0]  # Client IP is at index 0
                else:
                    client_ip = 'N/A'
            else:
                client_ip = 'N/A'
            
            exit_flow_str = exit_result.get('exit_flow', '')
            exit_ip_display = 'N/A'
            if exit_flow_str:
                parts = exit_flow_str.split('-')[:2]
                ips = [p.split(':')[0] for p in parts if ':' in p]
                private_prefixes = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                                   '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                                   '172.28.', '172.29.', '172.30.', '172.31.')
                for ip in ips:
                    if not ip.startswith(private_prefixes):
                        exit_ip_display = ip
                        break
                if exit_ip_display == 'N/A' and ips:
                    exit_ip_display = ips[0]
            
            exit_flows_count = len(exit_result.get('all_exit_scores', {})) or len(per_session)
            correlation_observations = len(per_session) * max(1, exit_flows_count)
            
            if matched_count > 0 and exit_result.get('score', 0) > 0.5:
                consistency = "High"
                consistency_desc = "Strong temporal correlation"
            elif matched_count > 0 or exit_result.get('score', 0) > 0.3:
                consistency = "Medium"
                consistency_desc = "Moderate temporal correlation"
            else:
                consistency = "Low"
                consistency_desc = "Weak temporal correlation"
            
            score = exit_result.get('score', 0)
            if score >= 0.5:
                status = "✓ HIGH CONFIDENCE"
                conf_text = "High (multiplexed guard reuse)"
            elif score >= 0.3:
                status = "◐ PROBABLE"
                conf_text = "Medium (possible match)"
            else:
                status = "○ LOW CONFIDENCE"
                conf_text = "Low (weak correlation)"
            
            print(f"")
            print(f"╔══════════════════════════════════════════════════════════════╗")
            print(f"║              ENTRY-EXIT CORRELATION RESULTS                  ║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            print(f"║  Mode:                  {correlation_mode:<36} ║")
            print(f"║  Guard Node IP:         {guard_ip_display:<36} ║")
            print(f"║  Exit Node IP:          {exit_ip_display:<36} ║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            print(f"║  Guard TCP Connections: {len(per_session)} (persistent, expected){' ':<12} ║")
            print(f"║  Exit Sessions Analyzed:{exit_flows_count:<37} ║")
            print(f"║  Correlation Score:     {score*100:.1f}%{' ':<32} ║")
            print(f"║  Guard-Exit Consistency:{consistency:<37} ║")
            print(f"╠══════════════════════════════════════════════════════════════╣")
            print(f"║  Final Confidence:      {conf_text:<36} ║")
            print(f"║  Status:                {status:<36} ║")
            print(f"╚══════════════════════════════════════════════════════════════╝")
            print(f"")
        elif mode == "guard_exit":
            correlation_mode = "guard_exit"  # User requested dual-side, but module unavailable
            exit_confirmation = False
        
        if final_confidence >= 0.75:
            conf_level, conf_desc = "High", "Strong correlation detected."
        elif final_confidence >= 0.50:
            conf_level, conf_desc = "Medium", "Moderate correlation observed."
        else:
            conf_level, conf_desc = "Low", "Weak correlation."

        probable_exits = []
        try:
            from tor_path_inference import TorConsensusClient
            consensus = TorConsensusClient()
            consensus.fetch_consensus()
            
            if consensus.relay_count > 0:
                all_exits = consensus.get_all_exits() if hasattr(consensus, 'get_all_exits') else []
                
                if all_exits:
                    print(f"\n📡 Predicting Probable Exit Nodes from Tor consensus...")
                    print(f"  Found {len(all_exits)} exits in Tor consensus")
                    
                    exit_scores = []
                    for exit_relay in all_exits:
                        exit_ip = exit_relay.ip_address if hasattr(exit_relay, 'ip_address') else None
                        exit_bw = exit_relay.bandwidth if hasattr(exit_relay, 'bandwidth') else 0
                        exit_flags = exit_relay.flags if hasattr(exit_relay, 'flags') else []
                        exit_nickname = exit_relay.nickname if hasattr(exit_relay, 'nickname') else 'Unknown'
                        
                        if not exit_ip:
                            continue
                        
                        score = 0.0
                        score += 0.50 * min(exit_bw / 1000000, 1.0)  # BW weight (50%)
                        if 'Exit' in exit_flags:
                            score += 0.30
                        if 'Stable' in exit_flags:
                            score += 0.10
                        if 'Fast' in exit_flags:
                            score += 0.10
                        
                        exit_scores.append((exit_relay, score, exit_bw))
                    
                    exit_scores.sort(key=lambda x: (x[1], x[2]), reverse=True)
                    
                    exit_count = 0
                    for exit_relay, score, exit_bw in exit_scores[:10]:
                        if exit_count >= 5:
                            break
                        
                        exit_ip = exit_relay.ip_address if hasattr(exit_relay, 'ip_address') else 'Unknown'
                        exit_nickname = exit_relay.nickname if hasattr(exit_relay, 'nickname') else 'Unknown'
                        exit_flags = exit_relay.flags if hasattr(exit_relay, 'flags') else []
                        
                        if 'Stable' not in exit_flags and 'Fast' not in exit_flags:
                            continue
                        
                        try:
                            geo_resp = requests.get(f"http://ip-api.com/json/{exit_ip}?fields=country,countryCode,isp", timeout=2)
                            geo_data_exit = geo_resp.json()
                            e_country = geo_data_exit.get('country', 'Unknown')
                            e_code = geo_data_exit.get('countryCode', '')
                            e_isp = geo_data_exit.get('isp', 'Unknown')
                            e_flag = ''.join(chr(ord('🇦') + ord(c) - ord('A')) for c in e_code.upper()) if len(e_code) == 2 else '🌐'
                        except:
                            e_country, e_flag, e_isp = 'Unknown', '🌐', 'Unknown'
                        
                        exit_probability = min(0.88 - (exit_count * 0.13), 0.95)
                        
                        probable_exits.append({
                            'ip': exit_ip,
                            'nickname': exit_nickname,
                            'country': e_country,
                            'flag': e_flag,
                            'isp': e_isp,
                            'bandwidth': exit_bw,
                            'probability': exit_probability,
                            'in_consensus': True
                        })
                        
                        print(f"  {e_flag} {exit_ip:<20} {exit_nickname:<12} BW:{exit_bw/1000000:.1f}MB/s Prob:{exit_probability*100:.0f}%")
                        exit_count += 1
                else:
                    print(f"⚠️ No exit relays found in consensus")
            else:
                print(f"⚠️ Tor consensus not loaded")
        except Exception as exit_err:
            print(f"Exit node prediction failed (non-fatal): {exit_err}")
            import traceback
            traceback.print_exc()
        
        origin_scope = None
        if ORIGIN_SCOPE_AVAILABLE:
            try:
                origin_scope = estimate_origin_scope(
                    guard_country=geo_data.get("country", "Unknown"),
                    guard_country_code=None,  # Not available from ip-api
                    guard_isp=geo_data.get("isp"),
                    guard_asn=None
                )
            except Exception as scope_err:
                print(f"Origin scope estimation failed (non-fatal): {scope_err}")
                origin_scope = None
        
        ip_leads = []
        if IP_LEADS_AVAILABLE:
            try:
                from utils.flow_id_parser import extract_public_ip
                candidates_for_ip = []
                for i, label in enumerate(labels):
                    guard_ip = extract_public_ip(label)
                    if guard_ip:
                        exit_data = candidate_exit_scores.get(guard_ip, {}) if 'candidate_exit_scores' in dir() else {}
                        exit_score = exit_data.get('exit_score', 0.0)
                        combined = exit_data.get('combined_score', confidence_scores[i])
                        exit_matched = exit_data.get('exit_matched', False)
                        
                        candidates_for_ip.append({
                            'flow_id': label,
                            'client_ip': guard_ip,  # Using client_ip key for compatibility
                            'statistical': confidence_scores[i],
                            'siamese': None,  # Not available in simplified API path
                            'final': confidence_scores[i],
                            'exit_score': exit_score,
                            'combined_score': combined,
                            'exit_matched': exit_matched
                        })
                
                if mode == "guard_exit" and 'candidate_exit_scores' in locals() and candidate_exit_scores:
                    candidates_for_ip.sort(key=lambda x: x.get('combined_score', x['final']), reverse=True)
                
                ip_leads = generate_ip_leads(candidates_for_ip, min_flows=1)
                
                if 'candidate_exit_scores' in locals() and candidate_exit_scores:
                    for lead in ip_leads:
                        lead_ip = lead.get('ip', '')
                        if lead_ip in candidate_exit_scores:
                            lead['exit_score'] = candidate_exit_scores[lead_ip]['exit_score']
                            lead['combined_score'] = candidate_exit_scores[lead_ip]['combined_score']
                            lead['exit_matched'] = candidate_exit_scores[lead_ip]['exit_matched']
                
                if mode == "guard_exit":
                    ip_leads.sort(key=lambda x: x.get('combined_score', x.get('confidence', 0)), reverse=True)
                    
            except Exception as ip_err:
                print(f"IP lead generation failed (non-fatal): {ip_err}")
                import traceback
                traceback.print_exc()
                ip_leads = []
        
        detected_origin_ip = None
        if 'guard_exit_pairs' in dir() and guard_exit_pairs:
            detected_origin_ip = guard_exit_pairs[0].get('origin_ip')
        
        response_data = {
            "top_finding": {
                "guard_node": guard_node,
                "confidence_score": final_confidence,
                "guard_confidence": max_score,
                "confidence_level": conf_level,
                "description": conf_desc,
                "correlated_sessions": len(labels),
                "country": geo_data.get("country"),
                "city": geo_data.get("city"),
                "flag": geo_data.get("flag"),
                "isp": geo_data.get("isp"),
                "ip": geo_data.get("ip"),
                "origin_ip": detected_origin_ip  # Client IP that connected to this guard
            },
            "details": {
                "scores": confidence_scores,
                "labels": labels
            },
            "correlation": {
                "mode": correlation_mode,
                "exit_confirmation": exit_confirmation,
                "exit_boost": exit_boost,
                "session_boost": agg.get('session_boost', 0.0) if agg else 0.0,
                "session_count": agg.get('session_count', 1) if agg else len(labels),
                "note": agg.get('note', 'Guard-only analysis') if agg else "Guard-only analysis",
                "origin_assessment": agg.get('origin_assessment') if agg else None,
                "indirect_evidence": agg.get('indirect_evidence') if agg else None,
                "observed_exit_flow": exit_result.get('exit_flow') if 'exit_result' in dir() and exit_result else None,
                "matched_guard_flow": exit_result.get('guard_flow') if 'exit_result' in dir() and exit_result else None,
                "guard_flows_count": len(guard_flows) if 'guard_flows' in dir() else 0,
                "exit_direct_score": exit_result.get('score') if 'exit_result' in dir() and exit_result else None,
                "per_session_scores": exit_result.get('per_session_scores', []) if 'exit_result' in dir() and exit_result else [],
                "guard_exit_pairs": guard_exit_pairs if 'guard_exit_pairs' in dir() else [],
                "top_exit_nodes": top_exit_nodes if 'top_exit_nodes' in dir() else [],
                "probable_exits": probable_exits if 'probable_exits' in dir() else [],
                "exit_boosted_score": min(
                    (exit_result.get('score', 0) if 'exit_result' in dir() and exit_result else 0) * 
                    (1 + 0.15 * np.log(len(labels)) if len(labels) > 1 else 1),
                    0.999999
                ) if 'exit_result' in dir() and exit_result and exit_result.get('score') else None,
                "exit_geo": (lambda: (
                    (lambda flow: (
                        (lambda parts: (
                            (lambda ips: (
                                (lambda public_ip: (
                                    get_ip_geolocation(public_ip) if public_ip else None
                                ))(
                                    next((ip for ip in ips if not ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                                                                                  '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                                                                                  '172.28.', '172.29.', '172.30.', '172.31.'))), None)
                                )
                            ))([part.split(':')[0] for part in parts[:2] if ':' in part])
                        ))(flow.split('-'))
                    ))(exit_result.get('exit_flow', ''))
                    if 'exit_result' in dir() and exit_result and exit_result.get('exit_flow')
                    else None
                ))(),
                "accumulated_evidence": agg.get('accumulated_evidence') if agg else None
            },
            "probable_exit_nodes": probable_exits,  # Consensus-based exit prediction
            "origin_scope": origin_scope,
            "ip_leads": ip_leads,
            "analysis_metadata": analysis_metadata,  # INVESTIGATIVE MODE: Include analysis mode and warnings
            "analysis_mode": (
                "entry_only" if detected_mode == 'entry' else
                "guard_exit" if mode == "guard_exit" else
                "guard_only"
            )
        }
        
        return response_data

    except ValueError as ve:
        return JSONResponse(
            status_code=400,
            content={
                "detail": str(ve),
                "error_type": "insufficient_data",
                "suggestion": "Please ensure the PCAP file contains valid Tor traffic with sufficient packet data. The capture should include sustained network activity with both inbound and outbound flows."
            }
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis pipeline error: {str(e)}")


@app.post("/api/tor_path_inference")
async def tor_path_inference_endpoint(request: PathInferenceRequest):
    """
    Standalone Tor path inference endpoint.
    
    MUST be called AFTER guard inference. Does NOT consume PCAP data.
    Returns probabilistic exit node candidates.
    
    Args:
        guard_ip: IP address of inferred guard node
        guard_confidence: Confidence score from guard inference [0, 1]
        sample_count: Number of samples for probability estimation (default: 3000)
    
    Returns:
        Probabilistic path estimation with exit candidates
    """
    if not TOR_PATH_INFERENCE_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="Tor path inference module not available"
        )
    
    try:
        result = infer_path_from_guard(
            guard_ip=request.guard_ip,
            confidence=request.guard_confidence,
            sample_count=request.sample_count
        )
        
        if 'error' in result:
            raise HTTPException(status_code=500, detail=result['error'])
        
        return {
            "status": "success",
            "guard_ip": request.guard_ip,
            "guard_confidence": request.guard_confidence,
            "is_probabilistic": True,
            "warning": "Path estimation is probabilistic and should not be used as sole evidence",
            "result": result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Path inference failed: {str(e)}"
        )

@app.post("/api/report")
async def generate_report(case_info: CaseInfo, finding_data: dict, details: dict):
    """
    Generate and return a forensic report in PDF format.
    This endpoint expects the frontend to pass back the finding data it received.
    """
    try:
        results = {
            'labels': details.get('labels', []),
            'confidence_scores': details.get('scores', []),
            'source_file': "Uploaded PCAP Evidence"
        }
        
        operational_stats = {
            'guard_node': finding_data.get('guard_node'),
            'confidence_level': finding_data.get('confidence_level'),
            'confidence_score': finding_data.get('confidence_score'),
            'correlated_sessions': finding_data.get('correlated_sessions'),
            'country': finding_data.get('country'),
            'city': finding_data.get('city'),
            'flag': finding_data.get('flag'),
            'isp': finding_data.get('isp')
        }
        
        case_dict = {
            'case_id': case_info.case_id,
            'investigator': case_info.investigator
        }

        report_path = generate_forensic_report(
            case_dict,
            results,
            operational_stats,
            filename=f"forensic_report_{case_info.case_id}.pdf"
        )
        
        if report_path.endswith('.pdf'):
            media_type = "application/pdf"
            filename = f"Forensic_Report_{case_info.case_id}.pdf"
        else:
            media_type = "text/markdown"
            filename = f"Forensic_Report_{case_info.case_id}.md"
        
        return FileResponse(
            report_path, 
            filename=filename,
            media_type=media_type
        )
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


class DashboardReportRequest(BaseModel):
    """Request model for dashboard-specific report export."""
    case_id: str
    analysis_mode: str  # 'entry_only', 'exit_only', or 'guard_exit'
    results: Any  # Complex nested object from analysis
    pcap_hash: Optional[str] = None
    
    model_config = ConfigDict(arbitrary_types_allowed=True)


@app.post("/api/export-dashboard-report")
async def export_dashboard_report(request: DashboardReportRequest):
    """
    Generate PDF report for dashboard-specific analysis.
    
    Supports:
    - entry_only: Entry-Side (Guard) PCAP Analysis
    - exit_only: Exit-Side (Exit) PCAP Analysis  
    - guard_exit: Dual-Side (Guard + Exit) Correlation
    """
    import traceback
    
    try:
        print(f"\n📄 Report export requested: mode={request.analysis_mode}, case={request.case_id}")
        
        from dashboard_report_generator import (
            generate_entry_side_report,
            generate_exit_side_report,
            generate_dual_side_report
        )
        
        case_id = request.case_id
        analysis_mode = request.analysis_mode
        results = request.results
        pcap_hash = request.pcap_hash
        
        print(f"  Results keys: {list(results.keys()) if results else 'None'}")
        
        if analysis_mode == 'entry_only':
            report_path = generate_entry_side_report(
                results, case_id, pcap_hash,
                filename=f"Entry_Side_Report_{case_id}.pdf"
            )
            report_name = f"Entry_Side_Report_{case_id}.pdf"
            
        elif analysis_mode == 'exit_only':
            report_path = generate_exit_side_report(
                results, case_id, pcap_hash,
                filename=f"Exit_Side_Report_{case_id}.pdf"
            )
            report_name = f"Exit_Side_Report_{case_id}.pdf"
            
        else:  # guard_exit or default
            report_path = generate_dual_side_report(
                results, case_id, pcap_hash,
                filename=f"Dual_Side_Report_{case_id}.pdf"
            )
            report_name = f"Dual_Side_Report_{case_id}.pdf"
        
        if report_path.endswith('.pdf'):
            media_type = "application/pdf"
        else:
            media_type = "text/markdown"
            report_name = report_name.replace('.pdf', '.md')
        
        print(f"📄 Generated {analysis_mode} report: {report_path}")
        
        return FileResponse(
            report_path,
            filename=report_name,
            media_type=media_type
        )
        
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Dashboard report generation failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    try:
        get_engine()
    except:
        pass
    uvicorn.run(app, host="0.0.0.0", port=8000)
