"""
Exit Correlation Module

Provides exit-side evidence correlation for GUARD_EXIT mode.
Reuses existing statistical_similarity module - NO new ML models.

Components:
- ExitFlowExtractor: Extract flows from exit-side PCAP
- ExitCorrelator: Correlate guard flows with exit flows
- ConfidenceAggregator: Combine guard + exit confidence
"""

import numpy as np
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import existing statistical similarity (reuse, don't replace)
try:
    from statistical_similarity import StatisticalCorrelator
    STAT_CORRELATOR_AVAILABLE = True
except ImportError:
    STAT_CORRELATOR_AVAILABLE = False
    logger.warning("StatisticalCorrelator not available - using basic similarity")

try:
    from analysis.exit_node_aggregator import ExitNodeAggregator
    from analysis.correlation_aggregator import CorrelationAggregator
    EXIT_AGGREGATOR = ExitNodeAggregator()
    CORRELATION_AGGREGATOR = CorrelationAggregator()
    AGGREGATORS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Session aggregators not available: {e}")
    EXIT_AGGREGATOR = None
    CORRELATION_AGGREGATOR = None
    AGGREGATORS_AVAILABLE = False


# Known non-Tor cloud provider IP ranges (penalty for false positives)
# AWS uses many IP ranges - we check the first octet patterns
AWS_IP_PREFIXES = ('3.', '13.', '15.', '16.', '18.', '35.', '44.', '52.', '54.', '99.', '100.', '172.31.')
GCP_IP_PREFIXES = ('34.', '35.', '104.', '130.')
AZURE_IP_PREFIXES = ('13.', '20.', '40.', '52.', '104.', '137.', '168.')

# Known Tor-friendly hosting ISPs (case-insensitive partial match)
TOR_FRIENDLY_ISPS = [
    'hetzner', 'online.net', 'ovh', 'leaseweb', 'frantech', 'choopa', 'vultr',
    'm247', 'digitalocean', 'aeza', 'mullvad', 'privex', 'njal', 'buyvm',
    'tor', 'relay', 'exit', 'privacy', 'vpn', 'anonymous'
]


def is_likely_tor_exit(ip: str, isp: str = None) -> tuple:
    """
    Check if an IP is likely from a Tor exit relay vs cloud infrastructure.
    
    Returns:
        (is_likely_tor, confidence_factor, reason)
        - is_likely_tor: True if likely Tor, False if likely cloud/non-Tor
        - confidence_factor: Multiplier for confidence (1.0 = no change, 0.0 = reject)
        - reason: Explanation string
    """
    ip = str(ip)
    isp_lower = (isp or '').lower()
    
    # FIRST: Check Tor consensus (authoritative source)
    is_verified, relay_info = is_verified_tor_exit(ip)
    if is_verified:
        nickname = relay_info.get('nickname', 'Unknown') if relay_info else 'Unknown'
        return (True, 1.0, f"Verified Tor Exit relay: {nickname}")
    
    # If not in consensus, check for known cloud infrastructure (hard reject)
    
    # Check AWS patterns
    if ip.startswith(AWS_IP_PREFIXES):
        return (False, 0.0, f"AWS IP detected - NOT a Tor exit relay")
    
    # Check GCP patterns
    if ip.startswith(GCP_IP_PREFIXES):
        return (False, 0.0, f"GCP IP detected - NOT a Tor exit relay")
    
    # Check Azure patterns
    if ip.startswith(AZURE_IP_PREFIXES):
        return (False, 0.0, f"Azure IP detected - NOT a Tor exit relay")
    
    # Private IPs - destination server (hard reject)
    if ip.startswith(('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                      '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                      '172.28.', '172.29.', '172.30.', '172.31.')):
        return (False, 0.0, f"Private IP - destination server, not exit relay")
    
    # Check for known Tor-friendly ISPs (soft accept with lower confidence)
    for tor_isp in TOR_FRIENDLY_ISPS:
        if tor_isp in isp_lower:
            return (True, 0.7, f"Known Tor-friendly ISP but not in consensus: {isp}")
    
    # Unknown and NOT in consensus - reject for forensic accuracy
    return (False, 0.0, "Not verified in Tor consensus - cannot use for correlation")


# Global Tor consensus client (lazy-loaded)
_tor_consensus_client = None


def _get_tor_consensus():
    """Get or initialize the Tor consensus client."""
    global _tor_consensus_client
    if _tor_consensus_client is None:
        try:
            from tor_path_inference import TorConsensusClient
            _tor_consensus_client = TorConsensusClient()
            _tor_consensus_client.fetch_consensus()
            logger.info(f"✓ Tor consensus loaded for exit verification: {_tor_consensus_client.relay_count} relays")
        except Exception as e:
            logger.warning(f"⚠️ Could not load Tor consensus: {e}")
            _tor_consensus_client = False  # Mark as unavailable
    return _tor_consensus_client if _tor_consensus_client else None


def is_verified_tor_exit(ip: str) -> Tuple[bool, Optional[Dict]]:
    """
    Check if an IP is a VERIFIED Tor exit relay in the current consensus.
    
    This is the authoritative check - if an IP is not in the Tor consensus,
    it should NOT be used for exit correlation.
    
    Args:
        ip: IP address to check
        
    Returns:
        (is_verified, relay_info)
        - is_verified: True if IP is a known Tor exit relay
        - relay_info: Dict with relay metadata or None
    """
    consensus = _get_tor_consensus()
    if not consensus:
        logger.warning(f"Tor consensus unavailable - cannot verify {ip}")
        return (False, None)
    
    try:
        relays = consensus.get_relays_by_ip(ip)
        if relays:
            relay = relays[0] if isinstance(relays, list) else relays
            # Check if it has Exit flag
            flags = relay.flags if hasattr(relay, 'flags') else []
            if 'Exit' in flags:
                return (True, {
                    'nickname': relay.nickname if hasattr(relay, 'nickname') else 'Unknown',
                    'fingerprint': relay.fingerprint if hasattr(relay, 'fingerprint') else None,
                    'bandwidth': relay.bandwidth if hasattr(relay, 'bandwidth') else 0,
                    'flags': flags
                })
            else:
                # In consensus but not an Exit relay
                logger.debug(f"IP {ip} is a Tor relay but NOT an Exit (flags: {flags})")
                return (False, None)
        else:
            # Not in consensus at all
            return (False, None)
    except Exception as e:
        logger.error(f"Error checking Tor consensus for {ip}: {e}")
        return (False, None)


class ExitFlowExtractor:
    """
    Extract and normalize flows from exit-side PCAP/logs.
    Uses same flow representation as guard-side for consistency.
    """
    
    def __init__(self):
        self.flows = []
    
    def extract_from_pcap(self, pcap_path: str) -> List[Dict]:
        """
        Extract flows from exit-side PCAP file.
        
        IMPORTANT: Only flows involving VERIFIED Tor exit relays from the
        consensus are included. All other IPs are filtered out for forensic
        accuracy.
        
        Args:
            pcap_path: Path to exit PCAP file
            
        Returns:
            List of flow dictionaries with normalized format (Tor exits only)
        """
        try:
            from pcap_processor import PCAPParser
            parser = PCAPParser(min_packets=3)  # Lower threshold for exit flows
            raw_flows = parser.parse_pcap(pcap_path)
            
            if not raw_flows:
                logger.warning(f"No flows extracted from exit PCAP: {pcap_path}")
                return []
            
            # Normalize to correlation format
            # Filter to ONLY include flows with verified Tor exit IPs
            normalized_flows = []
            excluded_ssh = 0
            excluded_non_tor = 0
            verified_exits = set()
            rejected_ips = set()
            
            for flow_id, flow_session in raw_flows.items():
                # Skip SSH traffic (port 22) - this is admin traffic to the server, not Tor exit
                if ':22-' in flow_id or flow_id.endswith(':22'):
                    excluded_ssh += 1
                    continue
                
                # Extract external IP from flow
                external_ip = self._extract_external_ip(flow_id)
                if not external_ip:
                    continue
                
                # CRITICAL: Verify IP is a Tor exit relay
                is_verified, relay_info = is_verified_tor_exit(external_ip)
                if not is_verified:
                    # Log and skip non-Tor IPs
                    if external_ip not in rejected_ips:
                        rejected_ips.add(external_ip)
                        logger.info(f"⚠️ Filtered non-Tor IP: {external_ip} (not in Tor consensus)")
                    excluded_non_tor += 1
                    continue
                
                # Track verified exit for reporting
                verified_exits.add(external_ip)
                    
                normalized = self._normalize_flow(flow_id, flow_session)
                if normalized.get('packets', 0) > 0:
                    # Add exit relay metadata
                    normalized['exit_relay'] = relay_info
                    normalized_flows.append(normalized)
            
            if excluded_ssh > 0:
                logger.info(f"Excluded {excluded_ssh} SSH flows from exit correlation")
            
            if excluded_non_tor > 0:
                print(f"⚠️ Filtered {excluded_non_tor} flows with non-Tor IPs: {', '.join(sorted(rejected_ips))}")
            
            self.flows = normalized_flows
            logger.info(f"Extracted {len(normalized_flows)} VERIFIED Tor exit flows from {pcap_path}")
            
            # Report verified exits
            if verified_exits:
                print(f"✓ Verified Tor exit IPs: {', '.join(sorted(verified_exits))}")
            else:
                print(f"⚠️ No verified Tor exit IPs found in PCAP - correlation may be limited")
            
            return normalized_flows
            
        except ImportError as e:
            logger.error(f"PCAPParser not available: {e}")
            return []
        except Exception as e:
            logger.error(f"Exit flow extraction failed: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _extract_external_ip(self, flow_id: str) -> Optional[str]:
        """Extract the external (non-private) IP from a flow ID."""
        PRIVATE_PREFIXES = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                           '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                           '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')
        
        parts = flow_id.split('-')[:2]
        for p in parts:
            if ':' in p:
                ip = p.split(':')[0]
                if not ip.startswith(PRIVATE_PREFIXES):
                    return ip
        return None
    
    def _normalize_flow(self, flow_id: str, flow_session) -> Dict:
        """Normalize FlowSession to standard correlation format."""
        try:
            # FlowSession has ingress_packets and egress_packets lists of (timestamp, size) tuples
            ingress = getattr(flow_session, 'ingress_packets', [])
            egress = getattr(flow_session, 'egress_packets', [])
            
            # Combine all packets for correlation
            all_packets = [(t, s, 'in') for t, s in ingress] + [(t, s, 'out') for t, s in egress]
            all_packets.sort(key=lambda x: x[0])  # Sort by timestamp
            
            if not all_packets:
                return {'id': flow_id, 'packets': 0, 'timestamps': [], 'sizes': []}
            
            # Extract relative timestamps and sizes
            base_time = all_packets[0][0]
            timestamps = [pkt[0] - base_time for pkt in all_packets]
            sizes = [abs(pkt[1]) for pkt in all_packets]
            
            return {
                'id': flow_id,
                'packets': len(all_packets),
                'timestamps': timestamps,
                'sizes': sizes,
                'duration': max(timestamps) - min(timestamps) if timestamps else 0
            }
        except Exception as e:
            logger.error(f"Failed to normalize flow {flow_id}: {e}")
            return {'id': flow_id, 'packets': 0, 'timestamps': [], 'sizes': []}


class ExitCorrelator:
    """
    Correlate guard-side flows with exit-side flows.
    Uses timing, burst, and packet size distribution similarity.
    
    DOES NOT train new models - reuses existing statistical methods.
    """
    
    def __init__(self):
        self.stat_correlator = None
        if STAT_CORRELATOR_AVAILABLE:
            self.stat_correlator = StatisticalCorrelator()
    
    def correlate(self, guard_flows: List[Dict], exit_flows: List[Dict]) -> Dict:
        """
        Correlate guard and exit flows.
        
        Args:
            guard_flows: Flows from guard-side analysis
            exit_flows: Flows from exit-side PCAP
            
        Returns:
            Correlation results with scores
        """
        if not guard_flows or not exit_flows:
            logger.warning("Empty flows provided for correlation")
            return {'matched': False, 'score': 0.0, 'reason': 'No flows to correlate', 'per_session_scores': []}
        
        # Calculate pairwise similarities and track per-session scores
        best_match = None
        best_score = 0.0
        per_session_scores = []  # Track each session's best match score
        
        # DEBUG: Track scores per exit IP for debugging
        exit_ip_scores = {}  # {exit_ip: best_score}
        
        for g_flow in guard_flows:
            session_best_score = 0.0
            session_best_exit = None
            for e_flow in exit_flows:
                score = self._calculate_similarity(g_flow, e_flow)
                
                # Track score per exit IP for debugging
                e_flow_id = e_flow.get('id', '')
                parts = e_flow_id.split('-')[:2]
                for p in parts:
                    if ':' in p:
                        eip = p.split(':')[0]
                        if not eip.startswith(('127.', '192.168.', '10.', '172.')):
                            if eip not in exit_ip_scores or score > exit_ip_scores[eip]:
                                exit_ip_scores[eip] = score
                            break
                
                if score > session_best_score:
                    session_best_score = score
                    session_best_exit = e_flow.get('id')
                if score > best_score:
                    best_score = score
                    best_match = (g_flow.get('id'), e_flow.get('id'))
            
            # Record this session's best correlation
            per_session_scores.append({
                'guard_flow': g_flow.get('id'),
                'best_exit_flow': session_best_exit,
                'score': float(session_best_score),
                'matched': bool(session_best_score > 0.5)  # Convert to Python bool for JSON
            })
        
        matched = best_score > 0.5  # Threshold for positive correlation
        
        # DEBUG: Print scores per exit IP (sorted by score)
        if exit_ip_scores:
            sorted_scores = sorted(exit_ip_scores.items(), key=lambda x: x[1], reverse=True)
            scores_str = ", ".join([f"{ip}: {s*100:.1f}%" for ip, s in sorted_scores[:5]])
            print(f"   📊 Exit IP scores: {scores_str}")
        
        result = {
            'matched': matched,
            'score': float(best_score),
            'guard_flow': best_match[0] if best_match else None,
            'exit_flow': best_match[1] if best_match else None,
            'method': 'statistical',
            'per_session_scores': per_session_scores,  # Per-session tracking for progression
            'all_exit_scores': {ip: float(s) for ip, s in exit_ip_scores.items()}  # All exit IP scores for tie detection
        }
        
        logger.info(f"Exit correlation: matched={matched}, score={best_score:.3f}, sessions={len(per_session_scores)}")
        return result
    
    def _calculate_similarity(self, flow_a: Dict, flow_b: Dict) -> float:
        """Calculate similarity between two flows using advanced metrics with adaptive weighting."""
        import math
        
        # Get packet counts for adaptive weighting
        count_a = flow_a.get('packets', 0)
        count_b = flow_b.get('packets', 0)
        min_packets = min(count_a, count_b) if count_a > 0 and count_b > 0 else 0
        
        # Adaptive weights based on packet count (small flows have less reliable timing/size)
        if min_packets < 20:
            # Low packet count: reduce timing/size weight, increase count weight
            TIMING_WEIGHT = 0.20
            COUNT_WEIGHT = 0.35
            SIZE_DIST_WEIGHT = 0.15
            DURATION_WEIGHT = 0.15
            TOTAL_BYTES_WEIGHT = 0.15
        else:
            # Normal packet count: timing is most distinctive
            TIMING_WEIGHT = 0.35
            COUNT_WEIGHT = 0.15
            SIZE_DIST_WEIGHT = 0.20
            DURATION_WEIGHT = 0.15
            TOTAL_BYTES_WEIGHT = 0.15
        
        weighted_score = 0.0
        total_weight = 0.0
        eps = 1e-6  # Epsilon for log normalization
        
        # 1. Timing similarity with lag tolerance (highest weight when enough packets)
        timing_score = self._timing_similarity_with_lag(
            flow_a.get('timestamps', []),
            flow_b.get('timestamps', [])
        )
        if timing_score > 0:
            weighted_score += timing_score * TIMING_WEIGHT
            total_weight += TIMING_WEIGHT
        
        # 2. Packet count similarity using log-normalized difference
        if count_a > 0 and count_b > 0:
            log_a = math.log(count_a + eps)
            log_b = math.log(count_b + eps)
            max_log = max(abs(log_a), abs(log_b), eps)
            count_score = 1 - abs(log_a - log_b) / max_log
            count_score = max(0, min(1, count_score))  # Clamp to [0, 1]
            weighted_score += count_score * COUNT_WEIGHT
            total_weight += COUNT_WEIGHT
        
        # 3. Size distribution similarity using Jensen-Shannon Divergence
        size_score = self._size_distribution_jsd(
            flow_a.get('sizes', []),
            flow_b.get('sizes', [])
        )
        if size_score > 0:
            weighted_score += size_score * SIZE_DIST_WEIGHT
            total_weight += SIZE_DIST_WEIGHT
        
        # 4. Duration similarity using log-normalized difference
        dur_a = flow_a.get('duration', 0)
        dur_b = flow_b.get('duration', 0)
        if dur_a > 0 and dur_b > 0:
            log_dur_a = math.log(dur_a + eps)
            log_dur_b = math.log(dur_b + eps)
            max_log_dur = max(abs(log_dur_a), abs(log_dur_b), eps)
            duration_score = 1 - abs(log_dur_a - log_dur_b) / max_log_dur
            duration_score = max(0, min(1, duration_score))
            weighted_score += duration_score * DURATION_WEIGHT
            total_weight += DURATION_WEIGHT
        
        # 5. Total bytes similarity using log-normalized difference
        sizes_a = flow_a.get('sizes', [])
        sizes_b = flow_b.get('sizes', [])
        bytes_a = sum(sizes_a) if sizes_a else 0
        bytes_b = sum(sizes_b) if sizes_b else 0
        if bytes_a > 0 and bytes_b > 0:
            log_bytes_a = math.log(bytes_a + eps)
            log_bytes_b = math.log(bytes_b + eps)
            max_log_bytes = max(abs(log_bytes_a), abs(log_bytes_b), eps)
            bytes_score = 1 - abs(log_bytes_a - log_bytes_b) / max_log_bytes
            bytes_score = max(0, min(1, bytes_score))
            weighted_score += bytes_score * TOTAL_BYTES_WEIGHT
            total_weight += TOTAL_BYTES_WEIGHT
        
        # Return normalized weighted average
        return weighted_score / total_weight if total_weight > 0 else 0.0
    
    def _timing_similarity_with_lag(self, times_a: List, times_b: List, max_lag: int = 3) -> float:
        """Calculate timing pattern similarity with lag tolerance.
        
        Computes max cosine similarity across ±max_lag packet shifts to handle
        timing offsets between entry and exit captures.
        """
        if not times_a or not times_b:
            return 0.0
        
        # Compare inter-packet delays
        ipt_a = np.diff(times_a) if len(times_a) > 1 else np.array([0])
        ipt_b = np.diff(times_b) if len(times_b) > 1 else np.array([0])
        
        ipt_a = np.array(ipt_a)
        ipt_b = np.array(ipt_b)
        
        if len(ipt_a) < 2 or len(ipt_b) < 2:
            return 0.0
        
        # Normalize
        max_val = max(np.max(np.abs(ipt_a)), np.max(np.abs(ipt_b)), 1e-6)
        ipt_a_norm = ipt_a / max_val
        ipt_b_norm = ipt_b / max_val
        
        # Compute max cosine similarity across lags
        best_score = 0.0
        for lag in range(-max_lag, max_lag + 1):
            if lag >= 0:
                a_slice = ipt_a_norm[lag:]
                b_slice = ipt_b_norm[:len(a_slice)]
            else:
                b_slice = ipt_b_norm[-lag:]
                a_slice = ipt_a_norm[:len(b_slice)]
            
            min_len = min(len(a_slice), len(b_slice))
            if min_len < 2:
                continue
            
            a_slice = a_slice[:min_len]
            b_slice = b_slice[:min_len]
            
            # Cosine similarity
            dot = np.dot(a_slice, b_slice)
            norm = np.linalg.norm(a_slice) * np.linalg.norm(b_slice)
            
            if norm > 0:
                cosine_sim = (dot / norm + 1) / 2  # Map to [0, 1]
                best_score = max(best_score, cosine_sim)
        
        return best_score
    
    def _size_distribution_jsd(self, sizes_a: List, sizes_b: List) -> float:
        """Compare packet size distributions using Jensen-Shannon Divergence.
        
        Returns similarity as: 1 - JSD(hist_a, hist_b)
        """
        if not sizes_a or not sizes_b:
            return 0.0
        
        # Bin packet sizes
        bins = [0, 100, 300, 500, 800, 1000, 1200, 1500, float('inf')]
        hist_a, _ = np.histogram(sizes_a, bins=bins)
        hist_b, _ = np.histogram(sizes_b, bins=bins)
        
        # Normalize to probability distributions
        eps = 1e-10
        p = hist_a / (hist_a.sum() + eps)
        q = hist_b / (hist_b.sum() + eps)
        
        # Add epsilon to avoid log(0)
        p = p + eps
        q = q + eps
        
        # Renormalize
        p = p / p.sum()
        q = q / q.sum()
        
        # Jensen-Shannon Divergence
        m = (p + q) / 2
        kl_pm = np.sum(p * np.log(p / m))
        kl_qm = np.sum(q * np.log(q / m))
        jsd = (kl_pm + kl_qm) / 2
        
        # JSD is in [0, log(2)], normalize to [0, 1] and invert for similarity
        jsd_normalized = jsd / np.log(2)
        similarity = 1 - jsd_normalized
        
        return max(0, min(1, similarity))
    
    def _timing_similarity(self, times_a: List, times_b: List) -> float:
        """Legacy method - calls new lag-tolerant version."""
        return self._timing_similarity_with_lag(times_a, times_b)
    
    def _size_distribution_similarity(self, sizes_a: List, sizes_b: List) -> float:
        """Compare packet size distributions."""
        if not sizes_a or not sizes_b:
            return 0.0
        
        # Bin packet sizes
        bins = [0, 100, 500, 1000, 1500, float('inf')]
        hist_a, _ = np.histogram(sizes_a, bins=bins)
        hist_b, _ = np.histogram(sizes_b, bins=bins)
        
        # Normalize
        hist_a = hist_a / (np.sum(hist_a) + 1e-6)
        hist_b = hist_b / (np.sum(hist_b) + 1e-6)
        
        # Histogram intersection
        return float(np.sum(np.minimum(hist_a, hist_b)))


class IndirectExitEvidenceScorer:
    """
    Compute partial confidence boost from indirect exit evidence.
    
    FORENSIC RATIONALE:
    When direct guard↔exit correlation fails threshold (< 0.5), we can still
    extract probabilistic value from circumstantial exit indicators.
    
    CRITICAL CONSTRAINTS:
    - This NEVER sets exit_confirmation = true
    - This ONLY contributes additive partial boost (capped at MAX_INDIRECT_BOOST)
    - All factors are individually bounded and defensible
    
    Each factor represents a forensically-relevant indicator that provides
    probabilistic support without meeting the threshold for confirmation.
    """
    
    # Factor weights - conservative defaults summing to MAX_INDIRECT_BOOST
    # Each weight represents the maximum contribution from that factor
    WEIGHTS = {
        'known_exit_asn': 0.08,      # Exit IP belongs to known Tor exit ASN/family
        'temporal_overlap': 0.06,    # Traffic timing overlaps guard-side windows
        'burst_similarity': 0.04,    # Packet burst patterns show weak similarity
        'session_duration': 0.04,    # Session length within Tor circuit norms
        'guard_stability': 0.03,     # Guard connection maintained for expected duration
    }
    
    # Hard cap on total indirect contribution - never exceed this
    MAX_INDIRECT_BOOST = 0.25
    
    # Known Tor exit ASN prefixes (common hosting providers for Tor exits)
    # Forensic note: Membership in these ASNs indicates higher probability of Tor exit
    KNOWN_TOR_EXIT_ASNS = {
        'AS24940',   # Hetzner (Germany) - major Tor exit host
        'AS16276',   # OVH (France) - significant Tor presence
        'AS12876',   # Scaleway (France)
        'AS51167',   # Contabo (Germany)
        'AS60781',   # LeaseWeb (Netherlands)
        'AS9009',    # M247 (UK/Romania)
        'AS20473',   # Choopa/Vultr - common VPS for exits
        'AS14061',   # DigitalOcean
        'AS63949',   # Linode
    }
    
    @classmethod
    def compute(
        cls,
        exit_flows: List[Dict],
        guard_flow: Optional[Dict],
        metadata: Optional[Dict] = None,
        direct_score: float = 0.0
    ) -> Dict:
        """
        Compute indirect exit evidence score from multiple factors.
        
        Args:
            exit_flows: Extracted flows from exit-side PCAP
            guard_flow: Best matching guard-side flow (if any)
            metadata: Additional context (ASN, timing, etc.)
            direct_score: The direct correlation score that failed threshold
            
        Returns:
            Dict with:
            - indirect_score: Total capped indirect boost
            - factor_scores: Individual factor contributions
            - factor_details: Forensic explanation for each factor
        """
        metadata = metadata or {}
        factor_scores = {}
        factor_details = {}
        
        # Factor 1: Known Exit ASN (0.08 max)
        # Forensic rationale: Exit IPs in known Tor hosting ASNs have higher
        # prior probability of being actual Tor exits
        asn_score, asn_detail = cls._score_known_exit_asn(exit_flows, metadata)
        factor_scores['known_exit_asn'] = asn_score
        factor_details['known_exit_asn'] = asn_detail
        
        # Factor 2: Temporal Overlap (0.06 max)
        # Forensic rationale: Traffic timing windows that overlap with guard
        # activity provide weak but non-zero attribution signal
        temporal_score, temporal_detail = cls._score_temporal_overlap(
            exit_flows, guard_flow, metadata
        )
        factor_scores['temporal_overlap'] = temporal_score
        factor_details['temporal_overlap'] = temporal_detail
        
        # Factor 3: Burst Similarity (0.04 max)
        # Forensic rationale: Weak packet burst similarity below threshold
        # still carries some correlation signal
        burst_score, burst_detail = cls._score_burst_similarity(
            exit_flows, guard_flow, direct_score
        )
        factor_scores['burst_similarity'] = burst_score
        factor_details['burst_similarity'] = burst_detail
        
        # Factor 4: Session Duration Plausibility (0.04 max)
        # Forensic rationale: Tor circuits typically last 10-600 seconds
        # Sessions within this range are more plausible
        duration_score, duration_detail = cls._score_session_duration(
            exit_flows, guard_flow, metadata
        )
        factor_scores['session_duration'] = duration_score
        factor_details['session_duration'] = duration_detail
        
        # Factor 5: Guard Stability (0.03 max)
        # Forensic rationale: Stable guard connections over time increase
        # confidence in guard→exit path attribution
        stability_score, stability_detail = cls._score_guard_stability(
            guard_flow, metadata
        )
        factor_scores['guard_stability'] = stability_score
        factor_details['guard_stability'] = stability_detail
        
        # Sum and cap at MAX_INDIRECT_BOOST
        raw_total = sum(factor_scores.values())
        indirect_score = min(raw_total, cls.MAX_INDIRECT_BOOST)
        
        logger.info(
            f"Indirect exit evidence: raw={raw_total:.4f}, "
            f"capped={indirect_score:.4f} (max={cls.MAX_INDIRECT_BOOST})"
        )
        
        return {
            'indirect_score': indirect_score,
            'factor_scores': factor_scores,
            'factor_details': factor_details,
            'was_capped': raw_total > cls.MAX_INDIRECT_BOOST
        }
    
    @classmethod
    def _score_known_exit_asn(
        cls, exit_flows: List[Dict], metadata: Dict
    ) -> Tuple[float, str]:
        """Check if exit IP belongs to known Tor exit ASN/family."""
        weight = cls.WEIGHTS['known_exit_asn']
        
        # Check metadata for ASN info
        exit_asn = metadata.get('exit_asn', '')
        
        if exit_asn and any(known in exit_asn for known in cls.KNOWN_TOR_EXIT_ASNS):
            return weight, f"Exit ASN {exit_asn} matches known Tor exit hosting provider"
        
        # Check for known exit IP indicators in flow metadata
        for flow in exit_flows:
            flow_asn = flow.get('asn', '')
            if flow_asn and any(known in flow_asn for known in cls.KNOWN_TOR_EXIT_ASNS):
                return weight * 0.8, f"Flow ASN {flow_asn} matches known exit provider"
        
        # No ASN match - check if we have exit flows at all (minimal score)
        if exit_flows:
            return weight * 0.2, "Exit flows present but ASN not in known Tor exit list"
        
        return 0.0, "No exit ASN information available"
    
    @classmethod
    def _score_temporal_overlap(
        cls, exit_flows: List[Dict], guard_flow: Optional[Dict], metadata: Dict
    ) -> Tuple[float, str]:
        """Evaluate temporal overlap between guard and exit traffic."""
        weight = cls.WEIGHTS['temporal_overlap']
        
        if not exit_flows or not guard_flow:
            return 0.0, "Insufficient flow data for temporal analysis"
        
        # Get guard timing window
        guard_timestamps = guard_flow.get('timestamps', [])
        if not guard_timestamps:
            return 0.0, "No guard timestamps available"
        
        guard_start = min(guard_timestamps) if guard_timestamps else 0
        guard_end = max(guard_timestamps) if guard_timestamps else 0
        guard_duration = guard_end - guard_start
        
        if guard_duration <= 0:
            return 0.0, "Invalid guard timing window"
        
        # Check exit flow timing overlap
        overlapping_flows = 0
        for flow in exit_flows:
            exit_timestamps = flow.get('timestamps', [])
            if exit_timestamps:
                exit_start = min(exit_timestamps)
                exit_end = max(exit_timestamps)
                
                # Check for temporal overlap (with Tor latency tolerance ~5s)
                tolerance = 5.0
                if (exit_start <= guard_end + tolerance and 
                    exit_end >= guard_start - tolerance):
                    overlapping_flows += 1
        
        if overlapping_flows == 0:
            return 0.0, "No temporal overlap between guard and exit traffic"
        
        overlap_ratio = min(overlapping_flows / max(len(exit_flows), 1), 1.0)
        score = weight * overlap_ratio
        
        return score, f"{overlapping_flows}/{len(exit_flows)} exit flows temporally overlap guard activity"
    
    @classmethod
    def _score_burst_similarity(
        cls, exit_flows: List[Dict], guard_flow: Optional[Dict], direct_score: float
    ) -> Tuple[float, str]:
        """Extract partial signal from burst similarity below threshold."""
        weight = cls.WEIGHTS['burst_similarity']
        
        # Use direct_score as proxy for burst similarity if available
        # The direct correlation already computed burst metrics
        if direct_score > 0:
            # Scale the sub-threshold score (0.0 to 0.5) to partial weight
            # e.g., direct_score of 0.4 → 80% of weight
            normalized = direct_score / 0.5
            score = weight * min(normalized, 1.0)
            return score, f"Burst correlation {direct_score:.2f} (below threshold, partial credit)"
        
        return 0.0, "No burst similarity data available"
    
    @classmethod
    def _score_session_duration(
        cls, exit_flows: List[Dict], guard_flow: Optional[Dict], metadata: Dict
    ) -> Tuple[float, str]:
        """Check if session duration is plausible for Tor circuits."""
        weight = cls.WEIGHTS['session_duration']
        
        # Tor circuit duration norms (seconds)
        MIN_TOR_CIRCUIT_DURATION = 10    # Circuits rarely shorter than 10s
        MAX_TOR_CIRCUIT_DURATION = 600   # Default circuit lifetime ~10 min
        OPTIMAL_RANGE = (30, 300)        # Most common range
        
        duration = None
        
        # Try to get duration from guard flow
        if guard_flow:
            duration = guard_flow.get('duration', 0)
        
        # Or from metadata
        if not duration:
            duration = metadata.get('session_duration', 0)
        
        if not duration or duration <= 0:
            return 0.0, "Session duration not available"
        
        # Score based on plausibility
        if OPTIMAL_RANGE[0] <= duration <= OPTIMAL_RANGE[1]:
            return weight, f"Session duration {duration:.1f}s within optimal Tor range"
        elif MIN_TOR_CIRCUIT_DURATION <= duration <= MAX_TOR_CIRCUIT_DURATION:
            return weight * 0.6, f"Session duration {duration:.1f}s within Tor circuit norms"
        elif duration < MIN_TOR_CIRCUIT_DURATION:
            return weight * 0.2, f"Session duration {duration:.1f}s unusually short for Tor"
        else:
            return weight * 0.3, f"Session duration {duration:.1f}s exceeds typical Tor circuit lifetime"
    
    @classmethod
    def _score_guard_stability(
        cls, guard_flow: Optional[Dict], metadata: Dict
    ) -> Tuple[float, str]:
        """Evaluate historical guard connection stability."""
        weight = cls.WEIGHTS['guard_stability']
        
        # Check for stability indicators in metadata
        guard_observations = metadata.get('guard_observation_count', 1)
        guard_persistence = metadata.get('guard_persistence_hours', 0)
        
        # Multiple observations of same guard increases confidence
        if guard_observations >= 5:
            return weight, f"Guard observed {guard_observations} times (high stability)"
        elif guard_observations >= 2:
            return weight * 0.6, f"Guard observed {guard_observations} times (moderate stability)"
        elif guard_persistence >= 24:
            return weight * 0.5, f"Guard connection persisted {guard_persistence}h"
        elif guard_flow:
            return weight * 0.3, "Guard flow present (single observation)"
        
        return 0.0, "No guard stability data available"


class ConfidenceAggregator:
    """
    Aggregate guard-only and exit correlation confidence.
    
    Supports three correlation modes:
    1. guard_only: No exit-side data available
    2. guard+exit_indirect: Exit data present but direct correlation < threshold
    3. guard+exit_confirmed: Direct exit correlation >= threshold
    
    FORENSIC CONSTRAINT:
    - exit_confirmation = true ONLY for guard+exit_confirmed mode
    - Indirect evidence NEVER elevates exit_confirmation to true
    """
    
    # Exit boost parameters (for DIRECT confirmation only)
    MAX_BOOST = 0.30  # Maximum 30% confidence increase for direct confirmation
    BOOST_WEIGHT = 0.5  # How much exit score affects boost
    
    # Confidence classification thresholds
    CONFIDENCE_THRESHOLDS = {
        'HIGH': 0.75,
        'MEDIUM': 0.50,
        'LOW': 0.0
    }
    
    @classmethod
    def _classify_confidence(cls, confidence: float) -> str:
        """Classify confidence into forensically-meaningful levels."""
        if confidence >= cls.CONFIDENCE_THRESHOLDS['HIGH']:
            return 'HIGH'
        elif confidence >= cls.CONFIDENCE_THRESHOLDS['MEDIUM']:
            return 'MEDIUM'
        return 'LOW'
    
    @classmethod
    def _build_origin_assessment(
        cls,
        guard_ip: Optional[str],
        final_confidence: float,
        confidence_sources: List[str],
        exit_evidence_type: str
    ) -> Dict:
        """
        Build standardized origin assessment for forensic output.
        
        FORENSIC NOTE: This structure is designed for police use and must
        remain legally conservative. All claims are probabilistic.
        """
        return {
            'primary_guard_ip': guard_ip,
            'final_confidence': final_confidence,
            'confidence_class': cls._classify_confidence(final_confidence),
            'confidence_sources': confidence_sources,
            'exit_evidence_type': exit_evidence_type,
            'forensic_note': 'Probabilistic attribution — not exact identification'
        }
    
    @classmethod
    def aggregate(
        cls,
        guard_confidence: float,
        exit_result: Optional[Dict] = None,
        guard_ip: Optional[str] = None,
        exit_flows: Optional[List[Dict]] = None,
        guard_flow: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
        session_count: int = 1  # Number of corroborating sessions within PCAP
    ) -> Dict:
        """
        Combine guard and exit confidence scores with confidence accumulation.
        
        Args:
            guard_confidence: Baseline guard-only confidence (0-1)
            exit_result: Exit correlation result dict (optional)
            guard_ip: IP of the primary guard node (for origin_assessment)
            exit_flows: Exit flows for indirect scoring (optional)
            guard_flow: Guard flow for indirect scoring (optional)
            metadata: Additional metadata for indirect scoring (optional)
            session_count: Number of sessions within PCAP that corroborate the finding
            
        Returns:
            Aggregated confidence with metadata including origin_assessment
        """
        # =====================================================================
        # SESSION CORROBORATION BOOST
        # More sessions within the PCAP that agree = higher confidence
        # Formula: session_boost = 0.05 * log(1 + session_count - 1) = 0.05 * log(session_count)
        # This adds up to ~0.1 boost for 7 sessions, ~0.15 for 20 sessions
        # =====================================================================
        session_boost = 0.0
        if session_count > 1:
            # Logarithmic boost for multiple corroborating sessions
            session_boost = 0.05 * np.log(session_count)
            logger.info(f"Session corroboration boost: +{session_boost:.3f} ({session_count} sessions)")
        # =====================================================================
        # CASE 1: No exit data at all → guard_only mode
        # =====================================================================
        if exit_result is None:
            # Apply session boost even in guard-only mode
            final_confidence = min(guard_confidence + session_boost, 0.999999)
            return {
                'final_confidence': final_confidence,
                'guard_confidence': guard_confidence,
                'exit_boost': 0.0,
                'session_boost': session_boost,
                'session_count': session_count,
                'mode': 'guard_only',
                'exit_confirmation': False,
                'note': f'Guard-only analysis ({session_count} sessions)',
                'origin_assessment': cls._build_origin_assessment(
                    guard_ip=guard_ip,
                    final_confidence=final_confidence,
                    confidence_sources=['guard_flow_correlation'],
                    exit_evidence_type='none'
                )
            }
        
        # =====================================================================
        # CASE 2: Direct exit correlation SUCCEEDED (>= threshold)
        # → guard+exit_confirmed mode, exit_confirmation = True
        # =====================================================================
        if exit_result.get('matched'):
            exit_score = exit_result.get('score', 0.0)
            exit_boost = exit_score * cls.BOOST_WEIGHT * cls.MAX_BOOST
            
            # Apply boost (multiplicative) + session boost and clamp
            boosted = guard_confidence * (1 + exit_boost) + session_boost
            final_confidence = min(boosted, 0.999999)
            
            return {
                'final_confidence': final_confidence,
                'guard_confidence': guard_confidence,
                'exit_boost': exit_boost,
                'session_boost': session_boost,
                'session_count': session_count,
                'exit_score': exit_score,
                'mode': 'guard+exit_confirmed',
                'exit_confirmation': True,  # ONLY true for direct confirmation
                'note': f'Guard + Exit corroboration ({session_count} sessions)',
                'origin_assessment': cls._build_origin_assessment(
                    guard_ip=guard_ip,
                    final_confidence=final_confidence,
                    confidence_sources=['guard_flow_correlation', 'direct_exit_correlation'],
                    exit_evidence_type='direct'
                )
            }
        
        # =====================================================================
        # CASE 3: Direct exit correlation FAILED (< threshold)
        # → Try indirect evidence scoring for partial boost
        # → guard+exit_indirect mode, exit_confirmation = False (NEVER elevated)
        # =====================================================================
        direct_score = exit_result.get('score', 0.0)
        
        # Compute indirect evidence score
        indirect_result = IndirectExitEvidenceScorer.compute(
            exit_flows=exit_flows or [],
            guard_flow=guard_flow,
            metadata=metadata,
            direct_score=direct_score
        )
        
        indirect_boost = indirect_result.get('indirect_score', 0.0)
        
        # Apply indirect boost + session boost (additive)
        # final_confidence = clamp(guard_confidence + indirect_boost + session_boost, 0.0, 0.999999)
        final_confidence = min(guard_confidence + indirect_boost + session_boost, 0.999999)
        final_confidence = max(final_confidence, 0.0)
        
        # Determine mode based on whether we got any indirect evidence
        if indirect_boost > 0:
            mode = 'guard+exit_indirect'
            note = f'Guard + indirect exit evidence (boost: {indirect_boost:.3f}, {session_count} sessions)'
            confidence_sources = ['guard_flow_correlation', 'indirect_exit_evidence']
            exit_evidence_type = 'indirect'
        else:
            mode = 'guard_only'
            note = f'No exit-side confirmation ({session_count} sessions)'
            confidence_sources = ['guard_flow_correlation']
            exit_evidence_type = 'none'
        
        return {
            'final_confidence': final_confidence,
            'guard_confidence': guard_confidence,
            'exit_boost': indirect_boost,  # Using indirect boost when direct fails
            'session_boost': session_boost,
            'session_count': session_count,
            'direct_score': direct_score,  # Preserve the failed direct score
            'indirect_evidence': indirect_result,  # Full breakdown for forensics
            'mode': mode,
            'exit_confirmation': False,  # CRITICAL: Never true for indirect
            'note': note,
            'origin_assessment': cls._build_origin_assessment(
                guard_ip=guard_ip,
                final_confidence=final_confidence,
                confidence_sources=confidence_sources,
                exit_evidence_type=exit_evidence_type
            )
        }


# Convenience function for pipeline integration
def run_exit_correlation(
    guard_flows: List[Dict],
    exit_pcap_path: Optional[str],
    guard_confidence: float,
    guard_ip: Optional[str] = None,
    metadata: Optional[Dict] = None,
    session_count: int = 1  # Number of corroborating sessions within PCAP
) -> Tuple[Dict, Dict]:
    """
    Run full exit correlation pipeline with indirect evidence support.
    
    Args:
        guard_flows: Flows from guard analysis
        exit_pcap_path: Path to exit PCAP (optional)
        guard_confidence: Guard-only confidence score
        guard_ip: Primary guard node IP for origin_assessment (optional)
        metadata: Additional metadata for indirect scoring (optional)
        session_count: Number of sessions within PCAP that corroborate (default 1)
        
    Returns:
        Tuple of (exit_result, aggregated_confidence)
    """
    import os
    logger.info(f"🔍 run_exit_correlation called with exit_pcap_path={exit_pcap_path}")
    
    if not exit_pcap_path:
        logger.warning("❌ exit_pcap_path is None or empty - falling back to guard-only")
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=guard_confidence,
            exit_result=None,
            guard_ip=guard_ip,
            session_count=session_count
        )
        return {}, agg
    
    # Check if file exists
    if not os.path.exists(exit_pcap_path):
        logger.error(f"❌ Exit PCAP file does not exist: {exit_pcap_path}")
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=guard_confidence,
            exit_result={'matched': False, 'score': 0.0},
            guard_ip=guard_ip,
            exit_flows=[],
            guard_flow=guard_flows[0] if guard_flows else None,
            metadata=metadata,
            session_count=session_count
        )
        return {'error': f'Exit PCAP not found: {exit_pcap_path}'}, agg
    
    logger.info(f"✅ Exit PCAP file exists: {exit_pcap_path}")
    
    # Extract exit flows
    extractor = ExitFlowExtractor()
    exit_flows = extractor.extract_from_pcap(exit_pcap_path)
    
    logger.info(f"🔍 Extracted {len(exit_flows)} exit flows")
    
    if not exit_flows:
        logger.warning("Exit PCAP extraction returned no flows")
        agg = ConfidenceAggregator.aggregate(
            guard_confidence=guard_confidence,
            exit_result={'matched': False, 'score': 0.0},
            guard_ip=guard_ip,
            exit_flows=[],
            guard_flow=guard_flows[0] if guard_flows else None,
            metadata=metadata,
            session_count=session_count
        )
        return {'error': 'No exit flows extracted'}, agg
    
    # Run direct correlation
    correlator = ExitCorrelator()
    exit_result = correlator.correlate(guard_flows, exit_flows)
    
    # Add exit_flows to result for downstream indirect scoring access
    exit_result['exit_flows'] = exit_flows
    # Note: guard_flow is already set by correlator.correlate() as just the ID string
    
    # =========================================================================
    # TOR EXIT VALIDATION: Penalize non-Tor exit IPs (AWS, GCP, Azure, etc.)
    # =========================================================================
    exit_flow_str = exit_result.get('exit_flow', '')
    if exit_flow_str and isinstance(exit_flow_str, str):
        # Extract public IP from exit_flow
        parts = exit_flow_str.split('-')[:2]
        ips = [p.split(':')[0] for p in parts if ':' in p]
        private_prefixes = ('127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
                           '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', 
                           '172.28.', '172.29.', '172.30.', '172.31.')
        
        exit_ip = None
        for ip in ips:
            if not ip.startswith(private_prefixes):
                exit_ip = ip
                break
        
        if exit_ip:
            is_tor, penalty_factor, reason = is_likely_tor_exit(exit_ip)
            if is_tor is False:
                # Apply penalty to score and mark all sessions as unmatched
                old_score = exit_result.get('score', 0)
                exit_result['score'] = old_score * penalty_factor
                exit_result['matched'] = False  # Not a true match
                exit_result['exit_validation'] = {
                    'is_tor_exit': False,
                    'penalty_factor': penalty_factor,
                    'reason': reason,
                    'original_score': old_score
                }
                # Mark per-session scores as unmatched
                for session in exit_result.get('per_session_scores', []):
                    session['score'] = session.get('score', 0) * penalty_factor
                    session['matched'] = False
                    session['penalized'] = True
                logger.warning(f"⚠️ Exit validation: {reason} - Score reduced from {old_score:.1%} to {exit_result['score']:.1%}")
            else:
                exit_result['exit_validation'] = {'is_tor_exit': is_tor, 'reason': reason}
    
    # Aggregate confidence with full context for indirect evidence scoring
    agg = ConfidenceAggregator.aggregate(
        guard_confidence=guard_confidence,
        exit_result=exit_result,
        guard_ip=guard_ip,
        exit_flows=exit_flows,
        guard_flow=guard_flows[0] if guard_flows else None,
        metadata=metadata,
        session_count=session_count
    )
    
    # =========================================================================
    # SESSION ACCUMULATION: Update persistent evidence stores
    # =========================================================================
    if AGGREGATORS_AVAILABLE:
        # Extract exit IP from exit_flow string (format: "ip:port-ip:port-proto")
        observed_exit_ip = None
        exit_flow_str = exit_result.get('exit_flow', '')
        if exit_flow_str and isinstance(exit_flow_str, str):
            # Parse format like "172.31.45.157:80-185.220.101.15:37874-tcp"
            parts = exit_flow_str.split('-')
            if len(parts) >= 2:
                # Second part is the exit IP:port
                exit_part = parts[1]
                if ':' in exit_part:
                    observed_exit_ip = exit_part.split(':')[0]
        
        direct_score = exit_result.get('score', 0.0)
        indirect_score = agg.get('indirect_evidence', {}).get('indirect_score', 0.0) if agg.get('indirect_evidence') else 0.0
        matched = agg.get('exit_confirmation', False)
        mode = agg.get('mode', 'guard_only')
        
        # Update exit node evidence
        if observed_exit_ip:
            EXIT_AGGREGATOR.update_evidence(
                exit_ip=observed_exit_ip,
                direct_score=direct_score,
                indirect_score=indirect_score,
                matched=matched
            )
            logger.info(f"📊 Updated exit evidence for {observed_exit_ip}")
        
        # Update entry-exit pair correlation evidence
        CORRELATION_AGGREGATOR.update_pair(
            entry_ip=guard_ip,
            exit_ip=observed_exit_ip,
            entry_confidence=guard_confidence,
            exit_confidence=direct_score,
            combined_confidence=agg.get('final_confidence', guard_confidence),
            mode=mode
        )
        logger.info(f"📊 Updated correlation evidence for pair {guard_ip}::{observed_exit_ip or 'none'}")
        
        # Add accumulated stats to aggregation result
        agg['accumulated_evidence'] = {
            'guard_observations': CORRELATION_AGGREGATOR.get_entry_stats(guard_ip).get('total_observations', 0) if guard_ip else 0,
            'guard_historical_score': CORRELATION_AGGREGATOR.get_entry_stats(guard_ip).get('historical_score', 0.0) if guard_ip else 0.0,
            'exit_observations': EXIT_AGGREGATOR.get_observation_count(observed_exit_ip) if observed_exit_ip else 0,
            'exit_historical_score': EXIT_AGGREGATOR.get_historical_score(observed_exit_ip) if observed_exit_ip else 0.0,
            'pair_observations': CORRELATION_AGGREGATOR.get_pair_count(guard_ip, observed_exit_ip) if guard_ip else 0,
            'pair_historical_score': CORRELATION_AGGREGATOR.get_pair_score(guard_ip, observed_exit_ip) if guard_ip else 0.0
        }
    
    return exit_result, agg
