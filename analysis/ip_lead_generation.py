"""
IP Lead Generation Module

Aggregates correlation results at IP level to produce actionable forensic leads.
"""

from collections import defaultdict
from typing import List, Dict, Any


def generate_ip_leads(ranked_candidates: List[Dict], min_flows: int = 2) -> List[Dict[str, Any]]:
    """
    Aggregate correlation candidates by client IP to generate IP-level leads.
    
    Args:
        ranked_candidates: List of correlation candidates with client_ip field
        min_flows: Minimum flows required to form an IP lead (default: 2)
        
    Returns:
        List of IP leads sorted by confidence descending
    """
    ip_buckets = defaultdict(list)

    for c in ranked_candidates:
        ip = c.get("client_ip")
        if ip:
            ip_buckets[ip].append(c)

    ip_leads = []

    for ip, flows in ip_buckets.items():
        if len(flows) < min_flows:
            continue

        avg_stat = sum(f["statistical"] for f in flows) / len(flows)

        siamese_vals = [f["siamese"] for f in flows if f["siamese"] is not None]
        avg_siamese = (
            sum(siamese_vals) / len(siamese_vals)
            if siamese_vals else None
        )

        confidence = sum(f["final"] for f in flows) / len(flows)

        ip_leads.append({
            "ip": ip,
            "confidence": round(confidence, 3),
            "flow_count": len(flows),
            "evidence": {
                "avg_statistical": round(avg_stat, 3),
                "avg_siamese": round(avg_siamese, 3) if avg_siamese else None
            }
        })

    ip_leads.sort(key=lambda x: x["confidence"], reverse=True)
    return ip_leads
