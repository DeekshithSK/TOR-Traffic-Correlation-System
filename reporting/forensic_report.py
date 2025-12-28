"""
Forensic Report Generation Module

Responsibilities:
- Generate case-style narrative reports
- Present probabilistic findings with appropriate confidence language
- Summarize methodology and limitations
- Output format: Markdown (convertible to PDF/HTML)

Tone: Investigator-focused, probabilistic, court-defensible.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import logging

from dataclasses import dataclass

@dataclass
class ForensicCaseParams:
    """Parameters for forensic case reporting."""
    case_reference: str
    investigator_name: str
    target_description: str

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ForensicReportGenerator:
    """
    Generates case reports from correlation results and aggregated evidence.
    """
    
    REPORT_TEMPLATE = """# TOR Traffic Analysis - Forensic Report

**Case Reference**: {case_ref}
**Date**: {date}
**Analyst**: Automated System (v2.0)


Traffic analysis was performed on target flow `{target_flow_id}` to identify potential entry points into the Tor network.
The system analyzed {candidate_count} candidate flows.

**Top Finding**:
The analysis identified **{top_suspect_id}** as the most probable guard node association, with a confidence of **{confidence:.1%}**.
*Note: This is a probabilistic correlation, not a definitive identification.*


This analysis utilizes a multi-stage correlation pipeline:
1.  **SUMo Filtering**: Traffic classification to isolate Tor-like flows.
2.  **Statistical Correlation**: Time-series analysis of packet sizes and inter-arrival times.
3.  **Siamese Network Verification**: Deep learning-based similarity scoring for refinement.
4.  **Evidence Aggregation**: Historical analysis of correlation persistence over time.

**Limitations**:
- Traffic correlation is statistical in nature.
- Results may be affected by network jitter, packet loss, or active countermeasures (padding).
- High confidence scores indicate strong flow similarity, not absolute proof of origin.



| Rank | Identifier / IP | Role | Confidence (Session) | Confidence (Aggr.) | Evidence Count |
|------|-----------------|------|----------------------|--------------------|----------------|
{ranking_table}

**Suspect**: `{top_suspect_id}`
{suspect_details}

- **First Observed**: {first_seen}
- **Last Observed**: {last_seen}
- **Total Correlated Sessions**: {evidence_count}


- **Target Flow Duration**: {duration}s
- **Statistical Model Weight**: {stat_weight}
- **Siamese Model Weight**: {siamese_weight}
- **Generated**: {timestamp}

---
*CONFIDENTIAL - FOR INVESTIGATIVE USE ONLY*
"""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, 
                        correlation_result: Dict, 
                        case_ref: str = "AUTO-001") -> str:
        """
        Generate a forensic report from a single correlation result.
        
        Args:
            correlation_result: Output from CorrelationPipeline.run()
            case_ref: Case reference ID.
            
        Returns:
            Path to the generated report file.
        """
        target_flow_id = correlation_result.get('target_flow_id', 'Unknown')
        ranked = correlation_result.get('ranked_candidates', [])
        metadata = correlation_result.get('metadata', {})
        
        if not ranked:
            logger.warning("No candidates provided for report.")
            return None
            
        top_suspect = ranked[0]
        top_id = top_suspect.get('guard_identifier', top_suspect['flow_id'])
        
        table_rows = []
        for i, suspect in enumerate(ranked[:5]):
            sid = suspect.get('guard_identifier', suspect['flow_id'])
            
            relay_info = suspect.get('tor_relay_info') or {}
            role = relay_info.get('role', 'Unknown')
            
            aggr_evidence = suspect.get('aggregated_evidence') or {}
            aggr_conf = aggr_evidence.get('confidence', 0.0)
            count = aggr_evidence.get('count', 0)
            
            row = f"| {i+1} | `{sid}` | {role} | {suspect['final']:.1%} | {aggr_conf:.1%} | {count} |"
            table_rows.append(row)
            
        ranking_table = "\n".join(table_rows)
        
        top_relay_info = top_suspect.get('tor_relay_info')
        suspect_details = ""
        if top_relay_info:
            suspect_details += f"\n**TOR Directory Info**:\n"
            suspect_details += f"- **Nickname**: {top_relay_info.get('nickname')}\n"
            suspect_details += f"- **Fingerprint**: `{top_relay_info.get('fingerprint')}`\n"
            suspect_details += f"- **Flags**: {', '.join(top_relay_info.get('flags', []))}\n"
        
        top_evidence = top_suspect.get('aggregated_evidence') or {}
        
        report_content = self.REPORT_TEMPLATE.format(
            case_ref=case_ref,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target_flow_id=target_flow_id,
            candidate_count=metadata.get('total_candidates', 0),
            top_suspect_id=top_id,
            confidence=top_suspect['final'],
            ranking_table=ranking_table,
            suspect_details=suspect_details,
            first_seen=top_evidence.get('first_seen', 'N/A'),
            last_seen=top_evidence.get('last_seen', 'N/A'),
            evidence_count=top_evidence.get('count', 1), # Current session counts as 1
            duration=f"{metadata.get('duration_seconds', 0):.2f}",
            stat_weight=metadata.get('statistical_weight', 0.7),
            siamese_weight=metadata.get('siamese_weight', 0.3),
            timestamp=datetime.now().isoformat()
        )
        
        filename = f"report_{case_ref}_{target_flow_id}.md"
        file_path = self.output_dir / filename
        
        with open(file_path, 'w') as f:
            f.write(report_content)
            
        logger.info(f"Report generated: {file_path}")
        return str(file_path)

if __name__ == "__main__":
    gen = ForensicReportGenerator("reports")
    
    dummy_result = {
        'target_flow_id': 'target_123',
        'metadata': {'total_candidates': 100, 'duration_seconds': 1.5},
        'ranked_candidates': [
            {
                'flow_id': 'flow_abc',
                'guard_identifier': '192.168.1.1',
                'final': 0.85,
                'tor_relay_info': {'nickname': 'GuardNode01', 'role': 'Guard', 'fingerprint': 'AAAA...'},
                'aggregated_evidence': {'confidence': 0.82, 'count': 5, 'first_seen': '2023-01-01', 'last_seen': '2023-01-02'}
            },
            {
                'flow_id': 'flow_xyz',
                'guard_identifier': '10.0.0.1',
                'final': 0.45,
                'tor_relay_info': None,
                'aggregated_evidence': None
            }
        ]
    }
    
    path = gen.generate_report(dummy_result, "TEST-CASE-001")
    print(f"Test report created at: {path}")
