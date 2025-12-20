"""
Police UX Dashboard
Built with Streamlit and Plotly.

Visualizes:
1. Timeline of increasing confidence
2. Ranked suspects
3. Evidence details

Usage:
    streamlit run viz/dashboard.py
"""

import streamlit as st
import pandas as pd
import json
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime

# Set Page Config
st.set_page_config(
    page_title="TOR Traffic Analysis - Investigator Dashboard",
    page_icon="🕵️",
    layout="wide"
)

# Constants
EVIDENCE_FILE = Path("data/guard_evidence.json")
REPORT_DIR = Path("reports")

def load_evidence():
    if EVIDENCE_FILE.exists():
        with open(EVIDENCE_FILE, 'r') as f:
            return json.load(f)
    return {}

def main():
    st.title("🕵️ TOR Traffic Analysis System")
    st.markdown("### Investigator Dashboard")

    # Sidebar
    st.sidebar.header("Case Management")
    case_ref = st.sidebar.text_input("Case Reference", "CASE-2025-001")
    
    # 1. Top Suspects Overview
    st.header("1. Top Suspected Guard Nodes")
    
    evidence = load_evidence()
    
    if not evidence:
        st.warning("No evidence collected yet. Run the correlation pipeline to generate data.")
        return

    # Convert to DataFrame
    data = []
    for guard_id, info in evidence.items():
        count = info['count']
        avg_conf = info['total_confidence'] / count
        score = info.get('score', 0) # Might need to recompute if not saved
        # Recompute score if missing (backward compatibility)
        import numpy as np
        if 'score' not in info:
             score = np.log1p(count) * avg_conf
             
        data.append({
            'Guard ID': guard_id,
            'Evidence Count': count,
            'Avg Confidence': avg_conf,
            'Score': score,
            'Last Seen': info['last_seen']
        })
    
    df = pd.DataFrame(data).sort_values('Score', ascending=False)
    
    # Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Suspects", len(df))
    if not df.empty:
        col2.metric("Top Confidence", f"{df.iloc[0]['Avg Confidence']:.1%}")
        col3.metric("Most Active", df.iloc[0]['Guard ID'])

    # Ranking Chart
    fig = px.bar(
        df.head(10), 
        x='Score', 
        y='Guard ID', 
        orientation='h',
        color='Avg Confidence',
        title="Top Guards by Risk Score",
        labels={'Score': 'Risk Score (Freq × Conf)', 'Guard ID': 'Node Identifier'},
        color_continuous_scale='Reds'
    )
    fig.update_layout(yaxis={'categoryorder': 'total ascending'})
    st.plotly_chart(fig, use_container_width=True)

    # 2. Detailed View
    st.header("2. Suspect Details")
    
    selected_guard = st.selectbox("Select Suspect for Detailed Analysis", df['Guard ID'].tolist())
    
    if selected_guard:
        guard_data = evidence[selected_guard]
        timestamps = guard_data.get('timestamps', [guard_data['last_seen']]) # Fallback
        
        # Timeline
        st.subheader(f"Activity Timeline: {selected_guard}")
        
        # Mock up timeline data if we only have counts (for robust demo)
        # In real app, we'd store each event. Implementation in aggregator stores timestamps.
        
        timeline_df = pd.DataFrame({'Timestamp': timestamps})
        timeline_df['Timestamp'] = pd.to_datetime(timeline_df['Timestamp'])
        timeline_df = timeline_df.sort_values('Timestamp')
        timeline_df['Cumulative Count'] = range(1, len(timeline_df) + 1)
        
        line_fig = px.line(
            timeline_df, 
            x='Timestamp', 
            y='Cumulative Count',
            markers=True,
            title="Accumulation of Evidence Over Time"
        )
        st.plotly_chart(line_fig, use_container_width=True)
        
        # Network Graph (Conceptual)
        st.subheader("Network Path Visualization")
        # Simple Graphviz
        st.graphviz_chart(f"""
            digraph {{
                rankdir=LR;
                Target[label="Exit Traffic\\n(Observed)", shape=doublecircle, style=filled, fillcolor=lightblue];
                Guard[label="{selected_guard}\\n(Suspect)", shape=box, style=filled, fillcolor=red];
                Middle[label="???\\n(Encrypted)", shape=circle, style=dashed];
                
                Target -> Middle [label="Flow Correlation"];
                Middle -> Guard [label="Path Inference"];
            }}
        """)

    # 3. Reporting
    st.header("3. Forensic Report")
    if st.button("Generate Report for Case"):
        st.success(f"Report generation trigger simulated for {case_ref}. (Backend integration required for live generation from UI)")
        st.info("Check the 'reports/' directory for auto-generated reports from the pipeline.")

if __name__ == "__main__":
    main()
