"""
Traffic Analysis Dashboard - Streamlit Frontend
RECTor-based Traffic Analysis for macOS M2

This dashboard provides:
- Interactive PCAP/Pickle file processing
- Real-time inference with MPS acceleration
- Flow visualization and confidence scoring
"""

import streamlit as st
import torch
import numpy as np
import pandas as pd
import pickle
import os
from pathlib import Path
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Optional
import tempfile

# Import backend modules
from backend import (
    TrafficPreprocessor, 
    RectorEngine, 
    DEVICE,
    get_device
)

# Import TOR and PCAP modules
try:
    from tor_collector import TORCollector, OnionooClient
    from pcap_processor import FlowExtractor, PCAPToPickleConverter
    import config
    TOR_PCAP_AVAILABLE = True
except ImportError as e:
    TOR_PCAP_AVAILABLE = False
    import_error = str(e)


# ============================================================================
# Page Configuration
# ============================================================================

st.set_page_config(
    page_title="Traffic Analysis Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better aesthetics
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .info-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #667eea;
        margin: 1rem 0;
    }
    .stAlert {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Session State Initialization
# ============================================================================

if 'preprocessor' not in st.session_state:
    st.session_state.preprocessor = None

if 'engine' not in st.session_state:
    st.session_state.engine = None

if 'model_loaded' not in st.session_state:
    st.session_state.model_loaded = False

if 'processing_complete' not in st.session_state:
    st.session_state.processing_complete = False

if 'results' not in st.session_state:
    st.session_state.results = {}


# ============================================================================
# Utility Functions
# ============================================================================

def format_device_info(device: torch.device) -> str:
    """Format device information for display."""
    if device.type == 'mps':
        return "🚀 MPS (Apple Silicon)"
    elif device.type == 'cuda':
        return f"🎮 CUDA (GPU: {torch.cuda.get_device_name(0)})"
    else:
        return "💻 CPU"


def create_packet_timing_chart(flow_data: List[Dict], flow_type: str) -> go.Figure:
    """
    Create dual-axis line chart showing packet timing (Time vs Size).
    
    Args:
        flow_data: List of {'iat': float, 'size': float} dictionaries
        flow_type: 'Ingress' or 'Egress'
    
    Returns:
        Plotly figure object
    """
    if not flow_data or len(flow_data) == 0:
        # Return empty chart if no data
        fig = go.Figure()
        fig.add_annotation(
            text="No data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20, color="gray")
        )
        return fig
    
    # Extract data
    packet_indices = list(range(len(flow_data)))
    iats = [pkt['iat'] for pkt in flow_data]
    sizes = [pkt['size'] for pkt in flow_data]
    
    # Compute cumulative time
    cumulative_time = np.cumsum([abs(iat) for iat in iats])
    
    # Create figure with secondary y-axis
    fig = make_subplots(
        specs=[[{"secondary_y": True}]],
        subplot_titles=[f"{flow_type} Flow - Packet Timing Analysis"]
    )
    
    # Add IAT trace
    fig.add_trace(
        go.Scatter(
            x=cumulative_time,
            y=iats,
            name="Inter-Arrival Time (IAT)",
            mode='lines+markers',
            line=dict(color='#667eea', width=2),
            marker=dict(size=4)
        ),
        secondary_y=False,
    )
    
    # Add Size trace
    fig.add_trace(
        go.Scatter(
            x=cumulative_time,
            y=sizes,
            name="Packet Size",
            mode='lines+markers',
            line=dict(color='#f093fb', width=2),
            marker=dict(size=4)
        ),
        secondary_y=True,
    )
    
    # Update axes
    fig.update_xaxes(title_text="Cumulative Time (ms)")
    fig.update_yaxes(title_text="IAT (ms)", secondary_y=False)
    fig.update_yaxes(title_text="Packet Size (bytes)", secondary_y=True)
    
    # Update layout
    fig.update_layout(
        height=400,
        hovermode='x unified',
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        ),
        margin=dict(l=40, r=40, t=40, b=40)
    )
    
    return fig


def visualize_embedding(embedding: torch.Tensor, method: str = 'bar') -> go.Figure:
    """
    Visualize embedding vector.
    
    Args:
        embedding: Embedding tensor (1, emb_size)
        method: 'bar' or 'heatmap'
    
    Returns:
        Plotly figure
    """
    emb_array = embedding.cpu().detach().numpy().flatten()
    
    if method == 'bar':
        fig = go.Figure(data=[
            go.Bar(
                x=list(range(len(emb_array))),
                y=emb_array,
                marker=dict(
                    color=emb_array,
                    colorscale='Viridis',
                    showscale=True,
                    colorbar=dict(title="Value")
                )
            )
        ])
        fig.update_layout(
            title="Embedding Vector Components",
            xaxis_title="Dimension",
            yaxis_title="Value",
            height=300,
            margin=dict(l=40, r=40, t=40, b=40)
        )
    else:  # heatmap
        emb_2d = emb_array.reshape(1, -1)
        fig = go.Figure(data=go.Heatmap(
            z=emb_2d,
            colorscale='Viridis',
            showscale=True
        ))
        fig.update_layout(
            title="Embedding Vector Heatmap",
            height=150,
            margin=dict(l=40, r=40, t=40, b=40)
        )
    
    return fig


# ============================================================================
# Sidebar Configuration
# ============================================================================

st.sidebar.markdown("## ⚙️ Configuration")

# Device Status
st.sidebar.markdown("### 🔧 Device Status")
device_info = format_device_info(DEVICE)
st.sidebar.info(f"**Active Device:** {device_info}")

if DEVICE.type == 'mps':
    st.sidebar.success("✅ MPS Acceleration Enabled")
else:
    st.sidebar.warning("⚠️ MPS not available - using CPU")

st.sidebar.markdown("---")

# Model Configuration
st.sidebar.markdown("### 🧠 Model Configuration")

model_type = st.sidebar.selectbox(
    "Model Architecture",
    options=['gru', 'df'],
    format_func=lambda x: "GRU + Attention (MIL)" if x == 'gru' else "Deep Fingerprinting (CNN)",
    help="Choose the model architecture matching your trained model"
)

uploaded_model = st.sidebar.file_uploader(
    "Upload Model Weights (.pth)",
    type=['pth'],
    help="Upload your trained model from Colab"
)

emb_size = st.sidebar.number_input(
    "Embedding Size",
    min_value=16,
    max_value=512,
    value=64,
    step=16,
    help="Embedding dimension (must match your training config)"
)

seq_length = st.sidebar.number_input(
    "Sequence Length",
    min_value=100,
    max_value=5000,
    value=1000,
    step=100,
    help="Padded sequence length (tor_len * 2 from training)"
)

# Initialize or update model
if uploaded_model is not None:
    # Save uploaded model temporarily
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pth') as tmp_file:
        tmp_file.write(uploaded_model.read())
        tmp_path = tmp_file.name
    
    try:
        # Initialize engine
        if st.session_state.engine is None or st.session_state.engine.model_type != model_type:
            with st.spinner("Initializing model architecture..."):
                st.session_state.engine = RectorEngine(
                    model_type=model_type,
                    input_shape=(seq_length, 1),
                    emb_size=emb_size,
                    num_windows=11
                )
        
        # Load weights
        with st.spinner("Loading model weights..."):
            st.session_state.engine.load_weights(tmp_path)
            st.session_state.model_loaded = True
        
        st.sidebar.success("✅ Model loaded successfully!")
        
    except Exception as e:
        st.sidebar.error(f"❌ Error loading model: {str(e)}")
        st.session_state.model_loaded = False
    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

st.sidebar.markdown("---")

# Preprocessing Configuration
st.sidebar.markdown("### 📊 Preprocessing Settings")

threshold = st.sidebar.slider(
    "Packet Threshold",
    min_value=5,
    max_value=50,
    value=10,
    help="Minimum packets per window"
)

interval = st.sidebar.slider(
    "Time Interval (seconds)",
    min_value=1,
    max_value=10,
    value=5,
    help="Time window size"
)

num_windows = st.sidebar.slider(
    "Number of Windows",
    min_value=5,
    max_value=15,
    value=10,
    help="Number of overlapping windows"
)

st.sidebar.markdown("---")

# Confidence Threshold
confidence_threshold = st.sidebar.slider(
    "Confidence Threshold",
    min_value=0.0,
    max_value=1.0,
    value=0.5,
    step=0.05,
    help="Minimum confidence for positive match"
)


# ============================================================================
# Main Dashboard
# ============================================================================

st.markdown('<h1 class="main-header">🔍 Traffic Analysis Dashboard</h1>', unsafe_allow_html=True)
st.markdown("**RECTor-based Network Traffic Analysis for macOS M2**")

# Create tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📁 Data Processing", 
    "🔬 Inference", 
    "📊 Results",
    "🌐 TOR Network",
    "📦 PCAP Upload"
])


# ---------------------------------------------------------------------------
# TAB 1: Data Processing
# ---------------------------------------------------------------------------

with tab1:
    st.markdown("### Step 1: Create Overlapping Windows")
    st.markdown("Process your traffic data directory containing `inflow/` and `outflow/` subdirectories.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        data_directory = st.text_input(
            "Data Directory Path",
            value="./Evaluation_data/",
            help="Path to directory with inflow/outflow subdirectories"
        )
        
        output_qualified_list = st.text_input(
            "Output File (Qualified Flows)",
            value="./qualified_flows.txt",
            help="Where to save the list of qualified flow files"
        )
    
    with col2:
        st.markdown("#### Current Settings")
        st.info(f"""
        - **Threshold:** {threshold} packets
        - **Interval:** {interval}s
        - **Windows:** {num_windows}
        """)
    
    if st.button("🚀 Run Step 1: Create Windows", type="primary", use_container_width=True):
        if not os.path.exists(data_directory):
            st.error(f"❌ Directory not found: {data_directory}")
        else:
            try:
                with st.spinner("Creating overlapping windows..."):
                    # Initialize preprocessor
                    if st.session_state.preprocessor is None:
                        st.session_state.preprocessor = TrafficPreprocessor()
                    
                    # Run Step 1
                    qualified_flows = st.session_state.preprocessor.create_overlap_windows(
                        data_path=data_directory,
                        output_file=output_qualified_list,
                        threshold=threshold,
                        interval=interval,
                        num_windows=num_windows,
                        add_num=2
                    )
                    
                    st.success(f"✅ Step 1 Complete! Found {len(qualified_flows)} qualified flows.")
                    st.session_state.results['qualified_flows'] = qualified_flows
                    
                    # Display sample
                    if len(qualified_flows) > 0:
                        st.markdown("**Sample Qualified Flows:**")
                        st.code('\n'.join(qualified_flows[:10]))
                    
            except Exception as e:
                st.error(f"❌ Error in Step 1: {str(e)}")
    
    st.markdown("---")
    st.markdown("### Step 2: Extract Features")
    st.markdown("Deep processing with IAT/Size extraction and super-packet consolidation.")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        qualified_file_path = st.text_input(
            "Qualified Flows File",
            value=output_qualified_list,
            help="Path to qualified flows file from Step 1"
        )
        
        output_pickle_prefix = st.text_input(
            "Output Pickle Prefix",
            value="./processed/",
            help="Directory and prefix for output pickle files"
        )
    
    if st.button("🚀 Run Step 2: Extract Features", type="primary", use_container_width=True):
        if not os.path.exists(qualified_file_path):
            st.error(f"❌ Qualified flows file not found: {qualified_file_path}")
        else:
            try:
                with st.spinner("Extracting features from flows..."):
                    # Initialize preprocessor if needed
                    if st.session_state.preprocessor is None:
                        st.session_state.preprocessor = TrafficPreprocessor()
                    
                    # Run Step 2
                    st.session_state.preprocessor.process_window_files(
                        data_path=data_directory,
                        file_list_path=qualified_file_path,
                        output_prefix=output_pickle_prefix,
                        interval=interval,
                        num_windows=num_windows,
                        add_num=2
                    )
                    
                    st.success(f"✅ Step 2 Complete! Pickle files saved to: {output_pickle_prefix}")
                    st.session_state.processing_complete = True
                    
            except Exception as e:
                st.error(f"❌ Error in Step 2: {str(e)}")


# ---------------------------------------------------------------------------
# TAB 2: Inference
# ---------------------------------------------------------------------------

with tab2:
    st.markdown("### Upload Processed Data for Inference")
    
    if not st.session_state.model_loaded:
        st.warning("⚠️ Please upload a model in the sidebar first!")
    
    uploaded_pickle = st.file_uploader(
        "Upload Pickle File (from Step 2)",
        type=['pickle'],
        help="Upload a processed pickle file containing ingress/egress flows"
    )
    
    if uploaded_pickle is not None and st.session_state.model_loaded:
        # Save to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pickle') as tmp_file:
            tmp_file.write(uploaded_pickle.read())
            pickle_path = tmp_file.name
        
        try:
            with st.spinner("Loading and processing pickle file..."):
                # Initialize preprocessor
                if st.session_state.preprocessor is None:
                    st.session_state.preprocessor = TrafficPreprocessor()
                
                # Load data
                ingress_tensor, egress_tensor, labels = st.session_state.preprocessor.load_for_inference(
                    pickle_path=pickle_path,
                    pad_length=seq_length
                )
                
                st.success(f"✅ Loaded {len(labels)} flows")
                
                # Store in session
                st.session_state.results['ingress_tensor'] = ingress_tensor
                st.session_state.results['egress_tensor'] = egress_tensor
                st.session_state.results['labels'] = labels
                
                # Load original flow data for visualization
                with open(pickle_path, 'rb') as f:
                    pickle_data = pickle.load(f)
                st.session_state.results['raw_flows'] = pickle_data
                
            # Display sample flow
            st.markdown("### 📊 Sample Flow Visualization")
            
            flow_idx = st.selectbox(
                "Select Flow Index",
                options=list(range(min(10, len(labels)))),
                format_func=lambda x: f"Flow {x}: {labels[x]}"
            )
            
            # Get flow data
            ingress_flow = pickle_data['ingress'][flow_idx]
            egress_flow = pickle_data['egress'][flow_idx]
            
            # Display statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Ingress Packets", len(ingress_flow))
            with col2:
                st.metric("Egress Packets", len(egress_flow))
            with col3:
                total_bytes = sum(abs(p['size']) for p in ingress_flow + egress_flow)
                st.metric("Total Bytes", f"{total_bytes:,.0f}")
            with col4:
                duration = max(
                    sum(abs(p['iat']) for p in ingress_flow),
                    sum(abs(p['iat']) for p in egress_flow)
                )
                st.metric("Duration (ms)", f"{duration:.2f}")
            
            # Visualize flows
            col1, col2 = st.columns(2)
            
            with col1:
                st.plotly_chart(
                    create_packet_timing_chart(ingress_flow, "Ingress"),
                    use_container_width=True
                )
            
            with col2:
                st.plotly_chart(
                    create_packet_timing_chart(egress_flow, "Egress"),
                    use_container_width=True
                )
            
            st.markdown("---")
            
            # Run Inference
            st.markdown("### 🔬 Run Inference")
            
            if st.button("🚀 Run Model Inference", type="primary", use_container_width=True):
                with st.spinner("Running inference on MPS..."):
                    try:
                        # Prepare input
                        if st.session_state.engine.model_type == 'gru':
                            # GRU model expects (batch, num_windows, seq_len, 1)
                            # We need to load multiple windows - for now use single window replicated
                            ingress_input = ingress_tensor.unsqueeze(1).repeat(1, 11, 1, 1)
                            egress_input = egress_tensor.unsqueeze(1).repeat(1, 11, 1, 1)
                            
                            ingress_emb, ingress_attn = st.session_state.engine.inference(ingress_input)
                            egress_emb, egress_attn = st.session_state.engine.inference(egress_input)
                        else:
                            # DF model expects (batch, seq_len, 1)
                            ingress_emb = st.session_state.engine.inference(ingress_tensor)
                            egress_emb = st.session_state.engine.inference(egress_tensor)
                        
                        # Calculate confidence scores
                        confidence_scores = []
                        for i in range(len(labels)):
                            score = st.session_state.engine.get_confidence_score(
                                ingress_emb[i:i+1],
                                egress_emb[i:i+1]
                            )
                            confidence_scores.append(score)
                        
                        # Store results
                        st.session_state.results['ingress_embeddings'] = ingress_emb
                        st.session_state.results['egress_embeddings'] = egress_emb
                        st.session_state.results['confidence_scores'] = confidence_scores
                        
                        st.success("✅ Inference complete!")
                        
                        # Display results for selected flow
                        st.markdown(f"### Results for Flow {flow_idx}")
                        
                        # Confidence score
                        confidence = confidence_scores[flow_idx]
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.metric(
                                "Confidence Score",
                                f"{confidence:.4f}",
                                delta="Match" if confidence >= confidence_threshold else "No Match",
                                delta_color="normal" if confidence >= confidence_threshold else "inverse"
                            )
                        
                        with col2:
                            # Progress bar
                            st.metric("Threshold", confidence_threshold)
                            st.progress(min(confidence, 1.0))
                        
                        # Embedding visualization
                        st.markdown("#### Embedding Vectors")
                        
                        viz_method = st.radio(
                            "Visualization Method",
                            options=['bar', 'heatmap'],
                            horizontal=True
                        )
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown("**Ingress Embedding**")
                            st.plotly_chart(
                                visualize_embedding(ingress_emb[flow_idx:flow_idx+1], viz_method),
                                use_container_width=True
                            )
                        
                        with col2:
                            st.markdown("**Egress Embedding**")
                            st.plotly_chart(
                                visualize_embedding(egress_emb[flow_idx:flow_idx+1], viz_method),
                                use_container_width=True
                            )
                        
                    except Exception as e:
                        st.error(f"❌ Inference error: {str(e)}")
                        import traceback
                        st.code(traceback.format_exc())
        
        finally:
            # Clean up
            if os.path.exists(pickle_path):
                os.remove(pickle_path)


# ---------------------------------------------------------------------------
# TAB 3: Results
# ---------------------------------------------------------------------------

with tab3:
    st.markdown("### 📊 Analysis Results")
    
    if 'confidence_scores' in st.session_state.results:
        scores = st.session_state.results['confidence_scores']
        labels = st.session_state.results['labels']
        
        # Summary statistics
        st.markdown("#### Summary Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Flows", len(scores))
        with col2:
            st.metric("Mean Confidence", f"{np.mean(scores):.4f}")
        with col3:
            st.metric("Max Confidence", f"{np.max(scores):.4f}")
        with col4:
            matches = sum(1 for s in scores if s >= confidence_threshold)
            st.metric("Matches", f"{matches}/{len(scores)}")
        
        # Confidence distribution
        st.markdown("#### Confidence Score Distribution")
        
        fig = go.Figure()
        fig.add_trace(go.Histogram(
            x=scores,
            nbinsx=30,
            marker=dict(
                color='#667eea',
                line=dict(color='white', width=1)
            ),
            name='Confidence Scores'
        ))
        
        # Add threshold line
        fig.add_vline(
            x=confidence_threshold,
            line_dash="dash",
            line_color="red",
            annotation_text=f"Threshold: {confidence_threshold}",
            annotation_position="top right"
        )
        
        fig.update_layout(
            xaxis_title="Confidence Score",
            yaxis_title="Frequency",
            height=400,
            showlegend=False
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Results table
        st.markdown("#### Detailed Results")
        
        results_df = pd.DataFrame({
            'Flow ID': labels,
            'Confidence': scores,
            'Match': ['✅' if s >= confidence_threshold else '❌' for s in scores]
        })
        
        st.dataframe(
            results_df,
            use_container_width=True,
            height=400
        )
        
        # Export options
        st.markdown("#### 💾 Export Results")
        
        col1, col2 = st.columns(2)
        
        with col1:
            csv_data = results_df.to_csv(index=False)
            st.download_button(
                label="📥 Download as CSV",
                data=csv_data,
                file_name="traffic_analysis_results.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            # Export embeddings
            if 'ingress_embeddings' in st.session_state.results:
                ingress_np = st.session_state.results['ingress_embeddings'].cpu().detach().numpy()
                egress_np = st.session_state.results['egress_embeddings'].cpu().detach().numpy()
                
                # Save as npz
                import io
                buffer = io.BytesIO()
                np.savez_compressed(
                    buffer,
                    ingress=ingress_np,
                    egress=egress_np,
                    labels=np.array(labels),
                    scores=np.array(scores)
                )
                buffer.seek(0)
                
                st.download_button(
                    label="📥 Download Embeddings (.npz)",
                    data=buffer,
                    file_name="embeddings.npz",
                    mime="application/octet-stream",
                    use_container_width=True
                )
    
    else:
        st.info("👈 Run inference in the 'Inference' tab to see results here.")


# ---------------------------------------------------------------------------
# TAB 4: TOR Network
# ---------------------------------------------------------------------------

with tab4:
    st.markdown("### 🌐 TOR Network Data Collection")
    
    if not TOR_PCAP_AVAILABLE:
        st.error(f"❌ TOR/PCAP modules not available: {import_error}")
        st.info("Make sure all dependencies are installed: `pip install -r requirements.txt`")
    else:
        st.markdown("""
        Collect and visualize TOR network relay information including guard nodes, 
        middle relays, and exit nodes with bandwidth and uptime statistics.
        """)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("#### Collection Controls")
            
            if st.button("🚀 Collect TOR Network Snapshot", type="primary", use_container_width=True):
                with st.spinner("Collecting TOR network data from Onionoo API..."):
                    try:
                        collector = TORCollector()
                        graph = collector.collect_snapshot()
                        
                        st.success("✅ Snapshot collected successfully!")
                        st.session_state.results['tor_graph'] = graph
                        
                        # Display statistics
                        st.code(graph.get_statistics_summary())
                        
                    except Exception as e:
                        st.error(f"❌ Collection failed: {str(e)}")
                        import traceback
                        st.code(traceback.format_exc())
            
            if st.button("🧹 Cleanup Old Snapshots", use_container_width=True):
                with st.spinner("Cleaning up old snapshots..."):
                    try:
                        collector = TORCollector()
                        collector.cleanup_old_snapshots()
                        st.success("✅ Cleanup complete!")
                    except Exception as e:
                        st.error(f"❌ Cleanup failed: {str(e)}")
        
        with col2:
            st.markdown("#### Settings")
            st.info(f"""
            **Collection Interval:** {config.TOR_COLLECTION_INTERVAL_HOURS}h
            **Retention:** {config.TOR_SNAPSHOT_RETENTION_DAYS} days
            **API:** Onionoo
            """)
        
        st.markdown("---")
        
        # Load and display latest snapshot
        st.markdown("#### Latest Snapshot")
        
        latest_snapshot = config.get_latest_tor_snapshot()
        
        if latest_snapshot and latest_snapshot.exists():
            try:
                import json
                with open(latest_snapshot, 'r') as f:
                    snapshot_data = json.load(f)
                
                stats = snapshot_data['statistics']
                
                # Display metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric("Total Relays", f"{stats['total_relays']:,}")
                with col2:
                    st.metric("Guard Nodes", f"{stats['guard_nodes']:,}")
                with col3:
                    st.metric("Exit Nodes", f"{stats['exit_nodes']:,}")
                with col4:
                    st.metric("Middle Relays", f"{stats['middle_relays']:,}")
                
                # Relay type distribution
                st.markdown("#### Relay Type Distribution")
                
                fig = go.Figure(data=[
                    go.Pie(
                        labels=['Guard Nodes', 'Exit Nodes', 'Middle Relays'],
                        values=[stats['guard_nodes'], stats['exit_nodes'], stats['middle_relays']],
                        marker=dict(colors=['#667eea', '#f093fb', '#4facfe']),
                        hole=0.4
                    )
                ])
                
                fig.update_layout(
                    title="TOR Network Composition",
                    height=400,
                    showlegend=True
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Bandwidth statistics
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric(
                        "Total Bandwidth", 
                        f"{stats['total_bandwidth'] / 1e9:.2f} GB/s"
                    )
                
                with col2:
                    st.metric(
                        "Avg per Relay",
                        f"{stats['avg_bandwidth'] / 1e6:.2f} MB/s"
                    )
                
                # Show snapshot info
                st.markdown("#### Snapshot Information")
                st.json({
                    "Timestamp": snapshot_data['timestamp'],
                    "Total Relays": stats['total_relays'],
                    "Running Relays": stats['running_relays'],
                    "Countries": stats['countries'],
                    "File": str(latest_snapshot.name)
                })
                
            except Exception as e:
                st.error(f"❌ Error loading snapshot: {str(e)}")
        else:
            st.info("📭 No snapshots available. Click 'Collect TOR Network Snapshot' to get started.")


# ---------------------------------------------------------------------------
# TAB 5: PCAP Upload
# ---------------------------------------------------------------------------

with tab5:
    st.markdown("### 📦 PCAP File Processing")
    
    if not TOR_PCAP_AVAILABLE:
        st.error(f"❌ PCAP modules not available: {import_error}")
        st.info("Make sure all dependencies are installed: `pip install -r requirements.txt`")
    else:
        st.markdown("""
        Upload PCAP files to extract network flows and convert them to RECTor-compatible format.
        Supports ISP logs, mail server logs, and proxy logs.
        """)
        
        # File upload
        uploaded_pcap = st.file_uploader(
            "Upload PCAP File",
            type=['pcap', 'pcapng', 'cap'],
            help=f"Maximum file size: {config.DASHBOARD_MAX_UPLOAD_SIZE_MB}MB"
        )
        
        col1, col2 = st.columns(2)
        
        with col1:
            log_type = st.selectbox(
                "Log Format Type",
                options=['standard', 'isp', 'mail', 'proxy'],
                format_func=lambda x: {
                    'standard': 'Standard PCAP',
                    'isp': 'ISP NetFlow Logs',
                    'mail': 'Mail Server Logs (SMTP/IMAP/POP3)',
                    'proxy': 'Proxy Server Logs'
                }[x],
                help="Select the type of network log"
            )
        
        with col2:
            min_packets = st.number_input(
                "Minimum Packets per Flow",
                min_value=1,
                max_value=100,
                value=config.PCAP_MIN_PACKETS,
                help="Filter flows with fewer packets"
            )
        
        processing_mode = st.radio(
            "Processing Mode",
            options=['extract', 'convert_pickle'],
            format_func=lambda x: {
                'extract': 'Extract to Inflow/Outflow Directories',
                'convert_pickle': 'Convert Directly to Pickle Format'
            }[x],
            horizontal=True
        )
        
        if uploaded_pcap is not None:
            # Save uploaded file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
                tmp_file.write(uploaded_pcap.read())
                pcap_path = tmp_file.name
            
            st.success(f"✅ Uploaded: {uploaded_pcap.name} ({uploaded_pcap.size / 1024:.2f} KB)")
            
            if st.button("🚀 Process PCAP File", type="primary", use_container_width=True):
                try:
                    if processing_mode == 'extract':
                        # Extract to inflow/outflow
                        output_dir = config.get_pcap_output_dir(uploaded_pcap.name)
                        
                        with st.spinner("Extracting flows from PCAP..."):
                            extractor = FlowExtractor(log_type=log_type)
                            extractor.parser.min_packets = min_packets
                            num_flows, num_packets = extractor.process_pcap(
                                pcap_path, 
                                str(output_dir)
                            )
                        
                        st.success(f"✅ Processing complete!")
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("Flows Extracted", num_flows)
                        with col2:
                            st.metric("Total Packets", f"{num_packets:,}")
                        with col3:
                            st.metric("Avg Packets/Flow", f"{num_packets / num_flows if num_flows > 0 else 0:.1f}")
                        
                        st.info(f"📁 Output saved to: `{output_dir}/`\n\nYou can now use this in the 'Data Processing' tab.")
                        
                        # Show directory structure
                        st.markdown("#### Output Directory Structure")
                        st.code(f"""
{output_dir}/
├── inflow/
│   ├── flow_1
│   ├── flow_2
│   └── ...
└── outflow/
    ├── flow_1
    ├── flow_2
    └── ...
                        """)
                        
                    else:
                        # Convert to pickle
                        output_pickle = str(config.PCAP_DATA_DIR / f"{Path(uploaded_pcap.name).stem}.pickle")
                        
                        with st.spinner("Converting PCAP to pickle format..."):
                            converter = PCAPToPickleConverter(log_type=log_type)
                            result_path = converter.convert(
                                pcap_path,
                                output_pickle,
                                window_params=config.PCAP_WINDOW_PARAMS
                            )
                        
                        st.success(f"✅ Conversion complete!")
                        st.info(f"📦 Pickle file saved to: `{result_path}`\n\nYou can upload this in the 'Inference' tab.")
                
                except Exception as e:
                    st.error(f"❌ Processing failed: {str(e)}")
                    import traceback
                    st.code(traceback.format_exc())
                
                finally:
                    # Cleanup temp file
                    if os.path.exists(pcap_path):
                        os.remove(pcap_path)
            
            # Show PCAP info
            st.markdown("---")
            st.markdown("#### File Information")
            st.json({
                "Filename": uploaded_pcap.name,
                "Size": f"{uploaded_pcap.size / 1024:.2f} KB",
                "Log Type": log_type,
                "Min Packets Filter": min_packets,
                "Processing Mode": processing_mode
            })
        else:
            st.info("👆 Upload a PCAP file to get started")
            
            # Show format info
            st.markdown("---")
            st.markdown("#### Supported Log Formats")
            
            format_info = {
                "Standard PCAP": "Regular packet captures with TCP/UDP traffic",
                "ISP NetFlow": "Internet Service Provider network flow logs",
                "Mail Server": "Email server traffic (SMTP/IMAP/POP3)",
                "Proxy Server": "HTTP/HTTPS proxy connection logs"
            }
            
            for format_name, description in format_info.items():
                st.markdown(f"**{format_name}**: {description}")



# ============================================================================
# Footer
# ============================================================================

st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p><strong>Traffic Analysis Dashboard</strong> | Powered by RECTor Framework</p>
    <p>Optimized for macOS M2 with MPS Acceleration</p>
</div>
""", unsafe_allow_html=True)
