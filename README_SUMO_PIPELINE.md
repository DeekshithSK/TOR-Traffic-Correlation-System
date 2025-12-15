# SUMo Filtering Pipeline

Integrated pipeline for filtering Tor traffic flows using pretrained SUMo (NDSS'24) models before correlation analysis.

## 🎯 Overview

This pipeline implements a **two-stage filtering** approach to reduce candidate flows before passing them to downstream correlation modules (DeepCoFFEA/ESPRESSO):

1. **Source Separation**: Separates client-side from onion-service-side flows
2. **Target Separation**: Identifies sessions to onion services from client flows

**CRITICAL**: SUMo features are used **ONLY for filtering decisions**. Original raw flow data is passed to ESPRESSO.

## 📊 Architecture

```
PCAP File
   ↓
Flow Extraction (pcap_processor.py)
   ↓
Flow Store (original time-series)  ←─┐
   ↓                                  │
SUMo Feature Extraction              │ Flow ID
   ↓                                  │ mapping
SUMo Filtering (BLACK BOX)           │
   ↓                                  │
Filtered Flow IDs ──────────────────┘
   ↓
Original Raw Flows Retrieved
   ↓
ESPRESSO Input (timestamps, sizes, directions)
```

### Key Principle: Data Flow Separation

- **SUMo Pipeline**: Features → Filtering → Flow IDs
- **ESPRESSO Pipeline**: Flow IDs → Original Raw Flows → Correlation
- **NO mixing**: SUMo features are NEVER passed to ESPRESSO

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Verify models are in place
ls sumo/sumo_pipeline/source_separation/models/
ls sumo/sumo_pipeline/target_separation/models/
```

### Basic Usage

```bash
# Run on a PCAP file
python run_sumo_pipeline.py \
    --pcap ./data/capture.pcap \
    --output ./results/
```

### Custom Thresholds

```bash
# Adjust filtering thresholds
python run_sumo_pipeline.py \
    --pcap ./data/capture.pcap \
    --output ./results/ \
    --source-threshold 0.01 \
    --target-threshold 0.85 \
    --fallback-top-k 100
```

## 📁 Output Structure

```
results/
├── flows/                    # All extracted flows
│   ├── inflow/              # Packets TO monitored host
│   └── outflow/             # Packets FROM monitored host
├── filtered_flows/          # ESPRESSO INPUT
│   ├── inflow/              # Filtered flows (original data)
│   ├── outflow/
│   └── espresso_manifest.json  # Metadata for ESPRESSO
└── metrics/
    └── pipeline_metrics.json   # Detailed metrics
```

## 📊 Output Format

### ESPRESSO Manifest

```json
{
  "timestamp": "2025-12-15T11:32:54",
  "sumo_filtering_applied": true,
  "total_input_flows": 1000,
  "filtered_output_flows": 87,
  "reduction_ratio": 0.913,
  "filtered_flow_ids": ["flow_001", "flow_042", ...],
  "data_format": {
    "note": "Original raw flow time-series data ONLY",
    "sumo_features_excluded": true,
    "format": "timestamp\\tpacket_size (tab-separated)"
  }
}
```

### Flow File Format

```
# inflow/flow_001
0.000000	1500
0.023145	1500
0.045221	1024
...

# outflow/flow_001
0.000000	512
0.010234	1500
0.033456	1024
...
```

## 🔧 Pipeline Stages

### Stage 1: PCAP Processing

Extracts flows from PCAP into inflow/outflow directories.

**Input**: PCAP file  
**Output**: Flow files (timestamp + size per packet)  
**Formats**: standard, isp, mail, proxy

### Stage 2: SUMo Feature Extraction

Computes 166 statistical features per flow.

**Features**:
- Packet counts & sizes (total, ingress, egress)
- Inter-packet times (mean, std, percentiles)
- Burst statistics (counts, sizes)

**IMPORTANT**: These features are **discarded after filtering**.

### Stage 3: SUMo Filtering (BLACK BOX)

Two-stage filtering using pretrained XGBoost models.

**Source Separation**:
- Threshold: 0.001 (default)
- Separates client vs OS-side flows

**Target Separation**:
- Threshold: 0.9 (default)
- Identifies onion service sessions

**Fallback**: If all flows filtered, returns top-K by confidence

### Stage 4: ESPRESSO Output Generation

Retrieves original raw flows using filtered IDs.

**Output**: Only original time-series data (NOT SUMo features)

## 📈 Metrics Logged

The pipeline logs detailed metrics for analysis:

```json
{
  "stages": {
    "pcap_processing": {
      "flow_count": 1000,
      "duration_seconds": 12.5
    },
    "feature_extraction": {
      "feature_count": 166,
      "flow_count": 1000,
      "duration_seconds": 8.3
    },
    "sumo_filtering": {
      "total_flows": 1000,
      "filtered_flows": 87,
      "reduction_ratio": 0.913,
      "source_separation": {
        "client_count": 234,
        "os_count": 766,
        "fallback_used": false
      },
      "target_separation": {
        "filtered_count": 87,
        "fallback_used": false
      },
      "duration_seconds": 2.1
    }
  }
}
```

## ⚙️ Configuration

### Thresholds

- `--source-threshold`: Default 0.001 (lower = more strict)
- `--target-threshold`: Default 0.9 (higher = more strict)

### Fallback

- `--fallback-top-k`: Default 50
- Activates when all flows filtered out
- Returns top-K flows by confidence

### Log Types

- `standard`: Generic PCAP
- `isp`: ISP-specific format
- `mail`: Mail server logs
- `proxy`: Proxy logs

## 🔬 Testing

### Verify Models

```bash
python test_sumo_models.py
```

### Test Inference

```bash
python verify_sumo_inference.py
```

### Test Pipeline

```bash
python test_sumo_pipeline.py
```

## 📦 Components

| File | Purpose |
|------|---------|
| `run_sumo_pipeline.py` | Main entry point |
| `sumo_adapter.py` | Feature extraction (166 features) |
| `sumo_filter.py` | Filtering wrapper (black box) |
| `pcap_processor.py` | PCAP → flows extraction |
| `test_sumo_*.py` | Verification tests |

## 🚨 Critical Constraints

### DO:
- ✅ Treat `sumo_filter.py` as black box
- ✅ Pass only flow IDs + raw flows to ESPRESSO
- ✅ Log reduction ratios (metrics for evaluation)
- ✅ Use fallback mechanism when needed

### DO NOT:
- ❌ Re-normalize flows for ESPRESSO using SUMo logic
- ❌ Merge SUMo + ESPRESSO features
- ❌ Train or modify pretrained models
- ❌ Pass SUMo features to ESPRESSO

## 🔗 Integration with ESPRESSO

```python
# After SUMo filtering
import json

# Load filtered flows
with open('results/filtered_flows/espresso_manifest.json') as f:
    manifest = json.load(f)

# Get filtered flow IDs
filtered_ids = manifest['filtered_flow_ids']

# Load flows for ESPRESSO (original time-series only)
inflow_dir = manifest['data_format']['directories']['inflow']
outflow_dir = manifest['data_format']['directories']['outflow']

for flow_id in filtered_ids:
    inflow_data = load_flow(f"{inflow_dir}/{flow_id}")  # timestamps, sizes
    outflow_data = load_flow(f"{outflow_dir}/{flow_id}")
    
    # Pass to ESPRESSO correlation
    espresso_correlate(inflow_data, outflow_data)
```

## 📚 References

- **SUMo Paper**: NDSS 2024
- **SUMo GitHub**: https://github.com/danielaLopes/sumo
- **Models**: Pretrained XGBoost classifiers (Bayesian optimization)

## 🐛 Troubleshooting

### Low Reduction Ratio

- Try adjusting thresholds (lower = stricter)
- Check fallback activation in metrics

### All Flows Filtered

- Fallback should activate automatically
- Check metrics: `fallback_used: true`

### ESPRESSO Compatibility Issues

- Verify manifest format
- Ensure only raw flows (not features) are passed
- Check file paths in manifest

## 📧 Support

For issues related to:
- SUMo models: Check original SUMo repository
- Pipeline integration: Review logs in `metrics/`
- ESPRESSO compatibility: Verify manifest schema

---

**Version**: 1.0.0  
**Last Updated**: 2025-12-15  
**Status**: Production Ready ✅
