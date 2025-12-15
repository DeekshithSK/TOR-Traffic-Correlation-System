# Traffic Analysis Dashboard - Project Summary

> **Comprehensive overview of the TOR network analysis platform with PCAP ingestion capabilities**

---

## 🎯 Project Overview

**Traffic Analysis Dashboard** is a sophisticated network analysis platform designed to:

1. **Collect TOR network data** - Automated scraping of TOR relay information (guard/middle/exit nodes)
2. **Process network captures** - PCAP ingestion with support for ISP, mail server, and proxy logs
3. **Analyze traffic patterns** - RECTor-based feature extraction and flow analysis
4. **ML-ready pipeline** - Prepared for model integration (currently placeholder)
5. **Interactive visualization** - Streamlit-based dashboard for real-time analysis

**Tech Stack:** Python, Streamlit, Scapy, PyTorch (MPS), Onionoo API, RECTor Framework

---

## 📁 Project Structure

```
/Users/deekshithsk/Desktop/prime/
│
├── Core Application
│   ├── app.py                      # Streamlit dashboard (5 tabs)
│   ├── backend.py                  # RECTor preprocessing engine
│   └── config.py                   # Centralized configuration
│
├── Data Collection
│   ├── tor_collector.py            # TOR network scraper
│   ├── pcap_processor.py           # PCAP ingestion pipeline
│   └── tor_cron_template.sh        # Automated collection script
│
├── Configuration
│   ├── requirements.txt            # Python dependencies
│   └── setup_env.sh                # Environment setup
│
├── Data Storage
│   └── data/
│       ├── tor_snapshots/          # TOR relay snapshots
│       ├── pcap_flows/             # Processed PCAP flows
│       └── traffic_analysis.log    # Application logs
│
└── Documentation
    ├── README_TOR_PCAP.md          # Quick start guide
    └── PROJECT_SUMMARY.md          # This file
```

---

## 🔧 Core Modules

### 1. **Dashboard (`app.py`)** - 1,103 lines

**Purpose:** Interactive Streamlit web interface

**Features:**
- 📁 **Data Processing Tab**
  - Create overlapping time windows
  - Extract IAT/Size features
  - Process inflow/outflow directories
  
- 🔬 **Inference Tab**
  - Upload pickle files
  - Run model inference (placeholder for RECTor model)
  - Visualize embeddings
  
- 📊 **Results Tab**
  - Confidence score distribution
  - Export results (CSV/NPZ)
  - Detailed flow analysis
  
- 🌐 **TOR Network Tab** ⭐ NEW
  - Collect TOR relay snapshots
  - Visualize guard/middle/exit node distribution
  - Display bandwidth and uptime statistics
  - Export JSON/pickle snapshots
  
- 📦 **PCAP Upload Tab** ⭐ NEW
  - Upload PCAP/PCAPNG files
  - Select log format (Standard/ISP/Mail/Proxy)
  - Extract to inflow/outflow directories
  - Direct pickle conversion

**Technologies:** Streamlit, Plotly, NumPy, Pandas

---

### 2. **Backend Engine (`backend.py`)** - 795 lines

**Purpose:** RECTor-based traffic preprocessing and feature extraction

**Components:**

#### a. **TrafficPreprocessor**
- Combines Step1 (window creation) + Step2 (feature extraction)
- MPS-optimized for Apple Silicon
- Supports PCAP-to-pickle conversion

#### b. **WindowCreator (Step1)**
- Parses inflow/outflow directories
- Creates overlapping time windows
- Filters flows by packet threshold
- **Output:** List of qualified flow files

#### c. **FeatureExtractor (Step2)**
- Extracts IAT (Inter-Arrival Time) and packet size
- Consolidates super-packets (zero-delay packets)
- Removes ACK packets (< threshold)
- **Output:** Pickle files with processed flows

#### d. **Model Architectures** 🚧 PLACEHOLDER
Two architectures prepared (not trained):

**GRU_MIL_Siamese:**
- GRU + Attention (Multi-Instance Learning)
- Processes 11 overlapping windows
- Outputs embedding + attention weights

**DFModel (Deep Fingerprinting):**
- CNN-based architecture
- Single window processing
- Conv → Pool → FC layers

#### e. **RectorEngine**
- Inference wrapper (ready for trained models)
- MPS acceleration support
- Cosine similarity scoring

**Note:** ML models are architectural placeholders. Training pipeline is not included in this project.

---

### 3. **TOR Collector (`tor_collector.py`)** - 589 lines

**Purpose:** Automated TOR network data collection via Onionoo API

**Components:**

#### a. **OnionooClient**
- API wrapper for TOR Metrics
- Endpoints: `/details`, `/bandwidth`, `/uptime`
- Rate limiting and retry logic
- **Fetches:** 6000+ TOR relays

#### b. **RelayClassifier**
- Classifies relays by flag:
  - **Guard nodes** - Entry points to TOR network
  - **Exit nodes** - Exit points from TOR network
  - **Middle relays** - Internal routing nodes
- Extracts metadata:
  - Bandwidth (observed, advertised, consensus weight)
  - Uptime (first seen, last seen)
  - Geolocation (country, coordinates, AS number)
  - Flags (Guard, Exit, Fast, Stable, Running, etc.)

#### c. **TORNetworkGraph**
- Time-indexed graph storage
- Snapshot management
- Statistics calculation:
  - Total relays by type
  - Bandwidth distribution
  - Geographic distribution
- Export formats: JSON, Pickle

#### d. **TORCollector**
- Orchestrates collection process
- Snapshot scheduling
- Automatic cleanup (30-day retention)

**CLI Usage:**
```bash
python tor_collector.py --test      # Test API
python tor_collector.py --collect   # Collect snapshot
python tor_collector.py --stats     # View latest
python tor_collector.py --cleanup   # Remove old files
```

**Cron Automation:** Hourly collection via `tor_cron_template.sh`

---

### 4. **PCAP Processor (`pcap_processor.py`)** - 590 lines

**Purpose:** Convert network captures to RECTor-compatible format

**Components:**

#### a. **FlowSession**
- Bidirectional flow tracking
- Packet metadata storage (timestamp, size, direction)
- Conversion to RECTor format (inflow/outflow)

#### b. **PCAPParser**
- Core parsing engine using Scapy
- Flow reassembly and timeout management
- Protocol filtering (TCP/UDP)
- **Min packets:** Configurable threshold (default: 5)

#### c. **Log Format Adapters**

**ISPLogAdapter:**
- NetFlow log processing
- IP anonymization (optional)

**MailServerAdapter:**
- Filters SMTP/IMAP/POP3 traffic
- Ports: 25, 587, 465, 143, 993, 110, 995

**ProxyLogAdapter:**
- HTTP/HTTPS proxy logs
- Ports: 8080, 8443, 3128, 8888

#### d. **FlowExtractor**
- Main extraction pipeline
- Creates inflow/outflow directory structure
- **Output format:**
  ```
  timestamp\tpacket_size
  ```

#### e. **PCAPToPickleConverter**
- Direct PCAP → Pickle conversion
- Integrates with RECTor preprocessing
- Auto-creates overlapping windows

**CLI Usage:**
```bash
# Extract flows
python pcap_processor.py capture.pcap --output ./flows/

# ISP logs
python pcap_processor.py isp.pcap --log-type isp --output ./isp_flows/

# Convert to pickle
python pcap_processor.py capture.pcap --to-pickle --output ./processed
```

---

### 5. **Configuration (`config.py`)** - 200 lines

**Purpose:** Centralized settings management

**Configuration Categories:**

#### Base Paths
- `DATA_DIR` - Main data directory
- `TOR_DATA_DIR` - TOR snapshots
- `PCAP_DATA_DIR` - PCAP-derived flows

#### TOR Collection
- `ONIONOO_BASE_URL` - API endpoint
- `TOR_COLLECTION_INTERVAL_HOURS` - Snapshot frequency (1 hour)
- `TOR_SNAPSHOT_RETENTION_DAYS` - Cleanup threshold (30 days)
- `TOR_RUNNING_ONLY` - Only collect running relays

#### PCAP Processing
- `PCAP_PROTOCOLS` - Protocols to extract (TCP/UDP)
- `PCAP_FLOW_TIMEOUT` - Flow timeout (60s)
- `PCAP_MIN_PACKETS` - Minimum packets per flow (5)
- `PCAP_PORTS_OF_INTEREST` - HTTP, HTTPS, SMTP, IMAP, TOR, etc.

#### Dashboard
- `DASHBOARD_MAX_UPLOAD_SIZE_MB` - PCAP upload limit (500 MB)
- `VIZ_MAX_RELAYS_DISPLAY` - Performance limit (1000 relays)

#### Logging
- `LOG_LEVEL` - INFO/DEBUG/WARNING
- `LOG_FILE` - Application log path

---

## 🔄 Data Flow Architecture

### Flow 1: TOR Network Collection

```
Onionoo API
    ↓
TORCollector.collect_snapshot()
    ↓
RelayClassifier (categorize by flags)
    ↓
TORNetworkGraph (time-indexed storage)
    ↓
Export: JSON + Pickle
    ↓
./data/tor_snapshots/tor_snapshot_YYYYMMDD_HHMMSS.{json,pickle}
```

### Flow 2: PCAP Ingestion Pipeline

```
PCAP File Upload
    ↓
PCAPParser (scapy)
    ↓
FlowExtractor (bidirectional flows)
    ↓
LogFormatAdapter (ISP/Mail/Proxy filtering)
    ↓
Export: inflow/ + outflow/ directories
    ↓
./data/pcap_flows/{capture_name}/
    ├── inflow/
    │   ├── flow_1
    │   ├── flow_2
    │   └── ...
    └── outflow/
        ├── flow_1
        ├── flow_2
        └── ...
```

### Flow 3: RECTor Preprocessing Pipeline

```
Inflow/Outflow Directories
    ↓
Step1: WindowCreator.create_overlap_windows()
    - Parse directories
    - Create overlapping time windows
    - Filter by threshold
    ↓
qualified_flows.txt (list of files appearing in all windows)
    ↓
Step2: FeatureExtractor.process_window_files()
    - Extract IAT + Size features
    - Consolidate super-packets
    - Remove ACK packets
    ↓
Pickle Files: {prefix}_{interval}_win{N}_addn{M}_superpkt.pickle
    {
        "ingress": [[{iat, size}, ...], ...],
        "egress": [[{iat, size}, ...], ...],
        "label": [filename1, filename2, ...]
    }
```

### Flow 4: Dashboard Workflow

```
User Interface (Streamlit)
    ↓
[Option A: Data Processing]
    → Upload inflow/outflow → Step1 → Step2 → Pickle
    
[Option B: PCAP Upload]
    → Upload PCAP → Extract flows → (Optional: Auto-process) → Pickle
    
[Option C: TOR Collection]
    → Collect snapshot → Store + Visualize

[Option D: Inference - PLACEHOLDER]
    → Upload Pickle → Load Model → Run Inference → Display Results
```

---

## 📊 Data Storage

### TOR Snapshots (`./data/tor_snapshots/`)

**Files:**
```
tor_snapshot_20251214_140000.json
tor_snapshot_20251214_140000.pickle
```

**JSON Structure:**
```json
{
  "timestamp": "2025-12-14T14:00:00",
  "relay_count": 6543,
  "relays_by_type": {
    "guard": ["fingerprint1", "fingerprint2", ...],
    "exit": [...],
    "middle": [...]
  },
  "relays": {
    "fingerprint1": {
      "nickname": "MyTorRelay",
      "address": "1.2.3.4:9001",
      "flags": ["Guard", "Fast", "Stable"],
      "bandwidth": {
        "observed": 123456789,
        "advertised": 100000000,
        "consensus_weight": 5000
      },
      "uptime": {...},
      "geolocation": {...},
      "relay_type": "guard"
    }
  },
  "statistics": {
    "total_relays": 6543,
    "guard_nodes": 2156,
    "exit_nodes": 1234,
    "middle_relays": 3153,
    "total_bandwidth": 123456789,
    "avg_bandwidth": 18876,
    "countries": 89,
    "running_relays": 6123
  }
}
```

### PCAP Flows (`./data/pcap_flows/`)

**Directory Structure:**
```
capture1/
├── inflow/
│   ├── 192_168_1_10_54321_8_8_8_8_443_tcp
│   ├── 192_168_1_10_54322_1_1_1_1_443_tcp
│   └── ...
└── outflow/
    ├── 192_168_1_10_54321_8_8_8_8_443_tcp
    ├── 192_168_1_10_54322_1_1_1_1_443_tcp
    └── ...
```

**File Format (tab-separated):**
```
0.0        1500
0.023456   1500
0.045678   1024
0.089012   512
```

### Processed Pickles (`./processed/`)

**File Naming:**
```
{prefix}_{interval}_win{window_num}_addn{step}_superpkt.pickle
```

Example: `mydata_5_win0_addn2_superpkt.pickle`

---

## 🚀 Features Summary

### ✅ Fully Implemented

1. **TOR Network Collection**
   - ✅ Onionoo API integration
   - ✅ Guard/middle/exit classification
   - ✅ Bandwidth and uptime tracking
   - ✅ Geolocation data
   - ✅ Hourly snapshots (via cron)
   - ✅ Automatic cleanup
   - ✅ JSON/Pickle export

2. **PCAP Ingestion**
   - ✅ PCAP/PCAPNG parsing
   - ✅ Flow extraction
   - ✅ ISP log support
   - ✅ Mail server log support
   - ✅ Proxy log support
   - ✅ Inflow/outflow conversion
   - ✅ Direct pickle conversion

3. **RECTor Preprocessing**
   - ✅ Overlapping window creation
   - ✅ IAT/Size feature extraction
   - ✅ Super-packet consolidation
   - ✅ ACK packet filtering
   - ✅ Pickle export

4. **Dashboard UI**
   - ✅ Data processing controls
   - ✅ TOR visualization (pie charts, metrics)
   - ✅ PCAP upload interface
   - ✅ Results export (CSV/NPZ)
   - ✅ MPS device detection

5. **Infrastructure**
   - ✅ Centralized configuration
   - ✅ Logging system
   - ✅ CLI tools
   - ✅ Cron automation
   - ✅ Documentation

### 🚧 Placeholder / Not Implemented

1. **Machine Learning Models**
   - 🚧 Model architectures defined (GRU_MIL_Siamese, DFModel)
   - ❌ No trained model weights
   - ❌ No training pipeline
   - ❌ Inference currently returns placeholder results

2. **Advanced Features (Future)**
   - ❌ Real-time packet capture
   - ❌ Live TOR relay monitoring
   - ❌ ML model training interface
   - ❌ Database integration
   - ❌ User authentication
   - ❌ Multi-user support

---

## 🛠️ Dependencies

### Core
- `python>=3.8`
- `torch>=2.0.0` (MPS support)
- `streamlit>=1.28.0`
- `scapy>=2.5.0`

### Data Processing
- `numpy>=1.24.0`
- `pandas>=2.0.0`
- `pickle` (built-in)

### Networking
- `requests>=2.31.0` (Onionoo API)
- `schedule>=1.2.0` (cron scheduling)

### Visualization
- `plotly>=5.17.0`
- `matplotlib>=3.7.0`
- `seaborn>=0.12.0`

### Utilities
- `tqdm>=4.66.0`
- `colorama>=0.4.6`

---

## 📖 Usage Examples

### 1. Collect TOR Snapshot

**Via CLI:**
```bash
python tor_collector.py --collect
```

**Via Dashboard:**
1. Navigate to **🌐 TOR Network** tab
2. Click **"Collect TOR Network Snapshot"**
3. View statistics and visualizations

**Output:** `./data/tor_snapshots/tor_snapshot_YYYYMMDD_HHMMSS.json`

---

### 2. Process PCAP File

**Via CLI:**
```bash
python pcap_processor.py capture.pcap --output ./my_flows/
```

**Via Dashboard:**
1. Navigate to **📦 PCAP Upload** tab
2. Upload PCAP file
3. Select log format
4. Click **"Process PCAP File"**

**Output:** `./data/pcap_flows/capture/inflow/` + `outflow/`

---

### 3. RECTor Preprocessing

**Via Dashboard:**
1. Navigate to **📁 Data Processing** tab
2. Set data directory (e.g., `./data/pcap_flows/capture/`)
3. Click **"Run Step 1: Create Windows"**
4. Click **"Run Step 2: Extract Features"**

**Output:** Pickle files in `./processed/`

---

### 4. Set Up Automated Collection

**Edit cron template:**
```bash
nano tor_cron_template.sh
# Update PROJECT_DIR path
```

**Install cron job:**
```bash
chmod +x tor_cron_template.sh
crontab -e
# Add: 0 * * * * /Users/deekshithsk/Desktop/prime/tor_cron_template.sh
```

**Result:** Hourly TOR snapshots automatically collected

---

## 🎯 Current Status

**Project Phase:** MVP Complete (except ML training)

**What Works:**
- ✅ Full data collection pipeline (TOR + PCAP)
- ✅ Complete preprocessing pipeline
- ✅ Interactive dashboard
- ✅ Export/import functionality

**What's Missing:**
- ❌ Trained RECTor model weights
- ❌ Model training scripts
- ❌ End-to-end inference validation

**Next Steps:**
1. Train RECTor models on labeled dataset
2. Export trained weights (.pth files)
3. Upload weights to dashboard for inference
4. Validate end-to-end pipeline

---

## 🔗 Related Documentation

- [README_TOR_PCAP.md](file:///Users/deekshithsk/Desktop/prime/README_TOR_PCAP.md) - Quick start guide
- [Walkthrough](file:///Users/deekshithsk/.gemini/antigravity/brain/5fa5c39c-607e-408d-8e4a-aa686a657505/walkthrough.md) - Detailed usage instructions
- [Implementation Plan](file:///Users/deekshithsk/.gemini/antigravity/brain/5fa5c39c-607e-408d-8e4a-aa686a657505/implementation_plan.md) - Technical architecture

---

## 📞 Quick Reference

**Dashboard:** http://localhost:8501

**Key Commands:**
```bash
# Run dashboard
streamlit run app.py

# Test TOR API
python tor_collector.py --test

# Process PCAP
python pcap_processor.py input.pcap --output ./flows/

# Configure settings
nano config.py
```

**Data Locations:**
- TOR: `./data/tor_snapshots/`
- PCAP: `./data/pcap_flows/`
- Logs: `./data/traffic_analysis.log`

---

**Last Updated:** 2025-12-14  
**Version:** 1.0.0  
**Status:** ✅ Production Ready (Data Pipeline Only)
