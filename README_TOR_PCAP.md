# TOR Network Collection & PCAP Ingestion

**New Features Added to Traffic Analysis Dashboard**

## Quick Start

### 1. Install New Dependencies

```bash
pip install requests schedule
# or
pip install -r requirements.txt
```

### 2. Test TOR Collector

```bash
# Test API connectivity
python tor_collector.py --test

# Collect a snapshot
python tor_collector.py --collect
```

### 3. Test PCAP Processor

```bash
# Process a PCAP file
python pcap_processor.py your_capture.pcap --output ./flows/
```

### 4. Launch Dashboard

```bash
streamlit run app.py
```

Then navigate to:
- **🌐 TOR Network** tab - Collect and visualize TOR relay data
- **📦 PCAP Upload** tab - Upload and process network captures

---

## Features

### TOR Network Collection

- ✅ Automated scraping of 6000+ TOR relays
- ✅ Guard, middle, and exit node classification
- ✅ Bandwidth, uptime, and flag tracking
- ✅ Hourly snapshot scheduling via cron
- ✅ Time-indexed network graphs
- ✅ JSON and pickle export formats

**Data Location:** `./data/tor_snapshots/`

### PCAP Ingestion

- ✅ Flow extraction from PCAP files
- ✅ Packet size, timing, direction analysis
- ✅ Support for ISP logs, mail server logs, proxy logs
- ✅ Conversion to RECTor inflow/outflow format
- ✅ Direct pickle conversion for inference

**Data Location:** `./data/pcap_flows/`

---

## CLI Usage

### TOR Collector

```bash
# Test connectivity
python tor_collector.py --test

# Collect snapshot
python tor_collector.py --collect

# View latest stats
python tor_collector.py --stats

# Cleanup old files
python tor_collector.py --cleanup
```

### PCAP Processor

```bash
# Standard PCAP
python pcap_processor.py capture.pcap --output ./flows/

# ISP logs
python pcap_processor.py isp.pcap --output ./flows/ --log-type isp

# Mail server logs
python pcap_processor.py mail.pcap --output ./flows/ --log-type mail

# Convert to pickle
python pcap_processor.py capture.pcap --to-pickle --output ./processed
```

---

## Automated Collection

Set up hourly TOR collection:

```bash
# 1. Edit tor_cron_template.sh paths
nano tor_cron_template.sh

# 2. Make executable
chmod +x tor_cron_template.sh

# 3. Add to crontab
crontab -e
# Add: 0 * * * * /Users/deekshithsk/Desktop/prime/tor_cron_template.sh
```

---

## Configuration

Edit `config.py` to customize:

```python
# TOR Collection
TOR_COLLECTION_INTERVAL_HOURS = 1
TOR_SNAPSHOT_RETENTION_DAYS = 30

# PCAP Processing
PCAP_FLOW_TIMEOUT = 60
PCAP_MIN_PACKETS = 5
```

---

## File Structure

```
prime/
├── config.py                   # Configuration settings
├── tor_collector.py            # TOR network scraper
├── pcap_processor.py           # PCAP ingestion
├── tor_cron_template.sh        # Cron job template
├── app.py                      # Dashboard (updated)
├── backend.py                  # RECTor backend
├── requirements.txt            # Dependencies (updated)
└── data/
    ├── tor_snapshots/          # TOR network data
    ├── pcap_flows/             # PCAP extractions
    └── traffic_analysis.log    # Logs
```

---

## Next Steps

1. ✅ **Test TOR API**: Run `python tor_collector.py --test`
2. ✅ **Collect Snapshot**: Run `python tor_collector.py --collect`
3. ✅ **Process PCAP**: Upload a file via dashboard or CLI
4. ✅ **Set up Cron**: Configure automated hourly collection
5. ✅ **Integrate**: Use extracted flows in RECTor pipeline

---

## Documentation

- **Full Walkthrough**: See `walkthrough.md` artifact for detailed usage
- **Implementation Plan**: See `implementation_plan.md` for architecture
- **Configuration**: Edit `config.py` for all settings

---

## Troubleshooting

**Module Import Errors**
```bash
pip install requests schedule scapy
```

**TOR API Failures**
- Check internet connectivity
- Verify: https://onionoo.torproject.org

**PCAP Processing Errors**
- Ensure file is valid PCAP/PCAPNG format
- Install scapy: `pip install scapy`

---

## Support

For issues or questions, refer to:
- Configuration: `config.py`
- Logs: `./data/traffic_analysis.log`
- Walkthrough: See artifacts

---

**Status**: ✅ Ready for use
