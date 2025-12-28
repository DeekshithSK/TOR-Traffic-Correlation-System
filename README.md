# Tor Forensic Analysis System

## Overview
This project is a network forensic tool I built to solve a specific challenge in cybersecurity: identifying the origin of anonymous Tor traffic. 

Analysts often encounter obfuscated traffic that makes attribution difficult. This system helps bridge that gap by using a dual-side correlation approach. It analyzes traffic patterns at both the entry and exit points of the network to statistically link a user to a destination server, even through encryption layers.

## Why I Built This
I created this to demonstrate how deep learning and statistical analysis can be applied to real-world forensic challenges. It shows that even anonymous networks leave "fingerprints" in packet timing and volume that can be analyzed for attribution.

## How It Works
The system follows a standard forensic workflow:

1. **Ingestion:** It takes raw PCAP files (standard network captures) as input.
2. **Analysis:** It processes these files to extract flow-level features like packet inter-arrival times and burst sizes.
3. **Correlation:** 
   - First, it applies statistical filtering to rule out obvious non-matches.
   - Then, it uses a **Siamese Neural Network** (which I implemented in PyTorch) to compare traffic shapes and assign a similarity score.
4. **Visualization:** The results are presented in a React-based dashboard that highlights high-confidence matches, helping an analyst quickly focus on relevant data.

## Tech Stack
*   **Infrastructure:** Docker & Docker Compose (for consistent deployment)
*   **Backend:** Python (FastAPI) & PyTorch
*   **Packet Processing:** Scapy & Pandas
*   **Frontend:** React & TailwindCSS

## Setup Instructions

**Prerequisites:** Docker Desktop

**Steps:**
1. Clone this repository.
2. Run the following command in the terminal:
   ```bash
   docker-compose up --build
   ```
3. Open your browser to `http://localhost:3000` to view the forensic dashboard.

4. Test the project using verify_entry.pcap and verify_exit.pcap
