# ai-network-traffic-analyzer

Architecture 


## Lab Environment

- MacBook Pro M1
- VMware Fusion
- Ubuntu ARM64 Sensor VM
- Kali Linux ARM64 Attacker VM

## Attack simulations and flows

┌──────────────────────────────┐
│         Kali Linux VM        │
│                              │
│ • Nmap Port Scan             │
│ • Hydra SSH Brute Force      │
│ • hping3 DoS Simulation      │
└──────────────┬───────────────┘
               │
               │ Attack Traffic
               ▼
┌──────────────────────────────┐
│        Ubuntu Sensor VM      │
│                              │
│ • tcpdump                    │
│ • tshark                     │
│ • Python Analytics Engine    │
└──────────────┬───────────────┘
               │
               │ PCAP Capture
               ▼
┌──────────────────────────────┐
│        PCAP Repository       │
│                              │
│ • normal.pcap                │
│ • nmap_scan.pcap             │
│ • hydra_attack.pcap          │
│ • dos_attack.pcap            │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│        PyShark Parser        │
│                              │
│ Extracts:                    │
│ • Source IP                  │
│ • Destination IP             │
│ • Protocol                   │
│ • Packet Length              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      Feature Extraction      │
│                              │
│ • Packet Count               │
│ • Avg Packet Size            │
│ • Total Bytes                │
│ • Unique Destinations        │
│ • Protocol Diversity         │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│    Isolation Forest Model    │
│                              │
│ • Train on Normal Traffic    │
│ • Detect Anomalies           │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│     Detection & Mapping      │
│                              │
│ Port Scan  → T1046           │
│ SSH BF     → T1110           │
│ DoS        → T1498           │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│      Streamlit Dashboard     │
│                              │
│ • Alert Summary              │
│ • Top Talkers                │
│ • Anomalies                  │
│ • MITRE ATT&CK Mapping       │
└──────────────────────────────┘

## Detection Techniques

- Statistical Feature Extraction
- Isolation Forest Anomaly Detection
- MITRE ATT&CK Mapping

## Technologies

- Python
- PyShark
- TShark
- Pandas
- Scikit-learn
- Streamlit