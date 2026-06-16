# ai-network-traffic-analyzer

Architecture 


## Lab Environment

- MacBook Pro M1
- VMware Fusion
- Ubuntu ARM64 Sensor VM
- Kali Linux ARM64 Attacker VM

## Simulations and flows

`mermaid
flowchart TD

    A["Kali Linux VM<br>Attack Simulation<br><br>• Nmap Port Scan<br>• Hydra SSH Brute Force<br>• hping3 DoS Simulation"]

    B["Ubuntu Sensor VM<br>Traffic Collection<br><br>• tcpdump<br>• tshark<br>• Python Analytics Engine"]

    C["PCAP Repository<br><br>• normal.pcap<br>• nmap_scan.pcap<br>• hydra_attack.pcap<br>• dos_attack.pcap"]

    D["PyShark Parser<br><br>Extracts:<br>• Source IP<br>• Destination IP<br>• Protocol<br>• Packet Length"]

    E["Feature Extraction<br><br>• Packet Count<br>• Avg Packet Size<br>• Total Bytes<br>• Unique Destinations<br>• Protocol Diversity"]

    F["Isolation Forest Model<br><br>• Train on Normal Traffic<br>• Detect Network Anomalies"]

    G["Threat Classification & MITRE ATT&CK Mapping<br><br>Port Scan → T1046<br>SSH Brute Force → T1110<br>DoS Attack → T1498"]

    H["Streamlit Dashboard<br><br>• Alert Summary<br>• Top Talkers<br>• Anomaly Timeline<br>• MITRE ATT&CK Mapping<br>• Threat Severity Metrics"]

    A -->|Attack Traffic| B
    B -->|PCAP Capture| C
    C -->|Packet Processing| D
    D -->|Feature Generation| E
    E -->|ML Input| F
    F -->|Anomaly Detection| G
    G -->|Visualization| H
`

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