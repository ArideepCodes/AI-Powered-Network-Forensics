# 🔒 AI-Powered Network Packet Forensics Analyzer

Created by **Arideep Kanshabanik** (India)

A comprehensive, production-ready network forensics tool that combines AI/ML threat detection with powerful packet analysis capabilities.

## 📋 Features

### 🔍 Core Capabilities
- **PCAP File Analysis**: Upload and analyze network packet capture files
- **AI/ML Threat Detection**: Automatic classification of network threats using Random Forest
- **Real-Time Packet Parsing**: Extract detailed metadata from network packets
- **Interactive Visualizations**: Beautiful charts and graphs powered by Plotly
- **Forensic Investigation Tools**: GeoIP, WHOIS, and Reverse DNS lookups
- **PDF Report Generation**: Export comprehensive forensic reports

### 🚨 Threat Detection Categories
The ML model classifies packets into 5 categories:
1. **Normal** - Standard network traffic
2. **Port Scan** - Reconnaissance activity detection
3. **DoS Attack** - Denial of Service attack patterns
4. **Malware Traffic** - Suspicious C&C communications
5. **Suspicious Anomaly** - Unusual traffic patterns

### 📊 Visualizations
- Protocol distribution (Pie chart)
- Threat type distribution (Bar chart)
- Traffic timeline (Line chart)
- Top destination ports (Bar chart)
- Source & Destination IP analysis

## 🏗️ Project Structure

```
/
├── app.py                      # Main Streamlit application
├── README.md                   # Project documentation
├── utils/                      # Utility modules
│   ├── __init__.py
│   ├── packet_parser.py        # PCAP parsing with Scapy
│   ├── ml_detector.py          # ML threat detection
│   ├── geoip_tools.py          # GeoIP, WHOIS, DNS tools
│   ├── visualizer.py           # Chart generation
│   └── report_builder.py       # PDF report generation
├── ai_model/
│   └── model.pkl               # Trained RandomForest model
└── assets/
    └── logo.png                # Application logo
```

## 🚀 Installation

### Requirements
- Python 3.11+
- Streamlit
- Scapy
- Scikit-learn
- Pandas, NumPy
- Matplotlib, Plotly
- ReportLab
- Python-whois
- Pycountry

### Running the Application

```bash
streamlit run app.py --server.port 5000
```

The application will start at `http://localhost:5000`

## 🎯 Usage Guide

### 1. Upload PCAP File
- Navigate to the **"PCAP Upload & Analysis"** tab
- Upload a `.pcap` or `.pcapng` file
- Wait for automatic analysis to complete

### 2. View Analysis Results
- Check the **"Dashboard"** tab for visualizations
- Review threat detection results
- Examine packet-by-packet AI analysis
- Filter results by threat type

### 3. Forensic Investigation
- Use the **"Forensic Tools"** tab
- Perform GeoIP lookups to locate IP addresses
- Run WHOIS queries for domain information
- Execute Reverse DNS lookups

### 4. Generate Reports
- Go to **"Generate Report"** tab
- Customize report filename
- Download professional PDF forensic report

## 🔬 Technical Details

### Packet Features Extracted
- Source/Destination IP addresses
- Source/Destination ports
- Protocol type (TCP, UDP, ICMP)
- Packet length and payload size
- TCP flags (SYN, FIN, ACK, etc.)
- Timestamp information

### ML Model
- **Algorithm**: Random Forest Classifier
- **Features**: 10 engineered features per packet
- **Training**: Synthetic dataset with 1000 samples
- **Classes**: 5 threat categories
- **Accuracy**: ~79% on training data

### AI Analysis
Each packet receives:
- Threat classification
- Risk score (0-100%)
- Detailed AI-generated analysis message
- Actionable security recommendations

## 📧 Contact

**Creator**: Arideep Kanshabanik  
**Email**: arideepkanshabanik@gmail.com  
**GitHub**: [github.com/ArideepCodes](https://github.com/ArideepCodes)  
**Portfolio**: [arideep.framer.ai](https://arideep.framer.ai)

## 🛡️ Use Cases

- **Network Security Auditing**: Analyze captured traffic for security assessment
- **Incident Response**: Investigate security incidents and breaches
- **Threat Hunting**: Proactive detection of malicious activity
- **Network Forensics**: Legal and compliance investigations
- **Educational**: Learn about network protocols and security

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have proper authorization before analyzing network traffic.

## 📜 License

This project is created for educational purposes. Please provide attribution when using or modifying.

---

**Built with ❤️ by Arideep Kanshabanik**
