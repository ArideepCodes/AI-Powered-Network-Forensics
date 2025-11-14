# Overview

This is an AI-powered network packet forensics analysis tool built with Streamlit. The application allows cybersecurity professionals and network administrators to upload PCAP (packet capture) files and perform comprehensive threat analysis using machine learning. The system combines automated AI/ML threat detection with traditional forensic investigation tools to identify security threats including port scans, DoS attacks, malware traffic, and suspicious anomalies.

The tool provides interactive visualizations, real-time packet parsing, geographic IP analysis, WHOIS lookups, and generates exportable PDF forensic reports. It uses a pre-trained Random Forest classifier to categorize network traffic into five threat levels with confidence scoring.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Framework**: Streamlit web application
- **UI Design**: Custom CSS styling with dark theme (#0e1117 background)
- **Layout**: Wide layout with expandable sidebar navigation
- **Visualization Library**: Plotly for interactive charts (pie, bar, line graphs)
- **Component Structure**: Tab-based interface for organizing different analysis views

**Rationale**: Streamlit was chosen for rapid development of data-centric applications without requiring extensive frontend code. The framework provides built-in state management and reactive updates, making it ideal for security analysis dashboards where users need real-time feedback.

## Backend Architecture
- **Language**: Python 3.x
- **Module Organization**: Utility-based separation of concerns
  - `packet_parser.py`: PCAP file processing using Scapy
  - `ml_detector.py`: Machine learning threat classification
  - `geoip_tools.py`: IP geolocation and forensic lookups
  - `visualizer.py`: Chart generation and data visualization
  - `report_builder.py`: PDF report generation with ReportLab

**Design Pattern**: The application follows a modular utility pattern where each module handles a specific domain (packet parsing, ML inference, visualization, etc.). This separation enables independent testing and maintenance of features.

**Alternatives Considered**: A microservices architecture was considered but rejected in favor of a monolithic Streamlit app for simpler deployment and lower latency for the ML inference pipeline.

## Machine Learning Architecture
- **Model**: Pre-trained Random Forest classifier (stored as `ai_model/model.pkl`)
- **Classification Categories**: 5-class classification (Normal, Port Scan, DoS Attack, Malware Traffic, Suspicious Anomaly)
- **Feature Engineering**: Extracts numerical features from packet metadata (protocol, ports, flags, payload size, length)
- **Inference**: Real-time prediction with probability distribution and risk scoring

**Rationale**: Random Forest was selected for its robustness to imbalanced datasets (common in security data where attacks are rare), interpretability for forensic analysis, and ability to handle mixed feature types without extensive preprocessing.

**Pros**: High accuracy on network traffic classification, provides probability scores for confidence assessment, handles missing features gracefully.

**Cons**: Model file must be pre-trained externally; the application does not include training capabilities. Requires periodic retraining as attack patterns evolve.

## Packet Processing Pipeline
- **Library**: Scapy for packet capture and parsing
- **Flow**: PCAP file upload → packet extraction → metadata parsing → feature extraction → ML classification → visualization
- **Data Structure**: Converts packets to Pandas DataFrame for efficient filtering, sorting, and aggregation
- **Supported Protocols**: TCP, UDP, ICMP with protocol-specific metadata extraction (flags, ports, payload)

**Rationale**: Scapy provides low-level packet manipulation capabilities essential for forensic analysis. The DataFrame conversion enables efficient batch processing and integration with ML pipelines.

## Report Generation
- **Library**: ReportLab for PDF generation
- **Components**: Title page, executive summary, detailed packet tables, threat analysis sections, visualizations
- **Styling**: Professional forensic report template with custom fonts, colors, and table formatting

**Rationale**: PDF export was chosen over HTML reports for legal compliance and evidence preservation requirements in forensic investigations.

# External Dependencies

## Third-Party Python Libraries
- **streamlit**: Web application framework for the user interface
- **scapy**: Packet capture and network protocol parsing
- **pandas**: Data manipulation and analysis for packet metadata
- **numpy**: Numerical computing for ML feature arrays
- **plotly**: Interactive visualization charts
- **reportlab**: PDF document generation for forensic reports
- **scikit-learn**: Machine learning model serialization (pickle format)
- **python-whois**: WHOIS domain/IP registration lookups
- **pycountry**: Country code and flag emoji mapping
- **requests**: HTTP client for external API calls

## External APIs
- **ip-api.com**: GeoIP location service (country, region, city, ISP, coordinates)
  - Free tier with rate limiting
  - HTTP JSON API with 5-second timeout
  - Returns geographic metadata for IP addresses

**Rationale**: ip-api.com was chosen as a free, reliable GeoIP service that doesn't require API keys for basic usage, simplifying deployment.

**Alternatives**: MaxMind GeoLite2 was considered but requires database downloads and updates, adding complexity.

## Network Services
- **DNS Reverse Lookup**: Python socket library for PTR record resolution
- **WHOIS Protocol**: Domain registration and ownership information retrieval

## Concurrency Model
- **ThreadPoolExecutor**: Used in `geoip_tools.py` for parallel forensic lookups (WHOIS, DNS)
- **Configuration**: Max 3 worker threads to prevent API rate limiting
- **Timeout Handling**: 5-second timeouts on external API calls to prevent blocking

**Rationale**: ThreadPoolExecutor provides simple parallelism for I/O-bound forensic lookups without the complexity of async/await patterns.

## File System Dependencies
- **Temporary Files**: Uses Python's `tempfile` module for uploaded PCAP file handling
- **Model Storage**: Expects pre-trained ML model at `ai_model/model.pkl`
- **Asset Storage**: Logo and branding assets in `assets/` directory

**Note**: The application currently uses pickle for model serialization. No database is configured, but the architecture could support PostgreSQL or other databases if persistent storage of analysis results is required in future iterations.