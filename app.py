import streamlit as st
import pandas as pd
import os
from datetime import datetime
import tempfile

from utils.packet_parser import parse_pcap_file, extract_packet_features
from utils.ml_detector import load_model, predict_threat, generate_ai_analysis, get_threat_recommendations
from utils.geoip_tools import get_geoip_info, get_whois_info, reverse_dns_lookup, get_country_flag_emoji
from utils.visualizer import (create_protocol_distribution_chart, create_threat_distribution_chart,
                               create_traffic_timeline, create_port_activity_chart, create_ip_communication_graph)
from utils.report_builder import generate_forensic_report
from utils.db_manager import DatabaseManager

st.set_page_config(
    page_title="AI Network Forensics Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1e2127;
        color: #ffffff;
        border-radius: 4px 4px 0px 0px;
        padding: 10px 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00ff00;
        color: #000000;
    }
    .threat-box {
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .normal {
        background-color: #00ff0020;
        border-left: 5px solid #00ff00;
    }
    .port-scan {
        background-color: #ffa50020;
        border-left: 5px solid #ffa500;
    }
    .dos {
        background-color: #ff000020;
        border-left: 5px solid #ff0000;
    }
    .malware {
        background-color: #8b00ff20;
        border-left: 5px solid #8b00ff;
    }
    .suspicious {
        background-color: #ffff0020;
        border-left: 5px solid #ffff00;
    }
    </style>
""", unsafe_allow_html=True)

if 'model' not in st.session_state:
    try:
        st.session_state.model = load_model()
    except Exception as e:
        st.error(f"Error loading ML model: {str(e)}")
        st.session_state.model = None

if 'packets_df' not in st.session_state:
    st.session_state.packets_df = pd.DataFrame()
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = []
if 'threats' not in st.session_state:
    st.session_state.threats = []
if 'current_session_id' not in st.session_state:
    st.session_state.current_session_id = None
if 'current_pcap_filename' not in st.session_state:
    st.session_state.current_pcap_filename = None

st.title("🔒 AI-Powered Network Packet Forensics Analyzer")
st.markdown("### Advanced Network Traffic Analysis & Threat Detection")

st.sidebar.title("📋 About")
st.sidebar.info("""
**AI-Powered Network Packet Forensics Analyzer**

A comprehensive tool for analyzing network traffic, detecting threats, and performing forensic investigations.

**Features:**
- 📦 PCAP File Analysis
- 🤖 AI/ML Threat Detection
- 📊 Interactive Visualizations
- 🌍 GeoIP & WHOIS Lookups
- 📄 PDF Forensic Reports
""")

st.sidebar.markdown("---")
st.sidebar.markdown("""
**Created by:**  
**Arideep Kanshabanik**

📧 arideepkanshabanik@gmail.com  
🐙 [github.com/ArideepCodes](https://github.com/ArideepCodes)  
🌐 [arideep.framer.ai](https://arideep.framer.ai)
""")

tabs = st.tabs(["📊 Dashboard", "📦 PCAP Upload & Analysis", "🛠️ Forensic Tools", "📄 Generate Report", "💾 Session History"])

with tabs[0]:
    st.header("📊 Network Analysis Dashboard")
    
    if st.session_state.packets_df.empty:
        st.info("👆 Upload a PCAP file in the 'PCAP Upload & Analysis' tab to start analyzing network traffic.")
        
        st.markdown("### 🎯 Quick Start Guide")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            **Step 1: Upload PCAP**
            - Go to PCAP Upload tab
            - Upload your .pcap file
            - Wait for analysis
            """)
        
        with col2:
            st.markdown("""
            **Step 2: View Analysis**
            - Check threat detection
            - Review visualizations
            - Examine packet details
            """)
        
        with col3:
            st.markdown("""
            **Step 3: Forensics**
            - Use forensic tools
            - Lookup IP information
            - Generate PDF report
            """)
    else:
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Packets", len(st.session_state.packets_df))
        with col2:
            unique_ips = st.session_state.packets_df['src_ip'].nunique()
            st.metric("Unique Source IPs", unique_ips)
        with col3:
            protocols = st.session_state.packets_df['protocol'].nunique()
            st.metric("Protocols Detected", protocols)
        with col4:
            if st.session_state.threats:
                threat_count = sum(1 for t in st.session_state.threats if t != 'Normal')
                st.metric("Threats Detected", threat_count)
            else:
                st.metric("Threats Detected", 0)
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.plotly_chart(create_protocol_distribution_chart(st.session_state.packets_df), 
                          use_container_width=True)
        
        with col2:
            if st.session_state.threats:
                st.plotly_chart(create_threat_distribution_chart(st.session_state.threats), 
                              use_container_width=True)
            else:
                st.info("No threat data available yet.")
        
        st.plotly_chart(create_traffic_timeline(st.session_state.packets_df), 
                       use_container_width=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.plotly_chart(create_port_activity_chart(st.session_state.packets_df), 
                          use_container_width=True)
        
        with col2:
            st.plotly_chart(create_ip_communication_graph(st.session_state.packets_df), 
                          use_container_width=True)

with tabs[1]:
    st.header("📦 PCAP File Upload & Analysis")
    
    uploaded_file = st.file_uploader("Upload a PCAP file for analysis", type=['pcap', 'pcapng'])
    
    if uploaded_file is not None:
        st.session_state.current_pcap_filename = uploaded_file.name
        with st.spinner("🔍 Analyzing PCAP file..."):
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
                    tmp_file.write(uploaded_file.read())
                    tmp_file_path = tmp_file.name
                
                packets_df = parse_pcap_file(tmp_file_path)
                st.session_state.packets_df = packets_df
                
                os.unlink(tmp_file_path)
                
                st.success(f"✅ Successfully parsed {len(packets_df)} packets!")
                
                MAX_PACKETS_FOR_ANALYSIS = 10000
                packets_to_analyze = packets_df
                
                if len(packets_df) > MAX_PACKETS_FOR_ANALYSIS:
                    st.warning(f"⚠️ Large PCAP file detected ({len(packets_df)} packets). For performance, analyzing first {MAX_PACKETS_FOR_ANALYSIS} packets. Full packet data is available in the dashboard visualizations.")
                    packets_to_analyze = packets_df.head(MAX_PACKETS_FOR_ANALYSIS)
                
                st.markdown("### 🤖 AI Threat Detection in Progress...")
                progress_bar = st.progress(0)
                
                analysis_results = []
                threats = []
                
                for idx, row in packets_to_analyze.iterrows():
                    features = extract_packet_features(row)
                    
                    if st.session_state.model:
                        threat, risk_score, probabilities = predict_threat(features, st.session_state.model)
                        ai_message = generate_ai_analysis(threat, risk_score, row.to_dict())
                    else:
                        threat = 'Unknown'
                        risk_score = 0
                        ai_message = 'ML model not available'
                    
                    threats.append(threat)
                    
                    result = {
                        'packet_num': row.get('packet_num', idx + 1),
                        'src_ip': row.get('src_ip'),
                        'dst_ip': row.get('dst_ip'),
                        'protocol': row.get('protocol'),
                        'src_port': row.get('src_port'),
                        'dst_port': row.get('dst_port'),
                        'threat': threat,
                        'risk_score': risk_score,
                        'ai_analysis': ai_message
                    }
                    analysis_results.append(result)
                    
                    progress_bar.progress((idx + 1) / len(packets_to_analyze))
                
                st.session_state.analysis_results = analysis_results
                st.session_state.threats = threats
                
                st.success("✅ AI analysis complete!")
                
                st.markdown("### 💾 Save Analysis Session")
                col1, col2 = st.columns([3, 1])
                with col1:
                    session_name = st.text_input("Session Name:", value=f"Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                with col2:
                    st.write("")
                    st.write("")
                    if st.button("💾 Save to Database"):
                        try:
                            db = DatabaseManager()
                            
                            analysis_df = pd.DataFrame(analysis_results)
                            analysis_df = analysis_df.rename(columns={
                                'packet_num': 'Packet #',
                                'src_ip': 'Source IP',
                                'dst_ip': 'Destination IP',
                                'protocol': 'Protocol',
                                'src_port': 'Source Port',
                                'dst_port': 'Destination Port',
                                'threat': 'Threat Type',
                                'risk_score': 'Risk Score',
                                'ai_analysis': 'AI Analysis'
                            })
                            
                            for col in ['Timestamp', 'Flags', 'Payload Size', 'Length']:
                                if col not in analysis_df.columns:
                                    if col == 'Timestamp':
                                        analysis_df[col] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                    elif col in ['Flags']:
                                        analysis_df[col] = ''
                                    else:
                                        analysis_df[col] = 0
                            
                            threat_counts = pd.Series(threats).value_counts().to_dict()
                            threat_summary = {
                                'total_threats': sum(1 for t in threats if t != 'Normal'),
                                'threat_breakdown': threat_counts
                            }
                            
                            session_id = db.save_analysis_session(
                                session_name=session_name,
                                pcap_filename=uploaded_file.name,
                                packets_df=analysis_df,
                                threat_summary=threat_summary
                            )
                            
                            st.session_state.current_session_id = session_id
                            db.close()
                            
                            st.success(f"✅ Session saved successfully! Session ID: {session_id}")
                        except Exception as e:
                            st.error(f"❌ Error saving session: {str(e)}")
                
                st.markdown("### 📋 Detailed Packet Analysis")
                
                threat_filter = st.multiselect(
                    "Filter by Threat Type:",
                    options=['All'] + list(set(threats)),
                    default=['All']
                )
                
                filtered_results = analysis_results
                if 'All' not in threat_filter and threat_filter:
                    filtered_results = [r for r in analysis_results if r['threat'] in threat_filter]
                
                for result in filtered_results[:50]:
                    threat_class = result['threat'].lower().replace(' ', '-')
                    
                    with st.expander(f"Packet #{result['packet_num']} - {result['threat']} (Risk: {result['risk_score']:.1f}%)"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"""
                            **Source:** {result['src_ip']}:{result['src_port']}  
                            **Destination:** {result['dst_ip']}:{result['dst_port']}  
                            **Protocol:** {result['protocol']}
                            """)
                        
                        with col2:
                            st.markdown(f"""
                            **Threat Type:** {result['threat']}  
                            **Risk Score:** {result['risk_score']:.1f}%
                            """)
                        
                        st.markdown(f"**AI Analysis:** {result['ai_analysis']}")
                        
                        if result['threat'] != 'Normal':
                            recommendations = get_threat_recommendations(result['threat'])
                            st.markdown("**Recommendations:**")
                            for rec in recommendations:
                                st.markdown(f"- {rec}")
                
                if len(filtered_results) > 50:
                    st.info(f"Showing 50 of {len(filtered_results)} packets. Use filters to narrow down results.")
                
            except Exception as e:
                st.error(f"❌ Error analyzing PCAP file: {str(e)}")
    else:
        st.info("Please upload a PCAP file to begin analysis.")

with tabs[2]:
    st.header("🛠️ Forensic Investigation Tools")
    
    tool_choice = st.selectbox("Select Forensic Tool:", 
                               ["GeoIP Lookup", "WHOIS Lookup", "Reverse DNS Lookup"])
    
    ip_address = st.text_input("Enter IP Address:", placeholder="e.g., 8.8.8.8")
    
    if st.button("🔍 Run Analysis"):
        if ip_address:
            with st.spinner(f"Running {tool_choice}..."):
                try:
                    if tool_choice == "GeoIP Lookup":
                        result = get_geoip_info(ip_address)
                        
                        if 'error' not in result:
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"### {get_country_flag_emoji(result['country_code'])} Geographic Information")
                                st.markdown(f"""
                                **IP Address:** {result['ip']}  
                                **Country:** {result['country']} ({result['country_code']})  
                                **Region:** {result['region']}  
                                **City:** {result['city']}  
                                **Timezone:** {result['timezone']}
                                """)
                            
                            with col2:
                                st.markdown("### 🏢 Organization Information")
                                st.markdown(f"""
                                **ISP:** {result['isp']}  
                                **Organization:** {result['org']}  
                                **Coordinates:** {result['lat']}, {result['lon']}
                                """)
                        else:
                            st.error(f"Error: {result.get('error', 'Unknown error')}")
                    
                    elif tool_choice == "WHOIS Lookup":
                        result = get_whois_info(ip_address)
                        
                        if 'error' not in result:
                            st.markdown("### 📝 WHOIS Information")
                            
                            for key, value in result.items():
                                if key != 'error':
                                    st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
                        else:
                            st.error(f"Error: {result['error']}")
                    
                    elif tool_choice == "Reverse DNS Lookup":
                        result = reverse_dns_lookup(ip_address)
                        
                        st.markdown("### 🔄 Reverse DNS Results")
                        
                        if result['success']:
                            st.success(f"✅ Hostname found: **{result['hostname']}**")
                            st.markdown(f"**IP Address:** {result['ip']}")
                            st.markdown(f"**Aliases:** {result['aliases']}")
                        else:
                            st.warning(f"⚠️ {result.get('error', 'No hostname found')}")
                
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("Please enter an IP address.")

with tabs[3]:
    st.header("📄 Generate Forensic Report")
    
    if st.session_state.packets_df.empty:
        st.info("Please upload and analyze a PCAP file first before generating a report.")
    else:
        st.markdown("### Report Summary")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Packets", len(st.session_state.packets_df))
        with col2:
            st.metric("Analyzed Packets", len(st.session_state.analysis_results))
        with col3:
            threats_detected = sum(1 for t in st.session_state.threats if t != 'Normal')
            st.metric("Threats Found", threats_detected)
        
        st.markdown("---")
        
        report_name = st.text_input("Report Filename:", value="forensic_report.pdf")
        
        if st.button("📥 Generate PDF Report"):
            with st.spinner("Generating comprehensive forensic report..."):
                try:
                    if not report_name.endswith('.pdf'):
                        report_name += '.pdf'
                    
                    output_file = generate_forensic_report(
                        st.session_state.packets_df,
                        st.session_state.threats,
                        st.session_state.analysis_results,
                        output_filename=report_name
                    )
                    
                    st.success(f"✅ Report generated successfully: {output_file}")
                    
                    with open(output_file, 'rb') as f:
                        pdf_data = f.read()
                    
                    st.download_button(
                        label="📥 Download Report",
                        data=pdf_data,
                        file_name=report_name,
                        mime="application/pdf"
                    )
                    
                except Exception as e:
                    st.error(f"❌ Error generating report: {str(e)}")

with tabs[4]:
    st.header("💾 Session History")
    
    st.markdown("### 📚 Saved Analysis Sessions")
    
    try:
        db = DatabaseManager()
        sessions = db.list_all_sessions()
        
        if not sessions:
            st.info("No saved sessions found. Upload and analyze a PCAP file, then save the session to see it here.")
        else:
            st.success(f"Found {len(sessions)} saved session(s)")
            
            for session in sessions:
                with st.expander(f"📁 {session['session_name']} - {session['pcap_filename']} ({session['upload_timestamp'].strftime('%Y-%m-%d %H:%M')})"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Total Packets", session['total_packets'])
                    with col2:
                        threats = session['threat_summary'].get('total_threats', 0)
                        st.metric("Threats Detected", threats)
                    with col3:
                        st.metric("Session ID", session['id'])
                    
                    st.markdown("**Threat Breakdown:**")
                    threat_breakdown = session['threat_summary'].get('threat_breakdown', {})
                    for threat_type, count in threat_breakdown.items():
                        st.markdown(f"- {threat_type}: {count}")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button(f"🔍 Load Session", key=f"load_{session['id']}"):
                            try:
                                loaded_session = db.load_analysis_session(session['id'])
                                
                                if loaded_session:
                                    st.session_state.packets_df = loaded_session['packets_df']
                                    
                                    analysis_results = []
                                    threats = []
                                    for _, row in loaded_session['packets_df'].iterrows():
                                        analysis_results.append({
                                            'packet_num': row.get('Packet #', 0),
                                            'src_ip': row.get('Source IP', ''),
                                            'dst_ip': row.get('Destination IP', ''),
                                            'protocol': row.get('Protocol', ''),
                                            'src_port': row.get('Source Port', ''),
                                            'dst_port': row.get('Destination Port', ''),
                                            'threat': row.get('Threat Type', 'Unknown'),
                                            'risk_score': row.get('Risk Score', 0.0),
                                            'ai_analysis': row.get('AI Analysis', '')
                                        })
                                        threats.append(row.get('Threat Type', 'Unknown'))
                                    
                                    st.session_state.analysis_results = analysis_results
                                    st.session_state.threats = threats
                                    st.session_state.current_session_id = session['id']
                                    st.session_state.current_pcap_filename = loaded_session['pcap_filename']
                                    
                                    st.success(f"✅ Session loaded! Go to the Dashboard tab to view the analysis.")
                                    st.rerun()
                                else:
                                    st.error("Session not found")
                            except Exception as e:
                                st.error(f"Error loading session: {str(e)}")
                    
                    with col2:
                        if st.button(f"📊 View Details", key=f"view_{session['id']}"):
                            try:
                                loaded_session = db.load_analysis_session(session['id'])
                                if loaded_session:
                                    st.markdown("**Packet Data Preview:**")
                                    st.dataframe(loaded_session['packets_df'].head(10), use_container_width=True)
                            except Exception as e:
                                st.error(f"Error viewing session: {str(e)}")
                    
                    with col3:
                        if st.button(f"🗑️ Delete", key=f"delete_{session['id']}"):
                            try:
                                if db.delete_session(session['id']):
                                    st.success("Session deleted successfully!")
                                    st.rerun()
                                else:
                                    st.error("Failed to delete session")
                            except Exception as e:
                                st.error(f"Error deleting session: {str(e)}")
        
        db.close()
    except Exception as e:
        st.error(f"❌ Error accessing database: {str(e)}")
        st.info("Make sure the database is properly configured with DATABASE_URL environment variable.")

st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #888888;'>
    <p><b>AI-Powered Network Packet Forensics Analyzer</b> | Created by Arideep Kanshabanik</p>
    <p>Email: arideepkanshabanik@gmail.com | GitHub: github.com/ArideepCodes | Portfolio: arideep.framer.ai</p>
</div>
""", unsafe_allow_html=True)
