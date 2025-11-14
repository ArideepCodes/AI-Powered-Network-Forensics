import pickle
import os
import numpy as np

threat_categories = ['Normal', 'Port Scan', 'DoS Attack', 'Malware Traffic', 'Suspicious Anomaly']

def load_model():
    model_path = 'ai_model/model.pkl'
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            return pickle.load(f)
    else:
        raise FileNotFoundError(f"Model file not found at {model_path}")

def predict_threat(features, model):
    try:
        features_array = np.array(features).reshape(1, -1)
        
        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]
        
        risk_score = max(probabilities) * 100
        threat_type = threat_categories[prediction]
        
        return threat_type, risk_score, probabilities
    except Exception as e:
        return 'Unknown', 0, []

def generate_ai_analysis(threat_type, risk_score, packet_info):
    analysis_messages = {
        'Normal': f"✅ Normal traffic detected. Risk Score: {risk_score:.1f}%. This packet shows typical communication patterns with no suspicious indicators.",
        'Port Scan': f"⚠️ Potential Port Scan detected! Risk Score: {risk_score:.1f}%. Sequential port probing behavior observed. This could indicate reconnaissance activity.",
        'DoS Attack': f"🚨 DoS Attack pattern detected! Risk Score: {risk_score:.1f}%. High volume of packets or SYN flooding detected. Immediate investigation recommended.",
        'Malware Traffic': f"🔴 Malware Traffic suspected! Risk Score: {risk_score:.1f}%. Unusual communication patterns consistent with C&C (Command & Control) servers.",
        'Suspicious Anomaly': f"⚡ Suspicious Anomaly detected! Risk Score: {risk_score:.1f}%. Traffic deviates from normal patterns. Further forensic analysis advised."
    }
    
    base_message = analysis_messages.get(threat_type, f"Unknown threat pattern. Risk Score: {risk_score:.1f}%")
    
    if packet_info.get('protocol') == 'TCP' and packet_info.get('flags'):
        flags = packet_info.get('flags', '')
        if 'S' in flags and 'A' not in flags:
            base_message += " | SYN flag detected without ACK."
        elif 'F' in flags:
            base_message += " | FIN flag detected."
    
    if packet_info.get('payload_size', 0) > 1000:
        base_message += " | Large payload detected."
    
    return base_message

def get_threat_recommendations(threat_type):
    recommendations = {
        'Normal': ["Continue monitoring", "No immediate action required"],
        'Port Scan': ["Block source IP temporarily", "Enable IDS/IPS rules", "Monitor for escalation"],
        'DoS Attack': ["Implement rate limiting", "Block malicious IPs", "Contact ISP if sustained", "Enable DDoS mitigation"],
        'Malware Traffic': ["Isolate affected system", "Run full malware scan", "Check for data exfiltration", "Update security policies"],
        'Suspicious Anomaly': ["Deep packet inspection required", "Correlate with other security logs", "Monitor source/destination", "Create custom detection rule"]
    }
    
    return recommendations.get(threat_type, ["Further investigation needed"])
