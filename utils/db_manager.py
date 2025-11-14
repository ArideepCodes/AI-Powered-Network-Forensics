import os
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import pandas as pd
import json

Base = declarative_base()

class AnalysisSession(Base):
    __tablename__ = 'analysis_sessions'
    
    id = Column(Integer, primary_key=True)
    session_name = Column(String(255), nullable=False)
    pcap_filename = Column(String(255), nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow)
    total_packets = Column(Integer)
    threat_summary = Column(JSON)
    
    packets = relationship("PacketRecord", back_populates="session", cascade="all, delete-orphan")
    forensic_data = relationship("ForensicLookup", back_populates="session", cascade="all, delete-orphan")

class PacketRecord(Base):
    __tablename__ = 'packet_records'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('analysis_sessions.id'))
    packet_number = Column(Integer)
    timestamp = Column(String(50))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    protocol = Column(String(10))
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    flags = Column(String(50), nullable=True)
    payload_size = Column(Integer)
    length = Column(Integer)
    threat_type = Column(String(100))
    risk_score = Column(Float)
    ai_message = Column(Text)
    
    session = relationship("AnalysisSession", back_populates="packets")

class ForensicLookup(Base):
    __tablename__ = 'forensic_lookups'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(Integer, ForeignKey('analysis_sessions.id'))
    ip_address = Column(String(45))
    lookup_type = Column(String(20))
    lookup_data = Column(JSON)
    lookup_timestamp = Column(DateTime, default=datetime.utcnow)
    
    session = relationship("AnalysisSession", back_populates="forensic_data")

class DatabaseManager:
    def __init__(self):
        database_url = os.getenv('DATABASE_URL')
        if not database_url:
            raise ValueError("DATABASE_URL environment variable not set")
        
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def save_analysis_session(self, session_name, pcap_filename, packets_df, threat_summary):
        try:
            analysis_session = AnalysisSession(
                session_name=session_name,
                pcap_filename=pcap_filename,
                total_packets=len(packets_df),
                threat_summary=threat_summary
            )
            
            self.session.add(analysis_session)
            self.session.flush()
            
            for _, row in packets_df.iterrows():
                packet_record = PacketRecord(
                    session_id=analysis_session.id,
                    packet_number=int(row.get('Packet #', 0)),
                    timestamp=str(row.get('Timestamp', '')),
                    source_ip=str(row.get('Source IP', '')),
                    destination_ip=str(row.get('Destination IP', '')),
                    protocol=str(row.get('Protocol', '')),
                    source_port=int(row['Source Port']) if pd.notna(row.get('Source Port')) and row.get('Source Port') != '' else None,
                    destination_port=int(row['Destination Port']) if pd.notna(row.get('Destination Port')) and row.get('Destination Port') != '' else None,
                    flags=str(row.get('Flags', '')),
                    payload_size=int(row.get('Payload Size', 0)),
                    length=int(row.get('Length', 0)),
                    threat_type=str(row.get('Threat Type', 'Unknown')),
                    risk_score=float(row.get('Risk Score', 0.0)),
                    ai_message=str(row.get('AI Analysis', ''))
                )
                self.session.add(packet_record)
            
            self.session.commit()
            return analysis_session.id
        except Exception as e:
            self.session.rollback()
            raise Exception(f"Failed to save analysis session: {str(e)}")
    
    def load_analysis_session(self, session_id):
        try:
            analysis_session = self.session.query(AnalysisSession).filter_by(id=session_id).first()
            if not analysis_session:
                return None
            
            packets = self.session.query(PacketRecord).filter_by(session_id=session_id).all()
            
            packets_data = []
            for pkt in packets:
                packets_data.append({
                    'Packet #': pkt.packet_number,
                    'Timestamp': pkt.timestamp,
                    'Source IP': pkt.source_ip,
                    'Destination IP': pkt.destination_ip,
                    'Protocol': pkt.protocol,
                    'Source Port': pkt.source_port if pkt.source_port is not None else '',
                    'Destination Port': pkt.destination_port if pkt.destination_port is not None else '',
                    'Flags': pkt.flags,
                    'Payload Size': pkt.payload_size,
                    'Length': pkt.length,
                    'Threat Type': pkt.threat_type,
                    'Risk Score': pkt.risk_score,
                    'AI Analysis': pkt.ai_message
                })
            
            packets_df = pd.DataFrame(packets_data)
            
            return {
                'session_name': analysis_session.session_name,
                'pcap_filename': analysis_session.pcap_filename,
                'upload_timestamp': analysis_session.upload_timestamp,
                'total_packets': analysis_session.total_packets,
                'threat_summary': analysis_session.threat_summary,
                'packets_df': packets_df
            }
        except Exception as e:
            raise Exception(f"Failed to load analysis session: {str(e)}")
    
    def list_all_sessions(self):
        try:
            sessions = self.session.query(AnalysisSession).order_by(AnalysisSession.upload_timestamp.desc()).all()
            return [{
                'id': s.id,
                'session_name': s.session_name,
                'pcap_filename': s.pcap_filename,
                'upload_timestamp': s.upload_timestamp,
                'total_packets': s.total_packets,
                'threat_summary': s.threat_summary
            } for s in sessions]
        except Exception as e:
            raise Exception(f"Failed to list sessions: {str(e)}")
    
    def delete_session(self, session_id):
        try:
            analysis_session = self.session.query(AnalysisSession).filter_by(id=session_id).first()
            if analysis_session:
                self.session.delete(analysis_session)
                self.session.commit()
                return True
            return False
        except Exception as e:
            self.session.rollback()
            raise Exception(f"Failed to delete session: {str(e)}")
    
    def save_forensic_lookup(self, session_id, ip_address, lookup_type, lookup_data):
        try:
            forensic_lookup = ForensicLookup(
                session_id=session_id,
                ip_address=ip_address,
                lookup_type=lookup_type,
                lookup_data=lookup_data
            )
            self.session.add(forensic_lookup)
            self.session.commit()
            return True
        except Exception as e:
            self.session.rollback()
            raise Exception(f"Failed to save forensic lookup: {str(e)}")
    
    def get_forensic_lookups(self, session_id):
        try:
            lookups = self.session.query(ForensicLookup).filter_by(session_id=session_id).all()
            return [{
                'ip_address': l.ip_address,
                'lookup_type': l.lookup_type,
                'lookup_data': l.lookup_data,
                'lookup_timestamp': l.lookup_timestamp
            } for l in lookups]
        except Exception as e:
            raise Exception(f"Failed to get forensic lookups: {str(e)}")
    
    def close(self):
        self.session.close()
