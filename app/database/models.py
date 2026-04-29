from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean, Index
from sqlalchemy.sql import func
from app.database.connection import Base

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    service = Column(String(100), nullable=False)
    alert_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    
    # ML fields
    is_noise = Column(Boolean, default=False)
    cluster_id = Column(Integer, nullable=True)
    similarity_score = Column(Float, nullable=True)
    
    # Metadata
    raw_data = Column(JSON, default=dict)
    
    # Indexes
    __table_args__ = (
        Index('idx_alert_timestamp', 'timestamp'),
        Index('idx_alert_severity', 'severity'),
        Index('idx_alert_service', 'service'),
    )

class Analysis(Base):
    __tablename__ = "analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    total_alerts = Column(Integer, default=0)
    filtered_alerts = Column(Integer, default=0)
    noise_removed = Column(Integer, default=0)
    reduction_percent = Column(Float, default=0.0)
    
    # AI results
    ai_summary = Column(Text, default="")
    root_cause = Column(JSON, default=dict)
    future_prediction = Column(JSON, default=dict)
    recommendations = Column(JSON, default=list)
    security_threats = Column(JSON, default=list)
    cascade_chain = Column(JSON, default=list)
    clusters = Column(JSON, default=list)
    
    # Statistics
    severity_distribution = Column(JSON, default=dict)
    type_counts = Column(JSON, default=dict)
    service_counts = Column(JSON, default=dict)
    
    # Metadata
    raw_analysis = Column(JSON, default=dict)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, server_default=func.now())
    threat_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    affected_services = Column(JSON, default=list)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)

class AlertPattern(Base):
    __tablename__ = "alert_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    pattern_hash = Column(String(64), unique=True, index=True)
    service = Column(String(100))
    alert_type = Column(String(100))
    count = Column(Integer, default=1)
    first_seen = Column(DateTime, server_default=func.now())
    last_seen = Column(DateTime, onupdate=func.now())