from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json

from app.database import models
from app.database.connection import get_db

class AlertRepository:
    @staticmethod
    def create(db: Session, alert_data: Dict) -> models.Alert:
        """Create a new alert"""
        # Ensure timestamp is datetime object
        if isinstance(alert_data.get("timestamp"), str):
            from datetime import datetime
            alert_data["timestamp"] = datetime.fromisoformat(alert_data["timestamp"].replace('Z', '+00:00'))
        
        alert = models.Alert(**alert_data)
        db.add(alert)
        db.flush()
        return alert
    
    @staticmethod
    def get_all(db: Session, limit: int = 1000) -> List[models.Alert]:
        """Get all alerts"""
        return db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(limit).all()
    
    @staticmethod
    def get_recent(db: Session, minutes: int = 60) -> List[models.Alert]:
        """Get recent alerts"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return db.query(models.Alert).filter(models.Alert.timestamp >= cutoff).all()
    
    @staticmethod
    def get_count(db: Session) -> int:
        """Get total alert count"""
        return db.query(func.count(models.Alert.id)).scalar() or 0
    
    @staticmethod
    def mark_noise(db: Session, alert_ids: List[int]) -> int:
        """Mark alerts as noise"""
        if not alert_ids:
            return 0
        count = db.query(models.Alert).filter(models.Alert.id.in_(alert_ids)).update(
            {models.Alert.is_noise: True}, synchronize_session=False
        )
        db.flush()
        return count
    
    @staticmethod
    def get_stats(db: Session) -> Dict:
        """Get comprehensive alert statistics"""
        total = db.query(func.count(models.Alert.id)).scalar() or 0
        
        if total == 0:
            return {
                "total_raw_alerts": 0,
                "total_noise_removed": 0,
                "total_clean_alerts": 0,
                "reduction_percent": 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "top_alert_types": {},
                "by_service": {}
            }
        
        # Count noise alerts
        noise = db.query(func.count(models.Alert.id)).filter(models.Alert.is_noise == True).scalar() or 0
        clean = total - noise
        
        # Severity distribution
        severity_results = db.query(
            models.Alert.severity, func.count(models.Alert.id)
        ).group_by(models.Alert.severity).all()
        by_severity = {s: c for s, c in severity_results}
        
        # Service distribution
        service_results = db.query(
            models.Alert.service, func.count(models.Alert.id)
        ).group_by(models.Alert.service).all()
        by_service = {s: c for s, c in service_results}
        
        # Top alert types
        type_results = db.query(
            models.Alert.alert_type, func.count(models.Alert.id)
        ).group_by(models.Alert.alert_type).order_by(func.count(models.Alert.id).desc()).limit(10).all()
        top_alert_types = {t: c for t, c in type_results}
        
        # Calculate reduction percentage (noise reduction effectiveness)
        reduction_percent = round((noise / total) * 100, 2) if total > 0 else 0
        
        return {
            "total_raw_alerts": total,
            "total_noise_removed": noise,
            "total_clean_alerts": clean,
            "reduction_percent": reduction_percent,
            "by_severity": by_severity,
            "top_alert_types": top_alert_types,
            "by_service": by_service
        }
    
    @staticmethod
    def clear_all(db: Session) -> int:
        """Clear all alerts"""
        count = db.query(models.Alert).delete()
        db.flush()
        return count

class AnalysisRepository:
    @staticmethod
    def create(db: Session, analysis_data: Dict) -> models.Analysis:
        """Create a new analysis record"""
        analysis = models.Analysis(**analysis_data)
        db.add(analysis)
        db.flush()
        return analysis
    
    @staticmethod
    def get_all(db: Session, limit: int = 20) -> List[models.Analysis]:
        """Get all analyses"""
        return db.query(models.Analysis).order_by(desc(models.Analysis.timestamp)).limit(limit).all()
    
    @staticmethod
    def get_by_id(db: Session, analysis_id: int) -> Optional[models.Analysis]:
        """Get analysis by ID"""
        return db.query(models.Analysis).filter(models.Analysis.id == analysis_id).first()
    
    @staticmethod
    def get_count(db: Session) -> int:
        """Get total analysis count"""
        return db.query(func.count(models.Analysis.id)).scalar() or 0
    
    @staticmethod
    def clear_all(db: Session) -> int:
        """Clear all analyses"""
        count = db.query(models.Analysis).delete()
        db.flush()
        return count