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
        alert = models.Alert(**alert_data)
        db.add(alert)
        db.flush()
        return alert
    
    @staticmethod
    def get_all(db: Session, limit: int = 1000) -> List[models.Alert]:
        return db.query(models.Alert).order_by(desc(models.Alert.timestamp)).limit(limit).all()
    
    @staticmethod
    def get_recent(db: Session, minutes: int = 60) -> List[models.Alert]:
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return db.query(models.Alert).filter(models.Alert.timestamp >= cutoff).all()
    
    @staticmethod
    def mark_noise(db: Session, alert_ids: List[int]) -> int:
        count = db.query(models.Alert).filter(models.Alert.id.in_(alert_ids)).update(
            {models.Alert.is_noise: True}, synchronize_session=False
        )
        db.flush()
        return count
    
    @staticmethod
    def get_stats(db: Session) -> Dict:
        total = db.query(func.count(models.Alert.id)).scalar() or 0
        noise = db.query(func.count(models.Alert.id)).filter(models.Alert.is_noise == True).scalar() or 0
        clean = total - noise
        
        severity = db.query(
            models.Alert.severity, func.count(models.Alert.id)
        ).group_by(models.Alert.severity).all()
        
        by_service = db.query(
            models.Alert.service, func.count(models.Alert.id)
        ).group_by(models.Alert.service).all()
        
        by_type = db.query(
            models.Alert.alert_type, func.count(models.Alert.id)
        ).group_by(models.Alert.alert_type).limit(10).all()
        
        reduction = (noise / total * 100) if total > 0 else 0
        
        return {
            "total_raw_alerts": total,
            "total_noise_removed": noise,
            "total_clean_alerts": clean,
            "reduction_percent": round(reduction, 2),
            "by_severity": {s: c for s, c in severity},
            "by_service": {s: c for s, c in by_service},
            "top_alert_types": {t: c for t, c in by_type}
        }
    
    @staticmethod
    def clear_all(db: Session) -> int:
        count = db.query(models.Alert).delete()
        db.query(models.Analysis).delete()
        db.flush()
        return count

class AnalysisRepository:
    @staticmethod
    def create(db: Session, analysis_data: Dict) -> models.Analysis:
        analysis = models.Analysis(**analysis_data)
        db.add(analysis)
        db.flush()
        return analysis
    
    @staticmethod
    def get_all(db: Session, limit: int = 20) -> List[models.Analysis]:
        return db.query(models.Analysis).order_by(desc(models.Analysis.timestamp)).limit(limit).all()
    
    @staticmethod
    def get_by_id(db: Session, analysis_id: int) -> Optional[models.Analysis]:
        return db.query(models.Analysis).filter(models.Analysis.id == analysis_id).first()