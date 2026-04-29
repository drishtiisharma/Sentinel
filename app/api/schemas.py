from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class GenerateRequest(BaseModel):
    alert_type: str
    service: str
    quantity: int = 1

class AnalyzeRequest(BaseModel):
    alerts: List[Any]

class AlertResponse(BaseModel):
    id: Optional[int]
    timestamp: str
    service: str
    type: str
    message: str
    severity: str
    is_noise: Optional[bool] = False

class AnalysisResponse(BaseModel):
    total_alerts: int
    filtered_alerts: int
    noise_removed: int
    reduction_percent: float
    ai_summary: str
    root_cause: Dict
    future_prediction: Dict
    security_threats: List
    cascade_chain: List
    top_alerts: List
    clusters: List
    priority_ranking: List
    recommendations: List
    severity_distribution: Dict
    type_counts: Dict
    analysis_id: Optional[int] = None

class StatsResponse(BaseModel):
    total_raw_alerts: int
    total_noise_removed: int
    total_clean_alerts: int
    reduction_percent: float
    by_severity: Dict
    by_service: Dict
    top_alert_types: Dict