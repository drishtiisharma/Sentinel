from fastapi import APIRouter, HTTPException, Query
from typing import List, Dict, Any
import logging

from app.api.schemas import GenerateRequest, AnalyzeRequest, StatsResponse
from app.services.alert_service import AlertService
from app.services.analysis_service import AnalysisService
from app.database.repository import AlertRepository
from app.database.connection import get_db
from app.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)
analysis_service = AnalysisService()

@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "gemini_configured": settings.GEMINI_ENABLED,
        "gemini_enabled": settings.GEMINI_ENABLED,
        "stored_alerts": AlertRepository.get_all(get_db().__enter__()).__len__() if False else 0,
        "version": settings.VERSION
    }

@router.post("/generate")
async def generate_alerts(request: GenerateRequest):
    """Generate realistic alerts"""
    try:
        alerts = AlertService.generate_alert(
            request.alert_type,
            request.service,
            request.quantity
        )
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Generate failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/simulate-incident")
async def simulate_incident():
    """Simulate a cascading incident"""
    try:
        result = AlertService.simulate_incident()
        return result
    except Exception as e:
        logger.error(f"Incident simulation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze")
async def analyze_alerts(request: AnalyzeRequest):
    """Perform ML-powered alert analysis"""
    try:
        analysis = await analysis_service.analyze_alerts(request.alerts)
        return analysis
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_stats():
    """Get alert statistics"""
    try:
        with get_db() as db:
            stats = AlertRepository.get_stats(db)
        return stats
    except Exception as e:
        logger.error(f"Stats failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history")
async def get_history(limit: int = Query(20, ge=1, le=100)):
    """Get analysis history"""
    try:
        history = AnalysisService.get_analysis_history(limit)
        return {"analyses": history}
    except Exception as e:
        logger.error(f"History failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/history/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Get specific analysis by ID"""
    try:
        analysis = AnalysisService.get_analysis_by_id(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        return analysis
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/clear-all")
async def clear_all():
    """Clear all alerts and history"""
    try:
        count = AlertService.clear_all_alerts()
        return {"status": "success", "message": f"Cleared {count} alerts", "cleared_count": count}
    except Exception as e:
        logger.error(f"Clear failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))