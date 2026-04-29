import os
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import services and ML modules
from app.services.alert_service import AlertService
from app.services.analysis_service import AnalysisService
from app.database.connection import init_db
from app.config import settings

# Define request/response models
class GenerateRequest(BaseModel):
    alert_type: str
    service: str
    quantity: int

class AnalyzeRequest(BaseModel):
    alerts: List[Any]

# Initialize services
analysis_service = AnalysisService()

# Create FastAPI app
app = FastAPI(title=settings.PROJECT_NAME, version=settings.VERSION)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
static_dir = Path(__file__).resolve().parent.parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    try:
        init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")

@app.get("/")
async def serve_frontend():
    index_path = static_dir / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return JSONResponse(status_code=404, content={"error": "index.html not found"})

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "gemini_configured": settings.GEMINI_ENABLED,
        "gemini_enabled": settings.GEMINI_ENABLED,
        "version": settings.VERSION
    }

@app.post("/generate")
async def generate_alerts(request: GenerateRequest):
    """Generate realistic alerts with patterns"""
    try:
        alerts = AlertService.generate_alert(
            request.alert_type,
            request.service,
            request.quantity
        )
        return {"alerts": alerts}
    except Exception as e:
        print(f"Generate error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/simulate-incident")
async def simulate_incident():
    """Simulate a cascading incident"""
    try:
        result = AlertService.simulate_incident()
        return result
    except Exception as e:
        print(f"Incident simulation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze")
async def analyze_alerts(request: AnalyzeRequest):
    """Perform ML-powered alert analysis"""
    try:
        if not request.alerts:
            return {
                "total_alerts": 0,
                "filtered_alerts": 0,
                "noise_removed": 0,
                "reduction_percent": 0,
                "ai_summary": "No alerts to analyze. Generate alerts to see AI intelligence in action.",
                "root_cause": {"service": "unknown", "confidence": "LOW", "affected": []},
                "future_prediction": {
                    "prediction": "NOMINAL",
                    "confidence": "HIGH",
                    "message": "No system activity detected",
                    "eta": "24h",
                    "risk_factors": {"critical_alerts": 0, "high_alerts": 0, "affected_services": 0}
                },
                "security_threats": [],
                "cascade_chain": [],
                "top_alerts": [],
                "clusters": [],
                "priority_ranking": [],
                "recommendations": [],
                "severity_distribution": {},
                "type_counts": {}
            }
        
        # Run full ML analysis
        analysis = await analysis_service.analyze_alerts(request.alerts)
        return analysis
    except Exception as e:
        print(f"Analysis error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_stats():
    """Get alert statistics"""
    try:
        from app.database.connection import get_db
        from app.database.repository import AlertRepository
        
        with get_db() as db:
            stats = AlertRepository.get_stats(db)
        return stats
    except Exception as e:
        print(f"Stats error: {e}")
        return {
            "reduction_percent": 0,
            "total_raw_alerts": 0,
            "total_noise_removed": 0,
            "total_clean_alerts": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "top_alert_types": {},
            "by_service": {}
        }

@app.get("/history")
async def get_history(limit: int = 20):
    """Get analysis history"""
    try:
        history = AnalysisService.get_analysis_history(limit)
        return {"analyses": history}
    except Exception as e:
        print(f"History error: {e}")
        return {"analyses": []}

@app.get("/history/{analysis_id}")
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
        print(f"Get analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/clear-all")
async def clear_all():
    """Clear all alerts and history"""
    try:
        count = AlertService.clear_all_alerts()
        return {"status": "success", "message": f"Cleared {count} alerts", "cleared_count": count}
    except Exception as e:
        print(f"Clear error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})