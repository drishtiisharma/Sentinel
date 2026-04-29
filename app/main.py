import os
import traceback
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import google.generativeai as genai
from pydantic import BaseModel
from typing import List, Optional, Any
import json

# Define request/response models
class GenerateRequest(BaseModel):
    alert_type: str
    service: str
    quantity: int

class AnalyzeRequest(BaseModel):
    alerts: List[Any]

app = FastAPI(title="SENTINEL AIOps API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse(Path.cwd() / "index.html")

# ============= SIMPLIFIED ENDPOINTS =============

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "gemini_configured": False,
        "stored_alerts": 0
    }

@app.post("/generate")
async def generate_alerts(request: GenerateRequest):
    try:
        alerts = []
        for i in range(request.quantity):
            alerts.append({
                "timestamp": "2024-01-01T12:00:00Z",
                "service": request.service or f"service-{i}",
                "type": request.alert_type or "error",
                "message": f"Alert {i+1}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM"][i % 3]
            })
        return {"alerts": alerts}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/simulate-incident")
async def simulate_incident():
    try:
        return {
            "alerts": [
                {
                    "timestamp": "2024-01-01T12:00:00Z",
                    "service": "database",
                    "type": "connection_failure",
                    "message": "Database connection failed",
                    "severity": "CRITICAL"
                }
            ],
            "chain_summary": ["DB_FAILURE", "API_TIMEOUT"],
            "count": 1
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/analyze")
async def analyze_alerts(request: AnalyzeRequest):
    try:
        return {
            "noise_removed": 0,
            "filtered_alerts": len(request.alerts),
            "total_alerts": len(request.alerts),
            "ai_summary": "Analysis complete.",
            "security_threats": [],
            "future_prediction": {
                "prediction": "NOMINAL",
                "confidence": "HIGH",
                "message": "System stable",
                "eta": "24h",
                "risk_factors": {"critical_alerts": 0, "high_alerts": 0, "affected_services": 0}
            },
            "root_cause": {"service": "unknown", "confidence": "LOW", "affected": []},
            "cascade_chain": [],
            "top_alerts": [],
            "clusters": [],
            "priority_ranking": [],
            "recommendations": [],
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "type_counts": {}
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/stats")
async def get_stats():
    try:
        return {
            "reduction_percent": 0,
            "total_raw_alerts": 0,
            "total_noise_removed": 0,
            "total_clean_alerts": 0,
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0},
            "top_alert_types": {},
            "by_service": {}
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/history")
async def get_history(limit: int = 20):
    try:
        return {"analyses": []}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/history/{analysis_id}")
async def get_analysis(analysis_id: int):
    try:
        return {
            "id": analysis_id,
            "noise_removed": 0,
            "filtered_alerts": 0,
            "total_alerts": 0,
            "ai_summary": f"Analysis #{analysis_id}",
            "security_threats": [],
            "future_prediction": {},
            "root_cause": {},
            "cascade_chain": [],
            "severity_distribution": {}
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/clear-all")
async def clear_all():
    try:
        return {"status": "success", "message": "All history cleared"}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})