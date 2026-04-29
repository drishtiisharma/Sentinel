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
from datetime import datetime
import random

# Load environment variables
load_dotenv()

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import services and ML modules
from app.services.alert_service import AlertService
from app.database.connection import init_db, get_db
from app.database.repository import AlertRepository
from app.config import settings

# Define request/response models
class GenerateRequest(BaseModel):
    alert_type: str
    service: str
    quantity: int

class AnalyzeRequest(BaseModel):
    alerts: List[Any]

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
        import traceback
        traceback.print_exc()
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
    """Analyze alerts with ML-powered insights"""
    try:
        alerts = request.alerts
        total_alerts = len(alerts)
        
        if total_alerts == 0:
            return {
                "total_alerts": 0,
                "filtered_alerts": 0,
                "noise_removed": 0,
                "reduction_percent": 0,
                "ai_summary": "No alerts to analyze. Generate alerts to see AI intelligence in action.",
                "security_threats": [],
                "future_prediction": {
                    "prediction": "NOMINAL",
                    "confidence": "HIGH",
                    "message": "No system activity detected",
                    "eta": "24h",
                    "risk_factors": {"critical_alerts": 0, "high_alerts": 0, "affected_services": 0}
                },
                "root_cause": {"service": "unknown", "confidence": "LOW", "affected": []},
                "cascade_chain": [],
                "top_alerts": [],
                "clusters": [],
                "priority_ranking": [],
                "recommendations": [],
                "severity_distribution": {},
                "type_counts": {}
            }
        
        # Calculate severity distribution
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_counts = {}
        service_counts = {}
        
        for alert in alerts:
            severity = alert.get("severity", "MEDIUM")
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            alert_type = alert.get("alert_type", "unknown")
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            service = alert.get("service", "unknown")
            service_counts[service] = service_counts.get(service, 0) + 1
        
        critical_count = severity_count.get("CRITICAL", 0)
        high_count = severity_count.get("HIGH", 0)
        medium_count = severity_count.get("MEDIUM", 0)
        
        # Calculate reduction percent (mock for now, based on noise detection)
        estimated_noise = medium_count // 2 if medium_count > 0 else 0
        reduction_percent = int((estimated_noise / total_alerts) * 100) if total_alerts > 0 else 0
        
        # Build priority ranking
        severity_weight = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 10}
        priority_ranking = []
        
        # Sort alerts by severity weight
        sorted_alerts = sorted(alerts, key=lambda x: severity_weight.get(x.get("severity", "MEDIUM"), 40), reverse=True)
        
        for i, alert in enumerate(sorted_alerts[:20]):
            severity = alert.get("severity", "MEDIUM")
            alert_type = alert.get("alert_type", "Unknown")
            service = alert.get("service", "unknown")
            
            priority_ranking.append({
                "type": alert_type,
                "severity": severity,
                "score": severity_weight.get(severity, 40),
                "reason": f"{severity} severity alert from {service}: {alert.get('message', '')[:50]}"
            })
        
        # Build top alerts
        top_alerts = []
        for alert in sorted_alerts[:10]:
            top_alerts.append({
                "service": alert.get("service", "unknown"),
                "type": alert.get("alert_type", "unknown"),
                "severity": alert.get("severity", "MEDIUM"),
                "score": severity_weight.get(alert.get("severity", "MEDIUM"), 40)
            })
        
        # Build clusters
        clusters = []
        cluster_map = {}
        for alert in alerts:
            alert_type = alert.get("alert_type", "unknown")
            if alert_type not in cluster_map:
                cluster_map[alert_type] = []
            cluster_map[alert_type].append(alert)
        
        for alert_type, cluster_alerts in cluster_map.items():
            if len(cluster_alerts) > 0:
                severities = [a.get("severity", "MEDIUM") for a in cluster_alerts]
                dominant = max(set(severities), key=severities.count)
                clusters.append({
                    "id": hash(alert_type) % 10000,
                    "count": len(cluster_alerts),
                    "dominant_severity": dominant,
                    "service": cluster_alerts[0].get("service", "unknown"),
                    "type": alert_type,
                    "total_score": sum(severity_weight.get(s, 40) for s in severities)
                })
        
        # Build recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append({
                "action": "🚨 Investigate Critical Alerts Immediately",
                "detail": f"{critical_count} critical alerts detected. These require immediate attention as they may indicate system failure or security breach.",
                "urgency": "IMMEDIATE"
            })
        
        if high_count > 0:
            recommendations.append({
                "action": "⚠️ Review High Severity Issues",
                "detail": f"{high_count} high severity alerts detected. Investigate root causes to prevent escalation.",
                "urgency": "SOON"
            })
        
        if len(clusters) > 3:
            recommendations.append({
                "action": "📊 Alert Clustering Detected",
                "detail": f"Found {len(clusters)} alert clusters. Similar alerts are grouped together for easier analysis.",
                "urgency": "MONITOR"
            })
        
        if total_alerts > 10:
            recommendations.append({
                "action": "🔧 Enable Noise Reduction",
                "detail": f"High alert volume detected ({total_alerts} alerts). Consider enabling noise reduction filters to reduce fatigue.",
                "urgency": "MONITOR"
            })
        
        # Determine root cause
        root_cause_service = "unknown"
        root_cause_confidence = "LOW"
        
        service_critical_count = {}
        for alert in alerts:
            service = alert.get("service", "unknown")
            severity = alert.get("severity", "MEDIUM")
            if severity in ["CRITICAL", "HIGH"]:
                service_critical_count[service] = service_critical_count.get(service, 0) + 1
        
        if service_critical_count:
            root_cause_service = max(service_critical_count, key=service_critical_count.get)
            max_count = service_critical_count[root_cause_service]
            if max_count >= 3:
                root_cause_confidence = "HIGH"
            elif max_count >= 1:
                root_cause_confidence = "MEDIUM"
        
        root_cause = {
            "service": root_cause_service,
            "confidence": root_cause_confidence,
            "affected": list(service_counts.keys())
        }
        
        # Generate cascade chain
        ordered_alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""))
        cascade_chain = []
        seen = set()
        for alert in ordered_alerts[:8]:
            service = alert.get("service", "")
            alert_type = alert.get("alert_type", "")
            key = f"{service}_{alert_type}"
            if key not in seen:
                cascade_chain.append(f"{service}:{alert_type}")
                seen.add(key)
        
        # Security threats detection
        security_threats = []
        auth_failures = [a for a in alerts if "auth" in a.get("alert_type", "").lower() or "authentication" in a.get("message", "").lower()]
        if len(auth_failures) >= 3:
            security_threats.append({
                "type": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": 75,
                "evidence": len(auth_failures),
                "description": f"Multiple authentication failures detected ({len(auth_failures)} attempts)",
                "affected_services": list(set(a.get("service") for a in auth_failures)),
                "indicators": [f"{a.get('service')}: {a.get('message', '')[:50]}" for a in auth_failures[:3]],
                "next_steps": ["Block suspicious IPs", "Enable rate limiting", "Review access logs"],
                "recommendations": ["Implement MFA", "Use strong passwords", "Monitor failed logins"],
                "time_pattern": "Multiple occurrences in short time window"
            })
        
        db_failures = [a for a in alerts if "database" in a.get("service", "").lower() or "database" in a.get("alert_type", "").lower()]
        if len(db_failures) >= 2:
            security_threats.append({
                "type": "SERVICE_ATTACK",
                "severity": "HIGH",
                "confidence": 60,
                "evidence": len(db_failures),
                "description": f"Database service experiencing failures ({len(db_failures)} incidents)",
                "affected_services": list(set(a.get("service") for a in db_failures)),
                "indicators": [f"{a.get('alert_type')}: {a.get('message', '')[:50]}" for a in db_failures[:3]],
                "next_steps": ["Check database health", "Verify connections", "Review logs"],
                "recommendations": ["Implement connection pooling", "Add database replica", "Monitor query performance"],
                "time_pattern": "Recurring failures detected"
            })
        
        # Generate AI summary
        if critical_count > 0:
            ai_summary = f"🚨 CRITICAL: {critical_count} critical alerts detected. The system is experiencing severe issues affecting {root_cause_service}. Immediate action required. " + \
                        f"Top issues: {', '.join(list(type_counts.keys())[:3])}. " + \
                        f"Recommend focusing on {root_cause_service} service first."
        elif high_count > 0:
            ai_summary = f"⚠️ WARNING: {high_count} high severity alerts detected. System degradation observed in {root_cause_service}. " + \
                        f"Alert types: {', '.join(list(type_counts.keys())[:3])}. " + \
                        f"Monitor {root_cause_service} closely and investigate root causes."
        else:
            ai_summary = f"✅ NOMINAL: Analyzed {total_alerts} alerts. No critical issues detected. " + \
                        f"System appears stable with {len(type_counts)} different alert types. " + \
                        f"Recommend continuing normal monitoring."

        # Future prediction
        if critical_count >= 2:
            prediction = "CRITICAL_FAILURE"
            pred_confidence = "HIGH"
            pred_message = "High probability of system failure - immediate intervention required"
            pred_eta = "1h"
        elif critical_count >= 1 or high_count >= 3:
            prediction = "MAJOR_DEGRADATION"
            pred_confidence = "MEDIUM"
            pred_message = "System degradation expected - investigate root causes"
            pred_eta = "3h"
        elif high_count >= 1:
            prediction = "INSTABILITY"
            pred_confidence = "MEDIUM"
            pred_message = "System showing signs of instability - monitor closely"
            pred_eta = "6h"
        else:
            prediction = "NOMINAL"
            pred_confidence = "HIGH"
            pred_message = "System appears stable - continue normal operations"
            pred_eta = "24h"

        # ============================================================
        # >>> ADD THE HISTORY SAVING TRY BLOCK RIGHT HERE <<<
        # ============================================================
        
        # Save analysis to history
        try:
            from app.database.repository import AnalysisRepository
            from app.database.connection import get_db
            
            with get_db() as db:
                analysis_record = {
                    "total_alerts": total_alerts,
                    "filtered_alerts": total_alerts - estimated_noise,
                    "noise_removed": estimated_noise,
                    "reduction_percent": reduction_percent,
                    "ai_summary": ai_summary,
                    "root_cause": root_cause,
                    "future_prediction": {
                        "prediction": prediction,
                        "confidence": pred_confidence,
                        "message": pred_message,
                        "eta": pred_eta,
                        "risk_factors": {
                            "critical_alerts": critical_count,
                            "high_alerts": high_count,
                            "affected_services": len(service_counts)
                        }
                    },
                    "recommendations": recommendations,
                    "security_threats": security_threats,
                    "cascade_chain": cascade_chain,
                    "clusters": clusters,
                    "severity_distribution": severity_count,
                    "type_counts": type_counts,
                    "service_counts": service_counts,
                    "raw_analysis": {}
                }
                AnalysisRepository.create(db, analysis_record)
                print(f"Analysis saved to history with ID")
        except Exception as e:
            print(f"Failed to save analysis to history: {e}")
            import traceback
            traceback.print_exc()
        
        # ============================================================
        # >>> THEN THE RETURN STATEMENT <<<
        # ============================================================
        
        return {
            "total_alerts": total_alerts,
            "filtered_alerts": total_alerts - estimated_noise,
            "noise_removed": estimated_noise,
            "reduction_percent": reduction_percent,
            "ai_summary": ai_summary,
            "security_threats": security_threats,
            "future_prediction": {
                "prediction": prediction,
                "confidence": pred_confidence,
                "message": pred_message,
                "eta": pred_eta,
                "risk_factors": {
                    "critical_alerts": critical_count,
                    "high_alerts": high_count,
                    "affected_services": len(service_counts)
                }
            },
            "root_cause": root_cause,
            "cascade_chain": cascade_chain,
            "top_alerts": top_alerts,
            "clusters": clusters,
            "priority_ranking": priority_ranking,
            "recommendations": recommendations,
            "severity_distribution": severity_count,
            "type_counts": type_counts
        }
        
    except Exception as e:
        print(f"Analysis error: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/stats")
async def get_stats():
    """Get alert statistics"""
    try:
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
        from app.database.repository import AnalysisRepository
        with get_db() as db:
            analyses = AnalysisRepository.get_all(db, limit)
            return {
                "analyses": [
                    {
                        "id": a.id,
                        "timestamp": a.timestamp.isoformat(),
                        "total_alerts": a.total_alerts,
                        "filtered_alerts": a.filtered_alerts,
                        "noise_removed": a.noise_removed,
                        "reduction_percent": a.reduction_percent,
                        "root_cause": a.root_cause.get("service", "unknown") if a.root_cause else "unknown",
                        "confidence": a.root_cause.get("confidence", "LOW") if a.root_cause else "LOW",
                        "ai_summary": a.ai_summary[:100] if a.ai_summary else ""
                    }
                    for a in analyses
                ]
            }
    except Exception as e:
        print(f"History error: {e}")
        return {"analyses": []}

@app.get("/history/{analysis_id}")
async def get_analysis(analysis_id: int):
    """Get specific analysis by ID"""
    try:
        from app.database.repository import AnalysisRepository
        with get_db() as db:
            analysis = AnalysisRepository.get_by_id(db, analysis_id)
            if not analysis:
                raise HTTPException(status_code=404, detail="Analysis not found")
            
            return {
                "id": analysis.id,
                "timestamp": analysis.timestamp.isoformat(),
                "total_alerts": analysis.total_alerts,
                "filtered_alerts": analysis.filtered_alerts,
                "noise_removed": analysis.noise_removed,
                "reduction_percent": analysis.reduction_percent,
                "ai_summary": analysis.ai_summary,
                "root_cause": analysis.root_cause,
                "future_prediction": analysis.future_prediction,
                "security_threats": analysis.security_threats,
                "cascade_chain": analysis.cascade_chain,
                "clusters": analysis.clusters,
                "recommendations": analysis.recommendations,
                "severity_distribution": analysis.severity_distribution,
                "type_counts": analysis.type_counts
            }
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