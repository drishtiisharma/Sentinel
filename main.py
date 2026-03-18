"""
SENTINEL AIOps Backend
======================
FastAPI + Google Gemini for intelligent alert analysis.
"""
import google.generativeai as genai
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import json
import asyncio
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()

app = FastAPI(title="SENTINEL AIOps API", version="1.0.0")

# ── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Service dependency graph ────────────────────────────────────────────────
SERVICE_GRAPH = {
    "Frontend": ["API Gateway"],
    "Backend": ["Database", "Cache"],
    "API Gateway": ["Auth Service", "Database"],
    "Auth Service": ["Database"],
    "Database": [],
    "Cache": ["Database"],
}

# ── Gemini client ───────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
if not GEMINI_API_KEY:
    print("WARNING: GOOGLE_API_KEY not set. AI features will use fallback mode.")
    genai.configure(api_key="dummy_key")  # Won't be used
    gemini_model = None
else:
    genai.configure(api_key=GEMINI_API_KEY)
    # Using the model you specified
    gemini_model = genai.GenerativeModel("models/gemini-2.0-flash")

# ── Data definitions ────────────────────────────────────────────────────────
ALERT_MESSAGES = {
    "CPU High": [
        "CPU utilization exceeded 95% threshold",
        "Core saturation detected on node-07",
        "Runaway process consuming 98% CPU — PID 44821",
        "Scheduler overload detected — queue depth 1240",
        "CPU steal time elevated: 42% on shared host",
    ],
    "Memory Leak": [
        "Heap memory growing unbounded — 14.2 GB RSS",
        "GC pressure critical — 80% time in GC pause",
        "OOM kill imminent — 97% memory consumed",
        "Memory RSS exceeding container limit",
        "Slab cache leak detected — kernel memory",
    ],
    "API Timeout": [
        "Request timeout after 30s — /api/v2/orders",
        "Upstream connection refused — service:8080",
        "Gateway response delayed >10s — p99 degraded",
        "Health check failing — 5 consecutive misses",
        "Circuit breaker opened — downstream unreachable",
    ],
    "Database Failure": [
        "Connection pool exhausted — 200/200 used",
        "Primary DB unreachable — failover initiated",
        "Replication lag critical — 48s behind primary",
        "Lock wait timeout exceeded — 121 blocked txns",
        "Deadlock detected — rolling back transaction",
    ],
    "Disk Full": [
        "Filesystem /var/log at 98% capacity",
        "Write operation failed: no space left on device",
        "Log rotation stalled — disk full",
        "Inode limit reached — cannot create files",
        "WAL archive disk at 99% — DB writes paused",
    ],
    "Network Spike": [
        "Packet loss 40% on eth0 — NIC degraded",
        "Bandwidth saturation — 9.8 Gbps / 10 Gbps",
        "ARP flood detected — 50k packets/sec",
        "MTU mismatch causing fragmentation storm",
        "BGP route flap — upstream instability",
    ],
    "Auth Failure": [
        "JWT validation failed — 1240 requests rejected",
        "Rate limit breached — 10k req/min from IP block",
        "Invalid credentials flood — brute force suspected",
        "Token revocation error — cache inconsistency",
        "OAuth2 introspection endpoint unreachable",
    ],
}

SEVERITY_MAP = {
    "CPU High":         ["HIGH", "MEDIUM", "HIGH", "MEDIUM"],
    "Memory Leak":      ["CRITICAL", "HIGH", "CRITICAL", "HIGH"],
    "API Timeout":      ["HIGH", "CRITICAL", "HIGH", "HIGH"],
    "Database Failure": ["CRITICAL", "CRITICAL", "CRITICAL", "HIGH"],
    "Disk Full":        ["HIGH", "MEDIUM", "HIGH", "CRITICAL"],
    "Network Spike":    ["MEDIUM", "HIGH", "MEDIUM", "HIGH"],
    "Auth Failure":     ["HIGH", "MEDIUM", "HIGH", "MEDIUM"],
}

INCIDENT_CHAINS = [
    [
        {"type": "Database Failure",  "service": "Database",    "severity": "CRITICAL"},
        {"type": "API Timeout",       "service": "API Gateway", "severity": "HIGH"},
        {"type": "Memory Leak",       "service": "Backend",     "severity": "HIGH"},
        {"type": "CPU High",          "service": "Frontend",    "severity": "MEDIUM"},
    ],
    [
        {"type": "Network Spike",     "service": "API Gateway", "severity": "HIGH"},
        {"type": "Auth Failure",      "service": "Auth Service","severity": "HIGH"},
        {"type": "API Timeout",       "service": "Backend",     "severity": "CRITICAL"},
    ],
    [
        {"type": "Disk Full",         "service": "Database",    "severity": "CRITICAL"},
        {"type": "Database Failure",  "service": "Database",    "severity": "CRITICAL"},
        {"type": "API Timeout",       "service": "API Gateway", "severity": "HIGH"},
        {"type": "Memory Leak",       "service": "Frontend",    "severity": "HIGH"},
    ],
]

# ── Helpers ───────────────────────────────────────────────────────────────────
def make_alert(alert_type: str, service: str, severity: str = None) -> dict:
    if severity is None:
        sev_options = SEVERITY_MAP.get(alert_type, ["MEDIUM"])
        severity = random.choice(sev_options)
    msgs = ALERT_MESSAGES.get(alert_type, ["Unknown alert"])
    return {
        "id": str(uuid.uuid4()),
        "type": alert_type,
        "service": service,
        "severity": severity,
        "message": random.choice(msgs),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

# ── Request / Response models ─────────────────────────────────────────────────
class GenerateRequest(BaseModel):
    alert_type: str
    service: str
    quantity: int = 1

class AnalyzeRequest(BaseModel):
    alerts: list[dict]

# ── Analysis functions ────────────────────────────────────────────────────────
SEVERITY_SCORE = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

def reduce_noise(alerts):
    """Remove duplicate alerts based on service + type + message fingerprint"""
    seen = set()
    filtered = []
    noise_count = 0
    
    for alert in alerts:
        # Create a fingerprint that's not too strict
        fingerprint = (alert["service"], alert["type"], alert.get("message", "")[:30])
        if fingerprint not in seen:
            seen.add(fingerprint)
            filtered.append(alert)
        else:
            noise_count += 1
    
    return filtered, noise_count

def score_alerts(alerts):
    """Add severity scores to alerts"""
    for alert in alerts:
        alert["score"] = SEVERITY_SCORE.get(alert["severity"], 1)
    return sorted(alerts, key=lambda x: x["score"], reverse=True)

def correlate_alerts(alerts):
    """Group alerts by service and type"""
    clusters = defaultdict(list)
    
    for alert in alerts:
        key = (alert["service"], alert["type"])
        clusters[key].append(alert)
    
    result = []
    for (service, type_), group in clusters.items():
        total_score = sum(a["score"] for a in group)
        dominant_severity = max(group, key=lambda x: x["score"])["severity"]
        
        result.append({
            "service": service,
            "type": type_,
            "count": len(group),
            "total_score": total_score,
            "dominant_severity": dominant_severity
        })
    
    return sorted(result, key=lambda x: x["total_score"], reverse=True)

def find_root_cause(alerts):
    """Identify the root cause service using dependency graph"""
    failing_services = set(a["service"] for a in alerts)
    candidates = []
    
    # Find services that don't have failing dependencies
    for service in failing_services:
        dependencies = SERVICE_GRAPH.get(service, [])
        if not any(dep in failing_services for dep in dependencies):
            candidates.append(service)
    
    # Build cascade chain
    cascade_chain = []
    if candidates:
        root = candidates[0]
        cascade_chain.append(f"{root} failure")
        
        # Add downstream effects
        for service in failing_services:
            if service != root:
                if root in SERVICE_GRAPH.get(service, []):
                    cascade_chain.append(f"{service} impacted")
                else:
                    cascade_chain.append(f"{service} degraded")
    else:
        # If no clear root, pick the most severe
        severe_alerts = sorted(alerts, key=lambda x: x.get("score", 0), reverse=True)
        if severe_alerts:
            root = severe_alerts[0]["service"]
            cascade_chain.append(f"{root} primary issue")
        else:
            root = "Unknown"
    
    # Determine confidence
    if len(candidates) == 1:
        confidence = "HIGH"
        reason = "Single service failing with no dependency failures"
    elif len(candidates) > 1:
        confidence = "MEDIUM"
        reason = "Multiple potential root causes identified"
    else:
        confidence = "LOW"
        reason = "Circular dependencies or unclear failure pattern"
        candidates = list(failing_services)[:1] if failing_services else ["Unknown"]
    
    return {
        "service": candidates[0] if candidates else "Unknown",
        "confidence": confidence,
        "reason": reason,
        "affected": list(failing_services),
        "cascade_chain": cascade_chain[:5]  # Limit to 5 steps
    }

def generate_recommendations(alerts, root_cause, clusters):
    """Generate actionable recommendations based on alert patterns"""
    recommendations = []
    severity_counts = defaultdict(int)
    service_counts = defaultdict(int)
    
    for alert in alerts:
        severity_counts[alert["severity"]] += 1
        service_counts[alert["service"]] += 1
    
    # Critical alerts need immediate action
    if severity_counts.get("CRITICAL", 0) > 0:
        recommendations.append({
            "action": "IMMEDIATE: Investigate critical alerts",
            "detail": f"{severity_counts.get('CRITICAL', 0)} critical alerts detected. Focus on {root_cause['service']} first.",
            "urgency": "IMMEDIATE"
        })
    
    # Root cause specific recommendations
    root_svc = root_cause["service"]
    if root_svc == "Database":
        recommendations.append({
            "action": "Scale database resources",
            "detail": "Increase connection pool, check for slow queries, consider read replicas",
            "urgency": "SOON"
        })
    elif root_svc == "API Gateway":
        recommendations.append({
            "action": "Review API Gateway configuration",
            "detail": "Check rate limits, timeout settings, and upstream health",
            "urgency": "SOON"
        })
    elif root_svc == "Cache":
        recommendations.append({
            "action": "Investigate cache hit ratio",
            "detail": "Low cache hit ratio may indicate need for cache warming or eviction policy review",
            "urgency": "SOON"
        })
    elif root_svc == "Auth Service":
        recommendations.append({
            "action": "Audit authentication logs",
            "detail": "Check for brute force attempts or token validation issues",
            "urgency": "SOON"
        })
    
    # High severity patterns
    if severity_counts.get("HIGH", 0) > 3:
        recommendations.append({
            "action": "Schedule performance review",
            "detail": f"Multiple HIGH severity alerts across {len(service_counts)} services",
            "urgency": "SOON"
        })
    
    # Cluster-based recommendations
    for cluster in clusters[:2]:
        if cluster["count"] > 3:
            recommendations.append({
                "action": f"Review {cluster['service']} {cluster['type']} pattern",
                "detail": f"Recurring {cluster['type']} issues detected. Consider proactive fixes.",
                "urgency": "MONITOR"
            })
    
    # Always include a monitoring recommendation
    recommendations.append({
        "action": "Continue monitoring",
        "detail": "Watch for recurrence and validate fixes",
        "urgency": "MONITOR"
    })
    
    # Limit to 5 recommendations
    return recommendations[:5]

async def generate_ai_summary(alerts, root_cause, clusters, severity_distribution):
    """Generate AI-powered narrative using Gemini"""
    
    if not gemini_model:
        # Fallback summary if Gemini not available
        return f"Root cause identified as {root_cause['service']} ({root_cause['confidence']} confidence). Affected services: {', '.join(root_cause['affected'][:3])}. Priority: Address CRITICAL alerts first, then investigate cascade pattern."
    
    try:
        # Prepare alert summary for Gemini
        total_critical = severity_distribution.get("CRITICAL", 0)
        total_high = severity_distribution.get("HIGH", 0)
        total_medium = severity_distribution.get("MEDIUM", 0)
        
        prompt = f"""You are an SRE expert analyzing an incident. Write a 3-4 sentence incident narrative based on this data:

Alert Statistics:
- Total alerts: {len(alerts)}
- CRITICAL: {total_critical}, HIGH: {total_high}, MEDIUM: {total_medium}
- Services affected: {', '.join(root_cause['affected'][:5])}

Root Cause Analysis:
- Primary cause: {root_cause['service']}
- Confidence: {root_cause['confidence']}
- Failure cascade: {' → '.join(root_cause.get('cascade_chain', ['Unknown']))}

Top alert clusters:
{chr(10).join([f"- {c['service']}: {c['count']} {c['type']} alerts ({c['dominant_severity']})" for c in clusters[:3]])}

Write a concise, technical narrative that:
1. Starts with the root cause
2. Explains the impact and cascade
3. Ends with recommended focus area

Keep it to 3-4 sentences total. Be direct and technical."""
        
        response = gemini_model.generate_content(prompt)
        return response.text.strip()
        
    except Exception as e:
        print(f"Gemini error: {e}")
        return f"Analysis complete. Root cause: {root_cause['service']} ({root_cause['confidence']}). Affected {len(root_cause['affected'])} services. Focus on CRITICAL alerts first."

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok", 
        "service": "SENTINEL AIOps Backend",
        "gemini_configured": gemini_model is not None
    }


@app.post("/generate")
def generate_alerts(req: GenerateRequest):
    """Generate N synthetic alerts for a given type + service."""
    if req.quantity < 1 or req.quantity > 200:
        raise HTTPException(400, "quantity must be 1–200")
    if req.alert_type not in ALERT_MESSAGES:
        raise HTTPException(400, f"Unknown alert_type: {req.alert_type}")

    alerts = [make_alert(req.alert_type, req.service) for _ in range(req.quantity)]
    return {"alerts": alerts, "count": len(alerts)}


@app.post("/simulate-incident")
def simulate_incident():
    """Generate a realistic incident cascade."""
    chain = random.choice(INCIDENT_CHAINS)
    alerts = []
    for step in chain:
        count = random.randint(2, 4)
        for _ in range(count):
            alerts.append(make_alert(step["type"], step["service"], step["severity"]))
    
    chain_summary = [f"{s['service']} → {s['type']}" for s in chain]
    return {
        "alerts": alerts,
        "chain_summary": chain_summary,
        "count": len(alerts),
    }


@app.post("/analyze")
async def analyze(data: dict):
    """Full alert analysis with AI-powered insights."""
    alerts = data.get("alerts", [])
    if not alerts:
        raise HTTPException(400, "No alerts to analyze")

    # Step 1: Noise reduction
    filtered_alerts, noise_count = reduce_noise(alerts)
    
    # Step 2: Score alerts
    scored_alerts = score_alerts(filtered_alerts)
    
    # Step 3: Correlation (clustering)
    clusters = correlate_alerts(scored_alerts)
    
    # Step 4: Root cause analysis
    root_cause = find_root_cause(scored_alerts)
    
    # Step 5: Generate recommendations
    recommendations = generate_recommendations(scored_alerts, root_cause, clusters)
    
    # Step 6: Priority ranking
    priority_ranking = []
    for i, alert in enumerate(scored_alerts[:7]):
        reason = f"{alert['severity']} impact on {alert['service']}"
        if i == 0 and alert["severity"] == "CRITICAL":
            reason = "Critical failure requiring immediate attention"
        elif alert["type"] == root_cause.get("service", ""):
            reason = "Potential root cause service"
        
        priority_ranking.append({
            "service": alert["service"],
            "type": alert["type"],
            "severity": alert["severity"],
            "score": alert["score"],
            "reason": reason
        })
    
    # Statistics
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    type_counts = {}
    service_counts = {}
    
    for alert in alerts:
        sev = alert.get("severity", "MEDIUM")
        severity_distribution[sev] = severity_distribution.get(sev, 0) + 1
        
        typ = alert.get("type", "Unknown")
        type_counts[typ] = type_counts.get(typ, 0) + 1
        
        svc = alert.get("service", "Unknown")
        service_counts[svc] = service_counts.get(svc, 0) + 1
    
    # Generate AI summary
    ai_summary = await generate_ai_summary(alerts, root_cause, clusters, severity_distribution)
    
    # Build cascade chain from root cause
    cascade_chain = root_cause.get("cascade_chain", [])
    if not cascade_chain and root_cause["service"] != "Unknown":
        cascade_chain = [f"{root_cause['service']} failure"]
        for svc in root_cause["affected"][:3]:
            if svc != root_cause["service"]:
                cascade_chain.append(f"{svc} degradation")
    
    # Return complete response matching frontend expectations
    return {
        "noise_removed": noise_count,
        "total_alerts": len(alerts),
        "filtered_alerts": len(filtered_alerts),
        "root_cause": root_cause["service"],
        "confidence": root_cause["confidence"],
        "cascade_chain": cascade_chain,
        "clusters": clusters,
        "priority_ranking": priority_ranking,
        "recommendations": recommendations,
        "ai_summary": ai_summary,
        "severity_distribution": severity_distribution,
        "type_counts": type_counts,
        "service_counts": service_counts,
        "top_alerts": scored_alerts[:5]
    }


@app.post("/analyze/stream")
async def analyze_alerts_stream(req: AnalyzeRequest):
    """Stream AI summary token by token for typewriter effect."""
    if not req.alerts:
        raise HTTPException(400, "No alerts to analyze")
    
    # Quick analysis for summary
    filtered, _ = reduce_noise(req.alerts)
    scored = score_alerts(filtered)
    root_cause = find_root_cause(scored)
    clusters = correlate_alerts(scored)
    
    # Get severity distribution
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for alert in req.alerts:
        severity_distribution[alert.get("severity", "MEDIUM")] += 1
    
    # Generate summary
    summary = await generate_ai_summary(req.alerts, root_cause, clusters, severity_distribution)
    
    async def event_generator():
        # Split into words and send as SSE
        words = summary.split()
        for word in words:
            yield f"data: {json.dumps({'token': word + ' '})}\n\n"
            await asyncio.sleep(0.03)  # 30ms between words
        yield "data: [DONE]\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)