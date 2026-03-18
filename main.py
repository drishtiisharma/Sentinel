"""
SENTINEL AIOps Backend
======================
FastAPI + Google Gemini for intelligent alert analysis with security threat detection.
"""
import google.generativeai as genai
import os
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import json
import asyncio
from dotenv import load_dotenv
from collections import defaultdict
import sqlite3
import re

load_dotenv()

# ── SQLite persistence ────────────────────────────────────────────────────────
_db = sqlite3.connect("sentinel.db", check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.executescript("""
CREATE TABLE IF NOT EXISTS alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id  TEXT NOT NULL,
    service   TEXT NOT NULL,
    type      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    message   TEXT,
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT NOT NULL,
    total_alerts INTEGER NOT NULL,
    noise_removed INTEGER NOT NULL,
    clean_alerts INTEGER NOT NULL,
    root_cause   TEXT,
    confidence   TEXT,
    payload      TEXT NOT NULL
);
""")
_db.commit()

def _store_alerts(alerts: list):
    _db.executemany(
        "INSERT INTO alerts (alert_id,service,type,severity,message,timestamp) VALUES (?,?,?,?,?,?)",
        [(a.get("id",""), a.get("service",""), a.get("type",""),
          a.get("severity","MEDIUM"), a.get("message",""), a.get("timestamp",""))
         for a in alerts]
    )
    _db.commit()

def _store_analysis(total: int, noise: int, clean: int, root: str, conf: str, payload: dict):
    import json as _json
    _db.execute(
        "INSERT INTO analyses (created_at,total_alerts,noise_removed,clean_alerts,root_cause,confidence,payload) VALUES (?,?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), total, noise, clean, root, conf, _json.dumps(payload))
    )
    _db.commit()

app = FastAPI(title="SENTINEL AIOps API", version="1.0.0")


@app.get("/")
def serve_frontend():
    return FileResponse("index.html")

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

# ── Security Patterns ────────────────────────────────────────────────────────
SECURITY_PATTERNS = {
    "brute_force": {
        "patterns": [
            r"invalid credentials.*\d+",
            r"failed login.*\d+",
            r"auth.*failed.*\d+",
            r"rate limit.*breach",
            r"jwt.*invalid",
        ],
        "services": ["Auth Service", "API Gateway"],
        "alert_types": ["Auth Failure", "API Timeout"],
        "threshold": 3,
        "severity": "HIGH"
    },
    "ddos_attempt": {
        "patterns": [
            r"packet loss.*\d+%",
            r"bandwidth.*saturation",
            r"arp flood",
            r"connection refused.*\d+",
            r"syn flood",
        ],
        "services": ["API Gateway", "Network"],
        "alert_types": ["Network Spike", "API Timeout"],
        "threshold": 2,
        "severity": "CRITICAL"
    },
    "data_exfiltration": {
        "patterns": [
            r"disk full.*rapid",
            r"unusual.*outbound",
            r"large.*response",
            r"memory.*spike.*unusual",
        ],
        "services": ["Database", "Backend", "Cache"],
        "alert_types": ["Disk Full", "Memory Leak"],
        "threshold": 2,
        "severity": "CRITICAL"
    },
    "privilege_escalation": {
        "patterns": [
            r"permission.*denied",
            r"unauthorized.*access",
            r"privilege.*escalation",
            r"sudo.*failure",
        ],
        "services": ["Auth Service", "Backend"],
        "alert_types": ["Auth Failure"],
        "threshold": 2,
        "severity": "HIGH"
    },
    "service_disruption": {
        "patterns": [
            r"circuit breaker.*open",
            r"health check.*failing",
            r"deadlock",
            r"connection pool.*exhausted",
        ],
        "services": ["Database", "API Gateway", "Backend"],
        "alert_types": ["Database Failure", "API Timeout"],
        "threshold": 1,
        "severity": "CRITICAL"
    }
}

# ── Threat Predictor Class ───────────────────────────────────────────────────
class ThreatPredictor:
    def __init__(self):
        self.attack_patterns = defaultdict(int)
        self.service_health = defaultdict(lambda: {"failures": 0, "last_failure": None})
        self.anomaly_scores = defaultdict(float)
    
    def analyze_threats(self, alerts):
        """Analyze alerts for security threats and predict attacks"""
        threats = []
        attack_signatures = defaultdict(list)
        
        # Group alerts by potential attack signatures
        for alert in alerts:
            # Check each security pattern
            for threat_name, config in SECURITY_PATTERNS.items():
                # Check if alert matches pattern
                if alert["service"] in config["services"] and alert["type"] in config["alert_types"]:
                    # Check message patterns
                    message = alert.get("message", "").lower()
                    for pattern in config["patterns"]:
                        if re.search(pattern, message, re.IGNORECASE):
                            attack_signatures[threat_name].append(alert)
                            self.attack_patterns[threat_name] += 1
                            break
        
        # Evaluate threats
        for threat_name, matching_alerts in attack_signatures.items():
            config = SECURITY_PATTERNS[threat_name]
            if len(matching_alerts) >= config["threshold"]:
                threat_level = self._assess_threat_level(threat_name, matching_alerts)
                
                threats.append({
                    "type": threat_name,
                    "confidence": threat_level["confidence"],
                    "severity": config["severity"],
                    "evidence": len(matching_alerts),
                    "description": self._get_threat_description(threat_name),
                    "indicators": [a["message"] for a in matching_alerts[:3]],
                    "affected_services": list(set(a["service"] for a in matching_alerts)),
                    "recommendations": self._get_threat_recommendations(threat_name),
                    "time_pattern": self._analyze_time_pattern(matching_alerts),
                    "probability": threat_level["probability"],
                    "next_steps": self._predict_next_actions(threat_name, matching_alerts)
                })
        
        return threats
    
    def _assess_threat_level(self, threat_name, alerts):
        """Assess confidence and probability of threat"""
        count = len(alerts)
        unique_services = len(set(a["service"] for a in alerts))
        
        if count >= 5 or unique_services >= 3:
            confidence = "HIGH"
            probability = 0.85
        elif count >= 3 or unique_services >= 2:
            confidence = "MEDIUM"
            probability = 0.65
        else:
            confidence = "LOW"
            probability = 0.40
        
        return {"confidence": confidence, "probability": probability}
    
    def _get_threat_description(self, threat_name):
        descriptions = {
            "brute_force": "Multiple authentication failures detected - potential brute force attack in progress",
            "ddos_attempt": "Network anomalies suggest possible DDoS attack targeting API endpoints",
            "data_exfiltration": "Unusual data access patterns - possible data exfiltration attempt",
            "privilege_escalation": "Multiple permission failures - possible privilege escalation attempt",
            "service_disruption": "Service instability - potential targeted disruption attack"
        }
        return descriptions.get(threat_name, "Security threat detected")
    
    def _get_threat_recommendations(self, threat_name):
        recommendations = {
            "brute_force": [
                "Enable rate limiting on auth endpoints",
                "Implement CAPTCHA after failed attempts",
                "Block suspicious IP ranges",
                "Enable 2FA for affected accounts"
            ],
            "ddos_attempt": [
                "Enable DDoS protection services",
                "Scale up edge infrastructure",
                "Implement request throttling",
                "Enable WAF rules"
            ],
            "data_exfiltration": [
                "Monitor outbound traffic patterns",
                "Enable data loss prevention (DLP)",
                "Review access logs for anomalies",
                "Rotate credentials immediately"
            ],
            "privilege_escalation": [
                "Audit permission changes",
                "Review sudoers file",
                "Enable least privilege access",
                "Monitor for suspicious process execution"
            ],
            "service_disruption": [
                "Enable circuit breakers",
                "Implement graceful degradation",
                "Scale redundant services",
                "Review deployment for malicious code"
            ]
        }
        return recommendations.get(threat_name, ["Investigate immediately"])
    
    def _analyze_time_pattern(self, alerts):
        """Analyze timing of alerts to detect patterns"""
        if len(alerts) < 2:
            return "Insufficient data for pattern analysis"
        
        try:
            times = []
            for alert in alerts:
                dt = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                times.append(dt)
            
            times.sort()
            
            # Calculate intervals
            intervals = [(times[i+1] - times[i]).seconds for i in range(len(times)-1)]
            avg_interval = sum(intervals) / len(intervals)
            
            if avg_interval < 5:
                return f"Rapid attacks every {avg_interval:.0f} seconds - automated attack suspected"
            elif avg_interval < 60:
                return f"Steady attack pattern every {avg_interval:.0f} seconds"
            else:
                return f"Slow, probing pattern over {len(times)} minutes"
        except:
            return "Pattern analysis unavailable"
    
    def _predict_next_actions(self, threat_name, alerts):
        """Predict what attacker might do next"""
        predictions = {
            "brute_force": [
                "Will target additional user accounts",
                "May switch to credential stuffing",
                "Likely to attempt password spraying next"
            ],
            "ddos_attempt": [
                "Will escalate to application-layer attacks",
                "May target different endpoints",
                "Could combine with other attack vectors"
            ],
            "data_exfiltration": [
                "Will attempt to extract larger datasets",
                "May establish persistence mechanisms",
                "Could target backup systems next"
            ],
            "privilege_escalation": [
                "Will attempt to execute malicious code",
                "May create backdoor accounts",
                "Likely to move laterally in network"
            ],
            "service_disruption": [
                "May attempt to corrupt data",
                "Could target failover systems",
                "Might attempt to wipe logs"
            ]
        }
        return predictions.get(threat_name, ["Monitor for escalation"])
    
    def predict_future_state(self, alerts, time_window_minutes=5):
        """Predict system state in near future"""
        if not alerts:
            return {"status": "stable", "confidence": "LOW"}
        
        # Calculate failure rate
        recent_alerts = alerts[-20:] if len(alerts) > 20 else alerts
        critical_count = sum(1 for a in recent_alerts if a.get('severity') == 'CRITICAL')
        high_count = sum(1 for a in recent_alerts if a.get('severity') == 'HIGH')
        
        # Trend analysis
        if critical_count > len(recent_alerts) * 0.3:
            prediction = "CRITICAL_FAILURE"
            confidence = "HIGH"
            eta = "within 2 minutes"
            message = "System collapse imminent - multiple critical failures detected"
        elif high_count > len(recent_alerts) * 0.5:
            prediction = "MAJOR_DEGRADATION"
            confidence = "MEDIUM"
            eta = "within 5 minutes"
            message = "Rapid degradation expected - take immediate action"
        elif critical_count > 0:
            prediction = "INSTABILITY"
            confidence = "MEDIUM"
            eta = "within 10 minutes"
            message = "Further failures likely if root cause not addressed"
        else:
            prediction = "STABLE"
            confidence = "HIGH"
            eta = "no immediate threat"
            message = "System appears stable with current intervention"
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "eta": eta,
            "message": message,
            "risk_factors": {
                "critical_alerts": critical_count,
                "high_alerts": high_count,
                "affected_services": len(set(a["service"] for a in recent_alerts))
            }
        }

# Initialize predictor
threat_predictor = ThreatPredictor()

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

def detect_temporal_patterns(alerts):
    """Detect time-based relationships between alerts"""
    if len(alerts) < 2:
        return []
    
    # Sort by timestamp
    sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''))
    patterns = []
    
    # Look for cascading failures (one service failing, then its dependencies)
    for i in range(len(sorted_alerts)-1):
        current = sorted_alerts[i]
        next_alert = sorted_alerts[i+1]
        
        # Check if next alert is from a dependent service
        deps = SERVICE_GRAPH.get(current['service'], [])
        if next_alert['service'] in deps:
            patterns.append({
                'type': 'cascade',
                'from': current['service'],
                'to': next_alert['service'],
                'time_diff': 'immediate'
            })
    
    # Look for correlated spikes (multiple alerts same time)
    time_groups = defaultdict(list)
    for alert in sorted_alerts:
        try:
            dt = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
            # Group by minute
            key = dt.strftime('%Y-%m-%d %H:%M')
            time_groups[key].append(alert)
        except:
            pass
    
    for minute, group in time_groups.items():
        if len(group) > 3:
            services = list(set(a['service'] for a in group))
            patterns.append({
                'type': 'spike',
                'time': minute,
                'services': services,
                'count': len(group)
            })
    
    return patterns[:5]  # Return top patterns

async def generate_ai_summary(alerts, root_cause, clusters, severity_distribution, threats=None, cascade_chain=None):
    """Generate AI-powered narrative using Gemini with relationship analysis"""
    
    # Build security context if threats exist
    security_context = ""
    if threats and len(threats) > 0:
        threat_descriptions = []
        for t in threats:
            threat_descriptions.append(f"- {t['type'].replace('_', ' ').upper()}: {t['description']} (Confidence: {t['confidence']})")
        
        security_context = f"""
SECURITY THREATS DETECTED:
{chr(10).join(threat_descriptions)}

This appears to be {'an active attack' if any(t['confidence'] == 'HIGH' for t in threats) else 'suspicious activity'}.
"""
    
    if not gemini_model:
        # Enhanced fallback with relationship mapping
        return generate_fallback_narrative(alerts, root_cause, clusters, cascade_chain, threats)
    
    try:
        # Prepare rich context for Gemini
        total_critical = severity_distribution.get("CRITICAL", 0)
        total_high = severity_distribution.get("HIGH", 0)
        total_medium = severity_distribution.get("MEDIUM", 0)
        
        # Group alerts by time to show patterns
        alerts_by_time = sorted(alerts, key=lambda x: x.get('timestamp', ''))
        time_window = "unknown"
        if len(alerts_by_time) >= 2:
            try:
                t1 = datetime.fromisoformat(alerts_by_time[0]['timestamp'].replace('Z', '+00:00'))
                t2 = datetime.fromisoformat(alerts_by_time[-1]['timestamp'].replace('Z', '+00:00'))
                delta = t2 - t1
                if delta.total_seconds() < 60:
                    time_window = f"{int(delta.total_seconds())} seconds"
                elif delta.total_seconds() < 3600:
                    time_window = f"{int(delta.total_seconds() // 60)} minutes"
                else:
                    time_window = f"{int(delta.total_seconds() // 3600)} hours"
            except Exception as e:
                print(f"Time parsing error: {e}")
                pass
        
        # Build service dependency relationships
        service_relations = []
        for svc in root_cause.get('affected', []):
            deps = SERVICE_GRAPH.get(svc, [])
            if deps:
                service_relations.append(f"{svc} depends on {', '.join(deps)}")
        
        # Build causal chains from cascade
        causal_relationships = []
        if cascade_chain and len(cascade_chain) > 1:
            for i in range(len(cascade_chain)-1):
                causal_relationships.append(f"{cascade_chain[i]} → {cascade_chain[i+1]}")
        
        # Group alerts by pattern
        pattern_groups = defaultdict(list)
        for alert in alerts[:10]:  # Limit for prompt size
            key = f"{alert['service']}:{alert['type']}"
            pattern_groups[key].append(alert)
        
        recurring_patterns = []
        for key, group in pattern_groups.items():
            if len(group) > 1:
                svc, typ = key.split(':')
                recurring_patterns.append(f"{typ} on {svc} occurred {len(group)} times")
        
        # Build the enhanced prompt
        prompt = f"""You are an SRE and security expert analyzing a complex incident with multiple correlated alerts. 

{security_context}

Write a detailed incident narrative (4-6 sentences) that explains the causal relationships between alerts and identifies if this is an attack.

Incident Data:
- Time window: {time_window}
- Total alerts: {len(alerts)} (Critical: {total_critical}, High: {total_high}, Medium: {total_medium})
- Services affected: {', '.join(root_cause.get('affected', [])[:7])}

Root Cause Analysis:
- Primary cause: {root_cause['service']} failure
- Confidence: {root_cause['confidence']}
- Failure cascade: {' → '.join(cascade_chain or ['Unknown'])}

Service Dependencies:
{chr(10).join(service_relations[:3])}

Causal Chain:
{chr(10).join(causal_relationships)}

Recurring Patterns:
{chr(10).join(recurring_patterns[:3])}

Top Alert Clusters:
{chr(10).join([f"- {c['service']}: {c['count']} {c['type']} alerts ({c['dominant_severity']})" for c in clusters[:4]])}

Write a narrative that:
1. Starts with the root cause and explains WHY it triggered other alerts
2. Shows the cascade of failures through service dependencies
3. Identifies if this is an attack or system failure
4. Predicts what might happen next
5. Quantifies the impact (how many services, severity levels)
6. Ends with specific remediation focus areas

Be technical but narrative. Explain the relationships between alerts, not just list them."""

        print(f"Sending prompt to Gemini: {prompt[:200]}...")  # Debug log
        response = gemini_model.generate_content(prompt)
        
        if response and response.text:
            return response.text.strip()
        else:
            print("Gemini returned empty response")
            return generate_fallback_narrative(alerts, root_cause, clusters, cascade_chain, threats)
        
    except Exception as e:
        print(f"Gemini error: {str(e)}")
        import traceback
        traceback.print_exc()
        return generate_fallback_narrative(alerts, root_cause, clusters, cascade_chain, threats)
    
def generate_fallback_narrative(alerts, root_cause, clusters, cascade_chain=None, threats=None):
    """Generate a relationship-aware narrative without Gemini"""
    
    total = len(alerts)
    critical = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
    high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
    
    # Build relationship sentences
    root_svc = root_cause.get('service', 'Unknown')
    affected = root_cause.get('affected', [])
    
    # Find dependent services
    downstream = []
    for svc in affected:
        if svc != root_svc and root_svc in SERVICE_GRAPH.get(svc, []):
            downstream.append(svc)
    
    # Add security context if threats exist
    if threats and len(threats) > 0:
        threat_types = [t['type'].replace('_', ' ') for t in threats]
        narrative = f"SECURITY INCIDENT: {', '.join(threat_types[:2]).upper()} detected. "
    else:
        narrative = f"System incident originated from {root_svc} failure"
    
    if downstream:
        narrative += f", cascading to {', '.join(downstream[:3])}"
    
    narrative += f". Impact includes {critical} critical and {high} high severity alerts"
    
    # Add pattern recognition
    repeating = []
    for cluster in clusters[:3]:
        if cluster['count'] > 2:
            repeating.append(f"{cluster['type']} on {cluster['service']} ({cluster['count']} times)")
    
    if repeating:
        narrative += f". Recurring patterns detected: {'; '.join(repeating[:2])}"
    
    # Add relationship insight
    if cascade_chain and len(cascade_chain) > 1:
        narrative += f". Failure cascade: {' → '.join(cascade_chain[:4])}"
    
    # Add threat prediction if any
    if threats and len(threats) > 0:
        narrative += f". Active threat requires immediate security response."
    
    # Add recommendation
    narrative += f". Priority: Investigate {root_svc} and monitor {', '.join(downstream[:2]) if downstream else 'affected services'}."
    
    return narrative

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    stored = _db.execute("SELECT COUNT(*) as n FROM alerts").fetchone()["n"]
    analyses = _db.execute("SELECT COUNT(*) as n FROM analyses").fetchone()["n"]
    return {
        "status": "ok",
        "service": "SENTINEL AIOps Backend",
        "gemini_configured": gemini_model is not None,
        "stored_alerts": stored,
        "stored_analyses": analyses,
    }


@app.post("/generate")
def generate_alerts(req: GenerateRequest):
    """Generate N synthetic alerts for a given type + service."""
    if req.quantity < 1 or req.quantity > 200:
        raise HTTPException(400, "quantity must be 1–200")
    if req.alert_type not in ALERT_MESSAGES:
        raise HTTPException(400, f"Unknown alert_type: {req.alert_type}")

    alerts = [make_alert(req.alert_type, req.service) for _ in range(req.quantity)]
    _store_alerts(alerts)
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
    _store_alerts(alerts)
    return {
        "alerts": alerts,
        "chain_summary": chain_summary,
        "count": len(alerts),
    }


@app.post("/analyze")
async def analyze(data: dict):
    """Full alert analysis with AI-powered insights and threat detection."""
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
    
    # Step 7: Threat detection and prediction
    threats = threat_predictor.analyze_threats(alerts)
    future_prediction = threat_predictor.predict_future_state(alerts)
    
    # Step 8: Temporal patterns
    temporal_patterns = detect_temporal_patterns(alerts)
    
    # Build cascade chain from root cause
    cascade_chain = root_cause.get("cascade_chain", [])
    if not cascade_chain and root_cause["service"] != "Unknown":
        cascade_chain = [f"{root_cause['service']} failure"]
        for svc in root_cause["affected"][:3]:
            if svc != root_cause["service"]:
                cascade_chain.append(f"{svc} degradation")
    
    # Enhanced cascade analysis
    enhanced_cascade = []
    if cascade_chain:
        for i, step in enumerate(cascade_chain):
            if i < len(cascade_chain) - 1:
                # Find alerts that caused this transition
                cause_alerts = [a for a in scored_alerts if a['service'] in step and a['severity'] == 'CRITICAL']
                enhanced_cascade.append({
                    'step': step,
                    'triggered_by': [a['type'] for a in cause_alerts[:2]],
                    'next': cascade_chain[i+1] if i+1 < len(cascade_chain) else None
                })
    
    # Generate AI summary with threat context
    ai_summary = await generate_ai_summary(alerts, root_cause, clusters, severity_distribution, threats, cascade_chain)
    
    # Impact summary
    impact_summary = {
        "services_affected": len(root_cause['affected']),
        "critical_services": len([s for s in root_cause['affected'] if any(a['service'] == s and a['severity'] == 'CRITICAL' for a in alerts)]),
        "cascade_depth": len(cascade_chain)
    }
    
    # Return complete response matching frontend expectations
    response = {
        "noise_removed": noise_count,
        "total_alerts": len(alerts),
        "filtered_alerts": len(filtered_alerts),
        "root_cause": root_cause["service"],
        "confidence": root_cause["confidence"],
        "cascade_chain": cascade_chain,
        "enhanced_cascade": enhanced_cascade,
        "clusters": clusters,
        "priority_ranking": priority_ranking,
        "recommendations": recommendations,
        "ai_summary": ai_summary,
        "severity_distribution": severity_distribution,
        "type_counts": type_counts,
        "service_counts": service_counts,
        "top_alerts": scored_alerts[:5],
        "security_threats": threats,
        "future_prediction": future_prediction,
        "attack_probability": len(threats) > 0,
        "security_status": "UNDER_ATTACK" if any(t["confidence"] == "HIGH" for t in threats) else "MONITORING",
        "temporal_patterns": temporal_patterns,
        "impact_summary": impact_summary
    }
    
    _store_analysis(len(alerts), noise_count, len(filtered_alerts),
                    root_cause["service"], root_cause["confidence"], response)
    return response


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
    threats = threat_predictor.analyze_threats(req.alerts)
    
    # Get severity distribution
    severity_distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for alert in req.alerts:
        severity_distribution[alert.get("severity", "MEDIUM")] += 1
    
    # Generate summary
    summary = await generate_ai_summary(req.alerts, root_cause, clusters, severity_distribution, threats)
    
    async def event_generator():
        # Split into words and send as SSE
        words = summary.split()
        for word in words:
            yield f"data: {json.dumps({'token': word + ' '})}\n\n"
            await asyncio.sleep(0.03)  # 30ms between words
        yield "data: [DONE]\n\n"
    
    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/stats")
def get_stats():
    """Aggregate reduction metrics — the '84% reduction' number lives here."""
    total_raw    = _db.execute("SELECT COALESCE(SUM(total_alerts),0) as n FROM analyses").fetchone()["n"]
    total_noise  = _db.execute("SELECT COALESCE(SUM(noise_removed),0) as n FROM analyses").fetchone()["n"]
    total_clean  = _db.execute("SELECT COALESCE(SUM(clean_alerts),0) as n FROM analyses").fetchone()["n"]
    by_sev       = _db.execute("SELECT severity, COUNT(*) as n FROM alerts GROUP BY severity").fetchall()
    by_type      = _db.execute("SELECT type, COUNT(*) as n FROM alerts GROUP BY type ORDER BY n DESC LIMIT 10").fetchall()
    by_svc       = _db.execute("SELECT service, COUNT(*) as n FROM alerts GROUP BY service ORDER BY n DESC").fetchall()
    reduction_pct = round((total_noise / total_raw * 100), 1) if total_raw > 0 else 0.0
    return {
        "total_raw_alerts":    total_raw,
        "total_noise_removed": total_noise,
        "total_clean_alerts":  total_clean,
        "reduction_percent":   reduction_pct,
        "by_severity":         {r["severity"]: r["n"] for r in by_sev},
        "top_alert_types":     {r["type"]: r["n"] for r in by_type},
        "by_service":          {r["service"]: r["n"] for r in by_svc},
    }


@app.get("/history")
def get_history(limit: int = 15):
    """Return last N analysis runs."""
    rows = _db.execute(
        "SELECT id, created_at, total_alerts, noise_removed, clean_alerts, root_cause, confidence FROM analyses ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return {"analyses": [dict(r) for r in rows]}


@app.get("/history/{analysis_id}")
def get_analysis(analysis_id: int):
    """Return full payload for a past analysis."""
    row = _db.execute("SELECT payload FROM analyses WHERE id=?", (analysis_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Analysis not found")
    return json.loads(row["payload"])

@app.post("/clear-all")
def clear_all():
    """Clear all alerts and analyses from the database."""
    try:
        # Delete all alerts
        _db.execute("DELETE FROM alerts")
        # Delete all analyses
        _db.execute("DELETE FROM analyses")
        # Reset SQLite auto-increment counters
        _db.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")
        _db.execute("DELETE FROM sqlite_sequence WHERE name='analyses'")
        _db.commit()
        
        return {
            "status": "success",
            "message": "All data cleared successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear data: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)