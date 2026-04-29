from datetime import datetime
import random
from typing import List, Dict
from app.database.connection import get_db
from app.database.repository import AlertRepository
from app.config import settings

class AlertService:
    @staticmethod
    def generate_alert(alert_type: str, service: str, quantity: int = 1) -> List[Dict]:
        alerts = []
        
        alert_templates = {
            "CPU High": {
                "base_message": "CPU usage exceeded {value}% on {host}",
                "severity": "HIGH",
                "values": [85, 92, 98, 100]
            },
            "Memory Leak": {
                "base_message": "Memory leak detected in {process}: {leak_rate} MB/hour",
                "severity": "CRITICAL",
                "processes": ["java", "node", "python", "nginx"]
            },
            "API Timeout": {
                "base_message": "API endpoint {endpoint} timeout after {timeout}s",
                "severity": "HIGH",
                "endpoints": ["/api/users", "/api/orders", "/api/auth", "/api/payments"]
            },
            "Database Failure": {
                "base_message": "Database {db_type} connection failed: {error}",
                "severity": "CRITICAL",
                "db_types": ["PostgreSQL", "MySQL", "MongoDB", "Redis"]
            },
            "Disk Full": {
                "base_message": "Disk {mount} is {percent}% full on {host}",
                "severity": "HIGH",
                "mounts": ["/var", "/data", "/", "/home"]
            },
            "Network Spike": {
                "base_message": "Network {direction} traffic spike: {rate} Mbps (baseline: {baseline})",
                "severity": "MEDIUM",
                "directions": ["inbound", "outbound"]
            },
            "Auth Failure": {
                "base_message": "Authentication failure from {ip}: {reason}",
                "severity": "HIGH",
                "reasons": ["invalid password", "user not found", "account locked", "MFA failed"]
            }
        }
        
        template = alert_templates.get(alert_type, alert_templates["CPU High"])
        
        for i in range(quantity):
            # Add some randomness for realistic patterns
            if settings.REALISTIC_NOISE and random.random() < settings.PATTERN_REPEAT_PROBABILITY:
                if alerts:
                    new_alert = alerts[-1].copy()
                    new_alert["timestamp"] = datetime.now()
                    alerts.append(new_alert)
                    continue
            
            # Generate message based on template
            message = template["base_message"]
            
            if "values" in template:
                message = message.format(value=random.choice(template["values"]), host=f"host-{random.randint(1,5)}")
            elif "processes" in template:
                message = message.format(process=random.choice(template["processes"]), 
                                        leak_rate=random.randint(50, 500))
            elif "endpoints" in template:
                message = message.format(endpoint=random.choice(template["endpoints"]), 
                                        timeout=random.randint(30, 120))
            elif "db_types" in template:
                message = message.format(db_type=random.choice(template["db_types"]), 
                                        error=random.choice(["timeout", "connection refused", "authentication failed"]))
            elif "mounts" in template:
                message = message.format(mount=random.choice(template["mounts"]), 
                                        percent=random.randint(85, 99), 
                                        host=f"host-{random.randint(1,5)}")
            elif "directions" in template:
                message = message.format(direction=random.choice(template["directions"]), 
                                        rate=random.randint(500, 5000), 
                                        baseline=random.randint(100, 300))
            elif "reasons" in template:
                message = message.format(ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}", 
                                        reason=random.choice(template["reasons"]))
            
            # Determine severity (with some variation)
            severity = template["severity"]
            if settings.REALISTIC_NOISE and random.random() < 0.2:
                severity = random.choice(["MEDIUM", "HIGH", "CRITICAL"])
            
            # Mark as noise if same (alert_type + service) already appeared in this batch
            pattern = f"{alert_type}_{service}"
            is_noise = any(
                f"{a.get('alert_type', '')}_{a.get('service', '')}" == pattern
                for a in alerts
            )

            alert = {
                "timestamp": datetime.now(),
                "service": service,
                "alert_type": alert_type,
                "message": message,
                "severity": severity,
                "is_noise": is_noise,
                "cluster_id": None,
                "similarity_score": None,
                "raw_data": {
                    "generated_at": datetime.now().isoformat(),
                    "pattern": alert_type
                }
            }
            alerts.append(alert)
        
        # ========== SAVE TO DATABASE ==========
        try:
            with get_db() as db:
                for alert in alerts:
                    AlertRepository.create(db, alert)
            print(f"Saved {len(alerts)} alerts to database")
        except Exception as e:
            print(f"Error saving alerts to database: {e}")
            import traceback
            traceback.print_exc()
        # ======================================
        
        return alerts
    
    @staticmethod
    def simulate_incident() -> Dict:
        """Simulate a cascading incident chain"""
        incidents = [
            {
                "name": "DB_CASCADE_FAILURE",
                "chain": ["DB_CONNECTION_LOST", "API_TIMEOUT", "CACHE_MISS", "USER_SESSION_ERROR"],
                "alerts": [
                    {"type": "Database Failure", "service": "Database", "severity": "CRITICAL"},
                    {"type": "API Timeout", "service": "API Gateway", "severity": "HIGH"},
                    {"type": "Memory Leak", "service": "Cache", "severity": "HIGH"},
                    {"type": "Auth Failure", "service": "Auth Service", "severity": "MEDIUM"}
                ]
            },
            {
                "name": "SECURITY_BREACH",
                "chain": ["AUTH_ANOMALY", "PRIVILEGE_ESCALATION", "DATA_ACCESS", "EXFILTRATION"],
                "alerts": [
                    {"type": "Auth Failure", "service": "Auth Service", "severity": "HIGH"},
                    {"type": "API Timeout", "service": "Backend", "severity": "CRITICAL"},
                    {"type": "Network Spike", "service": "API Gateway", "severity": "HIGH"},
                    {"type": "CPU High", "service": "Database", "severity": "MEDIUM"}
                ]
            },
            {
                "name": "RESOURCE_EXHAUSTION",
                "chain": ["MEMORY_LEAK", "CPU_SPIKE", "DISK_FULL", "OUTAGE"],
                "alerts": [
                    {"type": "Memory Leak", "service": "Frontend", "severity": "HIGH"},
                    {"type": "CPU High", "service": "Backend", "severity": "HIGH"},
                    {"type": "Disk Full", "service": "Database", "severity": "CRITICAL"},
                    {"type": "API Timeout", "service": "API Gateway", "severity": "HIGH"}
                ]
            }
        ]
        
        incident = random.choice(incidents)
        alerts = []
        
        for alert_template in incident["alerts"]:
            alert = {
                "timestamp": datetime.now(),
                "service": alert_template["service"],
                "alert_type": alert_template["type"],
                "message": f"Incident: {incident['name']} - {alert_template['type']} detected",
                "severity": alert_template["severity"],
                "is_noise": False,
                "cluster_id": None,
                "similarity_score": None,
                "raw_data": {
                    "generated_at": datetime.now().isoformat(),
                    "pattern": alert_template["type"],
                    "incident": incident["name"]
                }
            }
            alerts.append(alert)
        
        # Save to database
        try:
            with get_db() as db:
                for alert in alerts:
                    AlertRepository.create(db, alert)
            print(f"Saved {len(alerts)} incident alerts to database")
        except Exception as e:
            print(f"Error saving incident alerts: {e}")
        
        return {
            "alerts": alerts,
            "chain_summary": incident["chain"],
            "count": len(alerts),
            "incident_type": incident["name"]
        }
    
    @staticmethod
    def clear_all_alerts() -> int:
        with get_db() as db:
            return AlertRepository.clear_all(db)