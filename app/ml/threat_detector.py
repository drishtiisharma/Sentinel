from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta
import re

class ThreatDetector:
    def __init__(self):
        self.threat_patterns = {
            "BRUTE_FORCE": {
                "keywords": ["failed login", "authentication failed", "invalid password"],
                "severity": "HIGH",
                "time_window_minutes": 5,
                "threshold": 10
            },
            "DATA_EXFILTRATION": {
                "keywords": ["large data transfer", "unusual export", "data leak"],
                "severity": "CRITICAL",
                "time_window_minutes": 10,
                "threshold": 3
            },
            "SERVICE_ATTACK": {
                "keywords": ["ddos", "flood", "overload", "rate limit exceeded"],
                "severity": "HIGH",
                "time_window_minutes": 2,
                "threshold": 20
            },
            "PRIVILEGE_ESCALATION": {
                "keywords": ["sudo", "admin access", "permission change", "role escalation"],
                "severity": "CRITICAL",
                "time_window_minutes": 15,
                "threshold": 2
            },
            "MALWARE_INDICATOR": {
                "keywords": ["suspicious process", "unknown binary", "cryptominer", "ransomware"],
                "severity": "CRITICAL",
                "time_window_minutes": 5,
                "threshold": 1
            },
            "RESOURCE_EXHAUSTION": {
                "keywords": ["memory leak", "cpu spike", "disk full", "out of memory"],
                "severity": "HIGH",
                "time_window_minutes": 10,
                "threshold": 5
            }
        }
    
    def detect_threats(self, alerts: List[Dict]) -> List[Dict]:
        """Detect security threats from alert patterns"""
        threats = []
        
        for threat_type, config in self.threat_patterns.items():
            matching_alerts = []
            
            for alert in alerts:
                message = f"{alert.get('message', '')} {alert.get('alert_type', '')}".lower()
                
                if any(keyword in message for keyword in config['keywords']):
                    matching_alerts.append(alert)
            
            if len(matching_alerts) >= config['threshold']:
                # Get unique affected services
                affected = list(set(a.get('service', 'unknown') for a in matching_alerts))
                
                threat = {
                    "type": threat_type,
                    "severity": config['severity'],
                    "confidence": min(100, len(matching_alerts) * 10),
                    "evidence": len(matching_alerts),
                    "description": f"Detected {len(matching_alerts)} alerts matching {threat_type.lower().replace('_', ' ')} pattern",
                    "affected_services": affected,
                    "indicators": [f"{a.get('alert_type', '')}: {a.get('message', '')[:50]}" for a in matching_alerts[:5]],
                    "next_steps": self._get_mitigation_steps(threat_type),
                    "recommendations": self._get_recommendations(threat_type),
                    "time_pattern": self._analyze_time_pattern(matching_alerts)
                }
                threats.append(threat)
        
        return threats
    
    def _get_mitigation_steps(self, threat_type: str) -> List[str]:
        """Get mitigation steps for threat type"""
        mitigation = {
            "BRUTE_FORCE": [
                "Block source IPs",
                "Enable rate limiting",
                "Implement CAPTCHA",
                "Review authentication logs"
            ],
            "DATA_EXFILTRATION": [
                "Block outgoing connections",
                "Revoke suspicious access tokens",
                "Enable data loss prevention",
                "Audit data access logs"
            ],
            "SERVICE_ATTACK": [
                "Enable DDoS protection",
                "Scale up resources",
                "Implement request throttling",
                "Contact upstream provider"
            ],
            "PRIVILEGE_ESCALATION": [
                "Revoke elevated privileges",
                "Force password reset",
                "Enable MFA",
                "Audit permission changes"
            ],
            "MALWARE_INDICATOR": [
                "Isolate affected systems",
                "Run antivirus scan",
                "Block known C2 domains",
                "Review running processes"
            ],
            "RESOURCE_EXHAUSTION": [
                "Restart affected services",
                "Increase resource limits",
                "Optimize memory usage",
                "Set up auto-scaling"
            ]
        }
        return mitigation.get(threat_type, ["Investigate immediately", "Review system logs"])
    
    def _get_recommendations(self, threat_type: str) -> List[str]:
        """Get security recommendations"""
        recommendations = {
            "BRUTE_FORCE": ["Implement account lockout", "Use strong passwords", "Enable MFA"],
            "DATA_EXFILTRATION": ["Encrypt sensitive data", "Monitor outbound traffic", "Implement DLP"],
            "SERVICE_ATTACK": ["Use CDN", "Implement WAF", "Rate limiting"],
            "PRIVILEGE_ESCALATION": ["Least privilege principle", "Regular permission audits", "PAM solution"],
            "MALWARE_INDICATOR": ["EDR solution", "Application whitelisting", "Regular patching"],
            "RESOURCE_EXHAUSTION": ["Auto-scaling", "Resource quotas", "Performance monitoring"]
        }
        return recommendations.get(threat_type, ["Monitor closely", "Security audit recommended"])
    
    def _analyze_time_pattern(self, alerts: List[Dict]) -> str:
        """Analyze time pattern of threats"""
        if len(alerts) < 2:
            return "Single occurrence"
        
        # In real implementation, parse timestamps and analyze frequency
        return f"Multiple occurrences over time window"