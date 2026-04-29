from typing import List, Dict, Any
from collections import defaultdict
from datetime import datetime, timedelta
import numpy as np

class SystemPredictor:
    def __init__(self):
        self.history_window = 60  # minutes
    
    def predict_future_state(self, alerts: List[Dict]) -> Dict:
        """Predict system future state based on current alerts"""
        if not alerts:
            return {
                "prediction": "NOMINAL",
                "confidence": "HIGH",
                "message": "No alerts detected, system appears stable",
                "eta": "24h",
                "risk_factors": {
                    "critical_alerts": 0,
                    "high_alerts": 0,
                    "affected_services": 0
                }
            }
        
        # Count severity levels
        critical_count = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
        high_count = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        services = set(a.get('service') for a in alerts)
        
        # Calculate risk score
        risk_score = (critical_count * 10) + (high_count * 5)
        
        # Determine prediction
        if critical_count >= 3 or risk_score > 50:
            prediction = "CRITICAL_FAILURE"
            confidence = "HIGH"
            message = f"High probability of system failure within next hour - {critical_count} critical alerts detected"
            eta = "1h"
        elif critical_count >= 1 or high_count >= 5 or risk_score > 25:
            prediction = "MAJOR_DEGRADATION"
            confidence = "MEDIUM"
            message = f"System degradation expected - multiple high-severity issues require immediate attention"
            eta = "3h"
        elif high_count >= 2 or risk_score > 10:
            prediction = "INSTABILITY"
            confidence = "MEDIUM"
            message = f"System showing signs of instability - monitor closely"
            eta = "6h"
        else:
            prediction = "NOMINAL"
            confidence = "HIGH"
            message = f"System appears stable with minor issues detected"
            eta = "24h"
        
        return {
            "prediction": prediction,
            "confidence": confidence,
            "message": message,
            "eta": eta,
            "risk_factors": {
                "critical_alerts": critical_count,
                "high_alerts": high_count,
                "affected_services": len(services),
                "risk_score": risk_score
            }
        }
    
    def predict_anomaly_score(self, alerts: List[Dict], historical_alerts: List[Dict]) -> float:
        """Calculate anomaly score based on historical patterns"""
        if not historical_alerts:
            return 0.0
        
        # Calculate current alert frequency
        current_rate = len(alerts) / 60  # per minute
        
        # Calculate historical average rate
        historical_rate = len(historical_alerts) / self.history_window
        
        # Calculate anomaly score
        if historical_rate > 0:
            anomaly_ratio = current_rate / historical_rate
            anomaly_score = min(1.0, anomaly_ratio / 3)  # Normalize
        else:
            anomaly_score = min(1.0, current_rate / 10)
        
        return round(anomaly_score * 100, 2)