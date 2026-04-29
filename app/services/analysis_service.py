from typing import List, Dict, Any
from collections import defaultdict
import logging

from app.ml.alert_analyzer import AlertAnalyzer
from app.ml.noise_reducer import NoiseReducer
from app.ml.threat_detector import ThreatDetector
from app.ml.predictor import SystemPredictor
from app.database.connection import get_db
from app.database.repository import AlertRepository, AnalysisRepository
from app.services.gemini_service import GeminiService
from app.config import settings

logger = logging.getLogger(__name__)

class AnalysisService:
    def __init__(self):
        self.analyzer = AlertAnalyzer()
        self.noise_reducer = NoiseReducer()
        self.threat_detector = ThreatDetector()
        self.predictor = SystemPredictor()
        self.gemini = GeminiService() if settings.GEMINI_ENABLED else None
    
    async def analyze_alerts(self, alerts: List[Dict]) -> Dict:
        """Perform comprehensive ML analysis on alerts"""
        if not alerts:
            return self._empty_analysis()
        
        # Step 1: Noise reduction
        noise_result = self.noise_reducer.reduce_noise(alerts)
        filtered_alerts = noise_result["filtered_alerts"]
        
        # Step 2: Find duplicates and clusters
        duplicate_groups = self.analyzer.find_duplicates(filtered_alerts)
        clusters = self.analyzer.cluster_alerts(filtered_alerts)
        
        # Step 3: Prioritize alerts
        prioritized = self.analyzer.prioritize_alerts(filtered_alerts)
        
        # Step 4: Root cause analysis
        root_cause = self.analyzer.identify_root_cause(filtered_alerts)
        
        # Step 5: Cascade chain
        cascade_chain = self.analyzer.generate_cascade_chain(filtered_alerts)
        
        # Step 6: Threat detection
        threats = self.threat_detector.detect_threats(filtered_alerts)
        
        # Step 7: Future prediction
        prediction = self.predictor.predict_future_state(filtered_alerts)
        
        # Step 8: Generate AI summary (if Gemini available)
        ai_summary = await self._generate_ai_summary(filtered_alerts, root_cause, threats, prediction)
        
        # Step 9: Calculate statistics
        severity_dist = defaultdict(int)
        type_counts = defaultdict(int)
        
        for alert in filtered_alerts:
            severity_dist[alert.get('severity', 'MEDIUM')] += 1
            type_counts[alert.get('alert_type', 'unknown')] += 1
        
        # Step 10: Generate recommendations
        recommendations = self._generate_recommendations(filtered_alerts, root_cause, threats)
        
        # Build top alerts (top 10 by priority)
        top_alerts = prioritized[:10]
        
        # Format clusters for output
        cluster_list = []
        for cluster_id, indices in clusters.items():
            if indices:
                cluster_alerts = [filtered_alerts[i] for i in indices]
                severity_list = [a.get('severity', 'MEDIUM') for a in cluster_alerts]
                cluster_list.append({
                    "id": cluster_id,
                    "count": len(indices),
                    "dominant_severity": max(set(severity_list), key=severity_list.count),
                    "service": cluster_alerts[0].get('service', 'unknown'),
                    "type": cluster_alerts[0].get('alert_type', 'unknown'),
                    "total_score": sum(prioritized[i].get('score', 0) for i in indices if i < len(prioritized))
                })
        
        analysis_result = {
            "total_alerts": len(alerts),
            "filtered_alerts": len(filtered_alerts),
            "noise_removed": noise_result["removed_count"],
            "reduction_percent": noise_result["reduction_percent"],
            "ai_summary": ai_summary,
            "root_cause": root_cause,
            "future_prediction": prediction,
            "security_threats": threats,
            "cascade_chain": cascade_chain,
            "top_alerts": top_alerts,
            "clusters": cluster_list,
            "priority_ranking": prioritized[:20],
            "recommendations": recommendations,
            "severity_distribution": dict(severity_dist),
            "type_counts": dict(type_counts),
            "duplicate_groups": duplicate_groups,
            "noise_metrics": {
                "duplicates_removed": noise_result["duplicate_count"],
                "noise_removed": noise_result["noise_count"]
            }
        }
        
        # Save analysis to database
        with get_db() as db:
            analysis = AnalysisRepository.create(db, {
                "total_alerts": analysis_result["total_alerts"],
                "filtered_alerts": analysis_result["filtered_alerts"],
                "noise_removed": analysis_result["noise_removed"],
                "reduction_percent": analysis_result["reduction_percent"],
                "ai_summary": analysis_result["ai_summary"],
                "root_cause": analysis_result["root_cause"],
                "future_prediction": analysis_result["future_prediction"],
                "recommendations": analysis_result["recommendations"],
                "security_threats": analysis_result["security_threats"],
                "cascade_chain": analysis_result["cascade_chain"],
                "clusters": analysis_result["clusters"],
                "severity_distribution": analysis_result["severity_distribution"],
                "type_counts": analysis_result["type_counts"],
                "service_counts": defaultdict(int),
                "raw_analysis": analysis_result
            })
            analysis_result["analysis_id"] = analysis.id
        
        # Mark noise alerts in database
        if noise_result["removed_indices"]:
            with get_db() as db:
                alert_ids = []
                all_alerts = AlertRepository.get_all(db)
                for idx in noise_result["removed_indices"]:
                    if idx < len(all_alerts):
                        alert_ids.append(all_alerts[idx].id)
                if alert_ids:
                    AlertRepository.mark_noise(db, alert_ids)
        
        return analysis_result
    
    async def _generate_ai_summary(self, alerts: List[Dict], root_cause: Dict, threats: List[Dict], prediction: Dict) -> str:
        """Generate AI-powered summary using Gemini or fallback"""
        if self.gemini and self.gemini.enabled:
            try:
                return await self.gemini.generate_analysis_summary(alerts, root_cause, threats, prediction)
            except Exception as e:
                logger.error(f"Gemini summary failed: {e}")
        
        # Fallback: generate rule-based summary
        return self._generate_rule_based_summary(alerts, root_cause, threats, prediction)
    
    def _generate_rule_based_summary(self, alerts: List[Dict], root_cause: Dict, threats: List[Dict], prediction: Dict) -> str:
        """Generate rule-based summary when AI is unavailable"""
        total = len(alerts)
        critical = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
        high = sum(1 for a in alerts if a.get('severity') == 'HIGH')
        
        summary_parts = []
        
        if total == 0:
            return "System analysis complete. No alerts detected. System appears healthy."
        
        summary_parts.append(f"Analysis of {total} alerts completed.")
        
        if critical > 0:
            summary_parts.append(f"Detected {critical} CRITICAL alerts requiring immediate attention.")
        if high > 0:
            summary_parts.append(f"Found {high} HIGH severity incidents.")
        
        if root_cause.get('service') != 'unknown':
            summary_parts.append(f"Primary root cause identified: {root_cause['service']} service "
                               f"with {root_cause.get('confidence', 'LOW')} confidence.")
        
        if threats:
            summary_parts.append(f"🚨 SECURITY THREATS DETECTED: {', '.join([t['type'] for t in threats])}")
        
        summary_parts.append(f"System forecast: {prediction.get('prediction', 'NOMINAL')} "
                           f"with {prediction.get('confidence', 'LOW')} confidence.")
        
        return " ".join(summary_parts)
    
    def _generate_recommendations(self, alerts: List[Dict], root_cause: Dict, threats: List[Dict]) -> List[Dict]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        # Critical alerts recommendation
        critical_alerts = [a for a in alerts if a.get('severity') == 'CRITICAL']
        if critical_alerts:
            recommendations.append({
                "action": "Investigate critical failures immediately",
                "detail": f"{len(critical_alerts)} critical alerts require immediate investigation",
                "urgency": "IMMEDIATE"
            })
        
        # Root cause recommendation
        if root_cause.get('confidence') == 'HIGH':
            recommendations.append({
                "action": f"Focus on {root_cause['service']} service",
                "detail": f"Root cause analysis points to {root_cause['service']} as primary failure point",
                "urgency": "IMMEDIATE"
            })
        
        # Threat recommendations
        for threat in threats:
            for rec in threat.get('recommendations', [])[:2]:
                recommendations.append({
                    "action": f"Address {threat['type']} threat",
                    "detail": rec,
                    "urgency": "IMMEDIATE" if threat['severity'] == 'CRITICAL' else "SOON"
                })
        
        # General recommendations
        if len(alerts) > 50:
            recommendations.append({
                "action": "Enable enhanced noise reduction",
                "detail": "High alert volume detected - consider tuning thresholds",
                "urgency": "SOON"
            })
        
        # Deduplicate
        unique_recs = []
        seen = set()
        for rec in recommendations:
            key = rec['action']
            if key not in seen:
                seen.add(key)
                unique_recs.append(rec)
        
        return unique_recs[:10]
    
    def _empty_analysis(self) -> Dict:
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
    
    @staticmethod
    def get_analysis_history(limit: int = 20) -> List[Dict]:
        with get_db() as db:
            analyses = AnalysisRepository.get_all(db, limit)
            return [
                {
                    "id": a.id,
                    "timestamp": a.timestamp.isoformat(),
                    "total_alerts": a.total_alerts,
                    "filtered_alerts": a.filtered_alerts,
                    "noise_removed": a.noise_removed,
                    "reduction_percent": a.reduction_percent,
                    "root_cause": a.root_cause.get('service', 'unknown'),
                    "confidence": a.root_cause.get('confidence', 'LOW')
                }
                for a in analyses
            ]
    
    @staticmethod
    def get_analysis_by_id(analysis_id: int) -> Dict:
        with get_db() as db:
            analysis = AnalysisRepository.get_by_id(db, analysis_id)
            if not analysis:
                return None
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
                "priority_ranking": analysis.raw_analysis.get('priority_ranking', []),
                "recommendations": analysis.recommendations,
                "severity_distribution": analysis.severity_distribution,
                "type_counts": analysis.type_counts
            }