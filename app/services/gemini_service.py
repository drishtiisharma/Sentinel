import google.generativeai as genai
from typing import List, Dict
import logging

from app.config import settings

logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self):
        self.enabled = bool(settings.GEMINI_API_KEY)
        if self.enabled:
            try:
                genai.configure(api_key=settings.GEMINI_API_KEY)
                self.model = genai.GenerativeModel('gemini-pro')
                logger.info("Gemini AI service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
                self.enabled = False
    
    async def generate_analysis_summary(self, alerts: List[Dict], root_cause: Dict, 
                                        threats: List[Dict], prediction: Dict) -> str:
        """Generate AI-powered analysis summary"""
        if not self.enabled:
            return "Gemini AI not configured. Please add GEMINI_API_KEY to .env file."
        
        try:
            # Prepare context for Gemini
            alert_summary = self._format_alerts_for_prompt(alerts)
            
            prompt = f"""You are an AIOps expert. Analyze these system alerts and provide a concise, actionable summary.

Alert Summary:
{alert_summary}

Root Cause Analysis:
- Primary service: {root_cause.get('service', 'unknown')}
- Confidence: {root_cause.get('confidence', 'LOW')}
- Affected services: {', '.join(root_cause.get('affected', []))}

Security Threats Detected: {len(threats)}
{self._format_threats_for_prompt(threats)}

System Prediction: {prediction.get('prediction', 'NOMINAL')}
Confidence: {prediction.get('confidence', 'LOW')}
Risk Score: {prediction.get('risk_factors', {}).get('risk_score', 0)}

Please provide:
1. A one-sentence executive summary
2. Top 3 immediate actions required
3. Any security concerns that need attention

Keep response under 200 words and be actionable."""
            
            response = self.model.generate_content(prompt)
            return response.text.strip()
        
        except Exception as e:
            logger.error(f"Gemini generation failed: {e}")
            return f"AI analysis temporarily unavailable. Error: {str(e)}"
    
    def _format_alerts_for_prompt(self, alerts: List[Dict]) -> str:
        """Format alerts for Gemini prompt"""
        if not alerts:
            return "No alerts detected."
        
        # Group by severity
        by_severity = {}
        for alert in alerts:
            severity = alert.get('severity', 'MEDIUM')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(alert)
        
        lines = []
        for severity, sev_alerts in by_severity.items():
            lines.append(f"- {severity}: {len(sev_alerts)} alerts")
            # Add sample of critical/high alerts
            if severity in ['CRITICAL', 'HIGH'] and sev_alerts:
                sample = sev_alerts[0]
                lines.append(f"  Sample: {sample.get('service')} - {sample.get('alert_type')}")
        
        return "\n".join(lines)
    
    def _format_threats_for_prompt(self, threats: List[Dict]) -> str:
        """Format threats for Gemini prompt"""
        if not threats:
            return "No active security threats detected."
        
        lines = []
        for threat in threats:
            lines.append(f"- {threat['type']} ({threat['severity']}): {threat['description'][:100]}")
        
        return "\n".join(lines)