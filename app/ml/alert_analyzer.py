import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import DBSCAN
from collections import defaultdict
from typing import List, Dict, Any, Tuple
import logging

from app.config import settings

logger = logging.getLogger(__name__)

class AlertAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=100,
            stop_words='english',
            ngram_range=(1, 2)
        )
        self.similarity_threshold = settings.SIMILARITY_THRESHOLD
        self.eps = settings.CLUSTERING_EPS
        self.min_samples = settings.CLUSTERING_MIN_SAMPLES
        
    def extract_features(self, alerts: List[Dict]) -> np.ndarray:
        """Extract text features from alerts"""
        texts = []
        for alert in alerts:
            # Combine relevant fields for feature extraction
            text = f"{alert.get('service', '')} {alert.get('alert_type', '')} {alert.get('message', '')}"
            texts.append(text.lower())
        
        if len(texts) < 2:
            return np.array([[0]])
        
        return self.vectorizer.fit_transform(texts).toarray()
    
    def find_duplicates(self, alerts: List[Dict]) -> List[List[int]]:
        """Find duplicate alerts using cosine similarity"""
        if len(alerts) < 2:
            return []
        
        features = self.extract_features(alerts)
        similarity = cosine_similarity(features)
        
        duplicate_groups = []
        visited = set()
        
        for i in range(len(alerts)):
            if i in visited:
                continue
                
            group = [i]
            for j in range(i + 1, len(alerts)):
                if similarity[i][j] > self.similarity_threshold:
                    group.append(j)
                    visited.add(j)
            
            if len(group) > 1:
                duplicate_groups.append(group)
            visited.add(i)
        
        return duplicate_groups
    
    def cluster_alerts(self, alerts: List[Dict]) -> Dict[int, List[int]]:
        """Cluster alerts using DBSCAN"""
        if len(alerts) < self.min_samples:
            return {}
        
        features = self.extract_features(alerts)
        
        # DBSCAN clustering
        clustering = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric='cosine')
        labels = clustering.fit_predict(features)
        
        clusters = defaultdict(list)
        for idx, label in enumerate(labels):
            if label != -1:  # -1 is noise
                clusters[int(label)].append(idx)
        
        return dict(clusters)
    
    def prioritize_alerts(self, alerts: List[Dict]) -> List[Dict]:
        """Rank alerts by severity and similarity score"""
        severity_weights = {
            "CRITICAL": 100,
            "HIGH": 70,
            "MEDIUM": 40,
            "LOW": 10
        }
        
        scored_alerts = []
        for i, alert in enumerate(alerts):
            base_score = severity_weights.get(alert.get('severity', 'MEDIUM'), 40)
            
            # Boost score based on alert type criticality
            critical_types = ["Database Failure", "Security Breach", "Data Loss"]
            if alert.get('alert_type') in critical_types:
                base_score += 30
            
            # Boost recent alerts
            # (would use timestamp in real implementation)
            
            scored_alerts.append({
                **alert,
                "score": base_score,
                "rank": i
            })
        
        return sorted(scored_alerts, key=lambda x: x['score'], reverse=True)
    
    def identify_root_cause(self, alerts: List[Dict]) -> Dict:
        """Identify potential root cause from alert clusters"""
        if not alerts:
            return {"service": "unknown", "confidence": "LOW", "affected": []}
        
        # Count occurrences by service and type
        service_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for alert in alerts:
            service_counts[alert.get('service', 'unknown')] += 1
            type_counts[alert.get('alert_type', 'unknown')] += 1
        
        # Primary suspected service
        primary_service = max(service_counts.items(), key=lambda x: x[1])[0]
        primary_type = max(type_counts.items(), key=lambda x: x[1])[0]
        
        # Calculate confidence based on distribution
        total = len(alerts)
        service_ratio = service_counts[primary_service] / total if total > 0 else 0
        
        if service_ratio > 0.7:
            confidence = "HIGH"
        elif service_ratio > 0.4:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return {
            "service": primary_service,
            "alert_type": primary_type,
            "confidence": confidence,
            "affected": list(service_counts.keys()),
            "impact_ratio": service_ratio
        }
    
    def generate_cascade_chain(self, alerts: List[Dict]) -> List[str]:
        """Generate alert cascade chain based on timestamps"""
        if not alerts:
            return []
        
        # Sort by timestamp (assuming ISO format)
        sorted_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''))
        
        # Extract unique services/types in order
        chain = []
        seen = set()
        
        for alert in sorted_alerts[:10]:  # Top 10 for chain
            service = alert.get('service', '')
            alert_type = alert.get('alert_type', '')
            key = f"{service}:{alert_type}"
            
            if key not in seen:
                chain.append(f"{service}_{alert_type}")
                seen.add(key)
        
        return chain