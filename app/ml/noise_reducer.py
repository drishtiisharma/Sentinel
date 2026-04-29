from typing import List, Dict, Set
from collections import defaultdict
import hashlib
import json

class NoiseReducer:
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.pattern_cache = {}
    
    def normalize_alert(self, alert: Dict) -> str:
        """Create normalized representation for deduplication"""
        # Remove timestamp and other variable fields
        normalized = {
            "service": alert.get('service', ''),
            "type": alert.get('alert_type', ''),
            "severity": alert.get('severity', ''),
            "message": alert.get('message', '')[:100]  # Trim long messages
        }
        return json.dumps(normalized, sort_keys=True)
    
    def get_pattern_hash(self, alert: Dict) -> str:
        """Generate hash for alert pattern"""
        normalized = self.normalize_alert(alert)
        return hashlib.sha256(normalized.encode()).hexdigest()
    
    def remove_duplicates(self, alerts: List[Dict]) -> Tuple[List[Dict], List[int]]:
        """Remove duplicate alerts and return unique alerts with duplicate indices"""
        seen_patterns = {}
        unique_alerts = []
        duplicate_indices = []
        
        for idx, alert in enumerate(alerts):
            pattern_hash = self.get_pattern_hash(alert)
            
            if pattern_hash in seen_patterns:
                duplicate_indices.append(idx)
            else:
                seen_patterns[pattern_hash] = len(unique_alerts)
                unique_alerts.append(alert)
        
        return unique_alerts, duplicate_indices
    
    def filter_noise(self, alerts: List[Dict], noise_threshold: int = 10) -> Tuple[List[Dict], List[int]]:
        """Filter out high-frequency noise alerts"""
        pattern_counts = defaultdict(int)
        pattern_indices = defaultdict(list)
        
        # Count pattern frequencies
        for idx, alert in enumerate(alerts):
            pattern_hash = self.get_pattern_hash(alert)
            pattern_counts[pattern_hash] += 1
            pattern_indices[pattern_hash].append(idx)
        
        # Identify noise patterns (too frequent)
        noise_indices = set()
        for pattern_hash, count in pattern_counts.items():
            if count > noise_threshold:
                # Keep first occurrence, mark rest as noise
                indices = pattern_indices[pattern_hash]
                noise_indices.update(indices[1:])  # All but first
        
        filtered_alerts = [a for i, a in enumerate(alerts) if i not in noise_indices]
        return filtered_alerts, list(noise_indices)
    
    def reduce_noise(self, alerts: List[Dict]) -> Dict:
        """Apply comprehensive noise reduction"""
        # Remove duplicates first
        unique_alerts, duplicates = self.remove_duplicates(alerts)
        
        # Then filter high-frequency noise
        filtered_alerts, noise_alerts = self.filter_noise(unique_alerts)
        
        # Calculate metrics
        total_original = len(alerts)
        total_filtered = len(filtered_alerts)
        total_removed = total_original - total_filtered
        
        reduction_percent = (total_removed / total_original * 100) if total_original > 0 else 0
        
        # Track which original indices were removed
        all_removed = set(duplicates)
        all_removed.update(noise_alerts)
        
        return {
            "filtered_alerts": filtered_alerts,
            "removed_count": total_removed,
            "reduction_percent": reduction_percent,
            "duplicate_count": len(duplicates),
            "noise_count": len(noise_alerts),
            "removed_indices": list(all_removed)
        }