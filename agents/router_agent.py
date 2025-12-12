"""
Router Agent

Monitors network traffic patterns, learns baseline network behavior,
and proactively detects anomalies such as unusual destinations, protocol
anomalies, and volume spikes.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import ipaddress

from agents.base_agent import BaseAgent
from knowledge_fusion.interfaces import Observation


class RouterAgent(BaseAgent):
    """Network traffic monitoring agent with proactive anomaly detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Router Agent."""
        super().__init__("router", config)
        self.known_destinations = set()
        self.known_protocols = set()
        
    def _initialize_baselines(self):
        """Initialize network-specific baseline models."""
        # Connection frequency baseline (connections per minute)
        self.baseline_learner.create_numeric_baseline(
            "router.connection_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Data volume baseline (bytes per connection)
        self.baseline_learner.create_numeric_baseline(
            "router.data_volume",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Connection duration baseline
        self.baseline_learner.create_numeric_baseline(
            "router.connection_duration",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Destination pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "router.destinations",
            min_frequency=self.config.get('min_destination_frequency', 3)
        )
        
        # Protocol pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "router.protocols",
            min_frequency=self.config.get('min_protocol_frequency', 2)
        )
        
        # Port pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "router.ports",
            min_frequency=self.config.get('min_port_frequency', 3)
        )
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from network traffic data.
        
        Args:
            data: Network traffic data dictionary with keys like:
                  - source_ip, dest_ip, protocol, port, bytes_sent, bytes_received,
                    duration, timestamp, etc.
        
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # Destination IP/domain
        dest = data.get('dest_ip') or data.get('dest_domain') or data.get('destination', '')
        if dest:
            features['destinations'] = str(dest)
        
        # Protocol
        protocol = data.get('protocol', '').upper()
        if protocol:
            features['protocols'] = protocol
        
        # Port
        port = data.get('port') or data.get('dest_port')
        if port:
            features['ports'] = str(port)
        
        # Data volume
        bytes_sent = data.get('bytes_sent', 0) or 0
        bytes_received = data.get('bytes_received', 0) or 0
        total_bytes = bytes_sent + bytes_received
        if total_bytes > 0:
            features['data_volume'] = float(total_bytes)
        
        # Connection duration
        duration = data.get('duration_seconds') or data.get('duration', 0)
        if duration:
            features['connection_duration'] = float(duration)
        
        # Connection frequency (would need to track this separately)
        # For now, we'll use a simple heuristic based on unique destinations
        features['connection_frequency'] = 1.0  # Placeholder
        
        return features
    
    def process_data(self, data: Dict[str, Any]) -> List[Observation]:
        """
        Process network traffic data and generate observations.
        
        Args:
            data: Network traffic data dictionary
        
        Returns:
            List of observations (empty if no anomalies detected)
        """
        observations = []
        
        if not isinstance(data, dict):
            return observations
        
        # Extract features
        features = self._extract_features(data)
        
        # Check for anomalies
        anomaly_scores = self.get_anomaly_scores(data)
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Threshold for generating observations
        threshold = self.config.get('anomaly_threshold', 0.5)
        
        if max_score < threshold:
            return observations
        
        # Build indicators
        indicators = []
        dest = data.get('dest_ip') or data.get('dest_domain') or data.get('destination', '')
        if dest:
            indicators.append(dest)
        
        source = data.get('source_ip') or data.get('source', '')
        if source:
            indicators.append(source)
        
        protocol = data.get('protocol', '')
        if protocol:
            indicators.append(protocol)
        
        port = data.get('port') or data.get('dest_port')
        if port:
            indicators.append(f"port:{port}")
        
        # Determine anomaly type and description
        description_parts = []
        
        # Check destination anomaly
        if 'destinations' in anomaly_scores and anomaly_scores['destinations'] > 0.6:
            dest = features.get('destinations', 'unknown')
            description_parts.append(f"Unusual destination: {dest}")
        
        # Check protocol anomaly
        if 'protocols' in anomaly_scores and anomaly_scores['protocols'] > 0.6:
            protocol = features.get('protocols', 'unknown')
            description_parts.append(f"Unusual protocol: {protocol}")
        
        # Check data volume anomaly
        if 'data_volume' in anomaly_scores and anomaly_scores['data_volume'] > 0.7:
            volume = features.get('data_volume', 0)
            description_parts.append(f"Unusual data volume: {volume:.0f} bytes")
        
        # Check port anomaly
        if 'ports' in anomaly_scores and anomaly_scores['ports'] > 0.6:
            port = features.get('ports', 'unknown')
            description_parts.append(f"Unusual port: {port}")
        
        # Check connection duration anomaly
        if 'connection_duration' in anomaly_scores and anomaly_scores['connection_duration'] > 0.7:
            duration = features.get('connection_duration', 0)
            description_parts.append(f"Unusual connection duration: {duration:.1f}s")
        
        if not description_parts:
            description_parts.append("Network traffic anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        # Additional checks for known attack patterns
        if self._check_c2_pattern(data, features):
            description += " Pattern matches command and control infrastructure."
            severity = "high"
        
        if self._check_data_exfiltration_pattern(data, features):
            description += " Pattern suggests potential data exfiltration."
            severity = "critical"
        
        # Create observation
        metadata = {
            'source_ip': source,
            'dest_ip': dest,
            'protocol': protocol,
            'port': port,
            'bytes_sent': data.get('bytes_sent', 0),
            'bytes_received': data.get('bytes_received', 0),
            'duration_seconds': data.get('duration_seconds', 0),
            **data.get('metadata', {})
        }
        
        observation = self.generate_observation(
            data=data,
            description=description,
            indicators=indicators,
            severity=severity,
            metadata=metadata
        )
        
        observations.append(observation)
        return observations
    
    def _check_c2_pattern(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """
        Check if traffic pattern matches command and control (C2) characteristics.
        
        Args:
            data: Network traffic data
            features: Extracted features
        
        Returns:
            True if C2 pattern detected
        """
        # C2 indicators:
        # - Long-lived connections
        # - Regular heartbeat pattern
        # - Encrypted protocols (HTTPS, TLS)
        # - Unusual destinations
        
        duration = features.get('connection_duration', 0)
        protocol = features.get('protocols', '').upper()
        
        # Long-lived encrypted connection to unusual destination
        if duration > 300 and protocol in ['HTTPS', 'TLS', 'SSL']:
            dest_score = features.get('destinations', '')
            if dest_score and self.baseline_learner.get_pattern_baseline('router.destinations'):
                baseline = self.baseline_learner.get_pattern_baseline('router.destinations')
                if not baseline.is_known(dest_score):
                    return True
        
        return False
    
    def _check_data_exfiltration_pattern(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """
        Check if traffic pattern suggests data exfiltration.
        
        Args:
            data: Network traffic data
            features: Extracted features
        
        Returns:
            True if exfiltration pattern detected
        """
        # Exfiltration indicators:
        # - Large outbound data volume
        # - Unusual destination
        # - Asymmetric traffic (much more sent than received)
        
        bytes_sent = data.get('bytes_sent', 0) or 0
        bytes_received = data.get('bytes_received', 0) or 0
        
        # Large outbound volume
        if bytes_sent > 10 * 1024 * 1024:  # > 10MB
            # Check if destination is unusual
            dest = features.get('destinations', '')
            if dest and self.baseline_learner.get_pattern_baseline('router.destinations'):
                baseline = self.baseline_learner.get_pattern_baseline('router.destinations')
                if not baseline.is_known(dest):
                    # Asymmetric traffic
                    if bytes_sent > 10 * bytes_received:
                        return True
        
        return False




