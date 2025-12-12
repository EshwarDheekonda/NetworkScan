"""
Router LLM Agent

Network monitoring agent with LLM reasoning for threat analysis,
proactive pattern recognition, and cross-agent communication.
"""

from typing import List, Dict, Any, Optional
import ipaddress

from agents.llm_agents.llm_base_agent import LLMBaseAgent
from knowledge_fusion.interfaces import Observation


class RouterLLMAgent(LLMBaseAgent):
    """Network traffic monitoring agent with LLM reasoning."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize Router LLM Agent."""
        super().__init__("router", config, **kwargs)
        self.known_destinations = set()
        self.known_protocols = set()
    
    def _initialize_baselines(self):
        """Initialize network-specific baseline models."""
        # Connection frequency baseline
        self.baseline_learner.create_numeric_baseline(
            "router.connection_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Data volume baseline
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
        """Extract features from network traffic data."""
        features = {}
        
        dest = data.get('dest_ip') or data.get('dest_domain') or data.get('destination', '')
        if dest:
            features['destinations'] = str(dest)
        
        protocol = data.get('protocol', '').upper()
        if protocol:
            features['protocols'] = protocol
        
        port = data.get('port') or data.get('dest_port')
        if port:
            features['ports'] = str(port)
        
        bytes_sent = data.get('bytes_sent', 0) or 0
        bytes_received = data.get('bytes_received', 0) or 0
        total_bytes = bytes_sent + bytes_received
        if total_bytes > 0:
            features['data_volume'] = float(total_bytes)
        
        duration = data.get('duration_seconds') or data.get('duration', 0)
        if duration:
            features['connection_duration'] = float(duration)
        
        features['connection_frequency'] = 1.0  # Placeholder
        
        return features
    
    def _extract_indicators(self, data: Any) -> List[str]:
        """Extract indicators from network data."""
        indicators = []
        if isinstance(data, dict):
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
        
        return indicators
    
    def _generate_statistical_observations(
        self,
        data: Any,
        anomaly_scores: Dict[str, float]
    ) -> List[Observation]:
        """Generate observations from statistical anomaly detection."""
        if not isinstance(data, dict):
            return []
        
        observations = []
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Build indicators
        indicators = self._extract_indicators(data)
        
        # Build description from anomaly scores
        description_parts = []
        
        if 'destinations' in anomaly_scores and anomaly_scores['destinations'] > 0.6:
            dest = data.get('dest_ip') or data.get('dest_domain', 'unknown')
            description_parts.append(f"Unusual destination: {dest}")
        
        if 'protocols' in anomaly_scores and anomaly_scores['protocols'] > 0.6:
            protocol = data.get('protocol', 'unknown')
            description_parts.append(f"Unusual protocol: {protocol}")
        
        if 'data_volume' in anomaly_scores and anomaly_scores['data_volume'] > 0.7:
            volume = data.get('bytes_sent', 0) + data.get('bytes_received', 0)
            description_parts.append(f"Unusual data volume: {volume:.0f} bytes")
        
        if 'ports' in anomaly_scores and anomaly_scores['ports'] > 0.6:
            port = data.get('port') or data.get('dest_port', 'unknown')
            description_parts.append(f"Unusual port: {port}")
        
        if 'connection_duration' in anomaly_scores and anomaly_scores['connection_duration'] > 0.7:
            duration = data.get('duration_seconds', 0)
            description_parts.append(f"Unusual connection duration: {duration:.1f}s")
        
        if not description_parts:
            description_parts.append("Network traffic anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Check for known attack patterns
        if self._check_c2_pattern(data):
            description += " Pattern matches command and control infrastructure."
        
        if self._check_data_exfiltration_pattern(data):
            description += " Pattern suggests potential data exfiltration."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        metadata = {
            'source_ip': data.get('source_ip', ''),
            'dest_ip': data.get('dest_ip') or data.get('dest_domain', ''),
            'protocol': data.get('protocol', ''),
            'port': data.get('port') or data.get('dest_port', ''),
            'bytes_sent': data.get('bytes_sent', 0),
            'bytes_received': data.get('bytes_received', 0),
            'duration_seconds': data.get('duration_seconds', 0),
            # Store anomaly scores in metadata so they're preserved
            'anomaly_scores': anomaly_scores,
            'max_anomaly_score': max_score,
            **data.get('metadata', {})
        }
        
        observation = self.generate_observation(
            data=data,
            description=description,
            indicators=indicators,
            severity=severity,
            metadata=metadata
        )
        
        # Ensure max_anomaly_score is set even if generate_observation recalculated
        if 'max_anomaly_score' not in observation.metadata or observation.metadata['max_anomaly_score'] == 0.0:
            observation.metadata['max_anomaly_score'] = max_score
        
        observations.append(observation)
        return observations
    
    def _check_c2_pattern(self, data: Dict[str, Any]) -> bool:
        """Check if traffic pattern matches C2 characteristics."""
        duration = data.get('duration_seconds', 0)
        protocol = data.get('protocol', '').upper()
        
        # Long-lived encrypted connection to unusual destination
        if duration > 300 and protocol in ['HTTPS', 'TLS', 'SSL']:
            dest = data.get('dest_ip') or data.get('dest_domain', '')
            if dest:
                baseline = self.baseline_learner.get_pattern_baseline('router.destinations')
                if baseline and not baseline.is_known(dest):
                    return True
        
        return False
    
    def _check_data_exfiltration_pattern(self, data: Dict[str, Any]) -> bool:
        """Check if traffic pattern suggests data exfiltration."""
        bytes_sent = data.get('bytes_sent', 0) or 0
        bytes_received = data.get('bytes_received', 0) or 0
        
        # Large outbound volume
        if bytes_sent > 10 * 1024 * 1024:  # > 10MB
            dest = data.get('dest_ip') or data.get('dest_domain', '')
            if dest:
                baseline = self.baseline_learner.get_pattern_baseline('router.destinations')
                if baseline and not baseline.is_known(dest):
                    # Asymmetric traffic
                    if bytes_sent > 10 * bytes_received:
                        return True
        
        return False
    
    def _get_crewai_role(self) -> str:
        """Get CrewAI role."""
        return "Network Security Analyst"
    
    def _get_crewai_goal(self) -> str:
        """Get CrewAI goal."""
        return "Monitor network traffic patterns, detect anomalies, and identify potential command & control, data exfiltration, and other network-based attacks"
    
    def _get_crewai_backstory(self) -> str:
        """Get CrewAI backstory."""
        return """You are an expert network security analyst specializing in network traffic analysis, 
        intrusion detection, and threat hunting. You have deep knowledge of network protocols, 
        command & control patterns, data exfiltration techniques, and MITRE ATT&CK framework. 
        You excel at identifying subtle anomalies in network traffic that may indicate advanced threats."""




