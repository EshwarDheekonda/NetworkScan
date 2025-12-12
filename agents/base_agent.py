"""
Base Agent Class

Provides common functionality for all proactive security agents including
baseline learning, observation generation, and message bus integration.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

from agents.baseline_learner import BaselineLearner
from knowledge_fusion.interfaces import AgentOutput, Observation


class BaseAgent(ABC):
    """Base class for all proactive security agents."""
    
    def __init__(self, agent_id: str, config: Optional[Dict[str, Any]] = None, baseline_learner: Optional[BaselineLearner] = None):
        """
        Initialize base agent.
        
        Args:
            agent_id: Unique identifier for the agent (router, computer, email)
            config: Configuration dictionary
            baseline_learner: Optional pre-trained BaselineLearner instance (from training system)
        """
        self.agent_id = agent_id
        self.config = config or {}
        
        # Use provided baseline learner or create new one
        if baseline_learner is not None:
            self.baseline_learner = baseline_learner
        else:
            self.baseline_learner = BaselineLearner(self.config.get('baseline', {}))
        
        self.logger = logging.getLogger(f"{__name__}.{agent_id}")
        self.is_running = False
        self.observation_count = 0
        self.anomaly_count = 0
        
        # Message bus publisher (will be set by communication layer)
        self.publisher = None
        
        # Feedback subscriber (will be set by communication layer)
        self.feedback_subscriber = None
        
        # Training mode tracking
        self.training_mode = "hybrid"  # 'training', 'inference', 'hybrid'
        
        # Initialize agent-specific baselines (only if not using pre-trained learner)
        if baseline_learner is None:
            self._initialize_baselines()
    
    @abstractmethod
    def _initialize_baselines(self):
        """Initialize agent-specific baseline models. Override in subclasses."""
        pass
    
    @abstractmethod
    def process_data(self, data: Any) -> List[Observation]:
        """
        Process incoming data and generate observations.
        
        Args:
            data: Raw data from data source (network traffic, logs, emails, etc.)
            
        Returns:
            List of observations (may be empty if nothing detected)
        """
        pass
    
    @abstractmethod
    def _extract_features(self, data: Any) -> Dict[str, Any]:
        """
        Extract features from data for baseline learning.
        
        Args:
            data: Raw data
            
        Returns:
            Dictionary of feature names to values
        """
        pass
    
    def update_baseline(self, data: Any):
        """
        Update baseline models with new data.
        
        Args:
            data: Raw data to learn from
        """
        # Skip learning if in inference mode
        if self.training_mode == "inference":
            return
        
        features = self._extract_features(data)
        
        for feature_name, feature_value in features.items():
            if isinstance(feature_value, (int, float)):
                # Numeric feature
                self.baseline_learner.update_numeric(
                    f"{self.agent_id}.{feature_name}",
                    float(feature_value),
                    datetime.now()
                )
            elif isinstance(feature_value, str):
                # Pattern feature
                self.baseline_learner.update_pattern(
                    f"{self.agent_id}.{feature_name}",
                    feature_value
                )
    
    def set_training_mode(self, mode: str):
        """
        Set training mode for the agent.
        
        Args:
            mode: Training mode ('training', 'inference', 'hybrid')
        """
        if mode in ['training', 'inference', 'hybrid']:
            self.training_mode = mode
            self.logger.info(f"Agent {self.agent_id} switched to {mode} mode")
        else:
            self.logger.warning(f"Invalid training mode: {mode}")
    
    def set_baseline_learner(self, baseline_learner: BaselineLearner):
        """
        Set baseline learner instance (for integration with training system).
        
        Args:
            baseline_learner: BaselineLearner instance
        """
        self.baseline_learner = baseline_learner
        self.logger.info(f"Baseline learner updated for agent {self.agent_id}")
    
    def check_anomaly(self, data: Any, threshold: float = 2.0) -> bool:
        """
        Check if data contains anomalies.
        
        Args:
            data: Data to check
            threshold: Anomaly detection threshold
            
        Returns:
            True if anomalies detected
        """
        features = self._extract_features(data)
        
        for feature_name, feature_value in features.items():
            baseline_name = f"{self.agent_id}.{feature_name}"
            if self.baseline_learner.check_anomaly(baseline_name, feature_value, threshold):
                return True
        
        return False
    
    def get_anomaly_scores(self, data: Any) -> Dict[str, float]:
        """
        Get anomaly scores for all features in data.
        
        Args:
            data: Data to score
            
        Returns:
            Dictionary mapping feature names to anomaly scores (0.0 to 1.0)
        """
        features = self._extract_features(data)
        scores = {}
        
        for feature_name, feature_value in features.items():
            baseline_name = f"{self.agent_id}.{feature_name}"
            score = self.baseline_learner.get_anomaly_score(baseline_name, feature_value)
            scores[feature_name] = score
        
        return scores
    
    def generate_observation(self, data: Any, description: str, 
                           indicators: List[str], severity: str = "medium",
                           metadata: Optional[Dict[str, Any]] = None) -> Observation:
        """
        Generate an observation from detected anomaly.
        
        Args:
            data: Source data
            description: Human-readable description
            indicators: List of indicators (IPs, domains, hashes, etc.)
            severity: Severity level (low, medium, high, critical)
            metadata: Additional metadata
            
        Returns:
            Observation object
        """
        # Use anomaly scores from metadata if provided, otherwise calculate
        if metadata and 'anomaly_scores' in metadata:
            anomaly_scores = metadata.get('anomaly_scores', {})
            max_score = metadata.get('max_anomaly_score', max(anomaly_scores.values()) if anomaly_scores else 0.0)
        else:
            anomaly_scores = self.get_anomaly_scores(data)
            max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Adjust severity based on anomaly score (but don't override if already set)
        if severity == "medium":  # Only adjust if default
            if max_score > 0.8:
                severity = "critical"
            elif max_score > 0.6:
                severity = "high"
            elif max_score > 0.4:
                severity = "medium"
            else:
                severity = "low"
        
        obs_metadata = {
            'anomaly_scores': anomaly_scores,
            'max_anomaly_score': max_score,
            'agent_id': self.agent_id,
            **(metadata or {})
        }
        
        # Ensure max_anomaly_score is set (metadata might override)
        obs_metadata['max_anomaly_score'] = max_score
        
        observation = Observation(
            type=self.agent_id,
            description=description,
            indicators=indicators,
            severity=severity,
            metadata=obs_metadata
        )
        
        return observation
    
    def process_and_publish(self, data: Any) -> Optional[AgentOutput]:
        """
        Process data, generate observations, and publish to message bus.
        
        Args:
            data: Raw data to process
            
        Returns:
            AgentOutput if observations generated, None otherwise
        """
        # Update baseline (learning phase)
        self.update_baseline(data)
        
        # Check for anomalies and generate observations
        observations = self.process_data(data)
        
        if not observations:
            return None
        
        # Calculate overall confidence
        confidence = self._calculate_confidence(observations)
        
        # Create agent output
        agent_output = AgentOutput(
            agent_id=self.agent_id,
            timestamp=datetime.now(),
            observations=observations,
            confidence=confidence,
            metadata={
                'observation_count': len(observations),
                'agent_version': self.config.get('version', '1.0')
            }
        )
        
        # Publish to message bus if available
        if self.publisher:
            try:
                self.publisher.publish(agent_output)
                self.logger.debug(f"Published {len(observations)} observations to message bus")
            except Exception as e:
                self.logger.error(f"Failed to publish observations: {e}")
        
        self.observation_count += len(observations)
        self.anomaly_count += len(observations)
        
        return agent_output
    
    def _calculate_confidence(self, observations: List[Observation]) -> float:
        """
        Calculate overall confidence score for observations.
        
        Args:
            observations: List of observations
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if not observations:
            return 0.0
        
        # Average of max anomaly scores from each observation
        scores = []
        for obs in observations:
            max_score = obs.metadata.get('max_anomaly_score', 0.5)
            scores.append(max_score)
        
        avg_score = sum(scores) / len(scores) if scores else 0.5
        
        # Adjust based on baseline readiness
        baseline_ready = self._is_baseline_ready()
        if not baseline_ready:
            # Reduce confidence if baseline not ready
            avg_score *= 0.7
        
        return min(1.0, avg_score)
    
    def _is_baseline_ready(self) -> bool:
        """Check if baseline models are ready (have enough samples)."""
        stats = self.baseline_learner.get_all_stats()
        numeric_baselines = stats.get('numeric_baselines', {})
        pattern_baselines = stats.get('pattern_baselines', {})
        
        # Check numeric baselines
        if numeric_baselines:
            for baseline_stats in numeric_baselines.values():
                if baseline_stats.get('is_ready', False):
                    return True
        
        # Check pattern baselines
        if pattern_baselines:
            for baseline_stats in pattern_baselines.values():
                if baseline_stats.get('is_ready', False):
                    return True
        
        return False
    
    def set_publisher(self, publisher):
        """Set message bus publisher."""
        self.publisher = publisher
    
    def set_feedback_subscriber(self, subscriber):
        """Set feedback subscriber for adaptive learning."""
        self.feedback_subscriber = subscriber
    
    def handle_feedback(self, feedback: Dict[str, Any]):
        """
        Handle feedback from Knowledge Fusion for adaptive learning.
        
        Args:
            feedback: Feedback data containing insights and recommendations
        """
        feedback_type = feedback.get('type', 'unknown')
        feedback_data = feedback.get('data', {})
        
        self.logger.info(f"Received feedback: {feedback_type}")
        
        # Adjust baseline thresholds based on confidence
        overall_confidence = feedback_data.get('overall_confidence', 0.5)
        technique_confidence = feedback_data.get('technique_matching_confidence', 0.5)
        
        # If confidence is high, we can be more sensitive
        # If confidence is low, we should be less sensitive (reduce false positives)
        if overall_confidence > 0.8:
            # High confidence - detection is working well
            # Could slightly increase sensitivity
            self.config['anomaly_threshold'] = self.config.get('anomaly_threshold', 0.5) * 0.95
        elif overall_confidence < 0.5:
            # Low confidence - may have false positives
            # Increase threshold to reduce false positives
            self.config['anomaly_threshold'] = self.config.get('anomaly_threshold', 0.5) * 1.1
            self.config['anomaly_threshold'] = min(0.9, self.config['anomaly_threshold'])
        
        # Learn from matched techniques
        matched_techniques = feedback_data.get('matched_techniques', [])
        if matched_techniques:
            # Update baseline learning based on successful detections
            # This helps the agent learn what patterns lead to valid detections
            for tech in matched_techniques:
                tech_name = tech.get('name', '')
                if tech_name:
                    # Could update pattern baselines here
                    pass
        
        # Process recommendations
        recommendations = feedback_data.get('recommendations', [])
        for rec in recommendations:
            self.logger.debug(f"Recommendation: {rec}")
        
        # Track feedback for statistics
        if not hasattr(self, 'feedback_count'):
            self.feedback_count = 0
        self.feedback_count += 1
    
    def start(self):
        """Start the agent."""
        self.is_running = True
        self.logger.info(f"Agent {self.agent_id} started")
    
    def stop(self):
        """Stop the agent."""
        self.is_running = False
        self.logger.info(f"Agent {self.agent_id} stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics."""
        return {
            'agent_id': self.agent_id,
            'is_running': self.is_running,
            'observation_count': self.observation_count,
            'anomaly_count': self.anomaly_count,
            'baseline_ready': self._is_baseline_ready(),
            'baseline_stats': self.baseline_learner.get_all_stats()
        }

