"""
Agent output normalization interface.

Handles validation, normalization, and preprocessing of agent outputs
before they are processed by the Knowledge Fusion module.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from knowledge_fusion.interfaces import AgentOutput, Observation


class AgentInterface:
    """Interface for normalizing and validating agent outputs."""
    
    # Valid agent IDs
    VALID_AGENT_IDS = {"router", "computer", "email"}
    
    # Valid severity levels
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}
    
    def __init__(self):
        """Initialize the agent interface."""
        pass
    
    def normalize_agent_output(self, data: Dict[str, Any]) -> AgentOutput:
        """
        Normalize and validate agent output data.
        
        Args:
            data: Raw agent output data (dict format)
            
        Returns:
            Validated and normalized AgentOutput object
            
        Raises:
            ValueError: If data doesn't conform to expected schema
        """
        # Validate agent_id
        agent_id = data.get("agent_id", "").lower()
        if agent_id not in self.VALID_AGENT_IDS:
            raise ValueError(f"Invalid agent_id: {agent_id}. Must be one of {self.VALID_AGENT_IDS}")
        
        # Normalize timestamp
        timestamp = self._normalize_timestamp(data.get("timestamp"))
        
        # Normalize observations
        observations = self._normalize_observations(data.get("observations", []))
        
        # Normalize confidence
        confidence = self._normalize_confidence(data.get("confidence", 0.5))
        
        # Extract metadata
        metadata = data.get("metadata", {})
        
        return AgentOutput(
            agent_id=agent_id,
            timestamp=timestamp,
            observations=observations,
            confidence=confidence,
            metadata=metadata
        )
    
    def _normalize_timestamp(self, timestamp: Any) -> datetime:
        """Normalize timestamp to datetime object."""
        if timestamp is None:
            return datetime.now()
        
        if isinstance(timestamp, datetime):
            return timestamp
        
        if isinstance(timestamp, str):
            # Try common datetime formats
            for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
            raise ValueError(f"Unable to parse timestamp string: {timestamp}")
        
        raise ValueError(f"Invalid timestamp type: {type(timestamp)}")
    
    def _normalize_observations(self, observations: Any) -> List[Observation]:
        """Normalize observations to list of Observation objects."""
        if not isinstance(observations, list):
            raise ValueError(f"Observations must be a list, got {type(observations)}")
        
        normalized = []
        for i, obs in enumerate(observations):
            if isinstance(obs, Observation):
                normalized.append(obs)
            elif isinstance(obs, dict):
                # Normalize severity
                severity = obs.get("severity", "medium").lower()
                if severity not in self.VALID_SEVERITIES:
                    severity = "medium"  # Default to medium if invalid
                
                normalized.append(Observation(
                    type=obs.get("type", "unknown"),
                    description=obs.get("description", ""),
                    indicators=obs.get("indicators", []),
                    severity=severity,
                    metadata=obs.get("metadata", {})
                ))
            else:
                raise ValueError(f"Invalid observation type at index {i}: {type(obs)}")
        
        return normalized
    
    def _normalize_confidence(self, confidence: Any) -> float:
        """Normalize confidence to float between 0.0 and 1.0."""
        if confidence is None:
            return 0.5  # Default confidence
        
        try:
            conf = float(confidence)
            # Clamp to [0.0, 1.0]
            return max(0.0, min(1.0, conf))
        except (ValueError, TypeError):
            return 0.5  # Default on error
    
    def validate_agent_output(self, agent_output: AgentOutput) -> bool:
        """
        Validate an AgentOutput object.
        
        Args:
            agent_output: AgentOutput to validate
            
        Returns:
            True if valid, raises ValueError if invalid
        """
        if agent_output.agent_id not in self.VALID_AGENT_IDS:
            raise ValueError(f"Invalid agent_id: {agent_output.agent_id}")
        
        if not (0.0 <= agent_output.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {agent_output.confidence}")
        
        if not agent_output.observations:
            raise ValueError("At least one observation is required")
        
        for obs in agent_output.observations:
            if obs.severity not in self.VALID_SEVERITIES:
                raise ValueError(f"Invalid severity: {obs.severity}")
        
        return True
    
    def aggregate_agent_outputs(self, agent_outputs: List[AgentOutput]) -> Dict[str, Any]:
        """
        Aggregate multiple agent outputs for cross-agent correlation.
        
        Args:
            agent_outputs: List of AgentOutput objects
            
        Returns:
            Aggregated data structure for fusion processing
        """
        if not agent_outputs:
            raise ValueError("Cannot aggregate empty list of agent outputs")
        
        # Group by agent
        by_agent = {}
        for output in agent_outputs:
            agent_id = output.agent_id
            if agent_id not in by_agent:
                by_agent[agent_id] = []
            by_agent[agent_id].append(output)
        
        # Extract all indicators across all agents
        all_indicators = set()
        all_observations = []
        for output in agent_outputs:
            all_observations.extend(output.observations)
            for obs in output.observations:
                all_indicators.update(obs.indicators)
        
        return {
            "agents": list(by_agent.keys()),
            "by_agent": by_agent,
            "all_indicators": list(all_indicators),
            "all_observations": all_observations,
            "timestamp_range": {
                "earliest": min(out.timestamp for out in agent_outputs),
                "latest": max(out.timestamp for out in agent_outputs)
            },
            "average_confidence": sum(out.confidence for out in agent_outputs) / len(agent_outputs)
        }
