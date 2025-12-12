"""
Context Builder

Builds rich context for LLM analysis by aggregating historical observations,
MITRE ATT&CK knowledge, cross-agent correlation data, and temporal context.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from knowledge_fusion.interfaces import AgentOutput, Observation
from knowledge_fusion.fusion_core import KnowledgeFusion


class ContextBuilder:
    """Builds rich context for LLM threat analysis."""
    
    def __init__(self, knowledge_fusion: Optional[KnowledgeFusion] = None):
        """
        Initialize the context builder.
        
        Args:
            knowledge_fusion: Optional KnowledgeFusion instance for MITRE knowledge
        """
        self.knowledge_fusion = knowledge_fusion
        self.historical_observations: List[AgentOutput] = []
        self.max_history_size = 1000
        self.temporal_window = timedelta(hours=24)  # 24-hour window for correlation
    
    def add_observation(self, agent_output: AgentOutput):
        """Add an observation to historical context."""
        self.historical_observations.append(agent_output)
        
        # Trim old observations
        if len(self.historical_observations) > self.max_history_size:
            self.historical_observations = self.historical_observations[-self.max_history_size:]
    
    def build_context(
        self,
        current_observations: List[Observation],
        agent_id: str,
        include_mitre: bool = True,
        include_correlation: bool = True,
        include_temporal: bool = True
    ) -> Dict[str, Any]:
        """
        Build comprehensive context for LLM analysis.
        
        Args:
            current_observations: Current observations to analyze
            agent_id: ID of the agent making the observations
            include_mitre: Whether to include MITRE ATT&CK context
            include_correlation: Whether to include cross-agent correlation
            include_temporal: Whether to include temporal context
            
        Returns:
            Dictionary with comprehensive context
        """
        context = {
            "current_observations": self._format_observations(current_observations),
            "agent_id": agent_id,
            "timestamp": datetime.now().isoformat()
        }
        
        # Add temporal context
        if include_temporal:
            context["temporal"] = self._build_temporal_context(current_observations)
        
        # Add historical context
        context["historical"] = self._build_historical_context(agent_id)
        
        # Add cross-agent correlation
        if include_correlation:
            context["correlation"] = self._build_correlation_context(current_observations, agent_id)
        
        # Add MITRE ATT&CK context
        if include_mitre and self.knowledge_fusion:
            context["mitre"] = self._build_mitre_context(current_observations)
        
        return context
    
    def _format_observations(self, observations: List[Observation]) -> List[Dict[str, Any]]:
        """Format observations for LLM context."""
        return [
            {
                "type": obs.type,
                "description": obs.description,
                "indicators": obs.indicators,
                "severity": obs.severity,
                "metadata": obs.metadata
            }
            for obs in observations
        ]
    
    def _build_temporal_context(self, observations: List[Observation]) -> Dict[str, Any]:
        """Build temporal context (recent patterns, trends)."""
        now = datetime.now()
        recent_window = now - self.temporal_window
        
        # Get recent observations
        recent_obs = [
            obs for obs in self.historical_observations
            if obs.timestamp >= recent_window
        ]
        
        # Count by type
        type_counts = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for obs_output in recent_obs:
            for obs in obs_output.observations:
                type_counts[obs.type] += 1
                severity_counts[obs.severity] += 1
        
        return {
            "recent_observation_count": len(recent_obs),
            "type_distribution": dict(type_counts),
            "severity_distribution": dict(severity_counts),
            "time_window_hours": self.temporal_window.total_seconds() / 3600
        }
    
    def _build_historical_context(self, agent_id: str) -> Dict[str, Any]:
        """Build historical context for specific agent."""
        agent_obs = [
            obs for obs in self.historical_observations
            if obs.agent_id == agent_id
        ]
        
        if not agent_obs:
            return {"total_observations": 0, "recent_patterns": []}
        
        # Get recent patterns
        recent = agent_obs[-10:] if len(agent_obs) > 10 else agent_obs
        
        return {
            "total_observations": len(agent_obs),
            "recent_patterns": [
                {
                    "timestamp": obs.timestamp.isoformat(),
                    "observation_count": len(obs.observations),
                    "avg_confidence": obs.confidence
                }
                for obs in recent
            ]
        }
    
    def _build_correlation_context(
        self,
        current_observations: List[Observation],
        agent_id: str
    ) -> Dict[str, Any]:
        """Build cross-agent correlation context."""
        now = datetime.now()
        correlation_window = now - timedelta(hours=1)  # 1-hour correlation window
        
        # Get recent observations from other agents
        other_agent_obs = [
            obs for obs in self.historical_observations
            if obs.agent_id != agent_id and obs.timestamp >= correlation_window
        ]
        
        if not other_agent_obs:
            return {"correlated_agents": [], "common_indicators": []}
        
        # Find common indicators
        current_indicators = set()
        for obs in current_observations:
            current_indicators.update(obs.indicators)
        
        common_indicators = []
        correlated_agents = set()
        
        for obs_output in other_agent_obs:
            for obs in obs_output.observations:
                obs_indicators = set(obs.indicators)
                common = current_indicators.intersection(obs_indicators)
                if common:
                    common_indicators.extend(list(common))
                    correlated_agents.add(obs_output.agent_id)
        
        return {
            "correlated_agents": list(correlated_agents),
            "common_indicators": list(set(common_indicators)),
            "correlation_window_hours": 1.0
        }
    
    def _build_mitre_context(self, observations: List[Observation]) -> Dict[str, Any]:
        """Build MITRE ATT&CK context using Knowledge Fusion."""
        if not self.knowledge_fusion or not observations:
            return {"techniques": [], "tactics": []}
        
        try:
            # Create agent outputs for Knowledge Fusion
            agent_outputs = []
            for obs in observations:
                # Create a temporary AgentOutput for each observation
                from knowledge_fusion.interfaces import AgentOutput
                agent_output = AgentOutput(
                    agent_id="context_builder",
                    timestamp=datetime.now(),
                    observations=[obs],
                    confidence=obs.metadata.get('max_anomaly_score', 0.5)
                )
                agent_outputs.append(agent_output)
            
            # Run Knowledge Fusion
            enriched = self.knowledge_fusion.fuse(agent_outputs)
            
            return {
                "techniques": [
                    {
                        "id": tech.id,
                        "name": tech.name,
                        "score": tech.score,
                        "tactic": tech.tactic
                    }
                    for tech in enriched.matched_mitre_techniques[:5]
                ],
                "tactics": [
                    {
                        "name": tactic.name,
                        "score": tactic.score
                    }
                    for tactic in enriched.matched_mitre_tactics[:3]
                ],
                "confidence": enriched.confidence_scores.get('overall', 0.0)
            }
        except Exception as e:
            # Return empty context on error
            return {"techniques": [], "tactics": [], "error": str(e)}
    
    def get_recent_patterns(self, agent_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent patterns for an agent."""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = [
            obs for obs in self.historical_observations
            if obs.agent_id == agent_id and obs.timestamp >= cutoff
        ]
        
        return [
            {
                "timestamp": obs.timestamp.isoformat(),
                "observations": len(obs.observations),
                "confidence": obs.confidence
            }
            for obs in recent
        ]




