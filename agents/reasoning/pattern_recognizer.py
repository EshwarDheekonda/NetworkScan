"""
Pattern Recognizer

LLM-based pattern recognition that identifies attack patterns across time windows,
recognizes multi-stage attack sequences, correlates patterns across agents, and
predicts next likely attack steps.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json

from knowledge_fusion.rag_pipeline import LLMProvider
from agents.reasoning.context_builder import ContextBuilder
from knowledge_fusion.interfaces import AgentOutput, Observation


class PatternRecognizer:
    """LLM-based pattern recognizer for attack sequences."""
    
    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        context_builder: Optional[ContextBuilder] = None
    ):
        """
        Initialize the pattern recognizer.
        
        Args:
            llm_provider: LLM provider instance
            context_builder: Context builder instance
        """
        self.llm_provider = llm_provider or LLMProvider()
        self.context_builder = context_builder or ContextBuilder()
        self.pattern_history: List[Dict[str, Any]] = []
        self.max_pattern_history = 100
    
    def recognize_patterns(
        self,
        observations: List[Observation],
        agent_id: str,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Recognize attack patterns in observations.
        
        Args:
            observations: Current observations
            agent_id: ID of the agent
            time_window_hours: Time window to analyze
            
        Returns:
            Dictionary with recognized patterns
        """
        # Get historical context
        cutoff = datetime.now() - timedelta(hours=time_window_hours)
        recent_obs = [
            obs for obs in self.context_builder.historical_observations
            if obs.timestamp >= cutoff
        ]
        
        # Build pattern context
        pattern_context = self._build_pattern_context(observations, recent_obs, agent_id)
        
        # Analyze with LLM
        prompt = self._build_pattern_prompt(pattern_context)
        
        system_message = """You are an expert cybersecurity analyst specializing in attack pattern recognition. Analyze security events to identify:
1. Multi-stage attack sequences
2. Attack progression patterns
3. Correlations across different security domains
4. Likely next steps in an attack chain

Use MITRE ATT&CK framework knowledge to identify attack patterns."""
        
        try:
            analysis_text = self.llm_provider.generate(prompt, system_message)
            patterns = self._parse_pattern_analysis(analysis_text)
        except Exception as e:
            patterns = self._fallback_pattern_analysis(pattern_context)
            patterns["error"] = str(e)
        
        # Store pattern
        patterns["timestamp"] = datetime.now().isoformat()
        patterns["agent_id"] = agent_id
        self.pattern_history.append(patterns)
        
        # Trim history
        if len(self.pattern_history) > self.max_pattern_history:
            self.pattern_history = self.pattern_history[-self.max_pattern_history:]
        
        return patterns
    
    def _build_pattern_context(
        self,
        current_obs: List[Observation],
        recent_obs: List[AgentOutput],
        agent_id: str
    ) -> Dict[str, Any]:
        """Build context for pattern recognition."""
        # Group observations by agent
        by_agent = defaultdict(list)
        for obs_output in recent_obs:
            by_agent[obs_output.agent_id].extend(obs_output.observations)
        
        # Add current observations
        by_agent[agent_id].extend(current_obs)
        
        # Extract indicators across agents
        all_indicators = set()
        for obs_list in by_agent.values():
            for obs in obs_list:
                all_indicators.update(obs.indicators)
        
        # Find common indicators
        indicator_agents = defaultdict(set)
        for agent, obs_list in by_agent.items():
            for obs in obs_list:
                for indicator in obs.indicators:
                    indicator_agents[indicator].add(agent)
        
        common_indicators = {
            ind: list(agents) for ind, agents in indicator_agents.items()
            if len(agents) > 1
        }
        
        # Timeline of events
        timeline = []
        for obs_output in recent_obs:
            for obs in obs_output.observations:
                timeline.append({
                    "timestamp": obs_output.timestamp.isoformat(),
                    "agent": obs_output.agent_id,
                    "type": obs.type,
                    "severity": obs.severity,
                    "indicators": obs.indicators[:3]
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return {
            "observations_by_agent": {
                agent: len(obs_list) for agent, obs_list in by_agent.items()
            },
            "common_indicators": common_indicators,
            "timeline": timeline[-20:],  # Last 20 events
            "total_indicators": len(all_indicators)
        }
    
    def _build_pattern_prompt(self, context: Dict[str, Any]) -> str:
        """Build pattern recognition prompt."""
        timeline_summary = "\n".join([
            f"{event['timestamp']}: [{event['agent']}] {event['type']} - {event['severity']}"
            for event in context.get("timeline", [])[-10:]
        ])
        
        common_indicators_summary = "\n".join([
            f"- {ind}: seen in {', '.join(agents)}"
            for ind, agents in list(context.get("common_indicators", {}).items())[:10]
        ])
        
        prompt = f"""Analyze the following security events to identify attack patterns and sequences.

OBSERVATIONS BY AGENT:
{json.dumps(context.get('observations_by_agent', {}), indent=2)}

COMMON INDICATORS (appearing across multiple agents):
{common_indicators_summary or 'None'}

RECENT TIMELINE (last 10 events):
{timeline_summary}

Identify:
1. Attack patterns and sequences
2. Multi-stage attack progression
3. Correlations across agents
4. Likely next attack steps

Provide analysis in JSON format:
{{
    "patterns_detected": ["pattern1", "pattern2", ...],
    "attack_sequence": ["stage1", "stage2", ...],
    "correlations": {{"agent1": ["related_event1", ...]}},
    "likely_next_steps": ["step1", "step2", ...],
    "mitre_tactics": ["tactic1", "tactic2", ...],
    "confidence": 0.0-1.0,
    "reasoning": "Explanation of patterns"
}}"""
        
        return prompt
    
    def _parse_pattern_analysis(self, analysis_text: str) -> Dict[str, Any]:
        """Parse pattern analysis from LLM response."""
        try:
            if "{" in analysis_text and "}" in analysis_text:
                start = analysis_text.find("{")
                end = analysis_text.rfind("}") + 1
                json_str = analysis_text[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback parsing
        return {
            "patterns_detected": [],
            "attack_sequence": [],
            "correlations": {},
            "likely_next_steps": [],
            "mitre_tactics": [],
            "confidence": 0.5,
            "reasoning": analysis_text
        }
    
    def _fallback_pattern_analysis(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback pattern analysis."""
        common_indicators = context.get("common_indicators", {})
        has_correlation = len(common_indicators) > 0
        
        patterns = []
        if has_correlation:
            patterns.append("Cross-agent indicator correlation")
        
        if len(context.get("timeline", [])) > 5:
            patterns.append("Temporal event clustering")
        
        return {
            "patterns_detected": patterns,
            "attack_sequence": [],
            "correlations": common_indicators,
            "likely_next_steps": [],
            "mitre_tactics": [],
            "confidence": 0.6 if has_correlation else 0.3,
            "reasoning": f"Detected {len(patterns)} pattern(s) based on statistical analysis"
        }
    
    def predict_next_steps(
        self,
        current_patterns: Dict[str, Any],
        agent_id: str
    ) -> List[str]:
        """
        Predict likely next attack steps based on current patterns.
        
        Args:
            current_patterns: Current pattern analysis
            agent_id: Agent ID
            
        Returns:
            List of predicted next steps
        """
        return current_patterns.get("likely_next_steps", [])
    
    def get_attack_sequence(self, pattern_analysis: Dict[str, Any]) -> List[str]:
        """Extract attack sequence from pattern analysis."""
        return pattern_analysis.get("attack_sequence", [])

