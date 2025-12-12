"""
Threat Analyzer

LLM-powered threat analysis that takes statistical anomaly scores as input
and uses LLM to determine if anomalies are actual threats, providing
contextual reasoning for detections.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import logging

from knowledge_fusion.rag_pipeline import LLMProvider
from agents.reasoning.context_builder import ContextBuilder
from knowledge_fusion.interfaces import Observation
from knowledge_fusion.proactive_rag import ProactiveRAG
from knowledge_fusion.fusion_core import KnowledgeFusion

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """LLM-powered threat analyzer."""
    
    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        context_builder: Optional[ContextBuilder] = None,
        proactive_rag: Optional[ProactiveRAG] = None,
        knowledge_fusion: Optional[KnowledgeFusion] = None
    ):
        """
        Initialize the threat analyzer.
        
        Args:
            llm_provider: LLM provider instance
            context_builder: Context builder instance
            proactive_rag: Optional ProactiveRAG instance for MITRE guidance
            knowledge_fusion: Optional KnowledgeFusion instance
        """
        self.llm_provider = llm_provider or LLMProvider()
        self.context_builder = context_builder or ContextBuilder()
        self.proactive_rag = proactive_rag or ProactiveRAG(knowledge_fusion=knowledge_fusion)
        self.knowledge_fusion = knowledge_fusion
    
    def analyze_threat(
        self,
        observations: List[Observation],
        agent_id: str,
        anomaly_scores: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Analyze if observations represent a real threat.
        
        Args:
            observations: List of observations to analyze
            anomaly_scores: Dictionary of anomaly scores for features
            agent_id: ID of the agent making the observations
            
        Returns:
            Dictionary with threat analysis results
        """
        # Step 1: Query MITRE RAG for guidance BEFORE analysis
        try:
            mitre_guidance = self.query_mitre_for_guidance(observations, agent_id)
            # Log MITRE guidance for debugging
            if mitre_guidance.get('matched_techniques'):
                logger.info(f"{agent_id} agent: MITRE guidance found {len(mitre_guidance.get('matched_techniques', []))} techniques")
            else:
                logger.warning(f"{agent_id} agent: MITRE guidance returned no techniques")
        except Exception as e:
            logger.error(f"{agent_id} agent: Error querying MITRE guidance: {e}", exc_info=True)
            mitre_guidance = {
                'matched_techniques': [],
                'matched_tactics': [],
                'guidance': f'MITRE query error: {str(e)}',
                'error': str(e)
            }
        
        # Build context (includes MITRE from context builder, but we also have proactive guidance)
        context = self.context_builder.build_context(
            observations,
            agent_id,
            include_mitre=True,
            include_correlation=True,
            include_temporal=True
        )
        
        # Merge proactive MITRE guidance into context
        context['proactive_mitre'] = mitre_guidance
        
        # Build prompt
        prompt = self._build_analysis_prompt(observations, anomaly_scores, context)
        
        # System message
        system_message = """You are an expert cybersecurity threat analyst. Your role is to analyze security observations and determine if they represent genuine threats or false positives.

Consider:
1. Statistical anomaly scores (higher = more anomalous)
2. Historical patterns and context
3. Cross-agent correlations
4. MITRE ATT&CK technique matches
5. Temporal patterns

Provide a clear assessment with reasoning."""

        # Get LLM analysis
        try:
            analysis_text = self.llm_provider.generate(prompt, system_message)
            analysis = self._parse_analysis(analysis_text)
        except Exception as e:
            # Fallback analysis
            analysis = self._fallback_analysis(observations, anomaly_scores)
            analysis["error"] = str(e)
        
        # Add metadata
        analysis["timestamp"] = datetime.now().isoformat()
        analysis["agent_id"] = agent_id
        analysis["observation_count"] = len(observations)
        analysis["max_anomaly_score"] = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Include proactive MITRE guidance in the analysis
        analysis["proactive_mitre"] = mitre_guidance
        
        return analysis
    
    def _build_analysis_prompt(
        self,
        observations: List[Observation],
        anomaly_scores: Dict[str, float],
        context: Dict[str, Any]
    ) -> str:
        """Build the analysis prompt for LLM."""
        obs_summary = "\n".join([
            f"- {obs.type}: {obs.description} (Severity: {obs.severity}, Indicators: {', '.join(obs.indicators[:3])})"
            for obs in observations
        ])
        
        anomaly_summary = "\n".join([
            f"- {feature}: {score:.2f}"
            for feature, score in sorted(anomaly_scores.items(), key=lambda x: x[1], reverse=True)[:5]
        ])
        
        prompt = f"""Analyze the following security observations and determine if they represent a genuine threat.

OBSERVATIONS:
{obs_summary}

ANOMALY SCORES (0.0 = normal, 1.0 = highly anomalous):
{anomaly_summary}

CONTEXT:
- Recent patterns: {context.get('temporal', {}).get('recent_observation_count', 0)} observations in last 24h
- Correlated agents: {', '.join(context.get('correlation', {}).get('correlated_agents', [])) or 'None'}
- Common indicators: {', '.join(context.get('correlation', {}).get('common_indicators', [])[:5]) or 'None'}
- MITRE techniques: {len(context.get('mitre', {}).get('techniques', []))} matched
- Proactive MITRE guidance: {context.get('proactive_mitre', {}).get('guidance', 'No guidance available')}
- Matched MITRE techniques: {', '.join([t.get('name', 'Unknown') for t in context.get('proactive_mitre', {}).get('matched_techniques', [])[:3]]) or 'None'}

Provide your analysis in the following JSON format:
{{
    "is_threat": true/false,
    "threat_level": "low"/"medium"/"high"/"critical",
    "confidence": 0.0-1.0,
    "reasoning": "Detailed explanation of why this is or isn't a threat",
    "attack_scenario": "Description of potential attack scenario if threat",
    "recommended_actions": ["action1", "action2", ...]
}}"""
        
        return prompt
    
    def _parse_analysis(self, analysis_text: str) -> Dict[str, Any]:
        """Parse LLM analysis response."""
        try:
            # Try to extract JSON from response
            if "{" in analysis_text and "}" in analysis_text:
                start = analysis_text.find("{")
                end = analysis_text.rfind("}") + 1
                json_str = analysis_text[start:end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        
        # Fallback: parse text response
        analysis = {
            "is_threat": "threat" in analysis_text.lower() or "attack" in analysis_text.lower(),
            "threat_level": "medium",
            "confidence": 0.5,
            "reasoning": analysis_text,
            "attack_scenario": "",
            "recommended_actions": []
        }
        
        # Try to extract threat level
        text_lower = analysis_text.lower()
        if "critical" in text_lower or "severe" in text_lower:
            analysis["threat_level"] = "critical"
        elif "high" in text_lower:
            analysis["threat_level"] = "high"
        elif "low" in text_lower:
            analysis["threat_level"] = "low"
        
        return analysis
    
    def _fallback_analysis(
        self,
        observations: List[Observation],
        anomaly_scores: Dict[str, float]
    ) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable."""
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        max_severity = max((obs.severity for obs in observations), default="low")
        
        is_threat = max_score > 0.6 or max_severity in ["high", "critical"]
        
        threat_level = "low"
        if max_score > 0.8 or max_severity == "critical":
            threat_level = "critical"
        elif max_score > 0.6 or max_severity == "high":
            threat_level = "high"
        elif max_score > 0.4:
            threat_level = "medium"
        
        return {
            "is_threat": is_threat,
            "threat_level": threat_level,
            "confidence": max_score,
            "reasoning": f"Statistical analysis: anomaly score {max_score:.2f}, max severity {max_severity}",
            "attack_scenario": "Unable to generate scenario (LLM unavailable)",
            "recommended_actions": ["Review observations manually", "Check correlated events"]
        }
    
    def generate_threat_narrative(
        self,
        observations: List[Observation],
        threat_analysis: Dict[str, Any]
    ) -> str:
        """
        Generate a human-readable threat narrative.
        
        Args:
            observations: List of observations
            threat_analysis: Results from analyze_threat
            
        Returns:
            Human-readable narrative
        """
        if not threat_analysis.get("is_threat", False):
            return f"No significant threat detected. {threat_analysis.get('reasoning', '')}"
        
        narrative = f"""THREAT DETECTED - {threat_analysis.get('threat_level', 'unknown').upper()}

{threat_analysis.get('reasoning', 'No reasoning provided')}

ATTACK SCENARIO:
{threat_analysis.get('attack_scenario', 'No scenario provided')}

OBSERVATIONS:
"""
        for obs in observations:
            narrative += f"- {obs.type}: {obs.description}\n"
            if obs.indicators:
                narrative += f"  Indicators: {', '.join(obs.indicators[:5])}\n"
        
        if threat_analysis.get("recommended_actions"):
            narrative += "\nRECOMMENDED ACTIONS:\n"
            for action in threat_analysis["recommended_actions"]:
                narrative += f"- {action}\n"
        
        return narrative
    
    def query_mitre_for_guidance(
        self,
        observations: List[Observation],
        agent_id: str
    ) -> Dict[str, Any]:
        """
        Query MITRE RAG to get guidance on what techniques match current observations.
        This helps guide threat assessment.
        
        Args:
            observations: Current observations
            agent_id: ID of the agent
            
        Returns:
            Dictionary with MITRE guidance
        """
        if not observations:
            return {
                'matched_techniques': [],
                'matched_tactics': [],
                'guidance': 'No observations to match'
            }
        
        # Extract all indicators from observations
        all_indicators = []
        for obs in observations:
            all_indicators.extend(obs.indicators)
        
        # Query ProactiveRAG for guidance
        try:
            guidance = self.proactive_rag.query_mitre_for_guidance(
                observations=observations,
                indicators=list(set(all_indicators)),
                limit=5
            )
            return guidance
        except Exception as e:
            # Fallback if ProactiveRAG fails
            return {
                'matched_techniques': [],
                'matched_tactics': [],
                'guidance': f'MITRE query failed: {str(e)}',
                'error': str(e)
            }



