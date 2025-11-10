"""
LLM prompt templates for threat intelligence synthesis.

Contains prompt templates for generating contextual threat analysis
from agent observations and MITRE ATT&CK knowledge.
"""

from typing import List, Dict, Any
from knowledge_fusion.interfaces import (
    AgentOutput, MITRETechnique, MITRETactic, Mitigation
)


class PromptTemplates:
    """Collection of prompt templates for threat intelligence generation."""
    
    @staticmethod
    def threat_analysis_prompt(
        agent_outputs: List[AgentOutput],
        matched_techniques: List[MITRETechnique],
        matched_tactics: List[MITRETactic],
        related_techniques: List[MITRETechnique],
        mitigations: List[Mitigation],
        confidence_scores: Dict[str, float]
    ) -> str:
        """
        Generate threat analysis prompt from enriched threat intelligence.
        
        Args:
            agent_outputs: Original agent outputs
            matched_techniques: Matched MITRE techniques
            matched_tactics: Matched MITRE tactics
            related_techniques: Related techniques
            mitigations: Recommended mitigations
            confidence_scores: Confidence scores
            
        Returns:
            Formatted prompt string
        """
        # Build observations section
        observations_text = ""
        for i, output in enumerate(agent_outputs, 1):
            observations_text += f"\nAgent {i}: {output.agent_id.upper()}\n"
            observations_text += f"  Timestamp: {output.timestamp}\n"
            observations_text += f"  Confidence: {output.confidence:.2f}\n"
            for j, obs in enumerate(output.observations, 1):
                observations_text += f"  Observation {j}:\n"
                observations_text += f"    Type: {obs.type}\n"
                observations_text += f"    Description: {obs.description}\n"
                observations_text += f"    Severity: {obs.severity}\n"
                if obs.indicators:
                    observations_text += f"    Indicators: {', '.join(obs.indicators[:5])}\n"
        
        # Build techniques section
        techniques_text = ""
        for i, tech in enumerate(matched_techniques[:10], 1):
            techniques_text += f"\n{i}. {tech.name}"
            if tech.external_id:
                techniques_text += f" ({tech.external_id})"
            techniques_text += f"\n   Tactic: {tech.tactic or 'N/A'}\n"
            techniques_text += f"   Relevance Score: {tech.score:.2f}\n"
            if tech.description:
                desc = tech.description[:200] + "..." if len(tech.description) > 200 else tech.description
                techniques_text += f"   Description: {desc}\n"
        
        # Build tactics section
        tactics_text = ""
        for i, tactic in enumerate(matched_tactics[:5], 1):
            tactics_text += f"\n{i}. {tactic.name} (Relevance: {tactic.score:.2f})"
        
        # Build mitigations section
        mitigations_text = ""
        for i, mitigation in enumerate(mitigations[:5], 1):
            mitigations_text += f"\n{i}. {mitigation.name}"
            if mitigation.description:
                desc = mitigation.description[:150] + "..." if len(mitigation.description) > 150 else mitigation.description
                mitigations_text += f": {desc}\n"
        
        # Build confidence summary
        confidence_text = f"""
Confidence Scores:
  - Technique Matching: {confidence_scores.get('technique_matching', 0):.2f}
  - Tactic Matching: {confidence_scores.get('tactic_matching', 0):.2f}
  - Agent Confidence: {confidence_scores.get('agent_confidence', 0):.2f}
  - Overall: {confidence_scores.get('overall', 0):.2f}
"""
        
        prompt = f"""You are a cybersecurity threat intelligence analyst. Analyze the following security observations and provide a comprehensive threat assessment based on MITRE ATT&CK framework.

## SECURITY OBSERVATIONS
{observations_text}

## MATCHED MITRE ATT&CK TECHNIQUES
{techniques_text}

## MATCHED MITRE ATT&CK TACTICS
{tactics_text}

## RECOMMENDED MITIGATIONS
{mitigations_text}

{confidence_text}

## YOUR TASK

Provide a comprehensive threat analysis that includes:

1. **Threat Summary**: A concise 2-3 sentence summary of what was observed and the primary threat.

2. **Attack Context**: Explain how the matched MITRE techniques relate to each other and describe the potential attack chain or sequence. Reference specific techniques by name or ID.

3. **Tactical Analysis**: Explain which MITRE ATT&CK tactics are involved and how they connect in the attack lifecycle.

4. **Risk Assessment**: Assess the severity and potential impact based on:
   - The confidence scores provided
   - The number of agents detecting suspicious activity
   - The type of techniques involved

5. **Recommendations**: Provide actionable recommendations referencing the suggested mitigations, prioritized by:
   - Immediate actions needed
   - Short-term defensive measures
   - Long-term hardening strategies

6. **Attribution Insights**: If applicable, note any patterns or characteristics that might indicate:
   - Attack sophistication level
   - Potential threat actor characteristics
   - Similarity to known attack patterns

## OUTPUT FORMAT

Structure your response in clear sections using the headings above. Be specific, technical, and actionable. Reference MITRE technique IDs when relevant. Keep the analysis professional and suitable for security operations teams.

Begin your analysis:"""
        
        return prompt
    
    @staticmethod
    def concise_threat_summary_prompt(
        matched_techniques: List[MITRETechnique],
        matched_tactics: List[MITRETactic]
    ) -> str:
        """
        Generate a concise threat summary prompt.
        
        Args:
            matched_techniques: Matched MITRE techniques
            matched_tactics: Matched MITRE tactics
            
        Returns:
            Formatted prompt string
        """
        techniques_list = "\n".join([
            f"- {tech.name} ({tech.external_id or 'N/A'}) - {tech.tactic or 'N/A'}"
            for tech in matched_techniques[:5]
        ])
        
        tactics_list = "\n".join([
            f"- {tactic.name}"
            for tactic in matched_tactics[:3]
        ])
        
        prompt = f"""Generate a concise 2-3 sentence threat summary based on these MITRE ATT&CK findings:

Techniques Detected:
{techniques_list}

Primary Tactics:
{tactics_list}

Provide a brief, actionable summary suitable for security alerts."""
        
        return prompt
    
    @staticmethod
    def explainability_prompt(
        technique: MITRETechnique,
        observation: Any,
        score: float
    ) -> str:
        """
        Generate explainability prompt for why a technique was matched.
        
        Args:
            technique: Matched MITRE technique
            observation: Agent observation
            score: Relevance score
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""Explain why the MITRE ATT&CK technique "{technique.name}" ({technique.external_id or 'N/A'}) was matched to this observation:

Observation: {observation.description}
Type: {observation.type}
Severity: {observation.severity}
Indicators: {', '.join(observation.indicators[:3]) if observation.indicators else 'None'}

Technique Description: {technique.description[:300]}

Relevance Score: {score:.2f}

Provide a brief explanation (2-3 sentences) of why this technique is relevant to the observation, focusing on specific indicators or behaviors that match."""
        
        return prompt
