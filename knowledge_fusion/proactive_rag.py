"""
Proactive RAG

Proactive knowledge retrieval that pre-fetches relevant MITRE techniques
based on patterns and provides early warning intelligence.
"""

from typing import Dict, Any, Optional, List
from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.retrieval_engine import HybridRetriever
from knowledge_fusion.interfaces import Observation


class ProactiveRAG:
    """Proactive RAG for early warning intelligence."""
    
    def __init__(self, knowledge_fusion: Optional[KnowledgeFusion] = None):
        """Initialize proactive RAG."""
        self.knowledge_fusion = knowledge_fusion or KnowledgeFusion()
        self.retriever = HybridRetriever()
    
    def predict_related_techniques(
        self,
        current_techniques: List[str],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Predict related techniques that might be used next.
        
        Args:
            current_techniques: List of current technique IDs
            limit: Maximum number of predictions
            
        Returns:
            List of predicted techniques
        """
        # Use graph relationships to find related techniques
        related = []
        for tech_id in current_techniques:
            related_techs = self.retriever.retrieve_related_techniques(tech_id, depth=2, top_k=limit)
            related.extend([r.technique for r in related_techs])
        
        # Deduplicate and return top predictions
        seen = set()
        unique = []
        for tech in related:
            if tech.id not in seen:
                seen.add(tech.id)
                unique.append({
                    'id': tech.id,
                    'name': tech.name,
                    'score': tech.score
                })
        
        return unique[:limit]
    
    def query_mitre_for_guidance(
        self,
        observations: List[Observation],
        indicators: List[str],
        limit: int = 5
    ) -> Dict[str, Any]:
        """
        Query MITRE RAG to get guidance on what techniques match current indicators.
        This helps agents understand what they should look for.
        
        Args:
            observations: Current observations
            indicators: List of indicators to match against
            limit: Maximum number of techniques to return
            
        Returns:
            Dictionary with matched techniques, tactics, and guidance
        """
        if not observations and not indicators:
            return {
                'matched_techniques': [],
                'matched_tactics': [],
                'guidance': 'No indicators provided for matching'
            }
        
        # Create temporary observations if only indicators provided
        if not observations and indicators:
            from knowledge_fusion.interfaces import Observation
            temp_obs = Observation(
                type="proactive_query",
                description=f"Querying MITRE for indicators: {', '.join(indicators[:5])}",
                indicators=indicators,
                severity="medium"
            )
            observations = [temp_obs]
        
        # Match techniques using hybrid retriever
        matched_techniques = []
        matched_tactics = []
        
        for obs in observations:
            # Match techniques to observation
            techniques = self.retriever.match_techniques_to_observation(obs, top_k=limit)
            matched_techniques.extend(techniques)
            
            # Match tactics
            tactics = self.retriever.match_tactics_to_observation(obs)
            matched_tactics.extend(tactics)
        
        # Deduplicate techniques
        seen_tech_ids = set()
        unique_techniques = []
        for tech in matched_techniques:
            if tech.id not in seen_tech_ids:
                seen_tech_ids.add(tech.id)
                unique_techniques.append({
                    'id': tech.id,
                    'external_id': tech.external_id,
                    'name': tech.name,
                    'description': tech.description,
                    'tactic': tech.tactic,
                    'score': tech.score
                })
        
        # Deduplicate tactics
        seen_tactic_names = set()
        unique_tactics = []
        for tactic in matched_tactics:
            if tactic.name not in seen_tactic_names:
                seen_tactic_names.add(tactic.name)
                unique_tactics.append({
                    'name': tactic.name,
                    'description': tactic.description,
                    'score': tactic.score
                })
        
        # Generate guidance
        guidance = self._generate_guidance(unique_techniques, unique_tactics, indicators)
        
        return {
            'matched_techniques': unique_techniques[:limit],
            'matched_tactics': unique_tactics[:3],
            'guidance': guidance,
            'indicator_count': len(indicators)
        }
    
    def _generate_guidance(
        self,
        techniques: List[Dict[str, Any]],
        tactics: List[Dict[str, Any]],
        indicators: List[str]
    ) -> str:
        """Generate guidance text based on matched techniques."""
        if not techniques:
            return "No MITRE techniques matched. Continue monitoring for anomalies."
        
        tech_names = [t['name'] for t in techniques[:3]]
        tactic_names = [t['name'] for t in tactics[:2]]
        
        guidance = f"Matched {len(techniques)} MITRE technique(s): {', '.join(tech_names)}"
        if tactic_names:
            guidance += f". Associated tactics: {', '.join(tactic_names)}"
        
        guidance += ". Monitor for related indicators and potential next steps in the attack chain."
        
        return guidance
    
    def predict_next_attack_steps(
        self,
        observations: List[Observation],
        current_techniques: Optional[List[str]] = None,
        limit: int = 5
    ) -> Dict[str, Any]:
        """
        Predict likely next attack steps based on current observations.
        
        Args:
            observations: Current observations
            current_techniques: Optional list of current technique IDs
            limit: Maximum number of predictions
            
        Returns:
            Dictionary with predicted next steps and related techniques
        """
        # Extract technique IDs from observations if not provided
        if current_techniques is None:
            # Try to extract from observation metadata
            current_techniques = []
            for obs in observations:
                if 'mitre_techniques' in obs.metadata:
                    techs = obs.metadata['mitre_techniques']
                    if isinstance(techs, list):
                        for tech in techs:
                            if isinstance(tech, dict):
                                tech_id = tech.get('id') or tech.get('external_id')
                            else:
                                tech_id = str(tech)
                            if tech_id:
                                current_techniques.append(tech_id)
        
        # If we have techniques, predict related ones
        predicted_techniques = []
        if current_techniques:
            predicted_techniques = self.predict_related_techniques(current_techniques, limit=limit)
        
        # Extract indicators from observations
        all_indicators = []
        for obs in observations:
            all_indicators.extend(obs.indicators)
        
        # Generate prediction summary
        prediction_summary = f"Based on {len(observations)} observation(s) and {len(current_techniques)} technique(s), "
        if predicted_techniques:
            tech_names = [t['name'] for t in predicted_techniques[:3]]
            prediction_summary += f"likely next steps may involve: {', '.join(tech_names)}"
        else:
            prediction_summary += "continue monitoring for attack progression indicators."
        
        return {
            'predicted_techniques': predicted_techniques,
            'indicators_to_watch': list(set(all_indicators))[:10],
            'prediction_summary': prediction_summary,
            'confidence': min(0.8, len(predicted_techniques) * 0.15) if predicted_techniques else 0.3
        }



