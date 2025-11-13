"""
Knowledge fusion logic for combining agent observations with MITRE knowledge.

Implements the core fusion logic that:
- Assembles context from retrieved MITRE knowledge
- Maps agent observations to MITRE techniques/tactics
- Enriches threats with related techniques and mitigations
- Correlates patterns across multiple agents
- Scores temporal and contextual relevance
"""

from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

from knowledge_fusion.interfaces import (
    AgentOutput, Observation, MITRETechnique, MITRETactic, 
    Mitigation, EnrichedThreatIntelligence
)
from knowledge_fusion.retrieval_engine import HybridRetriever, GraphRetriever
from knowledge_fusion.utils.graph_queries import GraphQueries
from py2neo import Graph
from knowledge_fusion.config import get_config


class ContextAssembler:
    """Assembles context from retrieved MITRE knowledge."""
    
    def __init__(self, graph_retriever: Optional[GraphRetriever] = None):
        """
        Initialize the context assembler.
        
        Args:
            graph_retriever: GraphRetriever instance. If None, creates a new one.
        """
        if graph_retriever is None:
            self.graph_retriever = GraphRetriever()
        else:
            self.graph_retriever = graph_retriever
        
        self.queries = GraphQueries()
    
    def assemble_technique_context(self, technique: MITRETechnique) -> Dict[str, Any]:
        """
        Assemble full context for a MITRE technique.
        
        Args:
            technique: MITRETechnique object
            
        Returns:
            Dictionary with assembled context
        """
        context = {
            "technique": {
                "id": technique.id,
                "external_id": technique.external_id,
                "name": technique.name,
                "description": technique.description,
                "tactic": technique.tactic,
                "score": technique.score
            },
            "related_techniques": [],
            "mitigations": [],
            "related_context": {}
        }
        
        # Get related techniques via graph
        if technique.id:
            related = self.graph_retriever.retrieve_related_techniques(technique.id, depth=2, top_k=5)
            context["related_techniques"] = [r.technique for r in related]
        
        # Get mitigations
        if technique.id:
            mitigations = self._get_mitigations_for_technique(technique.id)
            context["mitigations"] = mitigations
        
        return context
    
    def assemble_observation_context(self, observation: Observation, matched_techniques: List[MITRETechnique]) -> Dict[str, Any]:
        """
        Assemble context from an observation and its matched techniques.
        
        Args:
            observation: Agent observation
            matched_techniques: List of matched MITRE techniques
            
        Returns:
            Dictionary with assembled context
        """
        context = {
            "observation": {
                "type": observation.type,
                "description": observation.description,
                "indicators": observation.indicators,
                "severity": observation.severity
            },
            "matched_techniques": matched_techniques,
            "tactics": [],
            "all_related_techniques": [],
            "all_mitigations": []
        }
        
        # Collect tactics from techniques
        tactics_dict = {}
        for technique in matched_techniques:
            if technique.tactic:
                if technique.tactic not in tactics_dict:
                    tactics_dict[technique.tactic] = []
                tactics_dict[technique.tactic].append(technique.score)
        
        # Create tactic list with average scores
        for tactic_name, scores in tactics_dict.items():
            avg_score = sum(scores) / len(scores) if scores else 0.0
            tactic = MITRETactic(name=tactic_name, description=None, score=avg_score)
            context["tactics"].append(tactic)
        
        # Collect all related techniques
        all_related = []
        for technique in matched_techniques:
            if technique.id:
                related = self.graph_retriever.retrieve_related_techniques(technique.id, depth=2, top_k=3)
                all_related.extend([r.technique for r in related])
        
        # Deduplicate related techniques
        seen_ids = set()
        unique_related = []
        for tech in all_related:
            if tech.id not in seen_ids:
                seen_ids.add(tech.id)
                unique_related.append(tech)
        context["all_related_techniques"] = unique_related[:10]  # Limit to top 10
        
        # Collect all mitigations
        all_mitigations = []
        for technique in matched_techniques:
            if technique.id:
                mitigations = self._get_mitigations_for_technique(technique.id)
                all_mitigations.extend(mitigations)
        
        # Deduplicate mitigations
        seen_mitigation_ids = set()
        unique_mitigations = []
        for mitigation in all_mitigations:
            if mitigation.id not in seen_mitigation_ids:
                seen_mitigation_ids.add(mitigation.id)
                unique_mitigations.append(mitigation)
        context["all_mitigations"] = unique_mitigations
        
        return context
    
    def _get_mitigations_for_technique(self, technique_id: str) -> List[Mitigation]:
        """Get mitigations for a technique."""
        query = self.queries.get_mitigations_for_technique(technique_id)
        config = get_config()
        graph = Graph(config.neo4j.uri, auth=(config.neo4j.username, config.neo4j.password))
        results = graph.run(query).data()
        
        mitigations = []
        for record in results:
            mitigation = Mitigation(
                id=record.get("id", ""),
                name=record.get("name", ""),
                description=record.get("description", ""),
                techniques=[technique_id]
            )
            mitigations.append(mitigation)
        
        return mitigations


class ObservationMapper:
    """Maps agent observations to MITRE techniques and tactics."""
    
    def __init__(self, hybrid_retriever: Optional[HybridRetriever] = None):
        """
        Initialize the observation mapper.
        
        Args:
            hybrid_retriever: HybridRetriever instance. If None, creates a new one.
        """
        if hybrid_retriever is None:
            self.hybrid_retriever = HybridRetriever()
        else:
            self.hybrid_retriever = hybrid_retriever
    
    def map_observation_to_mitre(self, observation: Observation, top_k: int = 5) -> Dict[str, Any]:
        """
        Map an observation to MITRE techniques and tactics.
        
        Args:
            observation: Agent observation
            top_k: Number of top techniques to return
            
        Returns:
            Dictionary with matched techniques and tactics
        """
        # Match techniques
        matched_techniques = self.hybrid_retriever.match_techniques_to_observation(observation, top_k=top_k)
        
        # Match tactics
        matched_tactics = self.hybrid_retriever.match_tactics_to_observation(observation)
        
        return {
            "techniques": matched_techniques,
            "tactics": matched_tactics,
            "mapping_confidence": self._calculate_mapping_confidence(matched_techniques, observation)
        }
    
    def _calculate_mapping_confidence(self, techniques: List[MITRETechnique], observation: Observation) -> float:
        """Calculate confidence in the mapping."""
        if not techniques:
            return 0.0
        
        # Average score of matched techniques, weighted by observation severity
        avg_score = sum(t.score for t in techniques) / len(techniques)
        
        # Severity multiplier
        severity_multiplier = {
            "low": 0.7,
            "medium": 0.85,
            "high": 1.0,
            "critical": 1.0
        }.get(observation.severity.lower(), 0.8)
        
        return min(1.0, avg_score * severity_multiplier)


class ThreatEnricher:
    """Enriches threats with related techniques, mitigations, and context."""
    
    def __init__(self, context_assembler: Optional[ContextAssembler] = None):
        """
        Initialize the threat enricher.
        
        Args:
            context_assembler: ContextAssembler instance. If None, creates a new one.
        """
        if context_assembler is None:
            self.context_assembler = ContextAssembler()
        else:
            self.context_assembler = context_assembler
    
    def enrich_threat(self, observation: Observation, matched_techniques: List[MITRETechnique]) -> Dict[str, Any]:
        """
        Enrich a threat with related techniques, mitigations, and context.
        
        Args:
            observation: Agent observation
            matched_techniques: List of matched MITRE techniques
            
        Returns:
            Dictionary with enriched threat information
        """
        # Assemble context
        context = self.context_assembler.assemble_observation_context(observation, matched_techniques)
        
        # Get related techniques (beyond direct matches)
        related_techniques = context["all_related_techniques"]
        
        # Get mitigations
        mitigations = context["all_mitigations"]
        
        # Prioritize mitigations by relevance
        prioritized_mitigations = self._prioritize_mitigations(mitigations, matched_techniques)
        
        return {
            "related_techniques": related_techniques,
            "mitigations": prioritized_mitigations,
            "tactics": context["tactics"],
            "enrichment_metrics": {
                "total_related_techniques": len(related_techniques),
                "total_mitigations": len(prioritized_mitigations),
                "tactics_count": len(context["tactics"])
            }
        }
    
    def _prioritize_mitigations(self, mitigations: List[Mitigation], techniques: List[MITRETechnique]) -> List[Mitigation]:
        """Prioritize mitigations based on technique matches."""
        # Score mitigations based on how many matched techniques they cover
        technique_ids = {t.id for t in techniques}
        
        scored_mitigations = []
        for mitigation in mitigations:
            # Count how many matched techniques this mitigation addresses
            coverage = sum(1 for tech_id in mitigation.techniques if tech_id in technique_ids)
            score = coverage / len(technique_ids) if technique_ids else 0.0
            
            scored_mitigations.append((mitigation, score))
        
        # Sort by score descending
        scored_mitigations.sort(key=lambda x: x[1], reverse=True)
        
        return [m[0] for m in scored_mitigations]


class CrossAgentCorrelator:
    """Correlates patterns across multiple agents."""
    
    def __init__(self, graph_retriever: Optional[GraphRetriever] = None):
        """
        Initialize the cross-agent correlator.
        
        Args:
            graph_retriever: GraphRetriever instance. If None, creates a new one.
        """
        if graph_retriever is None:
            self.graph_retriever = GraphRetriever()
        else:
            self.graph_retriever = graph_retriever
    
    def correlate_agents(self, agent_outputs: List[AgentOutput]) -> Dict[str, Any]:
        """
        Correlate observations across multiple agents.
        
        Args:
            agent_outputs: List of agent outputs from different agents
            
        Returns:
            Dictionary with correlation analysis
        """
        if len(agent_outputs) < 2:
            return {"correlated": False, "reason": "Insufficient agents for correlation"}
        
        # Extract all observations
        all_observations = []
        for output in agent_outputs:
            all_observations.extend(output.observations)
        
        # Find common indicators across agents
        indicator_counts = defaultdict(list)
        for output in agent_outputs:
            for obs in output.observations:
                for indicator in obs.indicators:
                    indicator_counts[indicator].append({
                        "agent": output.agent_id,
                        "observation_type": obs.type,
                        "severity": obs.severity
                    })
        
        # Find correlated indicators (appearing in multiple agents)
        correlated_indicators = {
            ind: data for ind, data in indicator_counts.items() 
            if len(set(d["agent"] for d in data)) > 1
        }
        
        # Extract common techniques/tactics
        technique_overlap = self._find_technique_overlap(agent_outputs)
        tactic_overlap = self._find_tactic_overlap(agent_outputs)
        
        return {
            "correlated": len(correlated_indicators) > 0 or len(technique_overlap) > 0,
            "correlated_indicators": correlated_indicators,
            "technique_overlap": technique_overlap,
            "tactic_overlap": tactic_overlap,
            "agent_count": len(agent_outputs),
            "observation_count": len(all_observations),
            "correlation_score": self._calculate_correlation_score(correlated_indicators, technique_overlap)
        }
    
    def _find_technique_overlap(self, agent_outputs: List[AgentOutput]) -> Dict[str, List[str]]:
        """Find MITRE techniques that appear across multiple agents."""
        # For now, return empty - this would require storing technique matches per agent
        # In full implementation, this would track which techniques match each agent's observations
        return {}
    
    def _find_tactic_overlap(self, agent_outputs: List[AgentOutput]) -> Dict[str, List[str]]:
        """Find MITRE tactics that appear across multiple agents."""
        # Similar to technique overlap
        return {}
    
    def _calculate_correlation_score(self, correlated_indicators: Dict, technique_overlap: Dict) -> float:
        """Calculate correlation score between 0.0 and 1.0."""
        indicator_score = min(1.0, len(correlated_indicators) * 0.3)
        technique_score = min(1.0, len(technique_overlap) * 0.4)
        return min(1.0, indicator_score + technique_score)


class RelevanceScorer:
    """Scores temporal and contextual relevance of threats."""
    
    def calculate_temporal_relevance(self, observations: List[Observation], base_time: Optional[datetime] = None) -> Dict[str, float]:
        """
        Calculate temporal relevance scores for observations.
        
        Args:
            observations: List of observations
            base_time: Base time for comparison. If None, uses current time.
            
        Returns:
            Dictionary mapping observation indices to temporal relevance scores
        """
        if base_time is None:
            base_time = datetime.now()
        
        scores = {}
        for i, obs in enumerate(observations):
            # For now, assume observations don't have explicit timestamps
            # In full implementation, would calculate based on recency
            scores[i] = 1.0  # Default to full relevance
        
        return scores
    
    def calculate_contextual_relevance(self, technique: MITRETechnique, observation: Observation) -> float:
        """
        Calculate contextual relevance score for a technique-observation pair.
        
        Args:
            technique: MITRE technique
            observation: Agent observation
            
        Returns:
            Relevance score between 0.0 and 1.0
        """
        score = technique.score  # Start with base retrieval score
        
        # Boost if observation type matches technique context
        obs_type_lower = observation.type.lower()
        tech_name_lower = technique.name.lower()
        tech_desc_lower = technique.description.lower()
        
        if obs_type_lower in tech_name_lower or obs_type_lower in tech_desc_lower:
            score = min(1.0, score * 1.2)
        
        # Boost if indicators match
        if observation.indicators:
            tech_text = f"{tech_name_lower} {tech_desc_lower}"
            indicator_matches = sum(1 for ind in observation.indicators if ind.lower() in tech_text)
            if indicator_matches > 0:
                score = min(1.0, score * (1.0 + indicator_matches * 0.1))
        
        # Adjust based on severity
        severity_weights = {
            "low": 0.7,
            "medium": 0.85,
            "high": 1.0,
            "critical": 1.0
        }
        score = score * severity_weights.get(observation.severity.lower(), 0.8)
        
        return min(1.0, score)


class KnowledgeFusion:
    """Main orchestrator for knowledge fusion process."""
    
    def __init__(
        self,
        hybrid_retriever: Optional[HybridRetriever] = None,
        context_assembler: Optional[ContextAssembler] = None,
        observation_mapper: Optional[ObservationMapper] = None,
        threat_enricher: Optional[ThreatEnricher] = None,
        cross_agent_correlator: Optional[CrossAgentCorrelator] = None,
        relevance_scorer: Optional[RelevanceScorer] = None
    ):
        """
        Initialize the Knowledge Fusion orchestrator.
        
        Args:
            hybrid_retriever: HybridRetriever instance
            context_assembler: ContextAssembler instance
            observation_mapper: ObservationMapper instance
            threat_enricher: ThreatEnricher instance
            cross_agent_correlator: CrossAgentCorrelator instance
            relevance_scorer: RelevanceScorer instance
        """
        self.hybrid_retriever = hybrid_retriever or HybridRetriever()
        self.context_assembler = context_assembler or ContextAssembler()
        self.observation_mapper = observation_mapper or ObservationMapper(self.hybrid_retriever)
        self.threat_enricher = threat_enricher or ThreatEnricher(self.context_assembler)
        self.cross_agent_correlator = cross_agent_correlator or CrossAgentCorrelator()
        self.relevance_scorer = relevance_scorer or RelevanceScorer()
    
    def fuse(self, agent_outputs: List[AgentOutput], threat_context_placeholder: str = "") -> EnrichedThreatIntelligence:
        """
        Main fusion method that processes agent outputs and returns enriched threat intelligence.
        
        Args:
            agent_outputs: List of agent outputs to process
            threat_context_placeholder: Placeholder for LLM-generated context (will be filled in Phase 5)
            
        Returns:
            EnrichedThreatIntelligence object
        """
        if not agent_outputs:
            raise ValueError("At least one agent output is required")
        
        # Step 1: Map observations to MITRE
        all_matched_techniques = []
        all_matched_tactics = []
        observation_mappings = []
        
        for agent_output in agent_outputs:
            for observation in agent_output.observations:
                mapping = self.observation_mapper.map_observation_to_mitre(observation, top_k=5)
                all_matched_techniques.extend(mapping["techniques"])
                all_matched_tactics.extend(mapping["tactics"])
                observation_mappings.append((observation, mapping))
        
        # Deduplicate techniques
        unique_techniques = self._deduplicate_techniques(all_matched_techniques)
        
        # Deduplicate tactics
        unique_tactics = self._deduplicate_tactics(all_matched_tactics)
        
        # Step 2: Enrich with related techniques and mitigations
        all_related_techniques = []
        all_mitigations = []
        
        for technique in unique_techniques:
            context = self.context_assembler.assemble_technique_context(technique)
            all_related_techniques.extend(context["related_techniques"])
            all_mitigations.extend(context["mitigations"])
        
        # Deduplicate related techniques
        unique_related = self._deduplicate_techniques(all_related_techniques)[:10]  # Limit to top 10
        
        # Deduplicate mitigations
        unique_mitigations = self._deduplicate_mitigations(all_mitigations)
        
        # Step 3: Cross-agent correlation
        correlation_result = self.cross_agent_correlator.correlate_agents(agent_outputs)
        
        # Step 4: Calculate confidence scores
        confidence_scores = self._calculate_confidence_scores(
            unique_techniques,
            unique_tactics,
            agent_outputs,
            correlation_result
        )
        
        # Step 5: Build attribution
        attribution = {
            "retrieval_methods": ["graph", "vector", "hybrid"],
            "correlation": correlation_result,
            "technique_count": len(unique_techniques),
            "tactic_count": len(unique_tactics),
            "related_technique_count": len(unique_related),
            "mitigation_count": len(unique_mitigations)
        }
        
        # Create enriched threat intelligence
        enriched = EnrichedThreatIntelligence(
            original_observations=agent_outputs,
            matched_mitre_techniques=unique_techniques[:10],  # Top 10 techniques
            matched_mitre_tactics=unique_tactics[:5],  # Top 5 tactics
            related_techniques=unique_related,
            mitigations=unique_mitigations[:10],  # Top 10 mitigations
            threat_context=threat_context_placeholder,  # Will be filled by RAG pipeline
            confidence_scores=confidence_scores,
            attribution=attribution,
            timestamp=datetime.now()
        )
        
        return enriched
    
    def _deduplicate_techniques(self, techniques: List[MITRETechnique]) -> List[MITRETechnique]:
        """Deduplicate techniques by ID, keeping highest scoring one."""
        seen = {}
        for technique in techniques:
            tech_id = technique.id
            if tech_id not in seen or technique.score > seen[tech_id].score:
                seen[tech_id] = technique
        
        # Sort by score descending
        unique = list(seen.values())
        unique.sort(key=lambda t: t.score, reverse=True)
        return unique
    
    def _deduplicate_tactics(self, tactics: List[MITRETactic]) -> List[MITRETactic]:
        """Deduplicate tactics by name, keeping highest scoring one."""
        seen = {}
        for tactic in tactics:
            name = tactic.name
            if name not in seen or tactic.score > seen[name].score:
                seen[name] = tactic
        
        # Sort by score descending
        unique = list(seen.values())
        unique.sort(key=lambda t: t.score, reverse=True)
        return unique
    
    def _deduplicate_mitigations(self, mitigations: List[Mitigation]) -> List[Mitigation]:
        """Deduplicate mitigations by ID."""
        seen = {}
        for mitigation in mitigations:
            mit_id = mitigation.id
            if mit_id not in seen:
                seen[mit_id] = mitigation
        
        return list(seen.values())
    
    def _calculate_confidence_scores(
        self,
        techniques: List[MITRETechnique],
        tactics: List[MITRETactic],
        agent_outputs: List[AgentOutput],
        correlation_result: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate overall confidence scores."""
        # Average technique score
        avg_technique_score = sum(t.score for t in techniques) / len(techniques) if techniques else 0.0
        
        # Average tactic score
        avg_tactic_score = sum(t.score for t in tactics) / len(tactics) if tactics else 0.0
        
        # Average agent confidence
        avg_agent_confidence = sum(ao.confidence for ao in agent_outputs) / len(agent_outputs) if agent_outputs else 0.0
        
        # Correlation boost
        correlation_boost = correlation_result.get("correlation_score", 0.0)
        
        return {
            "technique_matching": avg_technique_score,
            "tactic_matching": avg_tactic_score,
            "agent_confidence": avg_agent_confidence,
            "correlation": correlation_boost,
            "overall": (avg_technique_score * 0.4 + avg_tactic_score * 0.3 + avg_agent_confidence * 0.2 + correlation_boost * 0.1)
        }

