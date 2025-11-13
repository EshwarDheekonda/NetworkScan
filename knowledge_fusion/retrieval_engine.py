"""
Hybrid retrieval engine (graph + vector) for MITRE ATT&CK knowledge.

Implements graph-based, vector-based, and hybrid retrieval strategies
for matching agent observations with MITRE ATT&CK knowledge.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import numpy as np
from py2neo import Graph

from knowledge_fusion.config import get_config, RetrievalConfig
from knowledge_fusion.interfaces import Observation, MITRETechnique, MITRETactic
from knowledge_fusion.utils.graph_queries import GraphQueries
from knowledge_fusion.vector_store import Neo4jVectorStore
from knowledge_fusion.mitre_embedder import MITREEmbedder


@dataclass
class RetrievalResult:
    """Represents a single retrieval result."""
    technique: MITRETechnique
    source: str  # 'graph' or 'vector'
    raw_score: float  # Original score from retrieval method
    normalized_score: float  # Normalized score for fusion


class GraphRetriever:
    """Graph-based retrieval from Neo4j using structured queries."""
    
    def __init__(self, graph: Optional[Graph] = None):
        """
        Initialize the graph retriever.
        
        Args:
            graph: Neo4j Graph instance. If None, creates connection from config.
        """
        if graph is None:
            config = get_config()
            self.graph = Graph(
                config.neo4j.uri,
                auth=(config.neo4j.username, config.neo4j.password)
            )
        else:
            self.graph = graph
        
        self.queries = GraphQueries()
    
    def retrieve_by_keywords(self, keywords: List[str], top_k: int = 10) -> List[RetrievalResult]:
        """
        Retrieve techniques matching keywords in name or description.
        
        Args:
            keywords: List of keywords to search for
            top_k: Number of results to return
            
        Returns:
            List of RetrievalResult objects
        """
        if not keywords:
            return []
        
        query = self.queries.get_techniques_by_keywords(keywords) + f" LIMIT {top_k}"
        results = self.graph.run(query).data()
        
        retrieval_results = []
        for record in results:
            tactics = record.get("tactics", []) or []
            tactic_name = tactics[0] if tactics else None
            
            technique = MITRETechnique(
                id=record.get("id", ""),
                external_id=record.get("external_id"),
                name=record.get("name", ""),
                description=record.get("description", ""),
                tactic=tactic_name,
                score=1.0  # Graph matches get full score initially
            )
            
            # Calculate keyword match score (simple: more keywords matched = higher score)
            name = record.get("name", "").lower()
            description = record.get("description", "").lower()
            matched_keywords = sum(1 for kw in keywords if kw.lower() in name or kw.lower() in description)
            match_score = min(1.0, matched_keywords / len(keywords)) if keywords else 0.0
            
            result = RetrievalResult(
                technique=technique,
                source="graph",
                raw_score=match_score,
                normalized_score=match_score
            )
            retrieval_results.append(result)
        
        return retrieval_results
    
    def retrieve_by_tactic(self, tactic_name: str, top_k: int = 10) -> List[RetrievalResult]:
        """
        Retrieve techniques associated with a specific tactic.
        
        Args:
            tactic_name: Name of the tactic
            top_k: Number of results to return
            
        Returns:
            List of RetrievalResult objects
        """
        query = self.queries.get_techniques_by_tactic(tactic_name) + f" LIMIT {top_k}"
        results = self.graph.run(query).data()
        
        retrieval_results = []
        for record in results:
            technique = MITRETechnique(
                id=record.get("id", ""),
                external_id=record.get("external_id"),
                name=record.get("name", ""),
                description=record.get("description", ""),
                tactic=tactic_name,
                score=0.9  # High score for tactic matches
            )
            
            result = RetrievalResult(
                technique=technique,
                source="graph",
                raw_score=0.9,
                normalized_score=0.9
            )
            retrieval_results.append(result)
        
        return retrieval_results
    
    def retrieve_by_external_id(self, external_id: str) -> Optional[RetrievalResult]:
        """
        Retrieve a technique by its MITRE external ID.
        
        Args:
            external_id: MITRE external ID (e.g., 'T1059.003')
            
        Returns:
            RetrievalResult or None if not found
        """
        query = self.queries.get_technique_by_external_id(external_id)
        results = self.graph.run(query).data()
        
        if not results:
            return None
        
        record = results[0]
        tactics = record.get("tactics", []) or []
        tactic_name = tactics[0] if tactics else None
        
        technique = MITRETechnique(
            id=record.get("id", ""),
            external_id=record.get("external_id"),
            name=record.get("name", ""),
            description=record.get("description", ""),
            tactic=tactic_name,
            score=1.0
        )
        
        return RetrievalResult(
            technique=technique,
            source="graph",
            raw_score=1.0,
            normalized_score=1.0
        )
    
    def retrieve_related_techniques(self, technique_id: str, depth: int = 2, top_k: int = 10) -> List[RetrievalResult]:
        """
        Retrieve techniques related to a given technique via graph relationships.
        
        Args:
            technique_id: ID of the source technique
            depth: Depth of graph traversal
            top_k: Number of results to return
            
        Returns:
            List of RetrievalResult objects
        """
        query = self.queries.get_related_techniques(technique_id, depth, limit=top_k)
        results = self.graph.run(query).data()
        
        retrieval_results = []
        for record in results:
            distance = record.get("distance", depth)
            # Score inversely related to distance
            score = max(0.3, 1.0 - (distance * 0.2))
            
            technique = MITRETechnique(
                id=record.get("id", ""),
                external_id=record.get("external_id"),
                name=record.get("name", ""),
                description=record.get("description", ""),
                tactic=None,  # Related techniques may have different tactics
                score=score
            )
            
            result = RetrievalResult(
                technique=technique,
                source="graph",
                raw_score=score,
                normalized_score=score
            )
            retrieval_results.append(result)
        
        return retrieval_results
    
    def get_tactics_for_observation(self, observation: Observation) -> List[MITRETactic]:
        """
        Retrieve tactics that might be relevant to an observation.
        
        Args:
            observation: Agent observation
            
        Returns:
            List of MITRETactic objects
        """
        # Extract keywords from observation
        keywords = observation.description.lower().split()
        # Filter out common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        keywords = [kw for kw in keywords if kw not in stop_words and len(kw) > 3]
        
        if not keywords:
            return []
        
        # Search for techniques matching keywords, then get their tactics
        techniques = self.retrieve_by_keywords(keywords[:5], top_k=20)
        
        # Extract unique tactics
        tactic_scores = {}
        for result in techniques:
            if result.technique.tactic:
                tactic_name = result.technique.tactic
                if tactic_name not in tactic_scores:
                    tactic_scores[tactic_name] = []
                tactic_scores[tactic_name].append(result.normalized_score)
        
        # Create MITRETactic objects with average scores
        tactics = []
        for tactic_name, scores in tactic_scores.items():
            avg_score = sum(scores) / len(scores) if scores else 0.0
            tactic = MITRETactic(
                name=tactic_name,
                description=None,
                score=avg_score
            )
            tactics.append(tactic)
        
        # Sort by score descending
        tactics.sort(key=lambda t: t.score, reverse=True)
        
        return tactics


class VectorRetriever:
    """Vector-based semantic retrieval using embeddings."""
    
    def __init__(self, embedder: Optional[MITREEmbedder] = None, vector_store: Optional[Neo4jVectorStore] = None):
        """
        Initialize the vector retriever.
        
        Args:
            embedder: MITREEmbedder instance. If None, creates a new one.
            vector_store: Neo4jVectorStore instance. If None, creates a new one.
        """
        if embedder is None:
            self.embedder = MITREEmbedder()
        else:
            self.embedder = embedder
        
        if vector_store is None:
            self.vector_store = Neo4jVectorStore()
        else:
            self.vector_store = vector_store
    
    def retrieve_semantic(self, query_text: str, top_k: int = 10, threshold: float = 0.6) -> List[RetrievalResult]:
        """
        Retrieve techniques using semantic similarity search.
        
        Args:
            query_text: Text query to search for
            top_k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of RetrievalResult objects
        """
        # Generate embedding for query
        query_embedding = self.embedder.embed_query(query_text)
        
        # Search in Neo4j
        search_results = self.vector_store.search_similar(
            query_embedding,
            node_label="Technique",
            top_k=top_k,
            threshold=threshold
        )
        
        retrieval_results = []
        for record in search_results:
            similarity = float(record.get("similarity", 0.0))
            
            # Get tactic for this technique (need to query separately)
            technique_id = record.get("id", "")
            tactic = self._get_tactic_for_technique(technique_id)
            
            technique = MITRETechnique(
                id=technique_id,
                external_id=record.get("external_id"),
                name=record.get("name", ""),
                description=record.get("description", ""),
                tactic=tactic,
                score=similarity
            )
            
            result = RetrievalResult(
                technique=technique,
                source="vector",
                raw_score=similarity,
                normalized_score=similarity
            )
            retrieval_results.append(result)
        
        return retrieval_results
    
    def retrieve_from_observation(self, observation: Observation, top_k: int = 10, threshold: float = 0.6) -> List[RetrievalResult]:
        """
        Retrieve techniques semantically similar to an agent observation.
        
        Args:
            observation: Agent observation
            top_k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of RetrievalResult objects
        """
        # Create query text from observation
        query_text = f"{observation.type} {observation.description}"
        if observation.indicators:
            query_text += " " + " ".join(observation.indicators[:3])  # Add first 3 indicators
        
        return self.retrieve_semantic(query_text, top_k=top_k, threshold=threshold)
    
    def _get_tactic_for_technique(self, technique_id: str) -> Optional[str]:
        """Get the tactic associated with a technique."""
        from py2neo import Graph
        from knowledge_fusion.config import get_config
        
        config = get_config()
        graph = Graph(config.neo4j.uri, auth=(config.neo4j.username, config.neo4j.password))
        
        query = f"""
        MATCH (tactic:Tactic)-[:USES]->(t:Technique {{id: '{technique_id}'}})
        RETURN tactic.name as name
        LIMIT 1
        """
        results = graph.run(query).data()
        
        if results:
            return results[0].get("name")
        return None


class HybridRetriever:
    """Hybrid retrieval combining graph and vector search."""
    
    def __init__(
        self,
        graph_retriever: Optional[GraphRetriever] = None,
        vector_retriever: Optional[VectorRetriever] = None,
        config: Optional[RetrievalConfig] = None
    ):
        """
        Initialize the hybrid retriever.
        
        Args:
            graph_retriever: GraphRetriever instance. If None, creates a new one.
            vector_retriever: VectorRetriever instance. If None, creates a new one.
            config: RetrievalConfig. If None, uses default config.
        """
        if graph_retriever is None:
            self.graph_retriever = GraphRetriever()
        else:
            self.graph_retriever = graph_retriever
        
        if vector_retriever is None:
            self.vector_retriever = VectorRetriever()
        else:
            self.vector_retriever = vector_retriever
        
        if config is None:
            self.config = get_config().retrieval
        else:
            self.config = config
    
    def retrieve(self, observation: Observation, top_k: int = 10) -> List[RetrievalResult]:
        """
        Perform hybrid retrieval combining graph and vector search.
        
        Args:
            observation: Agent observation to match
            top_k: Total number of results to return
            
        Returns:
            List of RetrievalResult objects, ranked by fusion score
        """
        # Extract keywords from observation
        keywords = self._extract_keywords(observation)
        
        # Graph retrieval
        graph_results = []
        if keywords:
            graph_results = self.graph_retriever.retrieve_by_keywords(keywords, top_k=self.config.top_k_graph)
        
        # Vector retrieval
        vector_results = self.vector_retriever.retrieve_from_observation(
            observation,
            top_k=self.config.top_k_vector,
            threshold=self.config.similarity_threshold
        )
        
        # Normalize scores from both methods (to same scale)
        graph_results = self._normalize_scores(graph_results, method="graph")
        vector_results = self._normalize_scores(vector_results, method="vector")
        
        # Combine and deduplicate by technique ID
        combined = self._merge_results(graph_results, vector_results)
        
        # Apply weighted fusion
        fused_results = self._weighted_fusion(combined)
        
        # Sort by fused score and return top_k
        fused_results.sort(key=lambda r: r.normalized_score, reverse=True)
        
        return fused_results[:top_k]
    
    def _extract_keywords(self, observation: Observation) -> List[str]:
        """Extract meaningful keywords from an observation."""
        # Combine description and indicators
        text = f"{observation.description} {' '.join(observation.indicators)}"
        
        # Simple keyword extraction (can be enhanced with NLP)
        words = text.lower().split()
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
            'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would'
        }
        
        # Filter meaningful words
        keywords = [w for w in words if w not in stop_words and len(w) > 3]
        
        # Remove duplicates while preserving order
        seen = set()
        unique_keywords = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                unique_keywords.append(kw)
        
        return unique_keywords[:10]  # Limit to top 10 keywords
    
    def _normalize_scores(self, results: List[RetrievalResult], method: str) -> List[RetrievalResult]:
        """Normalize scores to [0, 1] range."""
        if not results:
            return results
        
        # Get score range
        scores = [r.raw_score for r in results]
        min_score = min(scores)
        max_score = max(scores)
        
        # Normalize to [0, 1]
        if max_score == min_score:
            # All scores are the same
            for result in results:
                result.normalized_score = 0.5
        else:
            for result in results:
                result.normalized_score = (result.raw_score - min_score) / (max_score - min_score)
        
        return results
    
    def _merge_results(self, graph_results: List[RetrievalResult], vector_results: List[RetrievalResult]) -> Dict[str, RetrievalResult]:
        """
        Merge results from graph and vector retrieval, handling duplicates.
        
        Returns:
            Dictionary mapping technique ID to merged RetrievalResult
        """
        merged = {}
        
        # Add graph results
        for result in graph_results:
            tech_id = result.technique.id
            if tech_id not in merged:
                merged[tech_id] = result
            else:
                # Keep higher scoring one, but mark both sources
                if result.normalized_score > merged[tech_id].normalized_score:
                    merged[tech_id] = result
        
        # Add vector results, combining with graph if duplicate
        for result in vector_results:
            tech_id = result.technique.id
            if tech_id not in merged:
                merged[tech_id] = result
            else:
                # This technique was found by both methods - combine scores
                existing = merged[tech_id]
                existing.source = "hybrid"
                # Average of both scores (can be weighted differently)
                existing.normalized_score = (existing.normalized_score + result.normalized_score) / 2
        
        return merged
    
    def _weighted_fusion(self, merged_results: Dict[str, RetrievalResult]) -> List[RetrievalResult]:
        """
        Apply weighted fusion to merged results.
        
        Args:
            merged_results: Dictionary of merged results
            
        Returns:
            List of results with fused scores
        """
        results = list(merged_results.values())
        
        for result in results:
            if result.source == "graph":
                # Apply graph weight
                result.normalized_score = result.normalized_score * self.config.graph_weight
            elif result.source == "vector":
                # Apply vector weight
                result.normalized_score = result.normalized_score * self.config.vector_weight
            elif result.source == "hybrid":
                # Hybrid gets weighted combination
                # Already averaged, now apply combined weight
                combined_weight = (self.config.graph_weight + self.config.vector_weight) / 2
                result.normalized_score = result.normalized_score * combined_weight
        
        return results
    
    def match_techniques_to_observation(self, observation: Observation, top_k: int = 5) -> List[MITRETechnique]:
        """
        Match MITRE techniques to an agent observation using hybrid retrieval.
        
        Args:
            observation: Agent observation
            top_k: Number of top matches to return
            
        Returns:
            List of MITRETechnique objects, sorted by relevance
        """
        results = self.retrieve(observation, top_k=top_k * 2)  # Get more for filtering
        
        # Filter and rank results
        filtered = self._filter_and_rank(results, observation)
        
        # Extract techniques
        techniques = [r.technique for r in filtered[:top_k]]
        
        return techniques
    
    def match_tactics_to_observation(self, observation: Observation) -> List[MITRETactic]:
        """
        Match MITRE tactics to an agent observation.
        
        Args:
            observation: Agent observation
            
        Returns:
            List of MITRETactic objects, sorted by relevance
        """
        # Use graph retriever to get tactics
        tactics = self.graph_retriever.get_tactics_for_observation(observation)
        
        return tactics
    
    def _filter_and_rank(self, results: List[RetrievalResult], observation: Observation) -> List[RetrievalResult]:
        """
        Filter and rank retrieval results based on observation characteristics.
        
        Args:
            results: List of retrieval results
            observation: Original observation for context
            
        Returns:
            Filtered and ranked results
        """
        # Apply severity-based filtering (high severity observations need high confidence matches)
        if observation.severity in ["high", "critical"]:
            # Only keep results with score >= 0.5 for high severity
            results = [r for r in results if r.normalized_score >= 0.5]
        
        # Boost scores for techniques matching observation type
        observation_type_lower = observation.type.lower()
        for result in results:
            technique_name_lower = result.technique.name.lower()
            technique_desc_lower = result.technique.description.lower()
            
            # If observation type matches technique context, boost score
            if observation_type_lower in technique_name_lower or observation_type_lower in technique_desc_lower:
                result.normalized_score = min(1.0, result.normalized_score * 1.2)
        
        # Boost scores for techniques matching indicators
        if observation.indicators:
            for result in results:
                technique_text = f"{result.technique.name} {result.technique.description}".lower()
                indicator_matches = sum(1 for ind in observation.indicators if ind.lower() in technique_text)
                
                if indicator_matches > 0:
                    boost = 1.0 + (indicator_matches * 0.1)
                    result.normalized_score = min(1.0, result.normalized_score * boost)
        
        # Sort by final score
        results.sort(key=lambda r: r.normalized_score, reverse=True)
        
        return results

