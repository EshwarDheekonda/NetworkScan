"""
Neo4j query templates for structured retrieval.

Contains Cypher queries for extracting MITRE ATT&CK content from Neo4j.
"""

from typing import List, Dict, Any


class GraphQueries:
    """Collection of Cypher queries for MITRE ATT&CK retrieval."""
    
    @staticmethod
    def get_all_techniques() -> str:
        """Get all MITRE techniques with their details."""
        return """
        MATCH (t:Technique)
        OPTIONAL MATCH (tactic:Tactic)-[:USES]->(t)
        RETURN t.id as id, 
               t.external_id as external_id,
               t.name as name,
               t.description as description,
               collect(DISTINCT tactic.name) as tactics
        ORDER BY t.external_id
        """
    
    @staticmethod
    def get_all_tactics() -> str:
        """Get all MITRE tactics with their details."""
        return """
        MATCH (t:Tactic)
        RETURN t.name as name,
               t.description as description
        ORDER BY t.name
        """
    
    @staticmethod
    def get_all_mitigations() -> str:
        """Get all MITRE mitigations with their details."""
        return """
        MATCH (m:Mitigation)
        RETURN m.id as id,
               m.name as name,
               m.description as description
        ORDER BY m.name
        """
    
    @staticmethod
    def get_techniques_by_tactic(tactic_name: str) -> str:
        """Get all techniques for a specific tactic."""
        return f"""
        MATCH (tactic:Tactic {{name: '{tactic_name}'}})-[:USES]->(t:Technique)
        RETURN t.id as id,
               t.external_id as external_id,
               t.name as name,
               t.description as description
        ORDER BY t.external_id
        """
    
    @staticmethod
    def get_technique_by_external_id(external_id: str) -> str:
        """Get a technique by its MITRE external ID (e.g., T1059.003)."""
        return f"""
        MATCH (t:Technique {{external_id: '{external_id}'}})
        OPTIONAL MATCH (tactic:Tactic)-[:USES]->(t)
        RETURN t.id as id,
               t.external_id as external_id,
               t.name as name,
               t.description as description,
               collect(DISTINCT tactic.name) as tactics
        """
    
    @staticmethod
    def get_techniques_by_keywords(keywords: List[str]) -> str:
        """Get techniques matching keywords in name or description."""
        # Build WHERE clause with OR conditions
        conditions = []
        for keyword in keywords:
            conditions.append(f"(t.name CONTAINS '{keyword}' OR t.description CONTAINS '{keyword}')")
        
        where_clause = " OR ".join(conditions)
        return f"""
        MATCH (t:Technique)
        WHERE {where_clause}
        OPTIONAL MATCH (tactic:Tactic)-[:USES]->(t)
        RETURN t.id as id,
               t.external_id as external_id,
               t.name as name,
               t.description as description,
               collect(DISTINCT tactic.name) as tactics
        """
    
    @staticmethod
    def get_related_techniques(technique_id: str, depth: int = 2, limit: int = 20) -> str:
        """Get related techniques via graph relationships."""
        return f"""
        MATCH (t:Technique {{id: '{technique_id}'}})
        MATCH path = (t)-[*1..{depth}]-(related:Technique)
        WHERE related.id <> '{technique_id}'
        RETURN DISTINCT related.id as id,
               related.external_id as external_id,
               related.name as name,
               related.description as description,
               length(path) as distance
        ORDER BY distance
        LIMIT {limit}
        """
    
    @staticmethod
    def get_mitigations_for_technique(technique_id: str) -> str:
        """Get mitigations that apply to a specific technique."""
        return f"""
        MATCH (t:Technique {{id: '{technique_id}'}})
        MATCH (m:Mitigation)-[:MITIGATES]->(t)
        RETURN m.id as id,
               m.name as name,
               m.description as description
        """
    
    @staticmethod
    def get_technique_context(technique_id: str) -> str:
        """Get full context for a technique including related entities."""
        return f"""
        MATCH (t:Technique {{id: '{technique_id}'}})
        OPTIONAL MATCH (tactic:Tactic)-[:USES]->(t)
        OPTIONAL MATCH (m:Mitigation)-[:MITIGATES]->(t)
        OPTIONAL MATCH (g:Group)-[:USES]->(t)
        RETURN t.id as id,
               t.external_id as external_id,
               t.name as name,
               t.description as description,
               collect(DISTINCT tactic.name) as tactics,
               collect(DISTINCT {{id: m.id, name: m.name}}) as mitigations,
               collect(DISTINCT g.name) as groups
        """
