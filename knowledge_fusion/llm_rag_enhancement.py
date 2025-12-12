"""
LLM RAG Enhancement

Agent-aware RAG that incorporates agent reasoning into RAG queries.
"""

from typing import Dict, Any, Optional, List
from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.interfaces import AgentOutput


class AgentAwareRAG:
    """RAG that understands agent context."""
    
    def __init__(self, knowledge_fusion: Optional[KnowledgeFusion] = None):
        """Initialize agent-aware RAG."""
        self.knowledge_fusion = knowledge_fusion or KnowledgeFusion()
    
    def enhance_with_agent_context(
        self,
        agent_outputs: List[AgentOutput],
        agent_reasoning: Optional[Dict[str, Any]] = None
    ):
        """Enhance RAG with agent reasoning context."""
        # Use existing Knowledge Fusion with agent context
        enriched = self.knowledge_fusion.fuse(agent_outputs)
        
        # Add agent reasoning to attribution
        if agent_reasoning:
            enriched.attribution['agent_reasoning'] = agent_reasoning
        
        return enriched




