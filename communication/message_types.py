"""
Message Types and Schemas

Defines message schemas for communication between components.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class Message(BaseModel):
    """Base message class."""
    message_type: str = Field(..., description="Type of message")
    timestamp: datetime = Field(default_factory=datetime.now, description="Message timestamp")
    source: str = Field(..., description="Source component")
    payload: Dict[str, Any] = Field(..., description="Message payload")


class AgentObservationMessage(Message):
    """Message containing agent observations."""
    message_type: str = "agent_observation"
    agent_id: str = Field(..., description="Agent identifier")
    observations: Dict[str, Any] = Field(..., description="Serialized AgentOutput")


class EnrichedIntelligenceMessage(Message):
    """Message containing enriched threat intelligence from Knowledge Fusion."""
    message_type: str = "enriched_intelligence"
    enriched_data: Dict[str, Any] = Field(..., description="Serialized EnrichedThreatIntelligence")


class FeedbackMessage(Message):
    """Message containing feedback for agents."""
    message_type: str = "feedback"
    target_agent: str = Field(..., description="Target agent ID")
    feedback_type: str = Field(..., description="Type of feedback")
    feedback_data: Dict[str, Any] = Field(..., description="Feedback data")


class AgentQueryMessage(Message):
    """Message for agent-to-agent queries."""
    message_type: str = "agent_query"
    querying_agent: str = Field(..., description="Agent making the query")
    target_agent: str = Field(..., description="Target agent ID")
    query_type: str = Field(..., description="Type of query (indicators, context, confirmation)")
    query_data: Dict[str, Any] = Field(..., description="Query payload")
    indicators: List[str] = Field(default_factory=list, description="Indicators to check")
    context: Dict[str, Any] = Field(default_factory=dict, description="Context to share")


class AgentResponseMessage(Message):
    """Message for agent-to-agent responses."""
    message_type: str = "agent_response"
    responding_agent: str = Field(..., description="Agent responding")
    query_id: str = Field(..., description="ID of the original query")
    has_related_activity: bool = Field(..., description="Whether related activity was found")
    related_indicators: List[str] = Field(default_factory=list, description="Related indicators found")
    confidence: float = Field(..., description="Confidence in response")
    response_data: Dict[str, Any] = Field(default_factory=dict, description="Additional response data")


class CollaborativeDetectionMessage(Message):
    """Message for collaborative detection confirmation."""
    message_type: str = "collaborative_detection"
    detecting_agents: List[str] = Field(..., description="Agents involved in detection")
    attack_type: str = Field(..., description="Type of attack detected")
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list, description="MITRE techniques")
    indicators: List[str] = Field(..., description="Common indicators")
    confidence: float = Field(..., description="Overall confidence")
    detection_data: Dict[str, Any] = Field(default_factory=dict, description="Detection details")


class ProactiveWarningMessage(Message):
    """Message for proactive threat warnings."""
    message_type: str = "proactive_warning"
    warning_type: str = Field(default="proactive_threat", description="Type of warning")
    attack_type: str = Field(..., description="Attack type name")
    severity: str = Field(..., description="Severity level")
    indicators: List[str] = Field(..., description="Attack indicators")
    description: str = Field(..., description="Warning description")
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list, description="MITRE techniques")
    mitre_tactics: List[Dict[str, Any]] = Field(default_factory=list, description="MITRE tactics")
    mitigations: List[Dict[str, Any]] = Field(default_factory=list, description="Mitigation measures")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended actions")
    detected_by: List[str] = Field(..., description="Agents that detected this")
    confidence: float = Field(..., description="Detection confidence")


# Message bus topics
class Topics:
    """Message bus topic constants."""
    # Agent observation topics
    ROUTER_OBSERVATIONS = "agent.router.observations"
    COMPUTER_OBSERVATIONS = "agent.computer.observations"
    EMAIL_OBSERVATIONS = "agent.email.observations"
    
    # Knowledge Fusion topics
    ENRICHED_INTELLIGENCE = "knowledge_fusion.enriched_intelligence"
    
    # Feedback topics
    FEEDBACK_ROUTER = "feedback.agent.router"
    FEEDBACK_COMPUTER = "feedback.agent.computer"
    FEEDBACK_EMAIL = "feedback.agent.email"
    
    # All agent observations (for Knowledge Fusion subscriber)
    ALL_AGENT_OBSERVATIONS = "agent.*.observations"
    
    # Agent collaboration topics
    AGENT_QUERY = "agent.collaboration.query"
    AGENT_RESPONSE = "agent.collaboration.response"
    COLLABORATIVE_DETECTION = "agent.collaboration.detection"
    PROACTIVE_WARNING = "agent.proactive.warning"
    
    @classmethod
    def get_agent_topic(cls, agent_id: str) -> str:
        """Get observation topic for an agent."""
        return f"agent.{agent_id}.observations"
    
    @classmethod
    def get_feedback_topic(cls, agent_id: str) -> str:
        """Get feedback topic for an agent."""
        return f"feedback.agent.{agent_id}"
    
    @classmethod
    def get_agent_query_topic(cls, agent_id: str) -> str:
        """Get query topic for an agent."""
        return f"agent.{agent_id}.query"
    
    @classmethod
    def get_agent_response_topic(cls, agent_id: str) -> str:
        """Get response topic for an agent."""
        return f"agent.{agent_id}.response"



