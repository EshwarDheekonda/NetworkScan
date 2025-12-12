"""
Communication Module

Provides message bus communication using Redis Pub/Sub for real-time
event streaming between agents, Knowledge Fusion, and feedback systems.
"""

from communication.message_bus import MessageBus, MessageBusPublisher, MessageBusSubscriber
from communication.agent_publisher import AgentPublisher
from communication.knowledge_fusion_subscriber import KnowledgeFusionSubscriber
from communication.feedback_handler import FeedbackHandler
from communication.message_types import Topics, Message, AgentObservationMessage, EnrichedIntelligenceMessage, FeedbackMessage

__all__ = [
    'MessageBus',
    'MessageBusPublisher',
    'MessageBusSubscriber',
    'AgentPublisher',
    'KnowledgeFusionSubscriber',
    'FeedbackHandler',
    'Topics',
    'Message',
    'AgentObservationMessage',
    'EnrichedIntelligenceMessage',
    'FeedbackMessage',
]

