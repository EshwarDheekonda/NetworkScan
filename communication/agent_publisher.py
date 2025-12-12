"""
Agent Publisher

Publishes agent observations to message bus.
"""

import logging
from typing import Optional

from communication.message_bus import MessageBus, MessageBusPublisher
from communication.message_types import Topics
from knowledge_fusion.interfaces import AgentOutput


class AgentPublisher:
    """Publisher for agent observations."""
    
    def __init__(self, message_bus: MessageBus, agent_id: str):
        """
        Initialize agent publisher.
        
        Args:
            message_bus: MessageBus instance
            agent_id: Agent identifier (router, computer, email)
        """
        self.message_bus = message_bus
        self.agent_id = agent_id
        self.topic = Topics.get_agent_topic(agent_id)
        self.publisher = MessageBusPublisher(message_bus, self.topic)
        self.logger = logging.getLogger(f"{__name__}.{agent_id}")
    
    def publish(self, agent_output: AgentOutput):
        """
        Publish agent output to message bus.
        
        Args:
            agent_output: AgentOutput to publish
        """
        try:
            # Verify agent_id matches
            if agent_output.agent_id != self.agent_id:
                self.logger.warning(
                    f"Agent ID mismatch: expected {self.agent_id}, "
                    f"got {agent_output.agent_id}"
                )
            
            self.publisher.publish(agent_output)
            self.logger.info(
                f"Published {len(agent_output.observations)} observations "
                f"from {self.agent_id} agent"
            )
        except Exception as e:
            self.logger.error(f"Failed to publish agent output: {e}")
            raise




