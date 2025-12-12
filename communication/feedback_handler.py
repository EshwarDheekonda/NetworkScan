"""
Feedback Handler

Handles feedback messages from Knowledge Fusion and routes them to agents
for adaptive learning.
"""

import logging
from typing import Dict, Any, Optional

from communication.message_bus import MessageBus, MessageBusSubscriber
from communication.message_types import Topics
from agents.base_agent import BaseAgent


class FeedbackHandler:
    """Handles feedback routing to agents."""
    
    def __init__(self, message_bus: MessageBus, agents: Dict[str, BaseAgent]):
        """
        Initialize feedback handler.
        
        Args:
            message_bus: MessageBus instance
            agents: Dictionary mapping agent_id to Agent instance
        """
        self.message_bus = message_bus
        self.agents = agents
        self.logger = logging.getLogger(__name__)
        
        # Create subscriber for feedback topics
        feedback_topics = [
            Topics.FEEDBACK_ROUTER,
            Topics.FEEDBACK_COMPUTER,
            Topics.FEEDBACK_EMAIL
        ]
        
        self.subscriber = MessageBusSubscriber(
            message_bus,
            feedback_topics,
            self._handle_feedback
        )
    
    def start(self, blocking: bool = False):
        """
        Start feedback handler.
        
        Args:
            blocking: If True, blocks and processes messages
        """
        self.logger.info("Starting feedback handler")
        self.subscriber.start(blocking=blocking)
    
    def stop(self):
        """Stop feedback handler."""
        self.subscriber.stop()
        self.logger.info("Feedback handler stopped")
    
    def _handle_feedback(self, topic: str, message_dict: Dict[str, Any]):
        """
        Handle incoming feedback message.
        
        Args:
            topic: Message topic
            message_dict: Message data
        """
        try:
            target_agent = message_dict.get('target_agent')
            if not target_agent:
                self.logger.warning(f"No target_agent in feedback message from {topic}")
                return
            
            # Get agent
            agent = self.agents.get(target_agent)
            if not agent:
                self.logger.warning(f"Agent {target_agent} not found")
                return
            
            # Extract feedback data
            feedback_data = message_dict.get('feedback_data', {})
            feedback_type = message_dict.get('feedback_type', 'unknown')
            
            # Create feedback structure
            feedback = {
                'type': feedback_type,
                'data': feedback_data,
                'timestamp': message_dict.get('timestamp')
            }
            
            # Send to agent
            agent.handle_feedback(feedback)
            
            self.logger.debug(f"Delivered feedback to {target_agent} agent")
            
        except Exception as e:
            self.logger.error(f"Error handling feedback from {topic}: {e}")




