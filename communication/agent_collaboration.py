"""
Agent Collaboration

Structured agent collaboration protocols for multi-agent investigations.
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
import logging
import threading
import uuid

from communication.message_bus import MessageBus
from communication.message_types import (
    Topics, AgentQueryMessage, AgentResponseMessage, 
    CollaborativeDetectionMessage
)


class AgentCollaboration:
    """Manages agent collaboration protocols with real-time querying."""
    
    def __init__(self, message_bus: Optional[MessageBus] = None, agent_id: Optional[str] = None):
        """
        Initialize agent collaboration.
        
        Args:
            message_bus: Optional MessageBus for real-time communication
            agent_id: Optional agent ID for this collaboration instance
        """
        self.logger = logging.getLogger(__name__)
        self.shared_context: Dict[str, Any] = {}
        self.message_bus = message_bus
        self.agent_id = agent_id
        
        # Pending queries and responses
        self.pending_queries: Dict[str, Dict[str, Any]] = {}
        self.query_responses: Dict[str, List[Dict[str, Any]]] = {}
        self.query_lock = threading.Lock()
        
        # Response timeout (seconds)
        self.response_timeout = 5.0
        
        # Setup message bus subscriber if available
        if message_bus and agent_id:
            self._setup_subscribers()
    
    def _setup_subscribers(self):
        """Setup message bus subscribers for collaboration."""
        if not self.message_bus:
            return
        
        from communication.message_bus import MessageBusSubscriber
        
        # Subscribe to query topic
        query_topic = Topics.get_agent_query_topic(self.agent_id)
        query_subscriber = MessageBusSubscriber(
            self.message_bus,
            [query_topic, Topics.AGENT_QUERY],
            self._handle_query
        )
        query_subscriber.start(blocking=False)
        
        # Subscribe to response topic
        response_topic = Topics.get_agent_response_topic(self.agent_id)
        response_subscriber = MessageBusSubscriber(
            self.message_bus,
            [response_topic, Topics.AGENT_RESPONSE],
            self._handle_response
        )
        response_subscriber.start(blocking=False)
        
        self.logger.info(f"Agent collaboration subscribers set up for {self.agent_id}")
    
    def share_context(self, agent_id: str, context: Dict[str, Any]):
        """Share context with other agents."""
        self.shared_context[agent_id] = context
        self.logger.debug(f"Context shared by {agent_id}")
        
        # Also publish to message bus if available
        if self.message_bus:
            try:
                self.message_bus.publish(
                    Topics.AGENT_QUERY,  # Reuse query topic for context sharing
                    {
                        'message_type': 'context_share',
                        'source_agent': agent_id,
                        'context': context,
                        'timestamp': datetime.now().isoformat()
                    }
                )
            except Exception as e:
                self.logger.warning(f"Failed to publish context share: {e}")
    
    def get_shared_context(self) -> Dict[str, Any]:
        """Get all shared context."""
        return self.shared_context.copy()
    
    def query_other_agents(
        self,
        query_type: str,
        indicators: List[str],
        context: Optional[Dict[str, Any]] = None,
        target_agents: Optional[List[str]] = None,
        timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Query other agents for related activity.
        
        Args:
            query_type: Type of query (indicators, context, confirmation)
            indicators: List of indicators to check
            context: Optional context to share
            target_agents: Optional list of agent IDs to query (None = all)
            timeout: Optional timeout in seconds (default: self.response_timeout)
            
        Returns:
            Dictionary with responses from agents
        """
        if not self.message_bus:
            self.logger.warning("Message bus not available for agent querying")
            return {'responses': [], 'error': 'Message bus not available'}
        
        if target_agents is None:
            # Default to all other agents
            all_agents = ['router', 'computer', 'email']
            target_agents = [a for a in all_agents if a != self.agent_id]
        
        if not target_agents:
            return {'responses': [], 'error': 'No target agents specified'}
        
        # Generate query ID
        query_id = str(uuid.uuid4())
        
        # Create query message
        query_data = {
            'query_id': query_id,
            'querying_agent': self.agent_id,
            'query_type': query_type,
            'indicators': indicators,
            'context': context or {},
            'timestamp': datetime.now().isoformat()
        }
        
        # Store pending query
        with self.query_lock:
            self.pending_queries[query_id] = {
                'query_data': query_data,
                'target_agents': target_agents,
                'timestamp': datetime.now(),
                'responses': {}
            }
            self.query_responses[query_id] = []
        
        # Send query to each target agent
        for target_agent in target_agents:
            try:
                target_topic = Topics.get_agent_query_topic(target_agent)
                self.message_bus.publish(target_topic, query_data)
                self.logger.debug(f"Sent query {query_id} to {target_agent}")
            except Exception as e:
                self.logger.error(f"Failed to send query to {target_agent}: {e}")
        
        # Wait for responses
        timeout = timeout or self.response_timeout
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            with self.query_lock:
                query_info = self.pending_queries.get(query_id)
                if query_info:
                    responses = self.query_responses.get(query_id, [])
                    if len(responses) >= len(target_agents):
                        # All responses received
                        break
            threading.Event().wait(0.1)  # Small delay
        
        # Collect responses
        with self.query_lock:
            responses = self.query_responses.get(query_id, [])
            if query_id in self.pending_queries:
                del self.pending_queries[query_id]
            if query_id in self.query_responses:
                del self.query_responses[query_id]
        
        return {
            'query_id': query_id,
            'responses': responses,
            'response_count': len(responses),
            'target_count': len(target_agents)
        }
    
    def collaborative_detection(
        self,
        indicators: List[str],
        attack_type: str,
        confidence: float,
        other_agents: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform collaborative detection with other agents.
        
        Args:
            indicators: List of indicators
            attack_type: Type of attack detected
            confidence: Detection confidence
            other_agents: Optional list of other agents to involve
            
        Returns:
            Dictionary with collaborative detection results
        """
        # Query other agents
        query_result = self.query_other_agents(
            query_type='confirmation',
            indicators=indicators,
            target_agents=other_agents
        )
        
        # Analyze responses
        responses = query_result.get('responses', [])
        confirmed_agents = [self.agent_id]
        related_indicators = set(indicators)
        
        for response in responses:
            if response.get('has_related_activity', False):
                confirmed_agents.append(response.get('responding_agent', 'unknown'))
                related_indicators.update(response.get('related_indicators', []))
        
        # Calculate collaborative confidence
        base_confidence = confidence
        if len(confirmed_agents) > 1:
            # Boost confidence when multiple agents confirm
            collaborative_boost = min(0.3, (len(confirmed_agents) - 1) * 0.15)
            collaborative_confidence = min(1.0, base_confidence + collaborative_boost)
        else:
            collaborative_confidence = base_confidence
        
        # Create collaborative detection message
        detection_data = {
            'detecting_agents': confirmed_agents,
            'attack_type': attack_type,
            'indicators': list(related_indicators),
            'confidence': collaborative_confidence,
            'individual_confidence': confidence,
            'response_count': len(responses),
            'timestamp': datetime.now().isoformat()
        }
        
        # Publish collaborative detection
        if self.message_bus:
            try:
                self.message_bus.publish(Topics.COLLABORATIVE_DETECTION, detection_data)
            except Exception as e:
                self.logger.error(f"Failed to publish collaborative detection: {e}")
        
        return detection_data
    
    def _handle_query(self, topic: str, message_dict: Dict[str, Any]):
        """Handle incoming query from another agent."""
        if not self.agent_id:
            return
        
        querying_agent = message_dict.get('querying_agent')
        if querying_agent == self.agent_id:
            return  # Ignore own queries
        
        query_type = message_dict.get('query_type', 'indicators')
        indicators = message_dict.get('indicators', [])
        query_id = message_dict.get('query_id')
        
        self.logger.debug(f"Received query {query_id} from {querying_agent}")
        
        # Check if we have related activity (simplified - would need agent's observation history)
        # For now, return a response indicating we'll check
        response = {
            'query_id': query_id,
            'responding_agent': self.agent_id,
            'has_related_activity': False,  # Would check actual observations
            'related_indicators': [],
            'confidence': 0.0,
            'response_data': {
                'message': f'Query received, checking for related activity'
            }
        }
        
        # Publish response
        if self.message_bus and querying_agent:
            try:
                response_topic = Topics.get_agent_response_topic(querying_agent)
                self.message_bus.publish(response_topic, response)
            except Exception as e:
                self.logger.error(f"Failed to publish response: {e}")
    
    def _handle_response(self, topic: str, message_dict: Dict[str, Any]):
        """Handle incoming response to a query."""
        query_id = message_dict.get('query_id')
        if not query_id:
            return
        
        with self.query_lock:
            if query_id in self.pending_queries:
                if query_id not in self.query_responses:
                    self.query_responses[query_id] = []
                self.query_responses[query_id].append(message_dict)
                self.logger.debug(f"Received response for query {query_id}")
    
    def set_response_handler(self, handler: Callable[[Dict[str, Any]], Dict[str, Any]]):
        """
        Set a handler function for processing queries.
        Handler should take query data and return response data.
        
        Args:
            handler: Function that processes queries and returns responses
        """
        self.query_handler = handler



