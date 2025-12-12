"""
Knowledge Fusion Subscriber

Subscribes to agent observations and feeds them into Knowledge Fusion module.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import threading
from queue import Queue

from communication.message_bus import MessageBus, MessageBusSubscriber
from communication.message_types import Topics
from knowledge_fusion.interfaces import AgentOutput
from knowledge_fusion.agent_interface import AgentInterface
from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.rag_pipeline import RAGPipeline


class KnowledgeFusionSubscriber:
    """Subscriber that processes agent observations through Knowledge Fusion."""
    
    def __init__(self, message_bus: MessageBus, 
                 knowledge_fusion: Optional[KnowledgeFusion] = None,
                 rag_pipeline: Optional[RAGPipeline] = None):
        """
        Initialize Knowledge Fusion subscriber.
        
        Args:
            message_bus: MessageBus instance
            knowledge_fusion: KnowledgeFusion instance (creates new if None)
            rag_pipeline: RAGPipeline instance (creates new if None)
        """
        self.message_bus = message_bus
        self.knowledge_fusion = knowledge_fusion or KnowledgeFusion()
        self.rag_pipeline = rag_pipeline or RAGPipeline()
        self.agent_interface = AgentInterface()
        self.logger = logging.getLogger(__name__)
        
        # Buffer for collecting observations from multiple agents
        self.observation_buffer: List[AgentOutput] = []
        self.buffer_lock = threading.Lock()
        self.buffer_timeout = 5.0  # seconds
        self.last_buffer_time = datetime.now()
        
        # Output callback for enriched intelligence
        self.output_callback: Optional[callable] = None
        
        # Create subscriber
        self.subscriber = MessageBusSubscriber(
            message_bus,
            [Topics.ROUTER_OBSERVATIONS, Topics.COMPUTER_OBSERVATIONS, Topics.EMAIL_OBSERVATIONS],
            self._handle_observation
        )
    
    def set_output_callback(self, callback: callable):
        """
        Set callback for enriched intelligence output.
        
        Args:
            callback: Function(enriched_intelligence) to call with results
        """
        self.output_callback = callback
    
    def start(self, blocking: bool = False):
        """
        Start subscribing to agent observations.
        
        Args:
            blocking: If True, blocks and processes messages
        """
        self.logger.info("Starting Knowledge Fusion subscriber")
        self.subscriber.start(blocking=blocking)
    
    def stop(self):
        """Stop subscriber."""
        self.subscriber.stop()
        self.logger.info("Knowledge Fusion subscriber stopped")
    
    def _handle_observation(self, topic: str, message_dict: Dict[str, Any]):
        """
        Handle incoming agent observation message.
        
        Args:
            topic: Message topic
            message_dict: Message data
        """
        try:
            # Extract AgentOutput from message
            agent_output = self._deserialize_agent_output(message_dict)
            
            if not agent_output:
                return
            
            # Add to buffer
            with self.buffer_lock:
                self.observation_buffer.append(agent_output)
                self.last_buffer_time = datetime.now()
            
            # Process buffer (collect observations from multiple agents)
            self._process_buffer()
            
        except Exception as e:
            self.logger.error(f"Error handling observation from {topic}: {e}")
    
    def _deserialize_agent_output(self, message_dict: Dict[str, Any]) -> Optional[AgentOutput]:
        """Deserialize AgentOutput from message dictionary."""
        try:
            # Remove metadata if present
            if '_metadata' in message_dict:
                del message_dict['_metadata']
            
            # Use AgentInterface to normalize
            agent_output = self.agent_interface.normalize_agent_output(message_dict)
            return agent_output
        except Exception as e:
            self.logger.error(f"Failed to deserialize AgentOutput: {e}")
            return None
    
    def _process_buffer(self):
        """Process observation buffer and run Knowledge Fusion."""
        with self.buffer_lock:
            # Check if we should process buffer
            time_since_last = (datetime.now() - self.last_buffer_time).total_seconds()
            
            # Process if we have observations from multiple agents or timeout
            agent_ids = set(obs.agent_id for obs in self.observation_buffer)
            should_process = (
                len(agent_ids) >= 2 or  # Multiple agents
                time_since_last > self.buffer_timeout or  # Timeout
                len(self.observation_buffer) >= 10  # Buffer full
            )
            
            if not should_process:
                return
            
            # Copy buffer and clear
            observations_to_process = self.observation_buffer.copy()
            self.observation_buffer.clear()
        
        # Process observations
        if observations_to_process:
            self._run_knowledge_fusion(observations_to_process)
    
    def _run_knowledge_fusion(self, agent_outputs: List[AgentOutput]):
        """
        Run Knowledge Fusion on agent outputs.
        
        Args:
            agent_outputs: List of AgentOutput objects
        """
        try:
            self.logger.info(
                f"Running Knowledge Fusion on {len(agent_outputs)} agent outputs"
            )
            
            # Run Knowledge Fusion
            enriched = self.knowledge_fusion.fuse(
                agent_outputs,
                threat_context_placeholder="[LLM context will be generated]"
            )
            
            # Enhance with RAG
            enhanced = self.rag_pipeline.enhance_with_rag(enriched, generate_context=True)
            enhanced = self.rag_pipeline.add_explainability_attribution(enhanced)
            
            # Publish enriched intelligence
            self._publish_enriched_intelligence(enhanced)
            
            # Call output callback if set
            if self.output_callback:
                try:
                    self.output_callback(enhanced)
                except Exception as e:
                    self.logger.error(f"Error in output callback: {e}")
            
            self.logger.info(
                f"Knowledge Fusion completed: {len(enhanced.matched_mitre_techniques)} "
                f"techniques matched"
            )
            
        except Exception as e:
            self.logger.error(f"Error running Knowledge Fusion: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
    
    def _publish_enriched_intelligence(self, enriched_intelligence):
        """Publish enriched intelligence to message bus and send feedback to agents."""
        try:
            # Serialize enriched intelligence
            message_dict = enriched_intelligence.model_dump()
            
            # Publish to topic
            self.message_bus.publish(Topics.ENRICHED_INTELLIGENCE, message_dict)
            
            # Send feedback to agents
            self._send_feedback_to_agents(enriched_intelligence)
            
            self.logger.debug("Published enriched intelligence to message bus")
        except Exception as e:
            self.logger.error(f"Failed to publish enriched intelligence: {e}")
    
    def _send_feedback_to_agents(self, enriched_intelligence):
        """
        Send feedback to agents based on enriched intelligence.
        
        Args:
            enriched_intelligence: EnrichedThreatIntelligence object
        """
        try:
            # Group observations by agent
            agent_observations = {}
            for agent_output in enriched_intelligence.original_observations:
                agent_id = agent_output.agent_id
                if agent_id not in agent_observations:
                    agent_observations[agent_id] = []
                agent_observations[agent_id].append(agent_output)
            
            # Send feedback to each agent
            for agent_id, observations in agent_observations.items():
                feedback = self._create_feedback(agent_id, observations, enriched_intelligence)
                
                # Publish feedback to agent's feedback topic
                feedback_topic = Topics.get_feedback_topic(agent_id)
                self.message_bus.publish(feedback_topic, feedback)
                
                self.logger.debug(f"Sent feedback to {agent_id} agent")
                
        except Exception as e:
            self.logger.error(f"Error sending feedback to agents: {e}")
    
    def _create_feedback(self, agent_id: str, observations: List[AgentOutput],
                        enriched_intelligence) -> Dict[str, Any]:
        """
        Create feedback message for an agent.
        
        Args:
            agent_id: Agent identifier
            observations: List of observations from this agent
            enriched_intelligence: Enriched threat intelligence
            
        Returns:
            Feedback dictionary
        """
        # Calculate feedback metrics
        confidence_scores = enriched_intelligence.confidence_scores
        matched_techniques = enriched_intelligence.matched_mitre_techniques
        
        # Determine feedback type
        overall_confidence = confidence_scores.get('overall', 0.5)
        
        if overall_confidence > 0.8:
            feedback_type = "high_confidence_detection"
        elif overall_confidence > 0.6:
            feedback_type = "medium_confidence_detection"
        else:
            feedback_type = "low_confidence_detection"
        
        # Extract relevant techniques for this agent
        agent_techniques = []
        for tech in matched_techniques:
            # Check if technique is relevant to agent's observations
            for obs in observations:
                if any(indicator in tech.description.lower() 
                      for indicator in obs.indicators):
                    agent_techniques.append({
                        'id': tech.external_id or tech.id,
                        'name': tech.name,
                        'tactic': tech.tactic,
                        'score': tech.score
                    })
                    break
        
        feedback = {
            'message_type': 'feedback',
            'target_agent': agent_id,
            'feedback_type': feedback_type,
            'timestamp': datetime.now().isoformat(),
            'feedback_data': {
                'overall_confidence': overall_confidence,
                'technique_matching_confidence': confidence_scores.get('technique_matching', 0.5),
                'tactic_matching_confidence': confidence_scores.get('tactic_matching', 0.5),
                'agent_confidence': confidence_scores.get('agent_confidence', 0.5),
                'matched_techniques': agent_techniques[:5],  # Top 5 techniques
                'matched_tactics': [
                    {
                        'name': tactic.name,
                        'score': tactic.score
                    }
                    for tactic in enriched_intelligence.matched_mitre_tactics[:3]
                ],
                'recommendations': self._generate_recommendations(
                    agent_id, overall_confidence, agent_techniques
                )
            }
        }
        
        return feedback
    
    def _generate_recommendations(self, agent_id: str, confidence: float,
                                 techniques: List[Dict]) -> List[str]:
        """Generate recommendations for agent based on feedback."""
        recommendations = []
        
        if confidence < 0.5:
            recommendations.append(
                "Consider lowering anomaly detection threshold to reduce false positives"
            )
        elif confidence > 0.8:
            recommendations.append(
                "High confidence detection - baseline learning is effective"
            )
        
        if len(techniques) == 0:
            recommendations.append(
                "No MITRE techniques matched - review observation patterns"
            )
        
        # Agent-specific recommendations
        if agent_id == "router":
            recommendations.append(
                "Monitor for additional network connections to detected destinations"
            )
        elif agent_id == "computer":
            recommendations.append(
                "Watch for related process execution and file access patterns"
            )
        elif agent_id == "email":
            recommendations.append(
                "Monitor for additional emails from detected sender domains"
            )
        
        return recommendations

