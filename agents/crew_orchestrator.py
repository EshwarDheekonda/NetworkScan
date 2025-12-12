"""
CrewAI Crew Orchestrator

Coordinates all three security agents (Router, Computer, Email) using CrewAI
framework for collaborative threat detection and analysis.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

try:
    from crewai import Crew, Process
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    Crew = None
    Process = None

from agents.llm_agents.router_llm_agent import RouterLLMAgent
from agents.llm_agents.computer_llm_agent import ComputerLLMAgent
from agents.llm_agents.email_llm_agent import EmailLLMAgent
from knowledge_fusion.interfaces import AgentOutput, Observation
from knowledge_fusion.fusion_core import KnowledgeFusion

# Optional import for training orchestrator
try:
    from baseline_training.training_orchestrator import TrainingOrchestrator
except ImportError:
    TrainingOrchestrator = None


class CrewOrchestrator:
    """Orchestrates security agents using CrewAI framework."""
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        knowledge_fusion: Optional[KnowledgeFusion] = None,
        training_orchestrator: Optional[Any] = None
    ):
        """
        Initialize the crew orchestrator.
        
        Args:
            config: Configuration dictionary
            knowledge_fusion: Optional KnowledgeFusion instance
            training_orchestrator: Optional TrainingOrchestrator instance for baseline integration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.knowledge_fusion = knowledge_fusion
        self.training_orchestrator = training_orchestrator
        
        # Retrieve trained baseline learners if training orchestrator is available
        baseline_learner_router = None
        baseline_learner_computer = None
        baseline_learner_email = None
        
        if training_orchestrator:
            try:
                baseline_learner_router = training_orchestrator.get_baseline_learner_for_agent('router')
                baseline_learner_computer = training_orchestrator.get_baseline_learner_for_agent('computer')
                baseline_learner_email = training_orchestrator.get_baseline_learner_for_agent('email')
                
                if baseline_learner_router:
                    self.logger.info("Using trained baseline learner for router agent")
                if baseline_learner_computer:
                    self.logger.info("Using trained baseline learner for computer agent")
                if baseline_learner_email:
                    self.logger.info("Using trained baseline learner for email agent")
            except Exception as e:
                self.logger.warning(f"Could not retrieve baseline learners from training orchestrator: {e}")
        
        # Initialize agents with trained baseline learners
        self.router_agent = RouterLLMAgent(
            config=self.config.get('router', {}),
            baseline_learner=baseline_learner_router,
            knowledge_fusion=knowledge_fusion
        )
        
        self.computer_agent = ComputerLLMAgent(
            config=self.config.get('computer', {}),
            baseline_learner=baseline_learner_computer,
            knowledge_fusion=knowledge_fusion
        )
        
        self.email_agent = EmailLLMAgent(
            config=self.config.get('email', {}),
            baseline_learner=baseline_learner_email,
            knowledge_fusion=knowledge_fusion
        )
        
        # Register agents with training orchestrator for mode synchronization
        if training_orchestrator and hasattr(training_orchestrator, 'register_agent'):
            training_orchestrator.register_agent('router', self.router_agent)
            training_orchestrator.register_agent('computer', self.computer_agent)
            training_orchestrator.register_agent('email', self.email_agent)
        
        # CrewAI crew (will be created when needed)
        self.crew = None
        self.crew_initialized = False
        
        # Agent registry
        self.agents = {
            'router': self.router_agent,
            'computer': self.computer_agent,
            'email': self.email_agent
        }
    
    def initialize_crew(self):
        """Initialize CrewAI crew with agents."""
        if not CREWAI_AVAILABLE:
            self.logger.warning("CrewAI not available - running without crew orchestration")
            self.crew_initialized = False
            return
        
        if self.crew_initialized:
            return
        
        try:
            # Get CrewAI agents from LLM agents
            crewai_agents = []
            
            if self.router_agent.crewai_agent:
                crewai_agents.append(self.router_agent.crewai_agent)
            if self.computer_agent.crewai_agent:
                crewai_agents.append(self.computer_agent.crewai_agent)
            if self.email_agent.crewai_agent:
                crewai_agents.append(self.email_agent.crewai_agent)
            
            if not crewai_agents:
                self.logger.warning("No CrewAI agents available - creating basic crew")
                # Create basic crew without specific agents
                self.crew = None
            else:
                # Create crew with agents
                # Note: In a full implementation, we would create Tasks for the crew
                # For now, we'll use the agents directly
                self.crew = Crew(
                    agents=crewai_agents,
                    process=Process.sequential,  # Sequential processing
                    verbose=True
                )
            
            self.crew_initialized = True
            self.logger.info("CrewAI crew initialized")
        
        except Exception as e:
            self.logger.error(f"Failed to initialize CrewAI crew: {e}")
            self.crew_initialized = False
    
    def process_data(
        self,
        agent_id: str,
        data: Any
    ) -> Optional[AgentOutput]:
        """
        Process data through a specific agent.
        
        Args:
            agent_id: ID of the agent (router, computer, email)
            data: Data to process
            
        Returns:
            AgentOutput if observations generated, None otherwise
        """
        if agent_id not in self.agents:
            self.logger.error(f"Unknown agent ID: {agent_id}")
            return None
        
        agent = self.agents[agent_id]
        return agent.process_and_publish(data)
    
    def process_multi_agent_data(
        self,
        data_by_agent: Dict[str, Any]
    ) -> List[AgentOutput]:
        """
        Process data through multiple agents and correlate results.
        
        Args:
            data_by_agent: Dictionary mapping agent_id to data
            
        Returns:
            List of AgentOutput objects
        """
        agent_outputs = []
        
        # Process each agent's data
        for agent_id, data in data_by_agent.items():
            output = self.process_data(agent_id, data)
            if output:
                agent_outputs.append(output)
        
        # Cross-agent correlation if multiple agents have observations
        if len(agent_outputs) > 1:
            self._correlate_agent_outputs(agent_outputs)
        
        return agent_outputs
    
    def _correlate_agent_outputs(self, agent_outputs: List[AgentOutput]):
        """
        Correlate observations across multiple agents and trigger proactive warnings.
        
        Args:
            agent_outputs: List of agent outputs to correlate
        """
        # Extract all indicators
        indicator_map = {}
        for output in agent_outputs:
            for obs in output.observations:
                for indicator in obs.indicators:
                    if indicator not in indicator_map:
                        indicator_map[indicator] = []
                    indicator_map[indicator].append({
                        'agent': output.agent_id,
                        'observation': obs
                    })
        
        # Find common indicators
        common_indicators = {
            ind: agents for ind, agents in indicator_map.items()
            if len(agents) > 1
        }
        
        if common_indicators:
            self.logger.info(f"Found {len(common_indicators)} common indicators across agents")
            
            # Add correlation metadata to observations
            for output in agent_outputs:
                for obs in output.observations:
                    correlated_indicators = []
                    for indicator in obs.indicators:
                        if indicator in common_indicators:
                            correlated_indicators.append(indicator)
                    
                    if correlated_indicators:
                        if 'correlation' not in obs.metadata:
                            obs.metadata['correlation'] = {}
                        obs.metadata['correlation']['common_indicators'] = correlated_indicators
                        obs.metadata['correlation']['correlated_agents'] = [
                            item['agent'] for item in common_indicators[correlated_indicators[0]]
                            if item['agent'] != output.agent_id
                        ]
            
            # Trigger proactive warning for coordinated attack
            self._trigger_coordinated_attack_warning(agent_outputs, common_indicators)
    
    def _trigger_coordinated_attack_warning(
        self,
        agent_outputs: List[AgentOutput],
        common_indicators: Dict[str, List[Dict[str, Any]]]
    ):
        """
        Trigger proactive warning for coordinated attack detected across multiple agents.
        
        Args:
            agent_outputs: List of agent outputs
            common_indicators: Dictionary of common indicators
        """
        try:
            # Collect all observations
            all_observations = []
            for output in agent_outputs:
                all_observations.extend(output.observations)
            
            if not all_observations:
                return
            
            # Extract indicators
            all_indicators = []
            for obs in all_observations:
                all_indicators.extend(obs.indicators)
            
            # Get MITRE techniques from observations
            mitre_techniques = []
            for obs in all_observations:
                if 'mitre_techniques' in obs.metadata:
                    techs = obs.metadata['mitre_techniques']
                    if isinstance(techs, list):
                        mitre_techniques.extend(techs)
            
            # Determine attack type
            attack_type = "Coordinated Multi-Vector Attack"
            if len(agent_outputs) == 2:
                agent_ids = [ao.agent_id for ao in agent_outputs]
                attack_type = f"Coordinated Attack ({' + '.join(agent_ids)})"
            
            # Determine severity
            max_severity = max(
                (obs.severity for obs in all_observations),
                default='medium'
            )
            
            # Calculate confidence based on correlation
            base_confidence = max(
                (ao.confidence for ao in agent_outputs),
                default=0.5
            )
            # Boost confidence for multi-agent correlation
            correlation_boost = min(0.3, len(common_indicators) * 0.1)
            confidence = min(1.0, base_confidence + correlation_boost)
            
            # Get detected agents
            detected_by = [ao.agent_id for ao in agent_outputs]
            
            # Generate warning (would need notification system)
            # For now, log it
            self.logger.warning(
                f"COORDINATED ATTACK DETECTED: {attack_type} "
                f"by {', '.join(detected_by)} agents. "
                f"Common indicators: {len(common_indicators)}. "
                f"Confidence: {confidence:.2f}"
            )
            
            # If knowledge fusion available, get mitigations
            mitigations = []
            if self.knowledge_fusion:
                try:
                    enriched = self.knowledge_fusion.fuse(agent_outputs)
                    mitigations = [
                        {
                            'id': m.id,
                            'name': m.name,
                            'description': m.description
                        }
                        for m in enriched.mitigations[:5]
                    ]
                except Exception as e:
                    self.logger.debug(f"Could not get mitigations: {e}")
            
            # Publish to message bus if available
            # (In full implementation, would use notification system)
            
        except Exception as e:
            self.logger.error(f"Error triggering coordinated attack warning: {e}")
    
    def start(self):
        """Start all agents."""
        self.initialize_crew()
        
        for agent_id, agent in self.agents.items():
            agent.start()
            self.logger.info(f"Started agent: {agent_id}")
    
    def stop(self):
        """Stop all agents."""
        for agent_id, agent in self.agents.items():
            agent.stop()
            self.logger.info(f"Stopped agent: {agent_id}")
    
    def set_action_guard(self, action_guard):
        """Set action guardrails for all agents."""
        for agent in self.agents.values():
            agent.set_action_guard(action_guard)
    
    def set_publishers(self, publishers: Dict[str, Any]):
        """Set message bus publishers for agents."""
        for agent_id, publisher in publishers.items():
            if agent_id in self.agents:
                self.agents[agent_id].set_publisher(publisher)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics from all agents."""
        stats = {
            'agents': {},
            'total_observations': 0,
            'total_anomalies': 0,
            'crew_initialized': self.crew_initialized
        }
        
        for agent_id, agent in self.agents.items():
            agent_stats = agent.get_stats()
            stats['agents'][agent_id] = agent_stats
            stats['total_observations'] += agent_stats.get('observation_count', 0)
            stats['total_anomalies'] += agent_stats.get('anomaly_count', 0)
        
        return stats



