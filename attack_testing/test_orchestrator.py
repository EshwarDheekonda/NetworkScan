"""
Test Orchestrator

Orchestrates the testing workflow: check training status, generate attacks,
feed to agents, collect results, and generate reports.
"""

import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid


from attack_testing.attack_generator import AttackGenerator, AttackData
from attack_testing.chat_interface import ChatInterface
from attack_testing.test_results import TestResult, TestReport, SequenceTestResult
from knowledge_fusion.interfaces import Observation
from baseline_training.training_orchestrator import TrainingOrchestrator

logger = logging.getLogger(__name__)


class TestOrchestrator:
    """Orchestrates attack testing workflow."""
    
    def __init__(
        self,
        agents: Dict[str, Any],  # Dict of agent_id -> agent instance
        training_orchestrator: Optional[TrainingOrchestrator] = None,
        attack_generator: Optional[AttackGenerator] = None,
        chat_interface: Optional[ChatInterface] = None
    ):
        """
        Initialize test orchestrator.
        
        Args:
            agents: Dictionary of agent instances (agent_id -> agent)
            training_orchestrator: Optional TrainingOrchestrator for checking training status
            attack_generator: Optional AttackGenerator instance
            chat_interface: Optional ChatInterface instance
        """
        self.agents = agents
        self.training_orchestrator = training_orchestrator
        self.attack_generator = attack_generator or AttackGenerator()
        self.chat_interface = chat_interface or ChatInterface(self.attack_generator)
        self.logger = logging.getLogger(__name__)
        
        # Store test results
        self.test_results: List[TestResult] = []
        self.sequence_results: List[SequenceTestResult] = []
    
    def check_training_status(self) -> Dict[str, Any]:
        """
        Check if agents are trained and ready for testing.
        
        Returns:
            Dictionary with training status for each agent
        """
        status = {
            'all_trained': True,
            'agents': {}
        }
        
        if not self.training_orchestrator:
            # If no training orchestrator, assume agents are ready
            for agent_id in self.agents.keys():
                status['agents'][agent_id] = {
                    'trained': True,
                    'reason': 'No training orchestrator configured'
                }
            return status
        
        # Check training status from orchestrator
        training_status = self.training_orchestrator.get_status()
        
        for agent_id in self.agents.keys():
            agent_status = training_status.get(agent_id, {})
            is_trained = agent_status.get('status') == 'trained'
            
            status['agents'][agent_id] = {
                'trained': is_trained,
                'status': agent_status.get('status', 'unknown'),
                'samples_trained': agent_status.get('samples_trained', 0),
                'reason': agent_status.get('message', '')
            }
            
            if not is_trained:
                status['all_trained'] = False
        
        return status
    
    def run_attack_test(
        self,
        attack_data: Dict[str, Any],
        agent_id: str,
        expected_detection: bool = True
    ) -> TestResult:
        """
        Run a single attack test.
        
        Args:
            attack_data: Attack data dictionary
            agent_id: Agent ID to test against
            expected_detection: Whether we expect the attack to be detected
            
        Returns:
            TestResult object
        """
        if agent_id not in self.agents:
            raise ValueError(f"Unknown agent ID: {agent_id}")
        
        agent = self.agents[agent_id]
        start_time = time.time()
        
        # Process attack data through agent
        try:
            # Set agent to inference mode (don't learn from attacks)
            original_mode = getattr(agent, 'training_mode', 'hybrid')
            if hasattr(agent, 'set_training_mode'):
                agent.set_training_mode('inference')
            
            # Mark this as attack test data in metadata
            if isinstance(attack_data, dict):
                attack_data['_is_attack_test'] = True
                attack_data['_attack_type'] = attack_data.get('attack_type', 'unknown')
            
            # Process the attack data
            # Try process_and_publish first, fallback to process_data
            if hasattr(agent, 'process_and_publish'):
                agent_output = agent.process_and_publish(attack_data)
            elif hasattr(agent, 'process_data'):
                observations_list = agent.process_data(attack_data)
                # Create mock AgentOutput for compatibility
                from knowledge_fusion.interfaces import AgentOutput
                agent_output = AgentOutput(
                    agent_id=agent_id,
                    timestamp=datetime.now(),
                    observations=observations_list,
                    confidence=0.0
                )
            else:
                raise ValueError(f"Agent {agent_id} does not have process_and_publish or process_data method")
            
            # Restore original mode
            if hasattr(agent, 'set_training_mode'):
                agent.set_training_mode(original_mode)
            
            # Extract observations
            observations = agent_output.observations if agent_output else []
            detected = len(observations) > 0
            
            # Calculate metrics
            max_anomaly_score = 0.0
            if observations:
                for obs in observations:
                    # Check for max_anomaly_score first, then fallback to anomaly_scores
                    score = obs.metadata.get('max_anomaly_score', 0.0)
                    if score == 0.0 and 'anomaly_scores' in obs.metadata:
                        # Extract max from anomaly_scores dict if available
                        anomaly_scores = obs.metadata.get('anomaly_scores', {})
                        if isinstance(anomaly_scores, dict) and anomaly_scores:
                            score = max(anomaly_scores.values())
                    max_anomaly_score = max(max_anomaly_score, score)
            
            confidence = agent_output.confidence if agent_output else 0.0
            
            execution_time = (time.time() - start_time) * 1000  # ms
            
            # Create test result
            result = TestResult(
                attack_data=attack_data,
                agent_id=agent_id,
                attack_type=attack_data.get('attack_type', 'unknown'),
                expected_detection=expected_detection,
                detections=observations,
                detected=detected,
                confidence=confidence,
                max_anomaly_score=max_anomaly_score,
                execution_time_ms=execution_time
            )
            
            result.calculate_metrics()
            self.test_results.append(result)
            
            return result
        
        except Exception as e:
            self.logger.error(f"Error running attack test: {e}", exc_info=True)
            
            result = TestResult(
                attack_data=attack_data,
                agent_id=agent_id,
                attack_type=attack_data.get('attack_type', 'unknown'),
                expected_detection=expected_detection,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000
            )
            
            self.test_results.append(result)
            return result
    
    def run_attack_sequence(
        self,
        sequence: List[Dict[str, Any]],
        technique_id: Optional[str] = None
    ) -> SequenceTestResult:
        """
        Run a multi-step attack sequence.
        
        Args:
            sequence: List of attack data dictionaries with step info
            technique_id: Optional MITRE technique ID
            
        Returns:
            SequenceTestResult object
        """
        sequence_id = str(uuid.uuid4())
        step_results = []
        
        for step_data in sequence:
            agent_id = step_data.get('agent', step_data.get('agent_type'))
            attack_data = step_data.get('data', step_data)
            
            if not agent_id:
                self.logger.warning("Step missing agent_id, skipping")
                continue
            
            # Run test for this step
            result = self.run_attack_test(attack_data, agent_id)
            step_results.append(result)
        
        # Create sequence result
        sequence_result = SequenceTestResult(
            sequence_id=sequence_id,
            technique_id=technique_id or 'unknown',
            steps=step_results
        )
        
        sequence_result.calculate_metrics()
        self.sequence_results.append(sequence_result)
        
        return sequence_result
    
    def run_test_from_attack_data(
        self,
        attack_data: AttackData,
        expected_detection: bool = True
    ) -> TestResult:
        """
        Run test from AttackData object.
        
        Args:
            attack_data: AttackData object
            expected_detection: Whether we expect detection
            
        Returns:
            TestResult object
        """
        return self.run_attack_test(
            attack_data.data,
            attack_data.agent_type,
            expected_detection
        )
    
    def generate_test_report(
        self,
        test_id: Optional[str] = None,
        results: Optional[List[TestResult]] = None
    ) -> TestReport:
        """
        Generate comprehensive test report.
        
        Args:
            test_id: Optional test ID (generated if not provided)
            results: Optional list of results (uses stored results if not provided)
            
        Returns:
            TestReport object
        """
        if test_id is None:
            test_id = f"test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if results is None:
            results = self.test_results
        
        report = TestReport(
            test_id=test_id,
            results=results,
            sequence_results=self.sequence_results
        )
        
        report.calculate_metrics()
        
        return report
    
    def clear_results(self):
        """Clear stored test results."""
        self.test_results = []
        self.sequence_results = []
    
    def get_recent_results(self, limit: int = 10) -> List[TestResult]:
        """
        Get recent test results.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of TestResult objects
        """
        return self.test_results[-limit:] if self.test_results else []
    
    def run_chat_test(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TestResult:
        """
        Run test from chat message.
        
        Args:
            message: User chat message
            context: Optional context
            
        Returns:
            TestResult object
        """
        # Process chat message
        chat_response = self.chat_interface.process_message(message, context)
        
        if chat_response.requires_clarification:
            raise ValueError(f"Clarification needed: {chat_response.message}")
        
        # Get attack data
        if chat_response.attack_data:
            return self.run_test_from_attack_data(chat_response.attack_data)
        elif chat_response.hacker_scenario:
            return self.run_test_from_attack_data(chat_response.hacker_scenario.attack_data)
        else:
            raise ValueError("No attack data generated from chat message")
    
    def run_hacker_mode_test(
        self,
        agent_type: str,
        context: Optional[Dict] = None
    ) -> TestResult:
        """
        Run test in hacker mode.
        
        Args:
            agent_type: Agent type to attack
            context: Optional context
            
        Returns:
            TestResult object
        """
        scenario = self.attack_generator.generate_hacker_scenario(agent_type, context)
        return self.run_test_from_attack_data(scenario.attack_data)
    
    def run_random_attack_test(self, agent_type: str) -> TestResult:
        """
        Run test with random attack.
        
        Args:
            agent_type: Agent type to attack
            
        Returns:
            TestResult object
        """
        attack_data = self.attack_generator.generate_random_attack(agent_type)
        return self.run_test_from_attack_data(attack_data)

