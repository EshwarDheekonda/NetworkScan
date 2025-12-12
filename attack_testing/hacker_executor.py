"""
Hacker Executor
Step-by-step attack execution engine with real-time progress streaming.
"""

import time
import uuid
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum
import logging

from attack_testing.attack_generator import AttackGenerator, AttackData, HackerScenario
from attack_testing.test_orchestrator import TestOrchestrator
from attack_testing.attack_scenarios import get_all_attack_types, get_attack_templates
from attack_testing.prompts.hacker_simulation import (
    get_predefined_attack_scenario_prompt,
    get_hacker_system_prompt
)
from knowledge_fusion.rag_pipeline import LLMProvider

logger = logging.getLogger(__name__)


class ExecutionState(Enum):
    """Execution state machine."""
    IDLE = "idle"
    INITIALIZING = "initializing"
    EXECUTING = "executing"
    WAITING_AGENT_REACTION = "waiting_agent_reaction"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class ExecutionStep:
    """Represents a single execution step."""
    
    def __init__(
        self,
        step_number: int,
        description: str,
        action: str,
        data: Optional[Dict[str, Any]] = None
    ):
        self.step_number = step_number
        self.description = description
        self.action = action
        self.data = data or {}
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.status: str = "pending"
        self.result: Optional[Dict[str, Any]] = None
        self.agent_reactions: List[Dict[str, Any]] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'step_number': self.step_number,
            'description': self.description,
            'action': self.action,
            'data': self.data,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'status': self.status,
            'result': self.result,
            'agent_reactions': self.agent_reactions,
            'duration_ms': (self.end_time - self.start_time) * 1000 if self.end_time and self.start_time else None
        }


class HackerExecutor:
    """Executes attacks step-by-step with real-time progress streaming."""
    
    def __init__(
        self,
        test_orchestrator: TestOrchestrator,
        attack_generator: Optional[AttackGenerator] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        """
        Initialize hacker executor.
        
        Args:
            test_orchestrator: TestOrchestrator instance
            attack_generator: Optional AttackGenerator instance
            event_emitter: Optional function to emit events (event_type, data)
        """
        self.test_orchestrator = test_orchestrator
        self.attack_generator = attack_generator or AttackGenerator()
        self.event_emitter = event_emitter
        self.execution_state = ExecutionState.IDLE
        self.current_execution_id: Optional[str] = None
        self.current_steps: List[ExecutionStep] = []
        self.current_step_index = 0
        self.cancelled = False  # Cancellation flag
        self.max_attack_attempts = 5  # Maximum number of attack attempts in continuous mode
        self.llm_provider = LLMProvider()  # For scenario generation
        self.logger = logging.getLogger(__name__)
    
    def cancel_execution(self):
        """Cancel current execution."""
        self.cancelled = True
        self.logger.info(f"Cancellation requested for execution {self.current_execution_id}")
        self.emit_event('hacker.execution.cancelled', {
            'execution_id': self.current_execution_id,
            'message': 'Execution cancelled by user'
        })
    
    def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit event if emitter is available."""
        if self.event_emitter:
            try:
                self.event_emitter(event_type, data)
            except Exception as e:
                self.logger.error(f"Error emitting event {event_type}: {e}", exc_info=True)
    
    def execute_predefined_attack(
        self,
        agent_type: str,
        attack_type: str,
        execution_id: Optional[str] = None,
        continuous: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a predefined attack scenario step-by-step with LLM scenario generation.
        
        Args:
            agent_type: Agent type to attack
            attack_type: Attack type identifier
            execution_id: Optional execution ID
            continuous: Whether to continue with multiple attack attempts
            
        Returns:
            Execution result dictionary
        """
        if self.execution_state != ExecutionState.IDLE:
            raise ValueError(f"Cannot start execution: current state is {self.execution_state.value}")
        
        execution_id = execution_id or str(uuid.uuid4())
        self.current_execution_id = execution_id
        self.execution_state = ExecutionState.INITIALIZING
        self.current_steps = []
        self.current_step_index = 0
        self.cancelled = False
        
        try:
            # Emit initialization event
            self.emit_event('hacker.execution.start', {
                'execution_id': execution_id,
                'agent_type': agent_type,
                'attack_type': attack_type,
                'mode': 'predefined',
                'continuous': continuous
            })
            
            # Get attack template info
            from attack_testing.attack_scenarios import get_attack_templates
            template = get_attack_templates(attack_type, agent_type)
            attack_name = template.get('name', attack_type) if template else attack_type
            attack_description = template.get('description', '') if template else ''
            
            # Step 0: Generate hacker scenario/plan using LLM
            step0 = ExecutionStep(
                step_number=0,
                description=f"Planning attack strategy for {attack_name}",
                action="generate_scenario"
            )
            self.current_steps.append(step0)
            self._execute_step(step0, lambda: self._generate_predefined_scenario_step(
                agent_type, attack_type, attack_name, attack_description
            ))
            
            if self.cancelled:
                raise InterruptedError("Execution cancelled by user")
            
            # Emit scenario for display
            scenario_text = step0.result.get('scenario_text', '') if step0.result else ''
            self.emit_event('hacker.scenario.generated', {
                'execution_id': execution_id,
                'scenario': scenario_text,
                'attack_type': attack_type,
                'attack_name': attack_name
            })
            
            # Wait a moment for user to see scenario
            time.sleep(1)
            
            # Continuous attack loop
            attack_attempt = 0
            all_attack_results = []
            
            while attack_attempt < self.max_attack_attempts and not self.cancelled:
                attack_attempt += 1
                step_num_base = len(self.current_steps)
                
                # Step 1: Generate attack data
                step1 = ExecutionStep(
                    step_number=step_num_base + 1,
                    description=f"Attack Attempt {attack_attempt}: Generating attack data",
                    action="generate_attack",
                    data={'attempt': attack_attempt}
                )
                self.current_steps.append(step1)
                self._execute_step(step1, lambda: self._generate_attack_step(agent_type, attack_type))
                
                if self.cancelled:
                    break
                
                # Step 2: Execute attack
                attack_data = step1.result.get('attack_data') if step1.result else None
                if not attack_data:
                    self.logger.warning(f"Failed to generate attack data for attempt {attack_attempt}")
                    continue
                
                step2 = ExecutionStep(
                    step_number=step_num_base + 2,
                    description=f"Attack Attempt {attack_attempt}: Executing attack against {agent_type} agent",
                    action="execute_attack",
                    data={'attempt': attack_attempt, 'attack_type': attack_type}
                )
                self.current_steps.append(step2)
                self._execute_step(step2, lambda: self._execute_attack_step(attack_data, agent_type))
                
                if self.cancelled:
                    break
                
                # Step 3: Analyze results
                test_result = step2.result.get('test_result') if step2.result else None
                all_attack_results.append({
                    'attempt': attack_attempt,
                    'test_result': test_result,
                    'detected': test_result.detected if test_result else False
                })
                
                step3 = ExecutionStep(
                    step_number=step_num_base + 3,
                    description=f"Attack Attempt {attack_attempt}: Analyzing agent reactions",
                    action="analyze_results",
                    data={'attempt': attack_attempt}
                )
                self.current_steps.append(step3)
                self._execute_step(step3, lambda: self._analyze_results_step(test_result))
                
                # Emit attack attempt result
                self.emit_event('hacker.attack.attempt', {
                    'execution_id': execution_id,
                    'attempt': attack_attempt,
                    'detected': test_result.detected if test_result else False,
                    'confidence': test_result.confidence if test_result else 0.0,
                    'max_anomaly_score': test_result.max_anomaly_score if test_result else 0.0
                })
                
                # If continuous mode and not cancelled, continue to next attack
                if not continuous:
                    break
                
                # Brief pause between attacks
                if attack_attempt < self.max_attack_attempts:
                    time.sleep(0.5)
            
            # Final summary
            if self.cancelled:
                self.execution_state = ExecutionState.FAILED
                result = {
                    'execution_id': execution_id,
                    'status': 'cancelled',
                    'agent_type': agent_type,
                    'attack_type': attack_type,
                    'steps': [step.to_dict() for step in self.current_steps],
                    'attack_attempts': attack_attempt,
                    'total_attempts': len(all_attack_results)
                }
                self.emit_event('hacker.execution.cancelled', result)
                return result
            else:
                self.execution_state = ExecutionState.COMPLETED
                detected_count = sum(1 for r in all_attack_results if r.get('detected', False))
                
                result = {
                    'execution_id': execution_id,
                    'status': 'completed',
                    'agent_type': agent_type,
                    'attack_type': attack_type,
                    'steps': [step.to_dict() for step in self.current_steps],
                    'total_attempts': len(all_attack_results),
                    'detected_count': detected_count,
                    'detection_rate': detected_count / len(all_attack_results) if all_attack_results else 0.0,
                    'attack_results': all_attack_results,
                    'total_duration_ms': sum(
                        (step.end_time - step.start_time) * 1000
                        for step in self.current_steps
                        if step.end_time and step.start_time
                    )
                }
                
                self.emit_event('hacker.execution.complete', result)
                return result
            
        except InterruptedError:
            # Cancellation handled above
            pass
        except Exception as e:
            self.logger.error(f"Error executing predefined attack: {e}", exc_info=True)
            self.execution_state = ExecutionState.FAILED
            error_result = {
                'execution_id': execution_id,
                'status': 'failed',
                'error': str(e),
                'steps': [step.to_dict() for step in self.current_steps]
            }
            self.emit_event('hacker.execution.failed', error_result)
            return error_result
        finally:
            # Reset state after a delay to allow events to be processed
            time.sleep(0.1)
            if self.execution_state in [ExecutionState.COMPLETED, ExecutionState.FAILED]:
                self.execution_state = ExecutionState.IDLE
                self.current_execution_id = None
                self.current_steps = []
                self.current_step_index = 0
                self.cancelled = False
    
    def execute_dynamic_attack(
        self,
        agent_type: str,
        context: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a dynamic hacker-generated attack step-by-step.
        
        Args:
            agent_type: Agent type to attack
            context: Optional context about target
            execution_id: Optional execution ID
            
        Returns:
            Execution result dictionary
        """
        if self.execution_state != ExecutionState.IDLE:
            raise ValueError(f"Cannot start execution: current state is {self.execution_state.value}")
        
        execution_id = execution_id or str(uuid.uuid4())
        self.current_execution_id = execution_id
        self.execution_state = ExecutionState.INITIALIZING
        self.current_steps = []
        self.current_step_index = 0
        
        try:
            # Emit initialization event
            self.emit_event('hacker.execution.start', {
                'execution_id': execution_id,
                'agent_type': agent_type,
                'mode': 'dynamic',
                'context': context
            })
            
            # Step 1: Generate hacker scenario
            step1 = ExecutionStep(
                step_number=1,
                description="Analyzing target and generating attack strategy",
                action="generate_strategy"
            )
            self.current_steps.append(step1)
            self._execute_step(step1, lambda: self._generate_strategy_step(agent_type, context))
            
            # Step 2: Execute attack
            scenario = step1.result.get('scenario') if step1.result else None
            if not scenario or not hasattr(scenario, 'attack_data'):
                raise ValueError("Failed to generate hacker scenario")
            
            step2 = ExecutionStep(
                step_number=2,
                description=f"Executing dynamic attack: {scenario.strategy}",
                action="execute_attack",
                data={'strategy': scenario.strategy, 'objectives': scenario.objectives}
            )
            self.current_steps.append(step2)
            self._execute_step(step2, lambda: self._execute_attack_step(scenario.attack_data, agent_type))
            
            # Step 3: Analyze and adapt
            test_result = step2.result.get('test_result') if step2.result else None
            step3 = ExecutionStep(
                step_number=3,
                description="Analyzing results and adapting strategy",
                action="analyze_and_adapt"
            )
            self.current_steps.append(step3)
            self._execute_step(step3, lambda: self._analyze_and_adapt_step(test_result, scenario))
            
            # Execution complete
            self.execution_state = ExecutionState.COMPLETED
            
            result = {
                'execution_id': execution_id,
                'status': 'completed',
                'agent_type': agent_type,
                'mode': 'dynamic',
                'strategy': scenario.strategy,
                'objectives': scenario.objectives,
                'steps': [step.to_dict() for step in self.current_steps],
                'final_result': step3.result if step3.result else {},
                'total_duration_ms': sum(
                    (step.end_time - step.start_time) * 1000
                    for step in self.current_steps
                    if step.end_time and step.start_time
                )
            }
            
            self.emit_event('hacker.execution.complete', result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing dynamic attack: {e}", exc_info=True)
            self.execution_state = ExecutionState.FAILED
            error_result = {
                'execution_id': execution_id,
                'status': 'failed',
                'error': str(e),
                'steps': [step.to_dict() for step in self.current_steps]
            }
            self.emit_event('hacker.execution.failed', error_result)
            return error_result
        finally:
            # Reset state after a delay
            time.sleep(0.1)
            if self.execution_state in [ExecutionState.COMPLETED, ExecutionState.FAILED]:
                self.execution_state = ExecutionState.IDLE
                self.current_execution_id = None
                self.current_steps = []
                self.current_step_index = 0
    
    def _execute_step(self, step: ExecutionStep, step_function: Callable[[], Dict[str, Any]]):
        """Execute a single step with progress tracking."""
        if self.cancelled:
            step.status = "cancelled"
            step.result = {'message': 'Step cancelled'}
            return
        
        step.status = "running"
        step.start_time = time.time()
        self.current_step_index = step.step_number - 1
        
        # Emit step start event
        self.emit_event('hacker.step.start', {
            'execution_id': self.current_execution_id,
            'step': step.to_dict()
        })
        
        try:
            # Execute step function
            self.execution_state = ExecutionState.EXECUTING
            
            # Emit progress update
            self.emit_event('hacker.step.progress', {
                'execution_id': self.current_execution_id,
                'step_number': step.step_number,
                'description': step.description,
                'status': 'executing'
            })
            
            # Check cancellation before executing
            if self.cancelled:
                step.status = "cancelled"
                step.result = {'message': 'Step cancelled before execution'}
                return
            
            result = step_function()
            
            # Check cancellation after execution
            if self.cancelled:
                step.status = "cancelled"
                step.result = result if result else {'message': 'Step cancelled after execution'}
                return
            
            step.result = result
            step.status = "completed"
            
            # Emit step complete event
            self.emit_event('hacker.step.complete', {
                'execution_id': self.current_execution_id,
                'step': step.to_dict()
            })
            
        except InterruptedError:
            step.status = "cancelled"
            step.result = {'message': 'Step cancelled'}
            raise
        except Exception as e:
            step.status = "failed"
            step.result = {'error': str(e)}
            self.logger.error(f"Error in step {step.step_number}: {e}", exc_info=True)
            
            self.emit_event('hacker.step.failed', {
                'execution_id': self.current_execution_id,
                'step': step.to_dict(),
                'error': str(e)
            })
            
            raise
        finally:
            step.end_time = time.time()
    
    def _generate_predefined_scenario_step(
        self, 
        agent_type: str, 
        attack_type: str, 
        attack_name: str, 
        attack_description: str
    ) -> Dict[str, Any]:
        """Generate hacker scenario/plan for predefined attack using LLM."""
        from attack_testing.prompts.hacker_simulation import (
            get_predefined_attack_scenario_prompt,
            get_hacker_system_prompt
        )
        
        prompt = get_predefined_attack_scenario_prompt(
            agent_type, attack_type, attack_name, attack_description
        )
        system_prompt = get_hacker_system_prompt()
        
        try:
            scenario_text = self.llm_provider.generate(prompt, system_prompt)
            
            return {
                'scenario_text': scenario_text,
                'attack_type': attack_type,
                'attack_name': attack_name,
                'agent_type': agent_type
            }
        except Exception as e:
            self.logger.error(f"Error generating scenario: {e}", exc_info=True)
            # Fallback scenario
            return {
                'scenario_text': f"Hacker plan: Execute {attack_name} attack against {agent_type} system. "
                               f"Strategy: {attack_description}. "
                               f"Will attempt to evade detection while achieving objectives.",
                'attack_type': attack_type,
                'attack_name': attack_name,
                'agent_type': agent_type,
                'error': str(e)
            }
    
    def _generate_attack_step(self, agent_type: str, attack_type: str) -> Dict[str, Any]:
        """Generate attack data step."""
        attack_data = self.attack_generator.generate_attack(
            attack_type=attack_type,
            agent_type=agent_type
        )
        
        return {
            'attack_data': attack_data,
            'description': attack_data.description,
            'technique_id': attack_data.technique_id,
            'technique_name': attack_data.technique_name
        }
    
    def _execute_attack_step(self, attack_data: AttackData, agent_type: str) -> Dict[str, Any]:
        """Execute attack against agent step."""
        self.execution_state = ExecutionState.WAITING_AGENT_REACTION
        
        # Emit attack starting event
        self.emit_event('hacker.attack.starting', {
            'execution_id': self.current_execution_id,
            'agent_type': agent_type,
            'attack_type': attack_data.attack_type,
            'attack_data': attack_data.data
        })
        
        # Run test - this should trigger agent processing and publishing
        test_result = self.test_orchestrator.run_test_from_attack_data(attack_data)
        
        # Collect agent reactions
        agent_reactions = []
        if test_result.detections:
            for detection in test_result.detections:
                reaction = {
                    'type': detection.type if hasattr(detection, 'type') else 'anomaly',
                    'severity': detection.metadata.get('severity', 'medium') if hasattr(detection, 'metadata') else 'medium',
                    'description': detection.description if hasattr(detection, 'description') else 'Anomaly detected',
                    'confidence': detection.metadata.get('confidence', 0.0) if hasattr(detection, 'metadata') else 0.0,
                    'anomaly_score': detection.metadata.get('anomaly_score', 0.0) if hasattr(detection, 'metadata') else 0.0,
                    'indicators': detection.indicators if hasattr(detection, 'indicators') else []
                }
                agent_reactions.append(reaction)
                
                # Emit agent reaction event immediately
                self.emit_event('hacker.agent.reaction', {
                    'execution_id': self.current_execution_id,
                    'step_number': self.current_step_index + 1,
                    'agent_type': agent_type,
                    'reaction': reaction,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Emit attack completion event
        self.emit_event('hacker.attack.completed', {
            'execution_id': self.current_execution_id,
            'agent_type': agent_type,
            'detected': test_result.detected,
            'reaction_count': len(agent_reactions),
            'confidence': test_result.confidence
        })
        
        return {
            'test_result': test_result,
            'detected': test_result.detected,
            'agent_reactions': agent_reactions,
            'confidence': test_result.confidence,
            'max_anomaly_score': test_result.max_anomaly_score,
            'reaction_count': len(agent_reactions)
        }
    
    def _analyze_results_step(self, test_result) -> Dict[str, Any]:
        """Analyze results step."""
        self.execution_state = ExecutionState.ANALYZING
        
        if not test_result:
            return {'analysis': 'No test result available'}
        
        analysis = {
            'detected': test_result.detected,
            'detection_count': len(test_result.detections) if test_result.detections else 0,
            'confidence': test_result.confidence,
            'max_anomaly_score': test_result.max_anomaly_score,
            'execution_time_ms': test_result.execution_time_ms,
            'summary': 'Attack detected' if test_result.detected else 'No detection'
        }
        
        return {'analysis': analysis}
    
    def _generate_strategy_step(self, agent_type: str, context: Optional[Dict]) -> Dict[str, Any]:
        """Generate hacker strategy step."""
        scenario = self.attack_generator.generate_hacker_scenario(agent_type, context)
        
        return {
            'scenario': scenario,
            'strategy': scenario.strategy,
            'objectives': scenario.objectives
        }
    
    def _analyze_and_adapt_step(self, test_result, scenario: HackerScenario) -> Dict[str, Any]:
        """Analyze results and adapt strategy step."""
        self.execution_state = ExecutionState.ANALYZING
        
        if not test_result:
            return {'analysis': 'No test result available', 'adaptation': 'No adaptation needed'}
        
        # Determine if attack was detected
        was_detected = test_result.detected
        
        adaptation = {
            'was_detected': was_detected,
            'detection_count': len(test_result.detections) if test_result.detections else 0,
            'recommendation': 'Attack was detected - consider evasion techniques' if was_detected else 'Attack went undetected - system may need improvement',
            'next_steps': []
        }
        
        if was_detected:
            adaptation['next_steps'].append('Consider using more sophisticated evasion techniques')
            adaptation['next_steps'].append('Try different attack vectors')
        else:
            adaptation['next_steps'].append('System did not detect attack - review detection capabilities')
        
        analysis = {
            'detected': was_detected,
            'confidence': test_result.confidence,
            'max_anomaly_score': test_result.max_anomaly_score,
            'adaptation': adaptation
        }
        
        return {'analysis': analysis}
    
    def get_predefined_scenarios(self, agent_type: str) -> List[Dict[str, Any]]:
        """
        Get list of predefined attack scenarios for an agent type.
        
        Args:
            agent_type: Agent type
            
        Returns:
            List of scenario dictionaries
        """
        attack_types = get_all_attack_types(agent_type)
        scenarios = []
        
        for attack_type in attack_types:
            template = get_attack_templates(attack_type, agent_type)
            if template:
                scenarios.append({
                    'attack_type': attack_type,
                    'name': template.get('name', attack_type),
                    'description': template.get('description', ''),
                    'techniques': template.get('techniques', []),
                    'characteristics': template.get('characteristics', [])
                })
        
        return scenarios
    
    def get_execution_status(self) -> Dict[str, Any]:
        """Get current execution status."""
        return {
            'state': self.execution_state.value,
            'execution_id': self.current_execution_id,
            'current_step': self.current_step_index + 1 if self.current_steps else 0,
            'total_steps': len(self.current_steps),
            'steps': [step.to_dict() for step in self.current_steps]
        }

