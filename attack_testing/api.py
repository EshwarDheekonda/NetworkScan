"""
REST API Endpoints

REST API for attack testing system integration.
"""

from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from datetime import datetime
import logging
import os
import tempfile
import threading

from attack_testing.test_orchestrator import TestOrchestrator
from attack_testing.attack_generator import AttackGenerator
from attack_testing.chat_interface import ChatInterface
from attack_testing.hacker_executor import HackerExecutor
from attack_testing.test_results import TestResult, TestReport
from baseline_training import training_api
from communication.message_bus import MessageBus, MessageBusSubscriber
from communication.message_types import Topics

logger = logging.getLogger(__name__)

# Global variables for system state
_system_running = False
_message_bus = None
_message_subscriber = None
_socketio = None
_socketio = None


def create_app(
    test_orchestrator: Optional[TestOrchestrator] = None,
    agents: Optional[Dict[str, Any]] = None,
    message_bus: Optional[MessageBus] = None
) -> Flask:
    """
    Create Flask app with attack testing API endpoints.
    
    Args:
        test_orchestrator: Optional TestOrchestrator instance
        agents: Optional dictionary of agents (used if orchestrator not provided)
        message_bus: Optional MessageBus instance for real-time updates
        
    Returns:
        Flask app instance
    """
    global _message_bus, _socketio
    
    app = Flask(__name__)
    CORS(app)  # Enable CORS for frontend integration
    
    # Initialize SocketIO
    global _socketio
    _socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
    
    # Initialize orchestrator if not provided
    if test_orchestrator is None:
        if agents is None:
            raise ValueError("Either test_orchestrator or agents must be provided")
        test_orchestrator = TestOrchestrator(agents=agents)
    
    orchestrator = test_orchestrator
    _message_bus = message_bus
    
    # Initialize hacker executor with event emitter
    def emit_hacker_event(event_type: str, data: Dict[str, Any]):
        """Emit hacker execution events via WebSocket."""
        if _socketio:
            _socketio.emit(event_type, data, namespace='/')
    
    hacker_executor = HackerExecutor(
        test_orchestrator=orchestrator,
        attack_generator=orchestrator.attack_generator,
        event_emitter=emit_hacker_event
    )
    
    # Initialize message bus subscriber if available
    if _message_bus:
        setup_message_bus_subscriber(_message_bus, _socketio)
    
    @app.route('/api/test/status', methods=['GET'])
    def get_status():
        """Get training and system status."""
        try:
            training_status = orchestrator.check_training_status()
            return jsonify({
                'success': True,
                'training_status': training_status,
                'agents_available': list(orchestrator.agents.keys()),
                'test_results_count': len(orchestrator.test_results)
            }), 200
        except Exception as e:
            logger.error(f"Error getting status: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/chat', methods=['POST'])
    def process_chat():
        """Process chat message and generate attack."""
        try:
            data = request.get_json()
            message = data.get('message', '')
            context = data.get('context')
            agent_type = data.get('agent_type')
            
            if not message:
                return jsonify({
                    'success': False,
                    'error': 'Message is required'
                }), 400
            
            # Process message through chat interface
            chat_response = orchestrator.chat_interface.process_message(
                message, context, agent_type
            )
            
            # If clarification needed, return that
            if chat_response.requires_clarification:
                return jsonify({
                    'success': True,
                    'requires_clarification': True,
                    'message': chat_response.message,
                    'questions': chat_response.clarification_questions
                }), 200
            
            # Don't auto-execute tests in chat - let user choose
            # Run test if attack data generated (only for backward compatibility)
            test_result = None
            auto_execute = data.get('auto_execute', False)
            if auto_execute and (chat_response.attack_data or chat_response.hacker_scenario):
                attack_data = chat_response.attack_data or chat_response.hacker_scenario.attack_data
                test_result = orchestrator.run_test_from_attack_data(attack_data)
            
            # Serialize attack_data properly
            attack_data_dict = None
            if chat_response.attack_data:
                attack_data_dict = {
                    'agent_type': chat_response.attack_data.agent_type,
                    'attack_type': chat_response.attack_data.attack_type,
                    'data': chat_response.attack_data.data,
                    'description': chat_response.attack_data.description,
                    'technique_id': chat_response.attack_data.technique_id,
                    'technique_name': chat_response.attack_data.technique_name,
                    'indicators': chat_response.attack_data.indicators
                }
            
            return jsonify({
                'success': True,
                'message': chat_response.message,
                'attack_data': attack_data_dict,
                'test_result': test_result.to_dict() if test_result else None,
                'intent': {
                    'agent_type': chat_response.intent.agent_type if chat_response.intent else None,
                    'attack_type': chat_response.intent.attack_type if chat_response.intent else None,
                    'mode': chat_response.intent.mode if chat_response.intent else None
                } if chat_response.intent else None
            }), 200
        
        except Exception as e:
            logger.error(f"Error processing chat: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/generate-attack', methods=['POST'])
    def generate_attack():
        """Generate attack data."""
        try:
            data = request.get_json()
            attack_type = data.get('attack_type')
            agent_type = data.get('agent_type')
            description = data.get('description')
            technique_id = data.get('technique_id')
            
            if not attack_type or not agent_type:
                return jsonify({
                    'success': False,
                    'error': 'attack_type and agent_type are required'
                }), 400
            
            # Generate attack
            attack_data = orchestrator.attack_generator.generate_attack(
                attack_type=attack_type,
                agent_type=agent_type,
                description=description,
                technique_id=technique_id
            )
            
            return jsonify({
                'success': True,
                'attack_data': {
                    'agent_type': attack_data.agent_type,
                    'attack_type': attack_data.attack_type,
                    'data': attack_data.data,
                    'description': attack_data.description,
                    'technique_id': attack_data.technique_id,
                    'technique_name': attack_data.technique_name,
                    'indicators': attack_data.indicators
                }
            }), 200
        
        except Exception as e:
            logger.error(f"Error generating attack: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/run-test', methods=['POST'])
    def run_test():
        """Run attack test."""
        try:
            data = request.get_json()
            attack_data = data.get('attack_data')
            agent_id = data.get('agent_id')
            expected_detection = data.get('expected_detection', True)
            
            if not attack_data or not agent_id:
                return jsonify({
                    'success': False,
                    'error': 'attack_data and agent_id are required'
                }), 400
            
            # Run test
            result = orchestrator.run_attack_test(
                attack_data=attack_data,
                agent_id=agent_id,
                expected_detection=expected_detection
            )
            
            return jsonify({
                'success': True,
                'test_result': result.to_dict()
            }), 200
        
        except Exception as e:
            logger.error(f"Error running test: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/auto-test', methods=['POST'])
    def auto_test():
        """Automatically generate and run an attack test with random agent and attack type."""
        try:
            import random
            
            # Define available attacks per agent
            AGENT_ATTACKS = {
                'router': ['c2_channel', 'data_exfiltration', 'port_scanning', 'lateral_movement'],
                'computer': ['process_injection', 'privilege_escalation', 'persistence', 'powershell_attack'],
                'email': ['phishing', 'malicious_attachment', 'email_spoofing', 'credential_harvesting']
            }
            
            # Randomly select agent type and attack type
            agent_type = random.choice(['router', 'computer', 'email'])
            attack_type = random.choice(AGENT_ATTACKS[agent_type])
            
            logger.info(f"Auto-test: Generating {attack_type} attack for {agent_type} agent")
            
            # Generate attack
            attack_data = orchestrator.attack_generator.generate_attack(
                attack_type=attack_type,
                agent_type=agent_type
            )
            
            # Run test and emit results via WebSocket
            try:
                logger.info(f"Running attack test for {agent_type} agent with attack type: {attack_data.attack_type}")
                logger.info(f"Attack data keys: {list(attack_data.data.keys()) if isinstance(attack_data.data, dict) else 'Not a dict'}")
                
                test_result = orchestrator.run_attack_test(
                    attack_data=attack_data.data,
                    agent_id=agent_type,
                    expected_detection=True
                )
                
                logger.info(f"Auto-test completed: detected={test_result.detected}, confidence={test_result.confidence}, observations={len(test_result.detections)}, max_anomaly_score={test_result.max_anomaly_score}")
                
                if test_result.error:
                    logger.error(f"Test had error: {test_result.error}")
                
                if test_result.detections:
                    logger.info(f"Generated {len(test_result.detections)} observations")
                    for i, obs in enumerate(test_result.detections[:3]):
                        logger.info(f"  Observation {i+1}: {obs.description[:80]}... (severity: {obs.severity})")
                else:
                    logger.warning(f"No observations generated! This might mean:")
                    logger.warning(f"  - Anomaly scores were too low (< 0.4)")
                    logger.warning(f"  - Baselines not ready and data doesn't look like attack")
                    logger.warning(f"  - LLM analysis determined it's not a threat")
                
                # Emit observations directly via WebSocket if available
                if _socketio:
                    if test_result.detections:
                        # Emit observations to the appropriate agent channel
                        agent_observation_event = f"{agent_type}-observation"
                        
                        # Convert observations to dict format
                        observations_data = []
                        for obs in test_result.detections:
                            # Use Pydantic's model_dump if available (v2), otherwise dict() (v1)
                            if hasattr(obs, 'model_dump'):
                                obs_dict = obs.model_dump()
                            elif hasattr(obs, 'dict'):
                                obs_dict = obs.dict()
                            else:
                                # Fallback manual conversion
                                obs_dict = {
                                    'type': getattr(obs, 'type', 'observation'),
                                    'description': obs.description,
                                    'severity': obs.severity,
                                    'indicators': obs.indicators,
                                    'metadata': obs.metadata
                                }
                            # Ensure timestamp is serializable
                            if 'timestamp' in obs_dict and hasattr(obs_dict['timestamp'], 'isoformat'):
                                obs_dict['timestamp'] = obs_dict['timestamp'].isoformat()
                            observations_data.append(obs_dict)
                        
                        # Emit agent output with observations
                        agent_output_data = {
                            'agent_id': agent_type,
                            'observations': observations_data,
                            'confidence': test_result.confidence,
                            'timestamp': test_result.timestamp.isoformat() if hasattr(test_result.timestamp, 'isoformat') else str(test_result.timestamp),
                            'metadata': {
                                'attack_type': attack_data.attack_type,
                                'detected': test_result.detected,
                                'max_anomaly_score': test_result.max_anomaly_score,
                                'anomaly_score': test_result.max_anomaly_score  # Also include for backward compatibility
                            }
                        }
                        
                        # Log MITRE data in observations for debugging
                        for i, obs_dict in enumerate(observations_data):
                            if obs_dict.get('metadata', {}).get('llm_analysis', {}).get('proactive_mitre'):
                                mitre_data = obs_dict['metadata']['llm_analysis']['proactive_mitre']
                                logger.info(f"Observation {i} for {agent_type} has MITRE data: {len(mitre_data.get('matched_techniques', []))} techniques, {len(mitre_data.get('matched_tactics', []))} tactics")
                            else:
                                logger.warning(f"Observation {i} for {agent_type} missing proactive_mitre in llm_analysis")
                        
                        # Emit directly - frontend expects the data structure directly
                        _socketio.emit(agent_observation_event, agent_output_data)
                        logger.info(f"Emitted {len(observations_data)} observations to {agent_observation_event}")
                        
                        # Emit agent output to outputs feed
                        _socketio.emit('agent-output', {
                            'agent_id': agent_type,
                            'output': {
                                'observations_count': len(observations_data),
                                'confidence': test_result.confidence,
                                'max_anomaly_score': test_result.max_anomaly_score,
                                'detected': test_result.detected,
                                'attack_type': attack_data.attack_type,
                                'timestamp': test_result.timestamp.isoformat() if hasattr(test_result.timestamp, 'isoformat') else str(test_result.timestamp)
                            }
                        })
                        
                        # Extract and emit proactive warnings from observations
                        for obs in test_result.detections:
                            if obs.metadata and 'llm_analysis' in obs.metadata:
                                llm_analysis = obs.metadata['llm_analysis']
                                if llm_analysis.get('is_threat', False):
                                    # Check for proactive warning data in llm_analysis first
                                    proactive_mitre = llm_analysis.get('proactive_mitre', {})
                                    
                                    # Fallback: check observation metadata directly
                                    if not proactive_mitre or not proactive_mitre.get('matched_techniques'):
                                        proactive_mitre = obs.metadata.get('proactive_mitre', {})
                                    
                                    logger.info(f"Found proactive_mitre for {agent_type}: techniques={len(proactive_mitre.get('matched_techniques', []))}, tactics={len(proactive_mitre.get('matched_tactics', []))}")
                                    
                                    # Log MITRE data for debugging
                                    if proactive_mitre.get('matched_techniques'):
                                        logger.info(f"MITRE techniques: {[t.get('id', t.get('name', 'Unknown')) for t in proactive_mitre.get('matched_techniques', [])[:3]]}")
                                    else:
                                        logger.warning(f"No MITRE techniques found in proactive_mitre for {agent_type}")
                                    
                                    # Build warning message
                                    # Get timestamp from metadata or use current time
                                    obs_timestamp = None
                                    if obs.metadata and 'timestamp' in obs.metadata:
                                        obs_timestamp = obs.metadata['timestamp']
                                    if not obs_timestamp:
                                        obs_timestamp = test_result.timestamp
                                    
                                    warning_data = {
                                        'attack_type': llm_analysis.get('attack_scenario', attack_data.attack_type),
                                        'severity': llm_analysis.get('threat_level', 'medium'),
                                        'description': llm_analysis.get('reasoning', obs.description),
                                        'indicators': obs.indicators,
                                        'confidence': llm_analysis.get('confidence', test_result.confidence),
                                        'detected_by': [agent_type],
                                        'mitre_techniques': proactive_mitre.get('matched_techniques', []),
                                        'mitre_tactics': proactive_mitre.get('matched_tactics', []),
                                        'recommended_actions': llm_analysis.get('recommended_actions', []),
                                        'timestamp': obs_timestamp.isoformat() if hasattr(obs_timestamp, 'isoformat') else (str(obs_timestamp) if obs_timestamp else datetime.now().isoformat())
                                    }
                                    
                                    # Mitigations will be added by knowledge fusion if available via message bus
                                    # For now, set empty list - they'll be populated if message bus is working
                                    warning_data['mitigations'] = []
                                    
                                # Emit directly - frontend expects the data structure directly
                                _socketio.emit('proactive_warning', {
                                    'message': warning_data,
                                    'timestamp': datetime.now().isoformat()
                                })
                                logger.info(f"Emitted proactive warning for {agent_type} agent")
                                break  # Only emit one warning per test
                    else:
                        # No observations generated - log this
                        logger.info(f"No observations generated for {agent_type} agent attack test")
                        # Still emit a status update to show the agent processed the attack
                        agent_observation_event = f"{agent_type}-observation"
                        # Emit directly - frontend expects the data structure directly
                        _socketio.emit(agent_observation_event, {
                            'agent_id': agent_type,
                            'observations': [],
                            'confidence': test_result.confidence,
                            'timestamp': test_result.timestamp.isoformat() if hasattr(test_result.timestamp, 'isoformat') else str(test_result.timestamp),
                            'metadata': {
                                'attack_type': attack_data.attack_type,
                                'detected': False,
                                'max_anomaly_score': test_result.max_anomaly_score,
                                'message': 'No anomalies detected'
                            }
                        })
                
            except Exception as e:
                logger.error(f"Error running auto-test: {e}", exc_info=True)
                # Continue anyway - return attack info
            
            # Return only attack information (not test results)
            return jsonify({
                'success': True,
                'attack_info': {
                    'agent_type': attack_data.agent_type,
                    'attack_type': attack_data.attack_type,
                    'description': attack_data.description,
                    'technique_id': attack_data.technique_id,
                    'technique_name': attack_data.technique_name
                }
            }), 200
        
        except Exception as e:
            logger.error(f"Error in auto-test: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/results', methods=['GET'])
    def get_results():
        """Get test results."""
        try:
            limit = request.args.get('limit', type=int)
            test_id = request.args.get('test_id')
            
            if test_id:
                # Get specific test report
                report = orchestrator.generate_test_report(test_id=test_id)
                return jsonify({
                    'success': True,
                    'report': report.to_dict()
                }), 200
            else:
                # Get recent results
                results = orchestrator.get_recent_results(limit=limit or 10)
                return jsonify({
                    'success': True,
                    'results': [r.to_dict() for r in results],
                    'total_count': len(orchestrator.test_results)
                }), 200
        
        except Exception as e:
            logger.error(f"Error getting results: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker-mode', methods=['POST'])
    def hacker_mode():
        """Enable hacker simulation mode and generate attack."""
        try:
            data = request.get_json()
            agent_type = data.get('agent_type', 'router')
            context = data.get('context')
            
            # Generate hacker scenario
            scenario = orchestrator.attack_generator.generate_hacker_scenario(
                agent_type, context
            )
            
            # Run test
            test_result = orchestrator.run_test_from_attack_data(scenario.attack_data)
            
            return jsonify({
                'success': True,
                'scenario': {
                    'strategy': scenario.strategy,
                    'objectives': scenario.objectives,
                    'attack_data': {
                        'agent_type': scenario.attack_data.agent_type,
                        'attack_type': scenario.attack_data.attack_type,
                        'data': scenario.attack_data.data,
                        'description': scenario.attack_data.description
                    }
                },
                'test_result': test_result.to_dict()
            }), 200
        
        except Exception as e:
            logger.error(f"Error in hacker mode: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/random-attack', methods=['POST'])
    def random_attack():
        """Generate and test random attack."""
        try:
            data = request.get_json()
            agent_type = data.get('agent_type', 'router')
            
            # Generate and run random attack
            test_result = orchestrator.run_random_attack_test(agent_type)
            
            return jsonify({
                'success': True,
                'test_result': test_result.to_dict()
            }), 200
        
        except Exception as e:
            logger.error(f"Error generating random attack: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/generate-report', methods=['POST'])
    def generate_report():
        """Generate comprehensive test report."""
        try:
            data = request.get_json() or {}
            test_id = data.get('test_id')
            
            report = orchestrator.generate_test_report(test_id=test_id)
            
            return jsonify({
                'success': True,
                'report': report.to_dict(),
                'summary': report.get_summary()
            }), 200
        
        except Exception as e:
            logger.error(f"Error generating report: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/clear-results', methods=['POST'])
    def clear_results():
        """Clear test results."""
        try:
            orchestrator.clear_results()
            return jsonify({
                'success': True,
                'message': 'Results cleared'
            }), 200
        except Exception as e:
            logger.error(f"Error clearing results: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # Proactive Warning Endpoints
    @app.route('/api/warnings', methods=['GET'])
    def get_warnings():
        """Get proactive threat warnings."""
        try:
            from observability.notification_system import NotificationSystem
            
            # Get notification system (would need to be passed in or retrieved)
            # For now, return empty list - in full implementation would retrieve from notification system
            limit = request.args.get('limit', type=int) or 50
            severity = request.args.get('severity')
            
            # In full implementation, would query notification system
            warnings = []
            
            return jsonify({
                'success': True,
                'warnings': warnings,
                'count': len(warnings)
            }), 200
        except Exception as e:
            logger.error(f"Error getting warnings: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/warnings/<warning_id>', methods=['GET'])
    def get_warning(warning_id: str):
        """Get specific warning by ID."""
        try:
            # In full implementation, would retrieve from notification system
            return jsonify({
                'success': True,
                'warning': None,
                'message': 'Warning retrieval not yet implemented'
            }), 200
        except Exception as e:
            logger.error(f"Error getting warning: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # Hacker Assistant Endpoints
    @app.route('/api/test/hacker/init', methods=['GET'])
    def hacker_init():
        """Initialize hacker assistant."""
        try:
            response = orchestrator.chat_interface.initialize_hacker_assistant()
            return jsonify({
                'success': True,
                'message': response.message,
                'intent': {
                    'mode': response.intent.mode if response.intent else None
                }
            }), 200
        except Exception as e:
            logger.error(f"Error initializing hacker assistant: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker/predefined-scenarios', methods=['GET'])
    def get_predefined_scenarios():
        """Get available predefined attack scenarios for an agent type."""
        try:
            agent_type = request.args.get('agent_type')
            if not agent_type:
                return jsonify({
                    'success': False,
                    'error': 'agent_type parameter is required'
                }), 400
            
            scenarios = orchestrator.chat_interface.get_predefined_scenarios(agent_type)
            
            return jsonify({
                'success': True,
                'agent_type': agent_type,
                'scenarios': scenarios
            }), 200
        except Exception as e:
            logger.error(f"Error getting predefined scenarios: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker/execute-predefined', methods=['POST'])
    def execute_predefined():
        """Execute a predefined attack scenario step-by-step."""
        try:
            data = request.get_json()
            agent_type = data.get('agent_type')
            attack_type = data.get('attack_type')
            execution_id = data.get('execution_id')
            
            if not agent_type or not attack_type:
                return jsonify({
                    'success': False,
                    'error': 'agent_type and attack_type are required'
                }), 400
            
            # Check execution state to prevent looping
            if orchestrator.chat_interface.check_execution_state():
                return jsonify({
                    'success': False,
                    'error': 'Execution already in progress',
                    'execution_id': orchestrator.chat_interface.execution_state['current_execution_id']
                }), 409
            
            # Set execution state
            orchestrator.chat_interface.set_execution_state(True, execution_id)
            
            # Execute in background thread to allow WebSocket events
            def execute_async():
                try:
                    result = hacker_executor.execute_predefined_attack(
                        agent_type=agent_type,
                        attack_type=attack_type,
                        execution_id=execution_id,
                        continuous=True  # Enable continuous multi-attack mode
                    )
                    return result
                finally:
                    orchestrator.chat_interface.set_execution_state(False)
            
            # Start execution in background
            import threading
            execution_thread = threading.Thread(target=execute_async, daemon=True)
            execution_thread.start()
            
            return jsonify({
                'success': True,
                'message': 'Execution started',
                'execution_id': execution_id,
                'agent_type': agent_type,
                'attack_type': attack_type
            }), 200
            
        except Exception as e:
            logger.error(f"Error executing predefined attack: {e}", exc_info=True)
            orchestrator.chat_interface.set_execution_state(False)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker/execute-dynamic', methods=['POST'])
    def execute_dynamic():
        """Execute a dynamic hacker-generated attack step-by-step."""
        try:
            data = request.get_json()
            agent_type = data.get('agent_type', 'router')
            context = data.get('context')
            execution_id = data.get('execution_id')
            
            # Check execution state to prevent looping
            if orchestrator.chat_interface.check_execution_state():
                return jsonify({
                    'success': False,
                    'error': 'Execution already in progress',
                    'execution_id': orchestrator.chat_interface.execution_state['current_execution_id']
                }), 409
            
            # Set execution state
            orchestrator.chat_interface.set_execution_state(True, execution_id)
            
            # Execute in background thread
            def execute_async():
                try:
                    result = hacker_executor.execute_dynamic_attack(
                        agent_type=agent_type,
                        context=context,
                        execution_id=execution_id
                    )
                    return result
                finally:
                    orchestrator.chat_interface.set_execution_state(False)
            
            # Start execution in background
            import threading
            execution_thread = threading.Thread(target=execute_async, daemon=True)
            execution_thread.start()
            
            return jsonify({
                'success': True,
                'message': 'Dynamic attack execution started',
                'execution_id': execution_id,
                'agent_type': agent_type
            }), 200
            
        except Exception as e:
            logger.error(f"Error executing dynamic attack: {e}", exc_info=True)
            orchestrator.chat_interface.set_execution_state(False)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker/execution-status', methods=['GET'])
    def get_execution_status():
        """Get current execution status."""
        try:
            status = hacker_executor.get_execution_status()
            return jsonify({
                'success': True,
                'status': status
            }), 200
        except Exception as e:
            logger.error(f"Error getting execution status: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/test/hacker/stop', methods=['POST'])
    def stop_hacker_execution():
        """Stop ongoing hacker execution."""
        try:
            data = request.get_json() or {}
            execution_id = data.get('execution_id')
            
            # Cancel execution
            hacker_executor.cancel_execution()
            
            return jsonify({
                'success': True,
                'message': 'Execution stop requested',
                'execution_id': execution_id or hacker_executor.current_execution_id
            }), 200
        except Exception as e:
            logger.error(f"Error stopping execution: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/health', methods=['GET'])
    def health():
        """Health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'service': 'attack_testing'
        }), 200
    
    # Training API Endpoints
    @app.route('/api/training/upload', methods=['POST'])
    def upload_training():
        """Upload training data for an agent."""
        try:
            if 'file' not in request.files:
                return jsonify({
                    'success': False,
                    'error': 'No file provided'
                }), 400
            
            file = request.files['file']
            agent_id = request.form.get('agent_id')
            
            if not agent_id:
                return jsonify({
                    'success': False,
                    'error': 'agent_id is required'
                }), 400
            
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'No file selected'
                }), 400
            
            # Save file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
                file.save(tmp_file.name)
                tmp_path = tmp_file.name
            
            try:
                # Upload training data
                result = training_api.upload_training_data(agent_id, tmp_path)
                
                return jsonify({
                    'success': result.success,
                    'records_processed': result.records_processed,
                    'records_valid': result.records_valid,
                    'records_invalid': result.records_invalid,
                    'status': result.status.to_dict() if hasattr(result.status, 'to_dict') else {
                        'baseline_ready': result.status.baseline_ready if hasattr(result.status, 'baseline_ready') else False,
                        'records_processed': result.status.records_processed if hasattr(result.status, 'records_processed') else 0,
                    },
                    'error_message': result.error_message if hasattr(result, 'error_message') else None
                }), 200
            finally:
                # Clean up temp file
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
        
        except Exception as e:
            logger.error(f"Error uploading training data: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/training/status/<agent_id>', methods=['GET'])
    def get_training_status(agent_id):
        """Get training status for an agent."""
        try:
            status = training_api.get_training_status(agent_id)
            return jsonify({
                'success': True,
                **status
            }), 200
        except Exception as e:
            logger.error(f"Error getting training status: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/training/clear/<agent_id>', methods=['POST'])
    def clear_baseline(agent_id):
        """Clear baseline for an agent."""
        try:
            result = training_api.clear_baseline(agent_id)
            return jsonify({
                'success': result,
                'message': 'Baseline cleared' if result else 'Failed to clear baseline'
            }), 200
        except Exception as e:
            logger.error(f"Error clearing baseline: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/training/statistics/<agent_id>', methods=['GET'])
    def get_training_statistics(agent_id):
        """Get detailed training statistics including baseline metrics for an agent."""
        try:
            stats = training_api.get_training_statistics(agent_id)
            return jsonify({
                'success': True,
                **stats
            }), 200
        except Exception as e:
            logger.error(f"Error getting training statistics: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # System Control Endpoints
    @app.route('/api/system/start', methods=['POST'])
    def start_system():
        """Start the system."""
        global _system_running
        try:
            _system_running = True
            if _message_bus and _socketio:
                setup_message_bus_subscriber(_message_bus, _socketio)
            return jsonify({
                'success': True,
                'message': 'System started'
            }), 200
        except Exception as e:
            logger.error(f"Error starting system: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/system/stop', methods=['POST'])
    def stop_system():
        """Stop the system."""
        global _system_running, _message_subscriber
        try:
            _system_running = False
            if _message_subscriber:
                _message_subscriber.stop()
                _message_subscriber = None
            return jsonify({
                'success': True,
                'message': 'System stopped'
            }), 200
        except Exception as e:
            logger.error(f"Error stopping system: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/system/reset', methods=['POST'])
    def reset_system():
        """Reset the system."""
        global _system_running, _message_subscriber
        try:
            _system_running = False
            if _message_subscriber:
                _message_subscriber.stop()
                _message_subscriber = None
            
            # Clear test results
            orchestrator.clear_results()
            
            return jsonify({
                'success': True,
                'message': 'System reset'
            }), 200
        except Exception as e:
            logger.error(f"Error resetting system: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    # WebSocket endpoint
    if _socketio:
        @_socketio.on('connect')
        def handle_connect():
            """Handle WebSocket connection."""
            logger.info('Client connected via WebSocket')
            emit('connected', {'message': 'Connected to agent updates'})
        
        @_socketio.on('disconnect')
        def handle_disconnect():
            """Handle WebSocket disconnection."""
            logger.info('Client disconnected from WebSocket')
        
        @_socketio.on('subscribe_hacker_events')
        def handle_subscribe_hacker_events():
            """Handle subscription to hacker execution events."""
            logger.info('Client subscribed to hacker events')
            emit('subscribed', {'message': 'Subscribed to hacker execution events'})
        
        @_socketio.on('subscribe_warnings')
        def handle_subscribe_warnings():
            """Handle subscription to proactive threat warnings."""
            logger.info('Client subscribed to proactive warnings')
            emit('subscribed', {'message': 'Subscribed to proactive threat warnings'})
    
    # Server-Sent Events endpoint (fallback)
    @app.route('/api/events/stream')
    def stream_events():
        """Server-Sent Events stream for agent updates."""
        from flask import Response, stream_with_context
        import json
        import queue
        import time
        
        message_queue = queue.Queue()
        
        def message_handler(topic: str, message_dict: Dict[str, Any]):
            """Handle message from message bus."""
            try:
                message_queue.put({
                    'topic': topic,
                    'data': message_dict
                })
            except Exception as e:
                logger.error(f"Error in message handler: {e}")
        
        # Setup subscriber if message bus available
        if _message_bus:
            subscriber = MessageBusSubscriber(
                _message_bus,
                [Topics.ROUTER_OBSERVATIONS, Topics.COMPUTER_OBSERVATIONS, Topics.EMAIL_OBSERVATIONS],
                message_handler
            )
            subscriber.start(blocking=False)
        
        def generate():
            """Generate SSE events."""
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            
            while True:
                try:
                    # Check for messages with timeout
                    try:
                        message = message_queue.get(timeout=1)
                        event_type = 'agent-update'
                        if 'router' in message['topic']:
                            event_type = 'agent.router.observations'
                        elif 'computer' in message['topic']:
                            event_type = 'agent.computer.observations'
                        elif 'email' in message['topic']:
                            event_type = 'agent.email.observations'
                        
                        yield f"event: {event_type}\n"
                        yield f"data: {json.dumps(message['data'], default=str)}\n\n"
                    except queue.Empty:
                        # Send heartbeat
                        yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': time.time()})}\n\n"
                except Exception as e:
                    logger.error(f"Error in SSE stream: {e}")
                    break
        
        return Response(stream_with_context(generate()), mimetype='text/event-stream')
    
    return app


def setup_message_bus_subscriber(message_bus: MessageBus, socketio: SocketIO):
    """Setup message bus subscriber to forward messages via WebSocket."""
    global _message_subscriber
    
    if _message_subscriber:
        _message_subscriber.stop()
    
    def handle_agent_message(topic: str, message_dict: Dict[str, Any]):
        """Handle message from message bus and emit via WebSocket."""
        try:
            # Extract agent ID from topic
            if 'router' in topic:
                socketio.emit('router-observation', {
                    'topic': topic,
                    'message': message_dict
                })
            elif 'computer' in topic:
                socketio.emit('computer-observation', {
                    'topic': topic,
                    'message': message_dict
                })
            elif 'email' in topic:
                socketio.emit('email-observation', {
                    'topic': topic,
                    'message': message_dict
                })
            elif 'proactive_warning' in topic or topic == Topics.PROACTIVE_WARNING:
                # Emit proactive warning event
                socketio.emit('proactive_warning', {
                    'topic': topic,
                    'message': message_dict,
                    'timestamp': datetime.now().isoformat()
                })
                logger.info(f"Emitted proactive warning: {message_dict.get('attack_type', 'Unknown')}")
            elif 'collaborative_detection' in topic or topic == Topics.COLLABORATIVE_DETECTION:
                # Emit collaborative detection event
                socketio.emit('collaborative_detection', {
                    'topic': topic,
                    'message': message_dict,
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            logger.error(f"Error handling message bus message: {e}", exc_info=True)
    
    # Subscribe to all agent observation topics and proactive warnings
    topics = [
        Topics.ROUTER_OBSERVATIONS,
        Topics.COMPUTER_OBSERVATIONS,
        Topics.EMAIL_OBSERVATIONS,
        Topics.PROACTIVE_WARNING,
        Topics.COLLABORATIVE_DETECTION
    ]
    
    _message_subscriber = MessageBusSubscriber(
        message_bus,
        topics,
        handle_agent_message
    )
    
    # Start subscriber in background thread
    def run_subscriber():
        _message_subscriber.start(blocking=True)
    
    subscriber_thread = threading.Thread(target=run_subscriber, daemon=True)
    subscriber_thread.start()
    logger.info('Message bus subscriber started for WebSocket forwarding')


def run_api_server(
    test_orchestrator: Optional[TestOrchestrator] = None,
    agents: Optional[Dict[str, Any]] = None,
    message_bus: Optional[MessageBus] = None,
    host: str = '0.0.0.0',
    port: int = 5000,
    debug: bool = False
):
    """
    Run the API server with WebSocket support.
    
    Args:
        test_orchestrator: Optional TestOrchestrator instance
        agents: Optional dictionary of agents
        message_bus: Optional MessageBus instance for real-time updates
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
    """
    app = create_app(test_orchestrator, agents, message_bus)
    if _socketio:
        _socketio.run(app, host=host, port=port, debug=debug)
    else:
        app.run(host=host, port=port, debug=debug)

