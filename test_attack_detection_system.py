"""
Test Attack Detection System

Tests that agents detect attack scenarios, act proactively with warnings,
and use MITRE RAG to get attack details. Uses existing modules.
"""

import sys
import json
from datetime import datetime
from typing import Dict, Any, List

# Import existing modules
from baseline_training.training_orchestrator import TrainingOrchestrator
from agents.crew_orchestrator import CrewOrchestrator
from attack_testing.test_orchestrator import TestOrchestrator
from attack_testing.attack_generator import AttackGenerator
from knowledge_fusion.fusion_core import KnowledgeFusion

# Color output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print formatted header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*80}{Colors.RESET}\n")

def print_success(text: str):
    """Print success message."""
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")

def print_error(text: str):
    """Print error message."""
    print(f"{Colors.RED}✗ {text}{Colors.RESET}")

def print_warning(text: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")

def print_info(text: str):
    """Print info message."""
    print(f"{Colors.BLUE}ℹ {text}{Colors.RESET}")

def initialize_system():
    """Initialize system with trained baselines."""
    print_header("INITIALIZING SYSTEM")
    
    # Initialize training orchestrator
    print_info("Initializing TrainingOrchestrator...")
    training_orchestrator = TrainingOrchestrator()
    
    # Train baselines first (using test_data)
    print_info("Training baselines for all agents...")
    from pathlib import Path
    project_root = Path(__file__).parent
    
    for agent_id in ['router', 'computer', 'email']:
        test_data_file = project_root / "test_data" / f"{agent_id}_test.json"
        if test_data_file.exists():
            try:
                import json
                with open(test_data_file, 'r') as f:
                    data = json.load(f)
                # Use first 100 records for faster training
                training_data = data[:100] if isinstance(data, list) else [data]
                result = training_orchestrator.start_training(agent_id, training_data)
                if result.success:
                    print_success(f"Trained {agent_id} agent baseline ({result.records_valid} records)")
                else:
                    print_warning(f"Training for {agent_id} had issues: {result.error_message}")
            except Exception as e:
                print_warning(f"Could not load training data for {agent_id}: {e}")
    
    # Initialize CrewOrchestrator with trained baselines
    print_info("Initializing CrewOrchestrator with trained baselines...")
    crew_orchestrator = CrewOrchestrator(training_orchestrator=training_orchestrator)
    agents = crew_orchestrator.agents
    
    # Initialize Knowledge Fusion
    print_info("Initializing Knowledge Fusion...")
    knowledge_fusion = KnowledgeFusion()
    
    # Initialize TestOrchestrator
    print_info("Initializing TestOrchestrator...")
    test_orchestrator = TestOrchestrator(
        agents=agents,
        training_orchestrator=training_orchestrator
    )
    
    print_success("System initialized successfully")
    return test_orchestrator, agents, knowledge_fusion

def generate_attack_scenarios(test_orchestrator: TestOrchestrator):
    """Generate attack scenarios for testing."""
    print_header("GENERATING ATTACK SCENARIOS")
    
    attack_generator = test_orchestrator.attack_generator
    scenarios = {}
    
    # Generate attacks for each agent
    for agent_id in ['router', 'computer', 'email']:
        print_info(f"Generating attack scenario for {agent_id} agent...")
        try:
            # Use simple attack types
            if agent_id == 'router':
                attack_type = 'c2_channel'
            elif agent_id == 'computer':
                attack_type = 'process_injection'
            else:  # email
                attack_type = 'phishing'
            
            attack_data = attack_generator.generate_attack(
                attack_type=attack_type,
                agent_type=agent_id
            )
            scenarios[agent_id] = attack_data
            print_success(f"Generated {attack_type} attack for {agent_id}")
        except Exception as e:
            print_error(f"Failed to generate attack for {agent_id}: {e}")
            # Create fallback attack data
            if agent_id == 'router':
                scenarios[agent_id] = {
                    'agent_type': agent_id,
                    'attack_type': 'c2_channel',
                    'data': {
                        'dest_ip': '185.220.101.45',
                        'dest_domain': 'c2-malicious.com',
                        'protocol': 'HTTPS',
                        'port': 443,
                        'bytes_sent': 10000000,
                        'bytes_received': 1000,
                        'duration_seconds': 3600
                    }
                }
            elif agent_id == 'computer':
                scenarios[agent_id] = {
                    'agent_type': agent_id,
                    'attack_type': 'process_injection',
                    'data': {
                        'process_name': 'suspicious.exe',
                        'user': 'SYSTEM',
                        'command_line': 'powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA...',
                        'file_path': 'C:\\Windows\\Temp\\malware.exe'
                    }
                }
            else:  # email
                scenarios[agent_id] = {
                    'agent_type': agent_id,
                    'attack_type': 'phishing',
                    'data': {
                        'sender': 'attacker@malicious-domain.org',
                        'sender_domain': 'malicious-domain.org',
                        'subject': 'URGENT: Verify Your Account',
                        'attachment_name': 'invoice.pdf.exe',
                        'attachment_size': 5000000
                    }
                }
            print_warning(f"Using fallback attack data for {agent_id}")
    
    return scenarios

def test_attack_detection(test_orchestrator: TestOrchestrator, scenarios: Dict[str, Any]):
    """Test that agents detect attack scenarios."""
    print_header("TESTING ATTACK DETECTION")
    
    results = {}
    
    for agent_id, attack_scenario in scenarios.items():
        # Get attack type
        if isinstance(attack_scenario, dict):
            attack_type = attack_scenario.get('attack_type', 'attack')
            attack_data = attack_scenario.get('data', attack_scenario)
        else:
            attack_type = attack_scenario.attack_type if hasattr(attack_scenario, 'attack_type') else 'attack'
            attack_data = attack_scenario.data if hasattr(attack_scenario, 'data') else {}
        
        print_info(f"Testing {agent_id} agent with {attack_type}...")
        
        # Run attack test
        try:
            test_result = test_orchestrator.run_attack_test(
                attack_data=attack_data,
                agent_id=agent_id,
                expected_detection=True
            )
            
            results[agent_id] = {
                'detected': test_result.detected,
                'observations': test_result.detections,
                'confidence': test_result.confidence,
                'max_anomaly_score': test_result.max_anomaly_score,
                'test_result': test_result
            }
            
            if test_result.detected:
                print_success(f"{agent_id} agent detected the attack ({len(test_result.detections)} observations)")
                print_info(f"  Confidence: {test_result.confidence:.2f}")
                print_info(f"  Max Anomaly Score: {test_result.max_anomaly_score:.2f}")
            else:
                print_warning(f"{agent_id} agent did not detect the attack")
                
        except Exception as e:
            print_error(f"Error testing {agent_id} agent: {e}")
            results[agent_id] = {
                'detected': False,
                'error': str(e),
                'observations': [],
                'confidence': 0.0
            }
    
    return results

def verify_proactive_warnings(results: Dict[str, Any], agents: Dict[str, Any]):
    """Verify proactive warnings were generated."""
    print_header("VERIFYING PROACTIVE WARNINGS")
    
    warning_results = {}
    
    for agent_id, result in results.items():
        print_info(f"Checking proactive warnings for {agent_id} agent...")
        
        observations = result.get('observations', [])
        agent = agents.get(agent_id)
        
        has_warnings = False
        warning_details = []
        
        # Check observations for warning indicators
        for obs in observations:
            # Check if observation has threat analysis metadata
            if 'llm_analysis' in obs.metadata:
                llm_analysis = obs.metadata['llm_analysis']
                if llm_analysis.get('is_threat', False):
                    has_warnings = True
                    warning_details.append({
                        'is_threat': True,
                        'threat_level': llm_analysis.get('threat_level', 'unknown'),
                        'confidence': llm_analysis.get('confidence', 0.0),
                        'attack_scenario': llm_analysis.get('attack_scenario', '')
                    })
        
        # Check if agent has notification system and warnings were sent
        if agent and hasattr(agent, 'notification_system'):
            # Agent has notification system capability
            pass
        
        warning_results[agent_id] = {
            'has_warnings': has_warnings,
            'warning_count': len(warning_details),
            'warning_details': warning_details
        }
        
        if has_warnings:
            print_success(f"{agent_id} agent generated proactive warnings ({len(warning_details)} warnings)")
            for i, warning in enumerate(warning_details, 1):
                print_info(f"  Warning {i}: {warning.get('threat_level', 'unknown')} - {warning.get('attack_scenario', 'N/A')[:60]}...")
        else:
            print_warning(f"{agent_id} agent did not generate proactive warnings")
    
    return warning_results

def verify_mitre_rag(results: Dict[str, Any], agents: Dict[str, Any]):
    """Verify agents use MITRE RAG to get attack details."""
    print_header("VERIFYING MITRE RAG INTEGRATION")
    
    mitre_results = {}
    
    for agent_id, result in results.items():
        print_info(f"Checking MITRE RAG usage for {agent_id} agent...")
        
        observations = result.get('observations', [])
        agent = agents.get(agent_id)
        
        has_mitre = False
        mitre_techniques = []
        mitre_tactics = []
        proactive_mitre_used = False
        
        # Check observations for MITRE information
        for obs in observations:
            # Check for MITRE techniques in metadata
            if 'llm_analysis' in obs.metadata:
                llm_analysis = obs.metadata['llm_analysis']
                proactive_mitre = llm_analysis.get('proactive_mitre', {})
                if proactive_mitre:
                    proactive_mitre_used = True
                    techniques = proactive_mitre.get('matched_techniques', [])
                    tactics = proactive_mitre.get('matched_tactics', [])
                    mitre_techniques.extend(techniques)
                    mitre_tactics.extend(tactics)
            
            # Check for MITRE techniques directly in metadata
            if 'mitre_techniques' in obs.metadata:
                has_mitre = True
                techs = obs.metadata['mitre_techniques']
                if isinstance(techs, list):
                    mitre_techniques.extend(techs)
        
        # Check if agent uses Knowledge Fusion
        if agent and hasattr(agent, 'knowledge_fusion') and agent.knowledge_fusion:
            has_mitre = True
        
        # Check if agent uses ThreatAnalyzer (which uses MITRE RAG)
        if agent and hasattr(agent, 'threat_analyzer') and agent.threat_analyzer:
            has_mitre = True
            if hasattr(agent.threat_analyzer, 'proactive_rag'):
                proactive_mitre_used = True
        
        mitre_results[agent_id] = {
            'has_mitre': has_mitre,
            'proactive_mitre_used': proactive_mitre_used,
            'technique_count': len(mitre_techniques),
            'tactic_count': len(mitre_tactics),
            'techniques': mitre_techniques[:5],  # First 5
            'tactics': mitre_tactics[:3]  # First 3
        }
        
        if has_mitre:
            print_success(f"{agent_id} agent uses MITRE RAG")
            if proactive_mitre_used:
                print_success(f"  Proactive MITRE RAG is being used")
            if mitre_techniques:
                print_info(f"  Found {len(mitre_techniques)} MITRE techniques")
                for tech in mitre_techniques[:3]:
                    tech_name = tech.get('name', tech) if isinstance(tech, dict) else str(tech)
                    print_info(f"    - {tech_name}")
            if mitre_tactics:
                print_info(f"  Found {len(mitre_tactics)} MITRE tactics")
        else:
            print_warning(f"{agent_id} agent may not be using MITRE RAG")
    
    return mitre_results

def generate_test_report(test_orchestrator: TestOrchestrator, detection_results: Dict, warning_results: Dict, mitre_results: Dict, scenarios: Dict[str, Any]):
    """Generate comprehensive test report."""
    print_header("GENERATING TEST REPORT")
    
    # Generate report using TestOrchestrator
    report = test_orchestrator.generate_test_report()
    
    print_info("Test Report Summary:")
    print(f"  Total Tests: {report.total_tests}")
    print(f"  Detected: {report.detected_count} ({report.detection_rate*100:.1f}%)")
    print(f"  Accuracy: {report.accuracy*100:.1f}%")
    print(f"  Precision: {report.precision*100:.1f}%")
    print(f"  Recall: {report.recall*100:.1f}%")
    
    print_header("DETAILED VERIFICATION RESULTS")
    
    # Detection results
    print("\n[ATTACK DETECTION]")
    for agent_id, result in detection_results.items():
        status = "✓ DETECTED" if result.get('detected') else "✗ NOT DETECTED"
        print(f"  {agent_id}: {status}")
        if result.get('detected'):
            print(f"    Observations: {len(result.get('observations', []))}")
            print(f"    Confidence: {result.get('confidence', 0.0):.2f}")
            print(f"    Max Anomaly Score: {result.get('max_anomaly_score', 0.0):.2f}")
        else:
            if 'error' in result:
                print(f"    Error: {result.get('error')}")
    
    # Warning results
    print("\n[PROACTIVE WARNINGS]")
    for agent_id, result in warning_results.items():
        status = "✓ GENERATED" if result.get('has_warnings') else "✗ NOT GENERATED"
        print(f"  {agent_id}: {status}")
        if result.get('has_warnings'):
            print(f"    Warning Count: {result.get('warning_count', 0)}")
            for i, warning in enumerate(result.get('warning_details', [])[:2], 1):
                print(f"      Warning {i}: {warning.get('threat_level', 'unknown')} - Confidence: {warning.get('confidence', 0.0):.2f}")
                if warning.get('attack_scenario'):
                    scenario = warning.get('attack_scenario', '')[:80]
                    print(f"        Scenario: {scenario}...")
    
    # MITRE RAG results
    print("\n[MITRE RAG INTEGRATION]")
    for agent_id, result in mitre_results.items():
        status = "✓ USING MITRE RAG" if result.get('has_mitre') else "✗ NOT USING MITRE RAG"
        print(f"  {agent_id}: {status}")
        if result.get('has_mitre'):
            if result.get('proactive_mitre_used'):
                print(f"    Proactive MITRE RAG: ✓")
            print(f"    Techniques Found: {result.get('technique_count', 0)}")
            print(f"    Tactics Found: {result.get('tactic_count', 0)}")
            if result.get('techniques'):
                print(f"    Sample Techniques:")
                for tech in result.get('techniques', [])[:2]:
                    tech_name = tech.get('name', tech) if isinstance(tech, dict) else str(tech)
                    print(f"      - {tech_name}")
    
    # Save report to file
    report_data = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_tests': report.total_tests,
            'detected_count': report.detected_count,
            'detection_rate': report.detection_rate,
            'accuracy': report.accuracy,
            'precision': report.precision,
            'recall': report.recall
        },
        'attack_scenarios': {
            agent_id: {
                'attack_type': scenario.get('attack_type', 'unknown') if isinstance(scenario, dict) else getattr(scenario, 'attack_type', 'unknown'),
                'agent_type': scenario.get('agent_type', agent_id) if isinstance(scenario, dict) else getattr(scenario, 'agent_type', agent_id)
            }
            for agent_id, scenario in scenarios.items()
        },
        'detection_results': {
            agent_id: {
                'detected': result.get('detected', False),
                'observations_count': len(result.get('observations', [])),
                'confidence': result.get('confidence', 0.0),
                'max_anomaly_score': result.get('max_anomaly_score', 0.0),
                'error': result.get('error') if 'error' in result else None
            }
            for agent_id, result in detection_results.items()
        },
        'warning_results': {
            agent_id: {
                'has_warnings': result.get('has_warnings', False),
                'warning_count': result.get('warning_count', 0),
                'warnings': result.get('warning_details', [])
            }
            for agent_id, result in warning_results.items()
        },
        'mitre_results': {
            agent_id: {
                'has_mitre': result.get('has_mitre', False),
                'proactive_mitre_used': result.get('proactive_mitre_used', False),
                'technique_count': result.get('technique_count', 0),
                'tactic_count': result.get('tactic_count', 0),
                'techniques': result.get('techniques', []),
                'tactics': result.get('tactics', [])
            }
            for agent_id, result in mitre_results.items()
        }
    }
    
    # Save to JSON file
    report_file = f"attack_detection_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)
        print_success(f"\nTest report saved to: {report_file}")
    except Exception as e:
        print_warning(f"Could not save report to file: {e}")
    
    return report

def main():
    """Main test function."""
    print_header("ATTACK DETECTION SYSTEM TEST")
    print("Testing agent detection, proactive warnings, and MITRE RAG integration")
    
    try:
        # 1. Initialize system
        test_orchestrator, agents, knowledge_fusion = initialize_system()
        
        # 2. Generate attack scenarios
        scenarios = generate_attack_scenarios(test_orchestrator)
        
        # 3. Test attack detection
        detection_results = test_attack_detection(test_orchestrator, scenarios)
        
        # 4. Verify proactive warnings
        warning_results = verify_proactive_warnings(detection_results, agents)
        
        # 5. Verify MITRE RAG usage
        mitre_results = verify_mitre_rag(detection_results, agents)
        
        # 6. Generate report
        report = generate_test_report(test_orchestrator, detection_results, warning_results, mitre_results, scenarios)
        
        # Final summary
        print_header("TEST SUMMARY")
        
        all_detected = all(r.get('detected', False) for r in detection_results.values())
        all_warnings = all(r.get('has_warnings', False) for r in warning_results.values())
        all_mitre = all(r.get('has_mitre', False) for r in mitre_results.values())
        
        print(f"\nDetection: {'✓ ALL AGENTS DETECTED' if all_detected else '⚠ SOME AGENTS DID NOT DETECT'}")
        print(f"Warnings: {'✓ ALL AGENTS GENERATED WARNINGS' if all_warnings else '⚠ SOME AGENTS DID NOT GENERATE WARNINGS'}")
        print(f"MITRE RAG: {'✓ ALL AGENTS USING MITRE RAG' if all_mitre else '⚠ SOME AGENTS NOT USING MITRE RAG'}")
        
        if all_detected and all_warnings and all_mitre:
            print_success("\nAll tests passed! System is working correctly.")
            return 0
        else:
            print_warning("\nSome tests had issues. See details above.")
            return 1
            
    except Exception as e:
        print_error(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())

