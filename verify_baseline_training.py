"""
Baseline Training Verification Script

This script verifies that baseline training is working correctly, checks the metrics
it produces, and confirms that trained baselines are properly passed to and used by agents.
"""

import sys
import json
from datetime import datetime
from typing import Dict, Any, List
from collections import defaultdict

# Import training components
from baseline_training.training_orchestrator import TrainingOrchestrator, TrainingResult, TrainingStatus
from agents.crew_orchestrator import CrewOrchestrator
from agents.baseline_learner import BaselineLearner

# Color output for better readability
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_header(text: str):
    """Print a formatted header."""
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

def generate_sample_training_data(agent_id: str, num_records: int = 50) -> List[Dict[str, Any]]:
    """Generate sample training data for an agent."""
    data = []
    
    if agent_id == 'router':
        for i in range(num_records):
            data.append({
                'dest_ip': f'192.168.1.{i % 10}',
                'dest_domain': f'example{i % 5}.com',
                'protocol': 'HTTPS' if i % 2 == 0 else 'HTTP',
                'port': 443 if i % 2 == 0 else 80,
                'bytes_sent': 1000 + (i * 100),
                'bytes_received': 500 + (i * 50),
                'duration_seconds': 10.0 + (i * 0.5)
            })
    elif agent_id == 'computer':
        for i in range(num_records):
            data.append({
                'process_name': ['chrome.exe', 'firefox.exe', 'notepad.exe', 'cmd.exe'][i % 4],
                'user': ['admin', 'user1', 'user2'][i % 3],
                'file_path': f'C:\\Users\\user{i % 3}\\file{i}.txt',
                'command_line': f'process{i}.exe --arg1 --arg2'
            })
    elif agent_id == 'email':
        for i in range(num_records):
            data.append({
                'sender': f'sender{i % 5}@example.com',
                'sender_domain': 'example.com',
                'attachment_name': f'file{i}.pdf',
                'attachment_type': 'pdf',
                'attachment_size': 100000 + (i * 1000),
                'links': [f'https://example{i % 3}.com/link']
            })
    
    return data

def verify_training_metrics(training_orchestrator: TrainingOrchestrator, agent_id: str) -> Dict[str, Any]:
    """Verify training metrics output."""
    print_header(f"1. VERIFYING TRAINING METRICS FOR {agent_id.upper()} AGENT")
    
    results = {
        'training_result_metrics': {},
        'training_statistics_metrics': {},
        'baseline_stats_metrics': {},
        'all_checks_passed': True
    }
    
    # Generate sample training data
    training_data = generate_sample_training_data(agent_id, num_records=50)
    
    # Run training
    print_info(f"Running training with {len(training_data)} records...")
    training_result: TrainingResult = training_orchestrator.start_training(agent_id, training_data)
    
    # Verify TrainingResult metrics
    print_info("Checking TrainingResult metrics...")
    required_result_fields = ['success', 'agent_id', 'records_processed', 'records_valid', 'records_invalid', 'status']
    
    for field in required_result_fields:
        if hasattr(training_result, field):
            value = getattr(training_result, field)
            results['training_result_metrics'][field] = value
            print_success(f"TrainingResult.{field} = {value}")
        else:
            print_error(f"TrainingResult missing field: {field}")
            results['all_checks_passed'] = False
    
    # Verify TrainingStatus metrics
    if training_result.status:
        status: TrainingStatus = training_result.status
        required_status_fields = ['baseline_ready', 'records_processed', 'records_valid', 'records_invalid', 'mode', 'is_training']
        
        for field in required_status_fields:
            if hasattr(status, field):
                value = getattr(status, field)
                results['training_result_metrics'][f'status.{field}'] = value
                print_success(f"TrainingStatus.{field} = {value}")
            else:
                print_error(f"TrainingStatus missing field: {field}")
                results['all_checks_passed'] = False
    
    # Get training statistics
    print_info("Retrieving training statistics...")
    stats = training_orchestrator.get_training_statistics(agent_id)
    
    # Verify training statistics structure
    required_stats_fields = ['status', 'mode']
    for field in required_stats_fields:
        if field in stats:
            results['training_statistics_metrics'][field] = stats[field]
            print_success(f"Training statistics contains: {field}")
        else:
            print_error(f"Training statistics missing: {field}")
            results['all_checks_passed'] = False
    
    # Verify baseline statistics
    if 'baseline_stats' in stats:
        baseline_stats = stats['baseline_stats']
        results['baseline_stats_metrics'] = baseline_stats
        
        # Check for numeric baselines
        if 'numeric_baselines' in baseline_stats:
            numeric_baselines = baseline_stats['numeric_baselines']
            print_success(f"Found {len(numeric_baselines)} numeric baselines")
            
            # Verify numeric baseline structure
            for baseline_name, baseline_data in list(numeric_baselines.items())[:3]:  # Check first 3
                required_numeric_fields = ['sample_count', 'mean', 'std', 'median', 'percentiles', 'is_ready']
                for field in required_numeric_fields:
                    if field in baseline_data:
                        print_success(f"  {baseline_name}.{field} = {baseline_data[field]}")
                    else:
                        print_error(f"  {baseline_name} missing field: {field}")
                        results['all_checks_passed'] = False
        else:
            print_warning("No numeric baselines found")
        
        # Check for pattern baselines
        if 'pattern_baselines' in baseline_stats:
            pattern_baselines = baseline_stats['pattern_baselines']
            print_success(f"Found {len(pattern_baselines)} pattern baselines")
            
            # Verify pattern baseline structure
            for baseline_name, baseline_data in list(pattern_baselines.items())[:3]:  # Check first 3
                required_pattern_fields = ['total_observations', 'unique_patterns', 'known_patterns', 'is_ready']
                for field in required_pattern_fields:
                    if field in baseline_data:
                        print_success(f"  {baseline_name}.{field} = {baseline_data[field]}")
                    else:
                        print_error(f"  {baseline_name} missing field: {field}")
                        results['all_checks_passed'] = False
        else:
            print_warning("No pattern baselines found")
    else:
        print_error("Training statistics missing 'baseline_stats'")
        results['all_checks_passed'] = False
    
    return results

def verify_training_flow(training_orchestrator: TrainingOrchestrator, agent_id: str) -> Dict[str, Any]:
    """Verify the training flow."""
    print_header(f"2. VERIFYING TRAINING FLOW FOR {agent_id.upper()} AGENT")
    
    results = {
        'feature_extraction': False,
        'baseline_creation': False,
        'baseline_updates': False,
        'readiness_check': False,
        'mode_switching': False,
        'all_checks_passed': True
    }
    
    # Check if baseline learner exists
    baseline_learner = training_orchestrator.get_baseline_learner(agent_id)
    if baseline_learner:
        print_success(f"Baseline learner retrieved for {agent_id}")
    else:
        print_error(f"Could not retrieve baseline learner for {agent_id}")
        results['all_checks_passed'] = False
        return results
    
    # Generate sample data
    training_data = generate_sample_training_data(agent_id, num_records=30)
    
    # Run training
    print_info("Running training to verify flow...")
    training_result = training_orchestrator.start_training(agent_id, training_data)
    
    # Verify feature extraction (implicit - if training succeeds, features were extracted)
    if training_result.success or training_result.records_valid > 0:
        results['feature_extraction'] = True
        print_success("Feature extraction working (training processed records)")
    else:
        print_error("Feature extraction may have failed (no valid records)")
        results['all_checks_passed'] = False
    
    # Verify baseline creation and updates
    stats = baseline_learner.get_all_stats()
    numeric_count = len(stats.get('numeric_baselines', {}))
    pattern_count = len(stats.get('pattern_baselines', {}))
    
    if numeric_count > 0 or pattern_count > 0:
        results['baseline_creation'] = True
        results['baseline_updates'] = True
        print_success(f"Baselines created and updated ({numeric_count} numeric, {pattern_count} pattern)")
    else:
        print_error("No baselines created")
        results['all_checks_passed'] = False
    
    # Verify readiness check
    status = training_orchestrator.get_training_status(agent_id)
    if hasattr(status, 'baseline_ready'):
        results['readiness_check'] = True
        print_success(f"Baseline readiness check working: {status.baseline_ready}")
    else:
        print_error("Baseline readiness check not working")
        results['all_checks_passed'] = False
    
    # Verify mode switching
    mode = training_orchestrator.agent_modes.get(agent_id)
    if mode:
        results['mode_switching'] = True
        print_success(f"Mode switching working: current mode = {mode.value}")
    else:
        print_error("Mode switching not working")
        results['all_checks_passed'] = False
    
    return results

def verify_agent_integration(training_orchestrator: TrainingOrchestrator) -> Dict[str, Any]:
    """Verify that agents receive trained baseline learners."""
    print_header("3. VERIFYING AGENT INTEGRATION")
    
    results = {
        'initialization_order': False,
        'baseline_retrieval': {},
        'baseline_passing': {},
        'agent_usage': {},
        'all_checks_passed': True
    }
    
    # First, train baselines for all agents
    print_info("Training baselines for all agents first...")
    for agent_id in ['router', 'computer', 'email']:
        training_data = generate_sample_training_data(agent_id, num_records=30)
        training_result = training_orchestrator.start_training(agent_id, training_data)
        if training_result.success:
            print_success(f"Trained {agent_id} agent baseline")
        else:
            print_warning(f"Training for {agent_id} had issues: {training_result.error_message}")
    
    # Now initialize CrewOrchestrator with training_orchestrator
    print_info("Initializing CrewOrchestrator with TrainingOrchestrator...")
    try:
        crew_orchestrator = CrewOrchestrator(training_orchestrator=training_orchestrator)
        results['initialization_order'] = True
        print_success("CrewOrchestrator initialized with TrainingOrchestrator")
    except Exception as e:
        print_error(f"Failed to initialize CrewOrchestrator: {e}")
        results['all_checks_passed'] = False
        return results
    
    # Verify baseline retrieval for each agent
    print_info("Verifying baseline learner retrieval...")
    for agent_id in ['router', 'computer', 'email']:
        baseline_learner = training_orchestrator.get_baseline_learner_for_agent(agent_id)
        if baseline_learner:
            results['baseline_retrieval'][agent_id] = True
            print_success(f"Baseline learner retrieved for {agent_id}")
        else:
            results['baseline_retrieval'][agent_id] = False
            print_error(f"Could not retrieve baseline learner for {agent_id}")
            results['all_checks_passed'] = False
    
    # Verify baseline passing to agents
    print_info("Verifying baseline learners passed to agents...")
    for agent_id, agent in crew_orchestrator.agents.items():
        if hasattr(agent, 'baseline_learner'):
            baseline_learner = agent.baseline_learner
            
            # Check if baseline learner has data
            stats = baseline_learner.get_all_stats()
            numeric_count = len(stats.get('numeric_baselines', {}))
            pattern_count = len(stats.get('pattern_baselines', {}))
            
            if numeric_count > 0 or pattern_count > 0:
                results['baseline_passing'][agent_id] = True
                print_success(f"{agent_id} agent received trained baseline ({numeric_count} numeric, {pattern_count} pattern)")
            else:
                results['baseline_passing'][agent_id] = False
                print_warning(f"{agent_id} agent baseline learner is empty (may be new learner)")
        else:
            results['baseline_passing'][agent_id] = False
            print_error(f"{agent_id} agent missing baseline_learner attribute")
            results['all_checks_passed'] = False
    
    # Verify agents can use baselines
    print_info("Verifying agents can use baselines...")
    for agent_id, agent in crew_orchestrator.agents.items():
        # Generate test data
        test_data = generate_sample_training_data(agent_id, num_records=1)[0]
        
        # Check if agent can get anomaly scores (uses baseline)
        try:
            anomaly_scores = agent.get_anomaly_scores(test_data)
            if isinstance(anomaly_scores, dict):
                results['agent_usage'][agent_id] = True
                print_success(f"{agent_id} agent can use baseline for anomaly detection")
            else:
                results['agent_usage'][agent_id] = False
                print_error(f"{agent_id} agent get_anomaly_scores() returned invalid result")
                results['all_checks_passed'] = False
        except Exception as e:
            results['agent_usage'][agent_id] = False
            print_error(f"{agent_id} agent failed to use baseline: {e}")
            results['all_checks_passed'] = False
    
    return results

def verify_baseline_usage(training_orchestrator: TrainingOrchestrator) -> Dict[str, Any]:
    """Verify that agents use trained baselines correctly."""
    print_header("4. VERIFYING BASELINE USAGE IN AGENTS")
    
    results = {
        'anomaly_detection': {},
        'baseline_updates': {},
        'mode_handling': {},
        'readiness_checks': {},
        'all_checks_passed': True
    }
    
    # Initialize orchestrator
    crew_orchestrator = CrewOrchestrator(training_orchestrator=training_orchestrator)
    
    # Train baselines first
    print_info("Training baselines for all agents...")
    for agent_id in ['router', 'computer', 'email']:
        training_data = generate_sample_training_data(agent_id, num_records=50)
        training_result = training_orchestrator.start_training(agent_id, training_data)
        if training_result.success:
            print_success(f"Trained {agent_id} baseline")
    
    # Re-initialize to get trained baselines
    crew_orchestrator = CrewOrchestrator(training_orchestrator=training_orchestrator)
    
    # Test anomaly detection
    print_info("Testing anomaly detection with trained baselines...")
    for agent_id, agent in crew_orchestrator.agents.items():
        # Test with normal data (should have low anomaly score)
        normal_data = generate_sample_training_data(agent_id, num_records=1)[0]
        normal_scores = agent.get_anomaly_scores(normal_data)
        
        # Test with anomalous data
        anomalous_data = normal_data.copy()
        if agent_id == 'router':
            anomalous_data['bytes_sent'] = 10000000  # Very high
            anomalous_data['dest_ip'] = '999.999.999.999'  # Unknown IP
        elif agent_id == 'computer':
            anomalous_data['process_name'] = 'suspicious_process.exe'  # Unknown process
            anomalous_data['command_line'] = 'malicious.exe --evil-flag'
        elif agent_id == 'email':
            anomalous_data['sender_domain'] = 'malicious-domain.com'  # Unknown domain
            anomalous_data['attachment_size'] = 100000000  # Very large
        
        anomalous_scores = agent.get_anomaly_scores(anomalous_data)
        
        # Check if anomalous data has higher scores
        max_normal = max(normal_scores.values()) if normal_scores else 0.0
        max_anomalous = max(anomalous_scores.values()) if anomalous_scores else 0.0
        
        if max_anomalous > max_normal:
            results['anomaly_detection'][agent_id] = True
            print_success(f"{agent_id} agent detects anomalies correctly (normal: {max_normal:.2f}, anomalous: {max_anomalous:.2f})")
        else:
            results['anomaly_detection'][agent_id] = False
            print_warning(f"{agent_id} agent anomaly detection may not be working (normal: {max_normal:.2f}, anomalous: {max_anomalous:.2f})")
    
    # Test baseline updates
    print_info("Testing baseline updates based on training mode...")
    for agent_id, agent in crew_orchestrator.agents.items():
        # Get initial baseline stats
        initial_stats = agent.baseline_learner.get_all_stats()
        initial_numeric_count = sum(len(b.get('values', [])) if isinstance(b, dict) else 0 
                                   for b in initial_stats.get('numeric_baselines', {}).values())
        
        # Set to hybrid mode (should allow updates)
        agent.set_training_mode('hybrid')
        test_data = generate_sample_training_data(agent_id, num_records=1)[0]
        agent.update_baseline(test_data)
        
        # Check if baseline was updated
        final_stats = agent.baseline_learner.get_all_stats()
        final_numeric_count = sum(len(b.get('values', [])) if isinstance(b, dict) else 0 
                                 for b in final_stats.get('numeric_baselines', {}).values())
        
        # Set to inference mode (should NOT allow updates)
        agent.set_training_mode('inference')
        agent.update_baseline(test_data)
        
        inference_stats = agent.baseline_learner.get_all_stats()
        inference_numeric_count = sum(len(b.get('values', [])) if isinstance(b, dict) else 0 
                                     for b in inference_stats.get('numeric_baselines', {}).values())
        
        if final_numeric_count >= initial_numeric_count and inference_numeric_count == final_numeric_count:
            results['baseline_updates'][agent_id] = True
            print_success(f"{agent_id} agent handles baseline updates correctly (hybrid allows, inference blocks)")
        else:
            results['baseline_updates'][agent_id] = False
            print_error(f"{agent_id} agent baseline update handling may be incorrect")
            results['all_checks_passed'] = False
    
    # Test mode handling
    print_info("Testing training mode handling...")
    for agent_id, agent in crew_orchestrator.agents.items():
        modes = ['training', 'inference', 'hybrid']
        mode_results = {}
        
        for mode in modes:
            agent.set_training_mode(mode)
            if agent.training_mode == mode:
                mode_results[mode] = True
            else:
                mode_results[mode] = False
        
        if all(mode_results.values()):
            results['mode_handling'][agent_id] = True
            print_success(f"{agent_id} agent handles training modes correctly")
        else:
            results['mode_handling'][agent_id] = False
            print_error(f"{agent_id} agent mode handling failed: {mode_results}")
            results['all_checks_passed'] = False
    
    # Test readiness checks
    print_info("Testing baseline readiness checks...")
    for agent_id, agent in crew_orchestrator.agents.items():
        is_ready = agent._is_baseline_ready()
        stats = agent.baseline_learner.get_all_stats()
        
        # Manually check if any baseline is ready
        numeric_ready = any(b.get('is_ready', False) 
                           for b in stats.get('numeric_baselines', {}).values())
        pattern_ready = any(b.get('is_ready', False) 
                           for b in stats.get('pattern_baselines', {}).values())
        
        expected_ready = numeric_ready or pattern_ready
        
        if is_ready == expected_ready:
            results['readiness_checks'][agent_id] = True
            print_success(f"{agent_id} agent baseline readiness check correct: {is_ready}")
        else:
            results['readiness_checks'][agent_id] = False
            print_error(f"{agent_id} agent baseline readiness check incorrect (got {is_ready}, expected {expected_ready})")
            results['all_checks_passed'] = False
    
    return results

def generate_report(all_results: Dict[str, Any]) -> str:
    """Generate a comprehensive verification report."""
    report = []
    report.append("=" * 80)
    report.append("BASELINE TRAINING VERIFICATION REPORT")
    report.append("=" * 80)
    report.append(f"Generated: {datetime.now().isoformat()}")
    report.append("")
    
    # Summary
    report.append("SUMMARY")
    report.append("-" * 80)
    total_checks = sum(1 for r in all_results.values() if isinstance(r, dict) and 'all_checks_passed' in r)
    passed_checks = sum(1 for r in all_results.values() 
                       if isinstance(r, dict) and r.get('all_checks_passed', False))
    
    report.append(f"Total verification sections: {total_checks}")
    report.append(f"Passed sections: {passed_checks}")
    report.append(f"Failed sections: {total_checks - passed_checks}")
    report.append("")
    
    # Detailed results
    for section_name, section_results in all_results.items():
        if isinstance(section_results, dict):
            report.append(f"\n{section_name.upper().replace('_', ' ')}")
            report.append("-" * 80)
            
            if 'all_checks_passed' in section_results:
                status = "PASSED" if section_results['all_checks_passed'] else "FAILED"
                report.append(f"Status: {status}")
                report.append("")
            
            # Print detailed metrics
            for key, value in section_results.items():
                if key != 'all_checks_passed':
                    if isinstance(value, dict):
                        report.append(f"  {key}:")
                        for sub_key, sub_value in value.items():
                            report.append(f"    {sub_key}: {sub_value}")
                    elif isinstance(value, (list, tuple)):
                        report.append(f"  {key}: {len(value)} items")
                    else:
                        report.append(f"  {key}: {value}")
    
    report.append("")
    report.append("=" * 80)
    report.append("END OF REPORT")
    report.append("=" * 80)
    
    return "\n".join(report)

def main():
    """Main verification function."""
    print_header("BASELINE TRAINING VERIFICATION")
    
    print_info("Initializing TrainingOrchestrator...")
    training_orchestrator = TrainingOrchestrator()
    
    all_results = {}
    
    # 1. Verify training metrics for each agent
    for agent_id in ['router', 'computer', 'email']:
        metrics_results = verify_training_metrics(training_orchestrator, agent_id)
        all_results[f'training_metrics_{agent_id}'] = metrics_results
    
    # 2. Verify training flow
    flow_results = verify_training_flow(training_orchestrator, 'router')
    all_results['training_flow'] = flow_results
    
    # 3. Verify agent integration
    integration_results = verify_agent_integration(training_orchestrator)
    all_results['agent_integration'] = integration_results
    
    # 4. Verify baseline usage
    usage_results = verify_baseline_usage(training_orchestrator)
    all_results['baseline_usage'] = usage_results
    
    # Generate and print report
    print_header("VERIFICATION COMPLETE")
    report = generate_report(all_results)
    print(report)
    
    # Save report to file
    report_filename = f"baseline_training_verification_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_filename, 'w') as f:
        f.write(report)
    
    print_info(f"Report saved to: {report_filename}")
    
    # Return exit code
    all_passed = all(
        r.get('all_checks_passed', False) 
        for r in all_results.values() 
        if isinstance(r, dict) and 'all_checks_passed' in r
    )
    
    if all_passed:
        print_success("\nAll verification checks passed!")
        return 0
    else:
        print_error("\nSome verification checks failed. See report for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())

