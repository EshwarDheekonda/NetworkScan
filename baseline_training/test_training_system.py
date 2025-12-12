"""
Test script for baseline training system.

Tests training data upload, status checking, and mode switching for all agents.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from baseline_training.training_api import (
    upload_training_data,
    get_training_status,
    get_training_statistics,
    switch_agent_mode,
    clear_baseline,
    get_orchestrator
)
from agents.crew_orchestrator import CrewOrchestrator


def test_router_training():
    """Test Router agent training."""
    print("\n" + "="*60)
    print("Testing Router Agent Training")
    print("="*60)
    
    file_path = project_root / "test_data" / "router_test.json"
    
    print(f"\nUploading training data from: {file_path}")
    result = upload_training_data("router", str(file_path), "json")
    
    if result.success:
        print(f"✓ Training successful!")
        print(f"  Records processed: {result.records_processed}")
        print(f"  Records valid: {result.records_valid}")
        print(f"  Baseline ready: {result.status.baseline_ready}")
    else:
        print(f"✗ Training failed: {result.error_message}")
        return False
    
    # Check status
    print("\nChecking training status...")
    status = get_training_status("router")
    print(f"  Mode: {status.get('mode')}")
    print(f"  Baseline ready: {status.get('baseline_ready')}")
    print(f"  Records processed: {status.get('records_processed')}")
    
    # Check statistics
    print("\nTraining statistics:")
    stats = get_training_statistics("router")
    baseline_stats = stats.get('baseline_stats', {})
    numeric_baselines = baseline_stats.get('numeric_baselines', {})
    pattern_baselines = baseline_stats.get('pattern_baselines', {})
    
    print(f"  Numeric baselines: {len(numeric_baselines)}")
    print(f"  Pattern baselines: {len(pattern_baselines)}")
    
    return True


def test_computer_training():
    """Test Computer agent training."""
    print("\n" + "="*60)
    print("Testing Computer Agent Training")
    print("="*60)
    
    file_path = project_root / "test_data" / "computer_test.json"
    
    print(f"\nUploading training data from: {file_path}")
    result = upload_training_data("computer", str(file_path), "json")
    
    if result.success:
        print(f"✓ Training successful!")
        print(f"  Records processed: {result.records_processed}")
        print(f"  Records valid: {result.records_valid}")
        print(f"  Baseline ready: {result.status.baseline_ready}")
    else:
        print(f"✗ Training failed: {result.error_message}")
        return False
    
    # Check status
    print("\nChecking training status...")
    status = get_training_status("computer")
    print(f"  Mode: {status.get('mode')}")
    print(f"  Baseline ready: {status.get('baseline_ready')}")
    
    return True


def test_email_training():
    """Test Email agent training."""
    print("\n" + "="*60)
    print("Testing Email Agent Training")
    print("="*60)
    
    file_path = project_root / "test_data" / "email_test.json"
    
    print(f"\nUploading training data from: {file_path}")
    result = upload_training_data("email", str(file_path), "json")
    
    if result.success:
        print(f"✓ Training successful!")
        print(f"  Records processed: {result.records_processed}")
        print(f"  Records valid: {result.records_valid}")
        print(f"  Baseline ready: {result.status.baseline_ready}")
    else:
        print(f"✗ Training failed: {result.error_message}")
        return False
    
    # Check status
    print("\nChecking training status...")
    status = get_training_status("email")
    print(f"  Mode: {status.get('mode')}")
    print(f"  Baseline ready: {status.get('baseline_ready')}")
    
    return True


def test_mode_switching():
    """Test mode switching."""
    print("\n" + "="*60)
    print("Testing Mode Switching")
    print("="*60)
    
    # Test switching to inference mode
    print("\nSwitching router to inference mode...")
    success = switch_agent_mode("router", "inference")
    if success:
        print("✓ Mode switched successfully")
        status = get_training_status("router")
        print(f"  Current mode: {status.get('mode')}")
    else:
        print("✗ Mode switch failed")
        return False
    
    # Test switching to hybrid mode
    print("\nSwitching router to hybrid mode...")
    success = switch_agent_mode("router", "hybrid")
    if success:
        print("✓ Mode switched successfully")
        status = get_training_status("router")
        print(f"  Current mode: {status.get('mode')}")
    else:
        print("✗ Mode switch failed")
        return False
    
    return True


def test_agent_integration():
    """Test that agents receive trained baselines."""
    print("\n" + "="*60)
    print("Testing Agent Integration with Trained Baselines")
    print("="*60)
    
    # Get the training orchestrator
    training_orchestrator = get_orchestrator()
    if not training_orchestrator:
        print("✗ Could not get training orchestrator")
        return False
    
    # Initialize CrewOrchestrator with training orchestrator
    print("\nInitializing agents with training orchestrator...")
    try:
        crew_orchestrator = CrewOrchestrator(training_orchestrator=training_orchestrator)
        print("✓ Agents initialized successfully")
    except Exception as e:
        print(f"✗ Failed to initialize agents: {e}")
        return False
    
    # Check each agent
    all_agents_ok = True
    for agent_id, agent in crew_orchestrator.agents.items():
        print(f"\nChecking {agent_id} agent...")
        
        # Check if agent has baseline learner
        if not hasattr(agent, 'baseline_learner'):
            print(f"  ✗ {agent_id} agent missing baseline_learner")
            all_agents_ok = False
            continue
        
        baseline_learner = agent.baseline_learner
        
        # Get baseline statistics
        stats = baseline_learner.get_all_stats()
        numeric_baselines = stats.get('numeric_baselines', {})
        pattern_baselines = stats.get('pattern_baselines', {})
        
        # Check if baselines have data
        has_numeric = len(numeric_baselines) > 0
        has_pattern = len(pattern_baselines) > 0
        
        if has_numeric or has_pattern:
            print(f"  ✓ {agent_id} agent has trained baselines")
            print(f"    - Numeric baselines: {len(numeric_baselines)}")
            print(f"    - Pattern baselines: {len(pattern_baselines)}")
            
            # Check baseline readiness
            baseline_ready = agent._is_baseline_ready()
            print(f"    - Baseline ready: {baseline_ready}")
        else:
            print(f"  ✗ {agent_id} agent baseline learner is empty")
            all_agents_ok = False
    
    return all_agents_ok


def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("Baseline Training System Test Suite")
    print("="*60)
    
    results = []
    
    # Test Router agent
    results.append(("Router Training", test_router_training()))
    
    # Test Computer agent
    results.append(("Computer Training", test_computer_training()))
    
    # Test Email agent
    results.append(("Email Training", test_email_training()))
    
    # Test mode switching
    results.append(("Mode Switching", test_mode_switching()))
    
    # Test agent integration
    results.append(("Agent Integration", test_agent_integration()))
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())




