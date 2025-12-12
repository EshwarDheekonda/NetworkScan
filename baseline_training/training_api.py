"""
Training API

Clean API functions for training operations.
"""

from typing import List, Dict, Any, Optional
import logging

from baseline_training.training_orchestrator import (
    TrainingOrchestrator,
    TrainingResult,
    TrainingStatus,
    TrainingMode
)
from baseline_training.data_ingestion import load_training_data
from baseline_training.config import get_config

logger = logging.getLogger(__name__)

# Global orchestrator instance
_global_orchestrator: Optional[TrainingOrchestrator] = None


def get_orchestrator() -> TrainingOrchestrator:
    """Get global training orchestrator instance."""
    global _global_orchestrator
    if _global_orchestrator is None:
        _global_orchestrator = TrainingOrchestrator(get_config())
    return _global_orchestrator


def set_orchestrator(orchestrator: TrainingOrchestrator):
    """Set global training orchestrator instance."""
    global _global_orchestrator
    _global_orchestrator = orchestrator


def upload_training_data(
    agent_id: str,
    file_path: str,
    format: str = None
) -> TrainingResult:
    """
    Upload training data from file for an agent.
    
    Args:
        agent_id: Agent identifier ('router', 'computer', 'email')
        file_path: Path to training data file
        format: File format ('json', 'csv', 'jsonl'). If None, auto-detect.
        
    Returns:
        TrainingResult object
    """
    try:
        # Load and validate data
        data = load_training_data(file_path, agent_id, format)
        
        if not data:
            return TrainingResult(
                success=False,
                agent_id=agent_id,
                records_processed=0,
                records_valid=0,
                records_invalid=0,
                status=get_training_status(agent_id),
                error_message="No data found in file"
            )
        
        # Start training
        orchestrator = get_orchestrator()
        result = orchestrator.start_training(agent_id, data)
        
        logger.info(f"Training completed for {agent_id}: {result.records_valid} valid, {result.records_invalid} invalid")
        
        return result
    
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return TrainingResult(
            success=False,
            agent_id=agent_id,
            records_processed=0,
            records_valid=0,
            records_invalid=0,
            status=get_training_status(agent_id),
            error_message=f"File not found: {e}"
        )
    except Exception as e:
        logger.error(f"Error uploading training data: {e}", exc_info=True)
        return TrainingResult(
            success=False,
            agent_id=agent_id,
            records_processed=0,
            records_valid=0,
            records_invalid=0,
            status=get_training_status(agent_id),
            error_message=f"Error: {str(e)}"
        )


def upload_training_data_from_dict(
    agent_id: str,
    data: List[Dict[str, Any]]
) -> TrainingResult:
    """
    Upload training data from dictionary/list for an agent.
    
    Args:
        agent_id: Agent identifier ('router', 'computer', 'email')
        data: List of training data dictionaries
        
    Returns:
        TrainingResult object
    """
    try:
        if not data:
            return TrainingResult(
                success=False,
                agent_id=agent_id,
                records_processed=0,
                records_valid=0,
                records_invalid=0,
                status=get_training_status(agent_id),
                error_message="No data provided"
            )
        
        # Start training
        orchestrator = get_orchestrator()
        result = orchestrator.start_training(agent_id, data)
        
        logger.info(f"Training completed for {agent_id}: {result.records_valid} valid, {result.records_invalid} invalid")
        
        return result
    
    except Exception as e:
        logger.error(f"Error uploading training data: {e}", exc_info=True)
        return TrainingResult(
            success=False,
            agent_id=agent_id,
            records_processed=0,
            records_valid=0,
            records_invalid=0,
            status=get_training_status(agent_id),
            error_message=f"Error: {str(e)}"
        )


def start_training(agent_id: str) -> bool:
    """
    Start training mode for an agent (placeholder for future async training).
    
    Args:
        agent_id: Agent identifier
        
    Returns:
        True if started successfully
    """
    # Currently training happens synchronously in upload_training_data
    # This function is a placeholder for future async training support
    logger.info(f"Training mode started for {agent_id}")
    return True


def stop_training(agent_id: str) -> bool:
    """
    Stop training for an agent.
    
    Args:
        agent_id: Agent identifier
        
    Returns:
        True if stopped successfully
    """
    try:
        orchestrator = get_orchestrator()
        orchestrator.stop_training(agent_id)
        logger.info(f"Training stopped for {agent_id}")
        return True
    except Exception as e:
        logger.error(f"Error stopping training: {e}")
        return False


def get_training_status(agent_id: str) -> Dict[str, Any]:
    """
    Get training status for an agent.
    
    Args:
        agent_id: Agent identifier
        
    Returns:
        Dictionary with training status information
    """
    try:
        orchestrator = get_orchestrator()
        status = orchestrator.get_training_status(agent_id)
        return status.to_dict()
    except Exception as e:
        logger.error(f"Error getting training status: {e}")
        return {
            'agent_id': agent_id,
            'mode': 'training',
            'is_training': False,
            'baseline_ready': False,
            'records_processed': 0,
            'records_valid': 0,
            'records_invalid': 0,
            'errors': [],
            'started_at': None,
            'completed_at': None
        }


def clear_baseline(agent_id: str) -> bool:
    """
    Clear baseline for an agent.
    
    Args:
        agent_id: Agent identifier
        
    Returns:
        True if cleared successfully
    """
    try:
        orchestrator = get_orchestrator()
        result = orchestrator.clear_baseline(agent_id)
        logger.info(f"Baseline cleared for {agent_id}")
        return result
    except Exception as e:
        logger.error(f"Error clearing baseline: {e}")
        return False


def get_training_statistics(agent_id: str) -> Dict[str, Any]:
    """
    Get training statistics for an agent.
    
    Args:
        agent_id: Agent identifier
        
    Returns:
        Dictionary with training statistics
    """
    try:
        orchestrator = get_orchestrator()
        return orchestrator.get_training_statistics(agent_id)
    except Exception as e:
        logger.error(f"Error getting training statistics: {e}")
        return {
            'status': get_training_status(agent_id),
            'mode': 'training',
            'baseline_stats': {}
        }


def switch_agent_mode(agent_id: str, mode: str) -> bool:
    """
    Switch agent mode (training, inference, hybrid).
    
    Args:
        agent_id: Agent identifier
        mode: Mode string ('training', 'inference', 'hybrid')
        
    Returns:
        True if switched successfully
    """
    try:
        orchestrator = get_orchestrator()
        
        mode_lower = mode.lower()
        if mode_lower == 'inference':
            orchestrator.switch_to_inference_mode(agent_id)
        elif mode_lower == 'hybrid':
            orchestrator.enable_continuous_learning(agent_id)
        elif mode_lower == 'training':
            # Reset to training mode
            orchestrator.agent_modes[agent_id] = TrainingMode.TRAINING
            if agent_id in orchestrator.training_statuses:
                orchestrator.training_statuses[agent_id].mode = TrainingMode.TRAINING
            # Update agent mode if registered
            if hasattr(orchestrator, 'agents') and agent_id in orchestrator.agents:
                try:
                    orchestrator.agents[agent_id].set_training_mode("training")
                except Exception as e:
                    logger.warning(f"Could not update agent {agent_id} mode: {e}")
        else:
            logger.warning(f"Unknown mode: {mode}")
            return False
        
        logger.info(f"Switched {agent_id} to {mode} mode")
        return True
    except Exception as e:
        logger.error(f"Error switching mode: {e}")
        return False




