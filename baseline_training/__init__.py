"""
Baseline Training System

Provides training infrastructure for uploading and processing baseline training data
for Router, Computer, and Email agents.
"""

__version__ = "0.1.0"

from baseline_training.training_api import (
    upload_training_data,
    upload_training_data_from_dict,
    start_training,
    stop_training,
    get_training_status,
    clear_baseline,
    get_training_statistics,
    switch_agent_mode
)

try:
    from baseline_training.training_orchestrator import TrainingOrchestrator, TrainingResult, TrainingStatus
except ImportError:
    # Handle case where dependencies might not be available
    TrainingOrchestrator = None
    TrainingResult = None
    TrainingStatus = None

__all__ = [
    'upload_training_data',
    'upload_training_data_from_dict',
    'start_training',
    'stop_training',
    'get_training_status',
    'clear_baseline',
    'get_training_statistics',
    'switch_agent_mode',
    'TrainingOrchestrator',
    'TrainingResult',
    'TrainingStatus',
]

