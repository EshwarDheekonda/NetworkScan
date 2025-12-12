"""
Training Orchestrator

Manages training modes, coordinates agent training, and tracks training progress.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

from agents.baseline_learner import BaselineLearner
from baseline_training.config import get_config
from baseline_training.validators import validate_batch

logger = logging.getLogger(__name__)


class TrainingMode(Enum):
    """Training mode enumeration."""
    TRAINING = "training"  # Only learning, no anomaly detection
    INFERENCE = "inference"  # Only detection, no learning
    HYBRID = "hybrid"  # Initial training complete, continuous learning enabled


@dataclass
class TrainingStatus:
    """Training status information."""
    agent_id: str
    mode: TrainingMode
    is_training: bool
    baseline_ready: bool
    records_processed: int
    records_valid: int
    records_invalid: int
    errors: List[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'agent_id': self.agent_id,
            'mode': self.mode.value,
            'is_training': self.is_training,
            'baseline_ready': self.baseline_ready,
            'records_processed': self.records_processed,
            'records_valid': self.records_valid,
            'records_invalid': self.records_invalid,
            'errors': self.errors,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class TrainingResult:
    """Training result information."""
    success: bool
    agent_id: str
    records_processed: int
    records_valid: int
    records_invalid: int
    status: TrainingStatus
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'success': self.success,
            'agent_id': self.agent_id,
            'records_processed': self.records_processed,
            'records_valid': self.records_valid,
            'records_invalid': self.records_invalid,
            'status': self.status.to_dict(),
            'error_message': self.error_message
        }


class TrainingOrchestrator:
    """Orchestrates baseline training for agents."""
    
    def __init__(self, config=None):
        """
        Initialize training orchestrator.
        
        Args:
            config: Optional TrainingConfig instance
        """
        self.config = config or get_config()
        self.baseline_learners: Dict[str, BaselineLearner] = {}
        self.training_statuses: Dict[str, TrainingStatus] = {}
        self.agent_modes: Dict[str, TrainingMode] = {}
        self.agents: Dict[str, Any] = {}  # Store agent references for mode synchronization
        
        # Initialize statuses for all agents
        for agent_id in ['router', 'computer', 'email']:
            self.training_statuses[agent_id] = TrainingStatus(
                agent_id=agent_id,
                mode=TrainingMode.TRAINING,
                is_training=False,
                baseline_ready=False,
                records_processed=0,
                records_valid=0,
                records_invalid=0
            )
            self.agent_modes[agent_id] = TrainingMode.TRAINING
    
    def register_agent(self, agent_id: str, agent: Any):
        """
        Register agent for mode synchronization.
        
        Args:
            agent_id: Agent identifier
            agent: Agent instance
        """
        self.agents[agent_id] = agent
        logger.info(f"Registered agent {agent_id} for mode synchronization")
    
    def get_baseline_learner(self, agent_id: str) -> BaselineLearner:
        """
        Get or create baseline learner for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            BaselineLearner instance
        """
        if agent_id not in self.baseline_learners:
            agent_config = self.config.get_agent_config(agent_id)
            self.baseline_learners[agent_id] = BaselineLearner(agent_config)
        
        return self.baseline_learners[agent_id]
    
    def start_training(self, agent_id: str, data: List[Dict[str, Any]]) -> TrainingResult:
        """
        Start training for an agent with provided data.
        
        Args:
            agent_id: Agent identifier
            data: List of training data dictionaries
            
        Returns:
            TrainingResult object
        """
        if agent_id not in ['router', 'computer', 'email']:
            return TrainingResult(
                success=False,
                agent_id=agent_id,
                records_processed=0,
                records_valid=0,
                records_invalid=0,
                status=self.training_statuses.get(agent_id, TrainingStatus(
                    agent_id=agent_id,
                    mode=TrainingMode.TRAINING,
                    is_training=False,
                    baseline_ready=False,
                    records_processed=0,
                    records_valid=0,
                    records_invalid=0
                )),
                error_message=f"Unknown agent type: {agent_id}"
            )
        
        status = self.training_statuses[agent_id]
        status.is_training = True
        status.started_at = datetime.now()
        status.errors = []
        
        # Validate data
        all_valid, validation_errors = validate_batch(data, agent_id)
        
        if not all_valid:
            status.records_invalid = len(validation_errors)
            status.errors = validation_errors[:10]  # Limit to first 10 errors
            status.is_training = False
            status.completed_at = datetime.now()
            
            return TrainingResult(
                success=False,
                agent_id=agent_id,
                records_processed=len(data),
                records_valid=0,
                records_invalid=len(validation_errors),
                status=status,
                error_message=f"Validation failed: {len(validation_errors)} errors found"
            )
        
        # Get baseline learner
        baseline_learner = self.get_baseline_learner(agent_id)
        
        # Process training data
        records_valid = 0
        records_invalid = 0
        processing_errors = []
        
        for record in data:
            try:
                # Extract features (simplified - in real implementation, would use agent's feature extraction)
                features = self._extract_features_for_training(agent_id, record)
                
                # Get agent config for baseline parameters
                agent_config = self.config.get_agent_config(agent_id)
                
                # Update baselines (ensure they're created with config parameters)
                for feature_name, feature_value in features.items():
                    baseline_name = f"{agent_id}.{feature_name}"
                    
                    if isinstance(feature_value, (int, float)):
                        # Ensure numeric baseline exists with config parameters
                        if baseline_name not in baseline_learner.numeric_baselines:
                            window_size = agent_config.get('window_size', 1000)
                            min_samples = agent_config.get('min_samples', 10)
                            baseline_learner.create_numeric_baseline(
                                baseline_name,
                                window_size=window_size,
                                min_samples=min_samples
                            )
                        baseline_learner.update_numeric(
                            baseline_name,
                            float(feature_value),
                            datetime.now()
                        )
                    elif isinstance(feature_value, str):
                        # Ensure pattern baseline exists with config parameters
                        if baseline_name not in baseline_learner.pattern_baselines:
                            # Get feature-specific min_frequency if available
                            min_freq_key = f"min_{feature_name}_frequency"
                            min_frequency = agent_config.get(min_freq_key, agent_config.get('min_frequency', 3))
                            baseline_learner.create_pattern_baseline(
                                baseline_name,
                                min_frequency=min_frequency
                            )
                        baseline_learner.update_pattern(
                            baseline_name,
                            feature_value
                        )
                
                records_valid += 1
            except Exception as e:
                records_invalid += 1
                error_msg = f"Error processing record: {str(e)}"
                processing_errors.append(error_msg)
                logger.warning(f"{agent_id} training error: {error_msg}")
        
        # Update status
        status.records_processed = len(data)
        status.records_valid = records_valid
        status.records_invalid = records_invalid
        status.errors = processing_errors[:10]
        
        # Check if baseline is ready
        stats = baseline_learner.get_all_stats()
        numeric_baselines = stats.get('numeric_baselines', {})
        pattern_baselines = stats.get('pattern_baselines', {})
        
        baseline_ready = False
        if numeric_baselines:
            for baseline_stats in numeric_baselines.values():
                if baseline_stats.get('is_ready', False):
                    baseline_ready = True
                    break
        
        if not baseline_ready and pattern_baselines:
            # Check pattern baselines using is_ready
            for baseline_stats in pattern_baselines.values():
                if baseline_stats.get('is_ready', False):
                    baseline_ready = True
                    break
        
        status.baseline_ready = baseline_ready
        status.is_training = False
        status.completed_at = datetime.now()
        
        # Switch to hybrid mode if training completed successfully
        if baseline_ready and self.config.is_continuous_learning_enabled():
            self.agent_modes[agent_id] = TrainingMode.HYBRID
            status.mode = TrainingMode.HYBRID
        
        return TrainingResult(
            success=records_invalid == 0,
            agent_id=agent_id,
            records_processed=len(data),
            records_valid=records_valid,
            records_invalid=records_invalid,
            status=status,
            error_message=None if records_invalid == 0 else f"{records_invalid} records failed to process"
        )
    
    def _extract_features_for_training(self, agent_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from data for training (simplified version).
        
        This mimics what agents do in their _extract_features methods.
        
        Args:
            agent_id: Agent identifier
            data: Data dictionary
            
        Returns:
            Dictionary of features
        """
        features = {}
        
        if agent_id == 'router':
            dest = data.get('dest_ip') or data.get('dest_domain') or data.get('destination', '')
            if dest:
                features['destinations'] = str(dest)
            
            protocol = data.get('protocol', '').upper()
            if protocol:
                features['protocols'] = protocol
            
            port = data.get('port') or data.get('dest_port')
            if port:
                features['ports'] = str(port)
            
            bytes_sent = data.get('bytes_sent', 0) or 0
            bytes_received = data.get('bytes_received', 0) or 0
            total_bytes = bytes_sent + bytes_received
            if total_bytes > 0:
                features['data_volume'] = float(total_bytes)
            
            duration = data.get('duration_seconds') or data.get('duration', 0)
            if duration:
                features['connection_duration'] = float(duration)
            
            features['connection_frequency'] = 1.0
        
        elif agent_id == 'computer':
            process_name = data.get('process_name') or data.get('process', '')
            if process_name:
                features['processes'] = str(process_name).lower()
            
            user = data.get('user') or data.get('username', '')
            if user:
                features['users'] = str(user)
            
            file_path = data.get('file_path') or data.get('file', '')
            if file_path:
                features['file_paths'] = str(file_path)
            
            command = data.get('command_line') or data.get('command', '')
            if command:
                cmd_parts = str(command).split()
                if cmd_parts:
                    base_cmd = cmd_parts[0].lower()
                    features['commands'] = base_cmd
            
            features['process_frequency'] = 1.0
            features['file_access_frequency'] = 1.0
        
        elif agent_id == 'email':
            sender_domain = data.get('sender_domain') or ''
            if not sender_domain:
                sender = data.get('sender') or data.get('from', '')
                if sender and '@' in sender:
                    sender_domain = sender.split('@')[1].lower()
            
            if sender_domain:
                features['sender_domains'] = sender_domain
            
            sender = data.get('sender') or data.get('from', '')
            if sender:
                features['senders'] = sender.lower()
            
            attachment_type = data.get('attachment_type') or ''
            if not attachment_type:
                attachment_name = data.get('attachment_name') or data.get('attachment', '')
                if attachment_name and '.' in attachment_name:
                    attachment_type = attachment_name.split('.')[-1].lower()
            
            if attachment_type:
                features['attachment_types'] = attachment_type
            
            links = data.get('links') or data.get('urls', [])
            if isinstance(links, str):
                links = [links]
            
            for link in links:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(link)
                    domain = parsed.netloc.lower()
                    if domain:
                        features['link_domains'] = domain
                        break
                except:
                    pass
            
            attachment_size = data.get('attachment_size') or data.get('size', 0)
            if attachment_size:
                features['attachment_size'] = float(attachment_size)
            
            features['frequency'] = 1.0
        
        return features
    
    def stop_training(self, agent_id: str):
        """Stop training for an agent."""
        if agent_id in self.training_statuses:
            status = self.training_statuses[agent_id]
            status.is_training = False
            status.completed_at = datetime.now()
    
    def get_training_status(self, agent_id: str) -> TrainingStatus:
        """
        Get training status for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            TrainingStatus object
        """
        if agent_id not in self.training_statuses:
            return TrainingStatus(
                agent_id=agent_id,
                mode=TrainingMode.TRAINING,
                is_training=False,
                baseline_ready=False,
                records_processed=0,
                records_valid=0,
                records_invalid=0
            )
        
        status = self.training_statuses[agent_id]
        
        # Update baseline_ready status
        if agent_id in self.baseline_learners:
            baseline_learner = self.baseline_learners[agent_id]
            stats = baseline_learner.get_all_stats()
            numeric_baselines = stats.get('numeric_baselines', {})
            pattern_baselines = stats.get('pattern_baselines', {})
            
            baseline_ready = False
            # Check numeric baselines
            for baseline_stats in numeric_baselines.values():
                if baseline_stats.get('is_ready', False):
                    baseline_ready = True
                    break
            
            # Check pattern baselines if numeric not ready
            if not baseline_ready and pattern_baselines:
                for baseline_stats in pattern_baselines.values():
                    if baseline_stats.get('is_ready', False):
                        baseline_ready = True
                        break
            
            status.baseline_ready = baseline_ready
        
        return status
    
    def switch_to_inference_mode(self, agent_id: str):
        """Switch agent to inference mode (no learning)."""
        if agent_id in self.agent_modes:
            self.agent_modes[agent_id] = TrainingMode.INFERENCE
            if agent_id in self.training_statuses:
                self.training_statuses[agent_id].mode = TrainingMode.INFERENCE
            # Update agent mode if registered
            if agent_id in self.agents:
                try:
                    self.agents[agent_id].set_training_mode("inference")
                    logger.info(f"Switched agent {agent_id} to inference mode")
                except Exception as e:
                    logger.warning(f"Could not update agent {agent_id} mode: {e}")
    
    def enable_continuous_learning(self, agent_id: str):
        """Enable continuous learning (hybrid mode)."""
        if agent_id in self.agent_modes:
            self.agent_modes[agent_id] = TrainingMode.HYBRID
            if agent_id in self.training_statuses:
                self.training_statuses[agent_id].mode = TrainingMode.HYBRID
            # Update agent mode if registered
            if agent_id in self.agents:
                try:
                    self.agents[agent_id].set_training_mode("hybrid")
                    logger.info(f"Switched agent {agent_id} to hybrid mode")
                except Exception as e:
                    logger.warning(f"Could not update agent {agent_id} mode: {e}")
    
    def get_training_statistics(self, agent_id: str) -> Dict[str, Any]:
        """
        Get training statistics for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Dictionary with training statistics
        """
        status = self.get_training_status(agent_id)
        stats = {
            'status': status.to_dict(),
            'mode': self.agent_modes.get(agent_id, TrainingMode.TRAINING).value
        }
        
        if agent_id in self.baseline_learners:
            baseline_learner = self.baseline_learners[agent_id]
            baseline_stats = baseline_learner.get_all_stats()
            stats['baseline_stats'] = baseline_stats
        
        return stats
    
    def clear_baseline(self, agent_id: str) -> bool:
        """
        Clear baseline for an agent.
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            True if cleared successfully
        """
        if agent_id in self.baseline_learners:
            del self.baseline_learners[agent_id]
        
        if agent_id in self.training_statuses:
            self.training_statuses[agent_id] = TrainingStatus(
                agent_id=agent_id,
                mode=TrainingMode.TRAINING,
                is_training=False,
                baseline_ready=False,
                records_processed=0,
                records_valid=0,
                records_invalid=0
            )
        
        self.agent_modes[agent_id] = TrainingMode.TRAINING
        
        return True
    
    def get_baseline_learner_for_agent(self, agent_id: str) -> Optional[BaselineLearner]:
        """
        Get baseline learner instance for an agent (for integration with agents).
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            BaselineLearner instance or None
        """
        return self.baseline_learners.get(agent_id)




