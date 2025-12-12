"""
Training Configuration

Centralized configuration for baseline training parameters and agent-specific settings.
"""

from typing import Dict, Any
import os
import json


class TrainingConfig:
    """Training configuration manager."""
    
    DEFAULT_CONFIG = {
        "training": {
            "min_samples": 10,
            "window_size": 1000,
            "min_frequency": 3,
            "enable_continuous_learning": True
        },
        "agents": {
            "router": {
                "min_samples": 10,
                "window_size": 1000,
                "min_destination_frequency": 3,
                "min_protocol_frequency": 2,
                "min_port_frequency": 3
            },
            "computer": {
                "min_samples": 10,
                "window_size": 1000,
                "min_process_frequency": 3,
                "min_user_frequency": 2,
                "min_file_frequency": 3,
                "min_command_frequency": 2
            },
            "email": {
                "min_samples": 10,
                "window_size": 1000,
                "min_domain_frequency": 3,
                "min_sender_frequency": 2,
                "min_attachment_frequency": 2,
                "min_link_frequency": 3
            }
        }
    }
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Optional path to JSON configuration file
        """
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = self.DEFAULT_CONFIG.copy()
    
    def get_training_config(self) -> Dict[str, Any]:
        """Get general training configuration."""
        return self.config.get("training", {})
    
    def get_agent_config(self, agent_id: str) -> Dict[str, Any]:
        """
        Get agent-specific configuration.
        
        Args:
            agent_id: Agent identifier (router, computer, email)
            
        Returns:
            Agent configuration dictionary
        """
        agent_configs = self.config.get("agents", {})
        agent_config = agent_configs.get(agent_id, {})
        
        # Merge with general training config as defaults
        training_config = self.get_training_config()
        merged = training_config.copy()
        merged.update(agent_config)
        
        return merged
    
    def get_min_samples(self, agent_id: str) -> int:
        """Get minimum samples required for baseline readiness."""
        agent_config = self.get_agent_config(agent_id)
        return agent_config.get("min_samples", 10)
    
    def get_window_size(self, agent_id: str) -> int:
        """Get window size for baseline models."""
        agent_config = self.get_agent_config(agent_id)
        return agent_config.get("window_size", 1000)
    
    def get_min_frequency(self, agent_id: str, feature_type: str = None) -> int:
        """
        Get minimum frequency for pattern baselines.
        
        Args:
            agent_id: Agent identifier
            feature_type: Optional specific feature type (e.g., 'destination', 'process')
            
        Returns:
            Minimum frequency threshold
        """
        agent_config = self.get_agent_config(agent_id)
        
        if feature_type:
            # Try agent-specific frequency setting
            key = f"min_{feature_type}_frequency"
            if key in agent_config:
                return agent_config[key]
        
        # Fall back to general min_frequency
        return agent_config.get("min_frequency", 3)
    
    def is_continuous_learning_enabled(self) -> bool:
        """Check if continuous learning is enabled."""
        training_config = self.get_training_config()
        return training_config.get("enable_continuous_learning", True)
    
    def update_config(self, updates: Dict[str, Any]):
        """
        Update configuration with new values.
        
        Args:
            updates: Dictionary of configuration updates
        """
        def deep_update(base_dict, update_dict):
            for key, value in update_dict.items():
                if isinstance(value, dict) and key in base_dict:
                    deep_update(base_dict[key], value)
                else:
                    base_dict[key] = value
        
        deep_update(self.config, updates)
    
    def save_config(self, config_file: str):
        """
        Save configuration to file.
        
        Args:
            config_file: Path to save configuration file
        """
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)


# Global configuration instance
_global_config: TrainingConfig = None


def get_config(config_file: str = None) -> TrainingConfig:
    """
    Get global configuration instance.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        TrainingConfig instance
    """
    global _global_config
    if _global_config is None:
        _global_config = TrainingConfig(config_file)
    return _global_config


def set_config(config: TrainingConfig):
    """
    Set global configuration instance.
    
    Args:
        config: TrainingConfig instance
    """
    global _global_config
    _global_config = config




