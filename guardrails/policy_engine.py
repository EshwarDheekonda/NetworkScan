"""
Policy Engine

Defines and enforces policies for agent actions, determining which actions
are allowed, require approval, or are blocked.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging


class PolicyEngine:
    """Policy definition and enforcement engine."""
    
    def __init__(self, policies: Optional[Dict[str, Any]] = None):
        """
        Initialize the policy engine.
        
        Args:
            policies: Optional custom policies dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.policies = policies or self._default_policies()
    
    def _default_policies(self) -> Dict[str, Any]:
        """Get default policies."""
        return {
            # All actions require approval by default
            'default': {
                'requires_approval': True,
                'blocked': False
            },
            # Observation actions
            'observation': {
                'requires_approval': True,
                'blocked': False,
                'severity_based': {
                    'critical': {'requires_approval': True, 'blocked': False},
                    'high': {'requires_approval': True, 'blocked': False},
                    'medium': {'requires_approval': True, 'blocked': False},
                    'low': {'requires_approval': True, 'blocked': False}
                }
            },
            # Alert actions
            'alert': {
                'requires_approval': True,
                'blocked': False
            },
            # Configuration changes
            'config_change': {
                'requires_approval': True,
                'blocked': False
            },
            # Threshold adjustments
            'threshold_adjustment': {
                'requires_approval': True,
                'blocked': False
            },
            # Blocked action types
            'blocked_types': [
                'system_shutdown',
                'data_deletion',
                'network_block'
            ]
        }
    
    def check_policy(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if action complies with policies.
        
        Args:
            action: Action dictionary
            
        Returns:
            Dictionary with policy check result:
            - blocked: bool
            - requires_approval: bool
            - reason: str
        """
        action_type = action.get('type', 'unknown')
        
        # Check if action type is blocked
        if action_type in self.policies.get('blocked_types', []):
            return {
                'blocked': True,
                'requires_approval': False,
                'reason': f'Action type {action_type} is blocked by policy'
            }
        
        # Get policy for action type
        type_policy = self.policies.get(action_type, self.policies.get('default', {}))
        
        # Check severity-based policies for observations
        if action_type == 'observation':
            severity = self._extract_severity(action)
            severity_policy = type_policy.get('severity_based', {}).get(severity, {})
            if severity_policy:
                type_policy = {**type_policy, **severity_policy}
        
        # Check time-based policies
        time_result = self._check_time_policy(action, type_policy)
        if time_result:
            return time_result
        
        # Return policy result
        return {
            'blocked': type_policy.get('blocked', False),
            'requires_approval': type_policy.get('requires_approval', True),
            'reason': type_policy.get('reason', 'Policy check completed')
        }
    
    def _extract_severity(self, action: Dict[str, Any]) -> str:
        """Extract severity from action."""
        # Try to get severity from observation
        observation = action.get('observation')
        if observation:
            if isinstance(observation, dict):
                return observation.get('severity', 'medium')
            elif hasattr(observation, 'severity'):
                return observation.severity
        
        # Try to get from data
        data = action.get('data', {})
        if isinstance(data, dict):
            return data.get('severity', 'medium')
        
        return 'medium'
    
    def _check_time_policy(self, action: Dict[str, Any], policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check time-based policies (e.g., business hours)."""
        # For now, no time-based restrictions
        # In a full implementation, this would check business hours, etc.
        return None
    
    def update_policy(self, action_type: str, policy: Dict[str, Any]):
        """
        Update policy for an action type.
        
        Args:
            action_type: Action type
            policy: Policy dictionary
        """
        self.policies[action_type] = policy
        self.logger.info(f"Updated policy for {action_type}")
    
    def get_policy(self, action_type: str) -> Dict[str, Any]:
        """Get policy for an action type."""
        return self.policies.get(action_type, self.policies.get('default', {}))




