"""
Action Guard

Core guardrails engine that intercepts all agent actions, validates them
against policies, and requires user approval.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

from guardrails.policy_engine import PolicyEngine
from guardrails.approval_manager import ApprovalManager
from guardrails.action_logger import ActionLogger


class ActionGuard:
    """Core guardrails engine for agent actions."""
    
    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        approval_manager: Optional[ApprovalManager] = None,
        action_logger: Optional[ActionLogger] = None
    ):
        """
        Initialize the action guard.
        
        Args:
            policy_engine: Policy engine instance
            approval_manager: Approval manager instance
            action_logger: Action logger instance
        """
        self.policy_engine = policy_engine or PolicyEngine()
        self.approval_manager = approval_manager or ApprovalManager()
        self.action_logger = action_logger or ActionLogger()
        self.logger = logging.getLogger(__name__)
        
        # Statistics
        self.actions_intercepted = 0
        self.actions_allowed = 0
        self.actions_blocked = 0
        self.actions_pending = 0
    
    def intercept_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercept and validate an agent action.
        
        Args:
            action: Action dictionary with keys:
                   - type: Action type (observation, alert, config_change, etc.)
                   - agent_id: ID of the agent
                   - data: Action data
                   - timestamp: Optional timestamp
                   
        Returns:
            Dictionary with action status:
            - allowed: bool
            - requires_approval: bool
            - action_id: str
            - message: str
        """
        self.actions_intercepted += 1
        
        # Add timestamp if not present
        if 'timestamp' not in action:
            action['timestamp'] = datetime.now().isoformat()
        
        # Generate action ID
        action_id = self._generate_action_id(action)
        action['action_id'] = action_id
        
        # Log action
        self.action_logger.log_action(action, status='intercepted')
        
        # Check policy
        policy_result = self.policy_engine.check_policy(action)
        
        if policy_result['blocked']:
            # Action is blocked by policy
            self.actions_blocked += 1
            self.action_logger.log_action(action, status='blocked', reason=policy_result.get('reason'))
            return {
                'allowed': False,
                'requires_approval': False,
                'action_id': action_id,
                'message': f"Action blocked by policy: {policy_result.get('reason', 'Unknown reason')}",
                'blocked': True
            }
        
        if policy_result['requires_approval']:
            # Action requires approval
            self.actions_pending += 1
            approval_request = self.approval_manager.request_approval(action)
            
            self.action_logger.log_action(action, status='pending_approval', approval_id=approval_request['approval_id'])
            
            return {
                'allowed': False,
                'requires_approval': True,
                'action_id': action_id,
                'approval_id': approval_request['approval_id'],
                'message': 'Action requires user approval',
                'pending': True
            }
        
        # Action is allowed without approval
        self.actions_allowed += 1
        self.action_logger.log_action(action, status='allowed')
        
        return {
            'allowed': True,
            'requires_approval': False,
            'action_id': action_id,
            'message': 'Action allowed by policy'
        }
    
    def request_approval(self, action: Dict[str, Any]) -> bool:
        """
        Request approval for an action (used by agents).
        
        Args:
            action: Action dictionary
            
        Returns:
            True if approved, False otherwise
        """
        result = self.intercept_action(action)
        
        if result.get('blocked'):
            return False
        
        if result.get('allowed'):
            return True
        
        if result.get('requires_approval'):
            # Check if approval was already granted
            approval_id = result.get('approval_id')
            if approval_id:
                approval_status = self.approval_manager.get_approval_status(approval_id)
                return approval_status.get('approved', False)
        
        return False
    
    def approve_action(self, approval_id: str, approved: bool, user: Optional[str] = None, reason: Optional[str] = None) -> Dict[str, Any]:
        """
        Approve or reject a pending action.
        
        Args:
            approval_id: Approval request ID
            approved: Whether action is approved
            user: User who made the decision
            reason: Reason for approval/rejection
            
        Returns:
            Dictionary with approval result
        """
        result = self.approval_manager.approve(approval_id, approved, user, reason)
        
        if result['success']:
            # Update action log
            action = result.get('action', {})
            status = 'approved' if approved else 'rejected'
            self.action_logger.log_action(action, status=status, approved_by=user, reason=reason)
            
            if approved:
                self.actions_allowed += 1
                self.actions_pending -= 1
            else:
                self.actions_blocked += 1
                self.actions_pending -= 1
        
        return result
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests."""
        return self.approval_manager.get_pending_approvals()
    
    def _generate_action_id(self, action: Dict[str, Any]) -> str:
        """Generate unique action ID."""
        import hashlib
        import json
        
        action_str = json.dumps(action, sort_keys=True, default=str)
        action_hash = hashlib.md5(action_str.encode()).hexdigest()[:12]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        return f"{action.get('type', 'action')}_{timestamp}_{action_hash}"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get guardrails statistics."""
        return {
            'actions_intercepted': self.actions_intercepted,
            'actions_allowed': self.actions_allowed,
            'actions_blocked': self.actions_blocked,
            'actions_pending': self.actions_pending,
            'pending_approvals_count': len(self.get_pending_approvals())
        }




