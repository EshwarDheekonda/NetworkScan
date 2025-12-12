"""
Approval Manager

Manages user approval workflow for agent actions, queues pending approvals,
and tracks approval history.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import uuid
import logging
from collections import deque


class ApprovalManager:
    """Manages approval workflow for agent actions."""
    
    def __init__(self, max_pending: int = 1000):
        """
        Initialize the approval manager.
        
        Args:
            max_pending: Maximum number of pending approvals to keep
        """
        self.logger = logging.getLogger(__name__)
        self.max_pending = max_pending
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.approval_history: deque = deque(maxlen=10000)  # Keep last 10k approvals
    
    def request_approval(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request approval for an action.
        
        Args:
            action: Action dictionary
            
        Returns:
            Dictionary with approval request info:
            - approval_id: str
            - status: str
            - timestamp: str
        """
        approval_id = str(uuid.uuid4())
        
        approval_request = {
            'approval_id': approval_id,
            'action': action,
            'status': 'pending',
            'requested_at': datetime.now().isoformat(),
            'approved': None,
            'approved_by': None,
            'approved_at': None,
            'reason': None
        }
        
        self.pending_approvals[approval_id] = approval_request
        
        # Trim if too many pending
        if len(self.pending_approvals) > self.max_pending:
            # Remove oldest pending
            oldest = min(
                self.pending_approvals.items(),
                key=lambda x: x[1].get('requested_at', '')
            )
            del self.pending_approvals[oldest[0]]
        
        self.logger.info(f"Approval requested: {approval_id} for action {action.get('type', 'unknown')}")
        
        return {
            'approval_id': approval_id,
            'status': 'pending',
            'timestamp': approval_request['requested_at']
        }
    
    def approve(
        self,
        approval_id: str,
        approved: bool,
        user: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Approve or reject a pending action.
        
        Args:
            approval_id: Approval request ID
            approved: Whether to approve
            user: User making the decision
            reason: Reason for decision
            
        Returns:
            Dictionary with approval result
        """
        if approval_id not in self.pending_approvals:
            return {
                'success': False,
                'error': f'Approval request {approval_id} not found'
            }
        
        approval_request = self.pending_approvals[approval_id]
        
        approval_request['status'] = 'approved' if approved else 'rejected'
        approval_request['approved'] = approved
        approval_request['approved_by'] = user or 'system'
        approval_request['approved_at'] = datetime.now().isoformat()
        approval_request['reason'] = reason
        
        # Move to history
        self.approval_history.append(approval_request.copy())
        
        # Remove from pending
        action = approval_request['action']
        del self.pending_approvals[approval_id]
        
        self.logger.info(
            f"Approval {approval_id} {'approved' if approved else 'rejected'} by {user or 'system'}"
        )
        
        return {
            'success': True,
            'approval_id': approval_id,
            'approved': approved,
            'action': action
        }
    
    def get_approval_status(self, approval_id: str) -> Dict[str, Any]:
        """Get status of an approval request."""
        if approval_id in self.pending_approvals:
            return self.pending_approvals[approval_id]
        
        # Check history
        for approval in self.approval_history:
            if approval['approval_id'] == approval_id:
                return approval
        
        return {'error': f'Approval {approval_id} not found'}
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get all pending approval requests."""
        return list(self.pending_approvals.values())
    
    def get_approval_history(
        self,
        limit: int = 100,
        action_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get approval history.
        
        Args:
            limit: Maximum number of records to return
            action_type: Optional filter by action type
            
        Returns:
            List of approval records
        """
        history = list(self.approval_history)
        
        if action_type:
            history = [
                h for h in history
                if h.get('action', {}).get('type') == action_type
            ]
        
        return history[-limit:]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get approval statistics."""
        total_approved = sum(1 for h in self.approval_history if h.get('approved', False))
        total_rejected = sum(1 for h in self.approval_history if not h.get('approved', True))
        
        return {
            'pending_count': len(self.pending_approvals),
            'total_approved': total_approved,
            'total_rejected': total_rejected,
            'total_processed': len(self.approval_history)
        }




