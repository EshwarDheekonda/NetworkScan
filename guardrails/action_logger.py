"""
Action Logger

Comprehensive logging of all agent actions, approval decisions, and
maintains complete audit trail.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
import json
from collections import deque
from pathlib import Path


class ActionLogger:
    """Comprehensive action logging with audit trail."""
    
    def __init__(
        self,
        log_file: Optional[str] = None,
        max_memory_logs: int = 10000
    ):
        """
        Initialize the action logger.
        
        Args:
            log_file: Optional file path for persistent logging
            max_memory_logs: Maximum logs to keep in memory
        """
        self.logger = logging.getLogger(__name__)
        self.log_file = log_file
        self.max_memory_logs = max_memory_logs
        
        # In-memory log buffer
        self.log_buffer: deque = deque(maxlen=max_memory_logs)
        
        # Initialize log file if provided
        if self.log_file:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
    
    def log_action(
        self,
        action: Dict[str, Any],
        status: str = 'logged',
        **kwargs
    ):
        """
        Log an agent action.
        
        Args:
            action: Action dictionary
            status: Action status (intercepted, allowed, blocked, pending_approval, approved, rejected)
            **kwargs: Additional metadata
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'action_id': action.get('action_id', 'unknown'),
            'action_type': action.get('type', 'unknown'),
            'agent_id': action.get('agent_id', 'unknown'),
            'status': status,
            'action': action,
            **kwargs
        }
        
        # Add to buffer
        self.log_buffer.append(log_entry)
        
        # Write to file if configured
        if self.log_file:
            self._write_to_file(log_entry)
        
        # Log to standard logger
        self.logger.info(
            f"Action logged: {action.get('type', 'unknown')} by {action.get('agent_id', 'unknown')} - {status}"
        )
    
    def _write_to_file(self, log_entry: Dict[str, Any]):
        """Write log entry to file."""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, default=str) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write to log file: {e}")
    
    def get_action_history(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get action history with optional filters.
        
        Args:
            agent_id: Filter by agent ID
            action_type: Filter by action type
            status: Filter by status
            limit: Maximum number of records
            
        Returns:
            List of log entries
        """
        history = list(self.log_buffer)
        
        # Apply filters
        if agent_id:
            history = [h for h in history if h.get('agent_id') == agent_id]
        
        if action_type:
            history = [h for h in history if h.get('action_type') == action_type]
        
        if status:
            history = [h for h in history if h.get('status') == status]
        
        return history[-limit:]
    
    def get_audit_trail(
        self,
        action_id: str
    ) -> List[Dict[str, Any]]:
        """
        Get complete audit trail for an action.
        
        Args:
            action_id: Action ID
            
        Returns:
            List of all log entries for the action
        """
        return [
            entry for entry in self.log_buffer
            if entry.get('action_id') == action_id
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get logging statistics."""
        status_counts = {}
        for entry in self.log_buffer:
            status = entry.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_logs': len(self.log_buffer),
            'status_counts': status_counts,
            'log_file': self.log_file
        }




