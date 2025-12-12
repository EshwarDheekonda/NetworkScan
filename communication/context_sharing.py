"""
Context Sharing

Shared context management for agents.
"""

from typing import Dict, Any, Optional
import logging
from datetime import datetime


class ContextSharing:
    """Manages shared threat context across agents."""
    
    def __init__(self):
        """Initialize context sharing."""
        self.logger = logging.getLogger(__name__)
        self.shared_threat_context: Dict[str, Any] = {}
        self.context_history: List[Dict[str, Any]] = []
    
    def update_threat_context(self, context: Dict[str, Any]):
        """Update shared threat context."""
        self.shared_threat_context.update(context)
        self.shared_threat_context['last_updated'] = datetime.now().isoformat()
        
        self.context_history.append({
            'timestamp': datetime.now().isoformat(),
            'context': context.copy()
        })
        
        # Keep last 1000 context updates
        if len(self.context_history) > 1000:
            self.context_history = self.context_history[-1000:]
    
    def get_threat_context(self) -> Dict[str, Any]:
        """Get current shared threat context."""
        return self.shared_threat_context.copy()




