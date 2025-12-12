"""
Notification System

Provides real-time notifications for pending approvals, critical threats,
summary reports, and integration with external systems.
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
import logging


class NotificationSystem:
    """Notification system for user alerts."""
    
    def __init__(self):
        """Initialize the notification system."""
        self.logger = logging.getLogger(__name__)
        self.notification_handlers: List[Callable] = []
        self.notification_history: List[Dict[str, Any]] = []
        self.max_history = 1000
    
    def register_handler(self, handler: Callable[[Dict[str, Any]], None]):
        """Register a notification handler."""
        self.notification_handlers.append(handler)
        self.logger.info(f"Registered notification handler: {handler.__name__}")
    
    def notify(
        self,
        notification_type: str,
        message: str,
        severity: str = "info",
        data: Optional[Dict[str, Any]] = None
    ):
        """
        Send a notification.
        
        Args:
            notification_type: Type of notification (approval, threat, summary, etc.)
            message: Notification message
            severity: Severity level (info, warning, error, critical)
            data: Additional notification data
        """
        notification = {
            'timestamp': datetime.now().isoformat(),
            'type': notification_type,
            'message': message,
            'severity': severity,
            'data': data or {}
        }
        
        # Add to history
        self.notification_history.append(notification)
        if len(self.notification_history) > self.max_history:
            self.notification_history = self.notification_history[-self.max_history:]
        
        # Send to all handlers
        for handler in self.notification_handlers:
            try:
                handler(notification)
            except Exception as e:
                self.logger.error(f"Notification handler failed: {e}")
        
        self.logger.info(f"Notification sent: {notification_type} - {message}")
    
    def notify_pending_approval(self, approval_id: str, action: Dict[str, Any]):
        """Notify about pending approval."""
        self.notify(
            'approval',
            f"Pending approval required: {action.get('type', 'unknown')} from {action.get('agent_id', 'unknown')}",
            severity='warning',
            data={'approval_id': approval_id, 'action': action}
        )
    
    def notify_critical_threat(self, threat_info: Dict[str, Any]):
        """Notify about critical threat."""
        self.notify(
            'threat',
            f"Critical threat detected: {threat_info.get('description', 'Unknown threat')}",
            severity='critical',
            data=threat_info
        )
    
    def notify_proactive_threat(
        self,
        attack_type: str,
        mitre_techniques: List[Dict[str, Any]],
        indicators: List[str],
        mitigations: List[Dict[str, Any]],
        detected_by: List[str],
        confidence: float,
        severity: str,
        description: Optional[str] = None,
        mitre_tactics: Optional[List[Dict[str, Any]]] = None,
        recommended_actions: Optional[List[str]] = None
    ):
        """
        Notify about proactive threat detection.
        
        Args:
            attack_type: Type of attack (e.g., "Command and Control", "Data Exfiltration")
            mitre_techniques: List of MITRE techniques matched
            indicators: List of attack indicators
            mitigations: List of mitigation measures
            detected_by: List of agent IDs that detected this
            confidence: Detection confidence (0.0-1.0)
            severity: Severity level (critical, high, medium, low)
            description: Optional description of the threat
            mitre_tactics: Optional list of MITRE tactics
            recommended_actions: Optional list of recommended actions
        """
        if description is None:
            technique_names = [t.get('name', t.get('id', 'Unknown')) for t in mitre_techniques[:3]]
            description = f"Proactive detection of {attack_type} attack. Matched MITRE techniques: {', '.join(technique_names)}"
        
        threat_data = {
            'warning_type': 'proactive_threat',
            'attack_type': attack_type,
            'severity': severity,
            'indicators': indicators,
            'description': description,
            'mitre_techniques': mitre_techniques,
            'mitre_tactics': mitre_tactics or [],
            'mitigations': mitigations,
            'recommended_actions': recommended_actions or [],
            'detected_by': detected_by,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
        
        self.notify(
            'proactive_threat',
            description,
            severity=severity,
            data=threat_data
        )
    
    def get_notification_history(
        self,
        notification_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get notification history."""
        history = self.notification_history
        
        if notification_type:
            history = [n for n in history if n.get('type') == notification_type]
        
        return history[-limit:]



