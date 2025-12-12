"""
Computer Agent

Monitors system logs, process trees, file access patterns, and scheduled tasks.
Learns baseline behavior and proactively detects anomalies such as unusual process
spawning, suspicious file access, and privilege escalation attempts.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import re

from agents.base_agent import BaseAgent
from knowledge_fusion.interfaces import Observation


class ComputerAgent(BaseAgent):
    """System log monitoring agent with proactive anomaly detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Computer Agent."""
        super().__init__("computer", config)
        self.known_processes = set()
        self.known_users = set()
        self.known_file_paths = set()
        
    def _initialize_baselines(self):
        """Initialize system-specific baseline models."""
        # Process execution frequency
        self.baseline_learner.create_numeric_baseline(
            "computer.process_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # File access frequency
        self.baseline_learner.create_numeric_baseline(
            "computer.file_access_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Process pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "computer.processes",
            min_frequency=self.config.get('min_process_frequency', 3)
        )
        
        # User pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "computer.users",
            min_frequency=self.config.get('min_user_frequency', 2)
        )
        
        # File path pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "computer.file_paths",
            min_frequency=self.config.get('min_file_frequency', 3)
        )
        
        # Command pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "computer.commands",
            min_frequency=self.config.get('min_command_frequency', 2)
        )
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from system log data.
        
        Args:
            data: System log data dictionary with keys like:
                  - event_type, process_name, user, file_path, command_line,
                    pid, parent_pid, timestamp, etc.
        
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # Process name
        process_name = data.get('process_name') or data.get('process', '')
        if process_name:
            features['processes'] = str(process_name).lower()
        
        # User
        user = data.get('user') or data.get('username', '')
        if user:
            features['users'] = str(user)
        
        # File path
        file_path = data.get('file_path') or data.get('file', '')
        if file_path:
            features['file_paths'] = str(file_path)
        
        # Command line
        command = data.get('command_line') or data.get('command', '')
        if command:
            # Extract base command (first word)
            cmd_parts = str(command).split()
            if cmd_parts:
                base_cmd = cmd_parts[0].lower()
                features['commands'] = base_cmd
        
        # Process frequency (placeholder - would need separate tracking)
        features['process_frequency'] = 1.0
        
        # File access frequency (placeholder)
        features['file_access_frequency'] = 1.0
        
        return features
    
    def process_data(self, data: Dict[str, Any]) -> List[Observation]:
        """
        Process system log data and generate observations.
        
        Args:
            data: System log data dictionary
        
        Returns:
            List of observations (empty if no anomalies detected)
        """
        observations = []
        
        if not isinstance(data, dict):
            return observations
        
        # Extract features
        features = self._extract_features(data)
        
        # Check for anomalies
        anomaly_scores = self.get_anomaly_scores(data)
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        # Threshold for generating observations
        threshold = self.config.get('anomaly_threshold', 0.5)
        
        if max_score < threshold:
            return observations
        
        # Build indicators
        indicators = []
        process_name = data.get('process_name') or data.get('process', '')
        if process_name:
            indicators.append(process_name)
        
        user = data.get('user') or data.get('username', '')
        if user:
            indicators.append(f"user:{user}")
        
        pid = data.get('pid')
        if pid:
            indicators.append(f"pid:{pid}")
        
        command = data.get('command_line') or data.get('command', '')
        if command:
            indicators.append(command[:100])  # Truncate long commands
        
        # Determine anomaly type and description
        description_parts = []
        event_type = data.get('event_type', 'unknown')
        
        # Check process anomaly
        if 'processes' in anomaly_scores and anomaly_scores['processes'] > 0.6:
            process = features.get('processes', 'unknown')
            description_parts.append(f"Unusual process execution: {process}")
        
        # Check user anomaly
        if 'users' in anomaly_scores and anomaly_scores['users'] > 0.6:
            user = features.get('users', 'unknown')
            description_parts.append(f"Unusual user activity: {user}")
        
        # Check file path anomaly
        if 'file_paths' in anomaly_scores and anomaly_scores['file_paths'] > 0.6:
            file_path = features.get('file_paths', 'unknown')
            description_parts.append(f"Unusual file access: {file_path}")
        
        # Check command anomaly
        if 'commands' in anomaly_scores and anomaly_scores['commands'] > 0.6:
            cmd = features.get('commands', 'unknown')
            description_parts.append(f"Unusual command execution: {cmd}")
        
        if not description_parts:
            description_parts.append(f"System {event_type} anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        # Additional checks for known attack patterns
        if self._check_powershell_obfuscation(data, features):
            description += " PowerShell obfuscation detected."
            severity = "high"
        
        if self._check_process_injection(data, features):
            description += " Process injection pattern detected."
            severity = "critical"
        
        if self._check_privilege_escalation(data, features):
            description += " Potential privilege escalation detected."
            severity = "critical"
        
        if self._check_persistence_mechanism(data, features):
            description += " Persistence mechanism detected."
            severity = "high"
        
        # Create observation
        metadata = {
            'event_type': event_type,
            'process_name': process_name,
            'user': user,
            'pid': pid,
            'parent_pid': data.get('parent_pid'),
            'command_line': command,
            'file_path': data.get('file_path'),
            **data.get('metadata', {})
        }
        
        observation = self.generate_observation(
            data=data,
            description=description,
            indicators=indicators,
            severity=severity,
            metadata=metadata
        )
        
        observations.append(observation)
        return observations
    
    def _check_powershell_obfuscation(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for PowerShell obfuscation patterns."""
        command = data.get('command_line') or data.get('command', '')
        process = features.get('processes', '')
        
        if 'powershell' in process.lower():
            # Check for obfuscation indicators
            obfuscation_patterns = [
                r'-enc\s+[A-Za-z0-9+/=]{20,}',  # Base64 encoded
                r'-e\s+[A-Za-z0-9+/=]{20,}',     # Short form
                r'Invoke-Expression',            # IEX
                r'FromBase64String',             # Base64 decoding
                r'\.Replace\([^)]+\)',            # String replacement obfuscation
            ]
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return True
        
        return False
    
    def _check_process_injection(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for process injection patterns."""
        process = features.get('processes', '')
        parent_pid = data.get('parent_pid')
        pid = data.get('pid')
        
        # Suspicious parent-child relationships
        # e.g., legitimate process spawning suspicious child
        suspicious_processes = ['powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe']
        
        if process.lower() in suspicious_processes:
            # Check if spawned from unusual parent
            # This would require tracking normal parent-child relationships
            return True
        
        return False
    
    def _check_privilege_escalation(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for privilege escalation patterns."""
        user = features.get('users', '')
        process = features.get('processes', '')
        command = data.get('command_line', '')
        
        # SYSTEM user running unusual processes
        if user.upper() == 'SYSTEM':
            if process.lower() not in ['svchost.exe', 'lsass.exe', 'services.exe', 'winlogon.exe']:
                return True
        
        # UAC bypass attempts
        uac_bypass_keywords = ['bypassuac', 'uac', 'elevate', 'runas']
        if any(keyword in command.lower() for keyword in uac_bypass_keywords):
            return True
        
        return False
    
    def _check_persistence_mechanism(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for persistence mechanism patterns."""
        event_type = data.get('event_type', '')
        file_path = data.get('file_path', '')
        command = data.get('command_line', '')
        
        # Scheduled task creation
        if 'scheduled' in event_type.lower() or 'task' in event_type.lower():
            return True
        
        # Registry modification (startup keys)
        if 'registry' in event_type.lower():
            startup_keys = [
                r'\\Run\\',
                r'\\RunOnce\\',
                r'\\RunServices\\',
            ]
            for key_pattern in startup_keys:
                if re.search(key_pattern, file_path, re.IGNORECASE):
                    return True
        
        # Service creation
        if 'service' in event_type.lower() and 'create' in event_type.lower():
            return True
        
        # WMI event subscription
        if 'wmi' in event_type.lower() or 'wmic' in command.lower():
            return True
        
        return False

