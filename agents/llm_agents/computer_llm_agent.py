"""
Computer LLM Agent

System log monitoring agent with LLM reasoning for threat analysis,
attack chain identification, and cross-agent correlation.
"""

from typing import List, Dict, Any, Optional
import re

from agents.llm_agents.llm_base_agent import LLMBaseAgent
from knowledge_fusion.interfaces import Observation


class ComputerLLMAgent(LLMBaseAgent):
    """System log monitoring agent with LLM reasoning."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize Computer LLM Agent."""
        super().__init__("computer", config, **kwargs)
        self.known_processes = set()
        self.known_users = set()
        self.known_file_paths = set()
    
    def _initialize_baselines(self):
        """Initialize system-specific baseline models."""
        self.baseline_learner.create_numeric_baseline(
            "computer.process_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        self.baseline_learner.create_numeric_baseline(
            "computer.file_access_frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "computer.processes",
            min_frequency=self.config.get('min_process_frequency', 3)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "computer.users",
            min_frequency=self.config.get('min_user_frequency', 2)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "computer.file_paths",
            min_frequency=self.config.get('min_file_frequency', 3)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "computer.commands",
            min_frequency=self.config.get('min_command_frequency', 2)
        )
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from system log data."""
        features = {}
        
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
        
        return features
    
    def _extract_indicators(self, data: Any) -> List[str]:
        """Extract indicators from system log data."""
        indicators = []
        if isinstance(data, dict):
            process_name = data.get('process_name') or data.get('process', '')
            if process_name:
                indicators.append(process_name)
            
            user = data.get('user') or data.get('username', '')
            if user:
                indicators.append(f"user:{user}")
            
            file_path = data.get('file_path') or data.get('file', '')
            if file_path:
                indicators.append(file_path)
            
            command = data.get('command_line') or data.get('command', '')
            if command:
                indicators.append(command[:100])  # Truncate long commands
            
            pid = data.get('pid')
            if pid:
                indicators.append(f"pid:{pid}")
        
        return indicators
    
    def _generate_statistical_observations(
        self,
        data: Any,
        anomaly_scores: Dict[str, float]
    ) -> List[Observation]:
        """Generate observations from statistical anomaly detection."""
        if not isinstance(data, dict):
            return []
        
        observations = []
        max_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        indicators = self._extract_indicators(data)
        description_parts = []
        
        if 'processes' in anomaly_scores and anomaly_scores['processes'] > 0.6:
            process = data.get('process_name') or data.get('process', 'unknown')
            description_parts.append(f"Unusual process: {process}")
        
        if 'users' in anomaly_scores and anomaly_scores['users'] > 0.6:
            user = data.get('user') or data.get('username', 'unknown')
            description_parts.append(f"Unusual user: {user}")
        
        if 'file_paths' in anomaly_scores and anomaly_scores['file_paths'] > 0.6:
            file_path = data.get('file_path') or data.get('file', 'unknown')
            description_parts.append(f"Unusual file access: {file_path}")
        
        if 'commands' in anomaly_scores and anomaly_scores['commands'] > 0.6:
            command = data.get('command_line') or data.get('command', 'unknown')
            description_parts.append(f"Unusual command: {command[:50]}")
        
        if not description_parts:
            description_parts.append("System log anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Check for known attack patterns
        if self._check_powershell_obfuscation(data):
            description += " PowerShell obfuscation detected."
        
        if self._check_process_injection(data):
            description += " Potential process injection detected."
        
        if self._check_privilege_escalation(data):
            description += " Potential privilege escalation detected."
        
        if self._check_persistence(data):
            description += " Potential persistence mechanism detected."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        metadata = {
            'process_name': data.get('process_name', ''),
            'user': data.get('user') or data.get('username', ''),
            'file_path': data.get('file_path') or data.get('file', ''),
            'command_line': data.get('command_line') or data.get('command', ''),
            'pid': data.get('pid'),
            'parent_pid': data.get('parent_pid'),
            'event_type': data.get('event_type', ''),
            # Store anomaly scores in metadata so they're preserved
            'anomaly_scores': anomaly_scores,
            'max_anomaly_score': max_score,
            **data.get('metadata', {})
        }
        
        observation = self.generate_observation(
            data=data,
            description=description,
            indicators=indicators,
            severity=severity,
            metadata=metadata
        )
        
        # Ensure max_anomaly_score is set even if generate_observation recalculated
        if 'max_anomaly_score' not in observation.metadata or observation.metadata['max_anomaly_score'] == 0.0:
            observation.metadata['max_anomaly_score'] = max_score
        
        observations.append(observation)
        return observations
    
    def _check_powershell_obfuscation(self, data: Dict[str, Any]) -> bool:
        """Check for PowerShell obfuscation patterns."""
        command = data.get('command_line') or data.get('command', '')
        process = data.get('process_name') or data.get('process', '')
        
        if 'powershell' in process.lower() or 'powershell' in command.lower():
            # Check for obfuscation patterns
            obfuscation_patterns = [
                r'-enc\s+',  # Encoded command
                r'-e\s+',    # Encoded command short
                r'FromBase64String',
                r'\.Replace\([^)]+\)',  # String replacement
                r'\$[a-z]+\s*=\s*['"][^'"]+['"]',  # Variable obfuscation
            ]
            
            for pattern in obfuscation_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return True
        
        return False
    
    def _check_process_injection(self, data: Dict[str, Any]) -> bool:
        """Check for process injection patterns."""
        process = data.get('process_name') or data.get('process', '')
        command = data.get('command_line') or data.get('command', '')
        
        # Suspicious process names
        suspicious_processes = ['rundll32', 'regsvr32', 'mshta', 'wscript', 'cscript']
        if any(sp in process.lower() for sp in suspicious_processes):
            # Check for suspicious command patterns
            if 'javascript:' in command.lower() or 'vbscript:' in command.lower():
                return True
        
        return False
    
    def _check_privilege_escalation(self, data: Dict[str, Any]) -> bool:
        """Check for privilege escalation patterns."""
        event_type = data.get('event_type', '')
        user = data.get('user') or data.get('username', '')
        
        # Check for UAC bypass or privilege escalation events
        if 'elevation' in event_type.lower() or 'privilege' in event_type.lower():
            return True
        
        # Check for suspicious user activity
        if user and user.lower() in ['system', 'administrator', 'root']:
            process = data.get('process_name', '')
            if process and process.lower() not in ['svchost', 'lsass', 'winlogon']:
                return True
        
        return False
    
    def _check_persistence(self, data: Dict[str, Any]) -> bool:
        """Check for persistence mechanisms."""
        file_path = data.get('file_path') or data.get('file', '')
        event_type = data.get('event_type', '')
        
        # Check for registry modifications
        if 'registry' in event_type.lower() or 'reg' in file_path.lower():
            if 'run' in file_path.lower() or 'startup' in file_path.lower():
                return True
        
        # Check for startup folder modifications
        startup_paths = [
            'startup', 'autostart', 'start menu', 'programs\\startup'
        ]
        if any(sp in file_path.lower() for sp in startup_paths):
            return True
        
        return False
    
    def _get_crewai_role(self) -> str:
        """Get CrewAI role."""
        return "Endpoint Security Analyst"
    
    def _get_crewai_goal(self) -> str:
        """Get CrewAI goal."""
        return "Monitor system logs, detect process anomalies, identify attack chains, and detect privilege escalation, persistence, and process injection attacks"
    
    def _get_crewai_backstory(self) -> str:
        """Get CrewAI backstory."""
        return """You are an expert endpoint security analyst specializing in system log analysis, 
        process monitoring, and attack chain detection. You have deep knowledge of Windows/Linux 
        system internals, process injection techniques, privilege escalation methods, persistence 
        mechanisms, and MITRE ATT&CK framework. You excel at identifying subtle indicators of 
        compromise in system logs."""




