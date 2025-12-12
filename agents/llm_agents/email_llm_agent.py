"""
Email LLM Agent

Email monitoring agent with LLM reasoning for phishing detection,
content analysis, and attachment/link analysis.
"""

from typing import List, Dict, Any, Optional
import re
from urllib.parse import urlparse

from agents.llm_agents.llm_base_agent import LLMBaseAgent
from knowledge_fusion.interfaces import Observation


class EmailLLMAgent(LLMBaseAgent):
    """Email monitoring agent with LLM reasoning."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, **kwargs):
        """Initialize Email LLM Agent."""
        super().__init__("email", config, **kwargs)
        self.known_senders = set()
        self.known_domains = set()
        self.known_attachment_types = set()
    
    def _initialize_baselines(self):
        """Initialize email-specific baseline models."""
        self.baseline_learner.create_numeric_baseline(
            "email.frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        self.baseline_learner.create_numeric_baseline(
            "email.attachment_size",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "email.sender_domains",
            min_frequency=self.config.get('min_domain_frequency', 3)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "email.senders",
            min_frequency=self.config.get('min_sender_frequency', 2)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "email.attachment_types",
            min_frequency=self.config.get('min_attachment_frequency', 2)
        )
        
        self.baseline_learner.create_pattern_baseline(
            "email.link_domains",
            min_frequency=self.config.get('min_link_frequency', 3)
        )
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from email data."""
        features = {}
        
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
                parsed = urlparse(link)
                domain = parsed.netloc.lower()
                if domain:
                    features['link_domains'] = domain
                    break
            except:
                pass
        
        attachment_size = data.get('attachment_size') or data.get('size', 0)
        if attachment_size:
            # Handle size strings with units (e.g., '215KB', '1.5MB')
            if isinstance(attachment_size, str):
                # Extract number and unit
                match = re.match(r'([\d.]+)\s*([KMGT]?B?)', attachment_size.upper())
                if match:
                    size_value = float(match.group(1))
                    unit = match.group(2) or 'B'
                    # Convert to bytes
                    multipliers = {'B': 1, 'KB': 1024, 'MB': 1024**2, 'GB': 1024**3, 'TB': 1024**4}
                    features['attachment_size'] = size_value * multipliers.get(unit, 1)
                else:
                    # Try to parse as plain number
                    try:
                        features['attachment_size'] = float(attachment_size)
                    except ValueError:
                        features['attachment_size'] = 0.0
            else:
                features['attachment_size'] = float(attachment_size)
        
        features['frequency'] = 1.0
        
        return features
    
    def _extract_indicators(self, data: Any) -> List[str]:
        """Extract indicators from email data."""
        indicators = []
        if isinstance(data, dict):
            sender = data.get('sender') or data.get('from', '')
            if sender:
                indicators.append(sender)
            
            sender_domain = data.get('sender_domain') or ''
            if not sender_domain and sender and '@' in sender:
                sender_domain = sender.split('@')[1]
            if sender_domain:
                indicators.append(sender_domain)
            
            subject = data.get('subject', '')
            if subject:
                indicators.append(f"subject:{subject[:50]}")
            
            attachment_name = data.get('attachment_name') or data.get('attachment', '')
            if attachment_name:
                indicators.append(f"attachment:{attachment_name}")
            
            links = data.get('links') or data.get('urls', [])
            if isinstance(links, str):
                links = [links]
            for link in links[:3]:  # First 3 links
                indicators.append(link)
        
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
        
        if 'sender_domains' in anomaly_scores and anomaly_scores['sender_domains'] > 0.6:
            domain = data.get('sender_domain') or ''
            if not domain:
                sender = data.get('sender') or data.get('from', '')
                if sender and '@' in sender:
                    domain = sender.split('@')[1]
            description_parts.append(f"Unusual sender domain: {domain}")
        
        if 'attachment_types' in anomaly_scores and anomaly_scores['attachment_types'] > 0.7:
            att_type = data.get('attachment_type') or ''
            if not att_type:
                att_name = data.get('attachment_name') or data.get('attachment', '')
                if att_name and '.' in att_name:
                    att_type = att_name.split('.')[-1]
            description_parts.append(f"Suspicious attachment type: {att_type}")
        
        if 'link_domains' in anomaly_scores and anomaly_scores['link_domains'] > 0.6:
            links = data.get('links') or data.get('urls', [])
            if isinstance(links, str):
                links = [links]
            if links:
                try:
                    parsed = urlparse(links[0])
                    domain = parsed.netloc
                    description_parts.append(f"Unusual link domain: {domain}")
                except:
                    pass
        
        if not description_parts:
            description_parts.append("Email anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Check for known attack patterns
        if self._check_phishing_indicators(data):
            description += " Phishing indicators detected."
        
        if self._check_malicious_attachment(data):
            description += " Malicious attachment detected."
        
        if self._check_url_obfuscation(data):
            description += " URL obfuscation detected."
        
        if self._check_spoofing(data):
            description += " Email spoofing detected."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        metadata = {
            'sender': data.get('sender') or data.get('from', ''),
            'sender_domain': data.get('sender_domain', ''),
            'subject': data.get('subject', ''),
            'attachment_name': data.get('attachment_name') or data.get('attachment', ''),
            'attachment_type': data.get('attachment_type', ''),
            'links': data.get('links') or data.get('urls', []),
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
    
    def _check_phishing_indicators(self, data: Dict[str, Any]) -> bool:
        """Check for phishing indicators."""
        subject = data.get('subject', '').lower()
        body = data.get('body', '').lower() or data.get('content', '').lower()
        
        phishing_keywords = [
            'urgent', 'verify', 'suspended', 'locked', 'expired',
            'click here', 'verify account', 'update now', 'immediately'
        ]
        
        if any(keyword in subject or keyword in body for keyword in phishing_keywords):
            return True
        
        return False
    
    def _check_malicious_attachment(self, data: Dict[str, Any]) -> bool:
        """Check for malicious attachment types."""
        attachment_name = data.get('attachment_name') or data.get('attachment', '')
        attachment_type = data.get('attachment_type', '')
        
        if not attachment_type and attachment_name and '.' in attachment_name:
            attachment_type = attachment_name.split('.')[-1].lower()
        
        malicious_extensions = ['exe', 'bat', 'cmd', 'scr', 'vbs', 'js', 'jar', 'ps1']
        if attachment_type.lower() in malicious_extensions:
            return True
        
        # Double extension trick
        if attachment_name and '.' in attachment_name:
            parts = attachment_name.split('.')
            if len(parts) >= 3:
                # e.g., document.pdf.exe
                if parts[-1].lower() in malicious_extensions:
                    return True
        
        return False
    
    def _check_url_obfuscation(self, data: Dict[str, Any]) -> bool:
        """Check for URL obfuscation."""
        links = data.get('links') or data.get('urls', [])
        if isinstance(links, str):
            links = [links]
        
        for link in links:
            # Check for IP address instead of domain
            try:
                parsed = urlparse(link)
                host = parsed.netloc
                # Check if host is an IP address
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                    return True
                # Check for URL shortening services
                if any(short in host.lower() for short in ['bit.ly', 'tinyurl', 'goo.gl', 't.co']):
                    return True
            except:
                pass
        
        return False
    
    def _check_spoofing(self, data: Dict[str, Any]) -> bool:
        """Check for email spoofing."""
        sender = data.get('sender') or data.get('from', '')
        sender_domain = data.get('sender_domain', '')
        
        if not sender_domain and sender and '@' in sender:
            sender_domain = sender.split('@')[1]
        
        # Check for display name spoofing
        if sender and '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            actual_email = sender.split('<')[1].split('>')[0]
            if display_name and actual_email and '@' in actual_email:
                actual_domain = actual_email.split('@')[1]
                # Display name might be different from actual domain
                # This is a simple check - more sophisticated checks would use SPF/DKIM
                pass
        
        return False
    
    def _get_crewai_role(self) -> str:
        """Get CrewAI role."""
        return "Email Security Analyst"
    
    def _get_crewai_goal(self) -> str:
        """Get CrewAI goal."""
        return "Monitor email traffic, detect phishing attempts, analyze email content and attachments, and identify email-based attacks"
    
    def _get_crewai_backstory(self) -> str:
        """Get CrewAI backstory."""
        return """You are an expert email security analyst specializing in phishing detection, 
        email content analysis, and email-based attack identification. You have deep knowledge 
        of email protocols, phishing techniques, social engineering, attachment analysis, and 
        MITRE ATT&CK framework. You excel at identifying subtle indicators of phishing and 
        malicious emails."""




