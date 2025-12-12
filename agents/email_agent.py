"""
Email Agent

Monitors email patterns including sender domains, attachment types, link patterns,
and timing. Learns baseline communication patterns and proactively detects
suspicious sender domains, unusual attachment types, and phishing indicators.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import re
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from knowledge_fusion.interfaces import Observation


class EmailAgent(BaseAgent):
    """Email monitoring agent with proactive phishing detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Email Agent."""
        super().__init__("email", config)
        self.known_senders = set()
        self.known_domains = set()
        self.known_attachment_types = set()
        
    def _initialize_baselines(self):
        """Initialize email-specific baseline models."""
        # Email frequency baseline
        self.baseline_learner.create_numeric_baseline(
            "email.frequency",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Attachment size baseline
        self.baseline_learner.create_numeric_baseline(
            "email.attachment_size",
            window_size=self.config.get('window_size', 1000),
            min_samples=self.config.get('min_samples', 10)
        )
        
        # Sender domain pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "email.sender_domains",
            min_frequency=self.config.get('min_domain_frequency', 3)
        )
        
        # Sender email pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "email.senders",
            min_frequency=self.config.get('min_sender_frequency', 2)
        )
        
        # Attachment type pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "email.attachment_types",
            min_frequency=self.config.get('min_attachment_frequency', 2)
        )
        
        # Link domain pattern baseline
        self.baseline_learner.create_pattern_baseline(
            "email.link_domains",
            min_frequency=self.config.get('min_link_frequency', 3)
        )
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from email data.
        
        Args:
            data: Email data dictionary with keys like:
                  - sender, sender_domain, subject, attachment_name,
                    attachment_type, links, timestamp, etc.
        
        Returns:
            Dictionary of feature names to values
        """
        features = {}
        
        # Sender domain
        sender_domain = data.get('sender_domain') or ''
        if not sender_domain:
            sender = data.get('sender') or data.get('from', '')
            if sender and '@' in sender:
                sender_domain = sender.split('@')[1].lower()
        
        if sender_domain:
            features['sender_domains'] = sender_domain
        
        # Sender email
        sender = data.get('sender') or data.get('from', '')
        if sender:
            features['senders'] = sender.lower()
        
        # Attachment type
        attachment_type = data.get('attachment_type') or ''
        if not attachment_type:
            attachment_name = data.get('attachment_name') or data.get('attachment', '')
            if attachment_name:
                # Extract extension
                if '.' in attachment_name:
                    attachment_type = attachment_name.split('.')[-1].lower()
        
        if attachment_type:
            features['attachment_types'] = attachment_type
        
        # Link domains
        links = data.get('links') or data.get('urls', [])
        if isinstance(links, str):
            links = [links]
        
        for link in links:
            try:
                parsed = urlparse(link)
                domain = parsed.netloc.lower()
                if domain:
                    features['link_domains'] = domain
                    break  # Use first link domain
            except:
                pass
        
        # Attachment size
        attachment_size = data.get('attachment_size') or data.get('size', 0)
        if attachment_size:
            features['attachment_size'] = float(attachment_size)
        
        # Email frequency (placeholder)
        features['frequency'] = 1.0
        
        return features
    
    def process_data(self, data: Dict[str, Any]) -> List[Observation]:
        """
        Process email data and generate observations.
        
        Args:
            data: Email data dictionary
        
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
        sender = data.get('sender') or data.get('from', '')
        if sender:
            indicators.append(sender)
        
        sender_domain = features.get('sender_domains', '')
        if sender_domain:
            indicators.append(sender_domain)
        
        subject = data.get('subject', '')
        if subject:
            indicators.append(subject[:50])  # Truncate long subjects
        
        attachment = data.get('attachment_name') or data.get('attachment', '')
        if attachment:
            indicators.append(attachment)
        
        links = data.get('links') or data.get('urls', [])
        if links:
            if isinstance(links, str):
                links = [links]
            indicators.extend(links[:3])  # Limit to first 3 links
        
        # Determine anomaly type and description
        description_parts = []
        
        # Check sender domain anomaly
        if 'sender_domains' in anomaly_scores and anomaly_scores['sender_domains'] > 0.6:
            domain = features.get('sender_domains', 'unknown')
            description_parts.append(f"Unusual sender domain: {domain}")
        
        # Check sender anomaly
        if 'senders' in anomaly_scores and anomaly_scores['senders'] > 0.6:
            sender_email = features.get('senders', 'unknown')
            description_parts.append(f"Unusual sender: {sender_email}")
        
        # Check attachment type anomaly
        if 'attachment_types' in anomaly_scores and anomaly_scores['attachment_types'] > 0.6:
            att_type = features.get('attachment_types', 'unknown')
            description_parts.append(f"Unusual attachment type: {att_type}")
        
        # Check link domain anomaly
        if 'link_domains' in anomaly_scores and anomaly_scores['link_domains'] > 0.6:
            link_domain = features.get('link_domains', 'unknown')
            description_parts.append(f"Unusual link domain: {link_domain}")
        
        if not description_parts:
            description_parts.append("Email anomaly detected")
        
        description = ". ".join(description_parts) + "."
        
        # Determine severity
        if max_score > 0.8:
            severity = "critical"
        elif max_score > 0.6:
            severity = "high"
        else:
            severity = "medium"
        
        # Additional checks for known attack patterns
        if self._check_phishing_indicators(data, features):
            description += " Multiple phishing indicators detected."
            severity = "high"
        
        if self._check_malicious_attachment(data, features):
            description += " Suspicious attachment detected."
            severity = "critical"
        
        if self._check_url_obfuscation(data, features):
            description += " URL obfuscation detected."
            severity = "high"
        
        if self._check_spoofing(data, features):
            description += " Email spoofing indicators detected."
            severity = "high"
        
        # Create observation
        metadata = {
            'sender': sender,
            'sender_domain': sender_domain,
            'subject': subject,
            'attachment_name': attachment,
            'attachment_type': features.get('attachment_types', ''),
            'attachment_size': data.get('attachment_size', 0),
            'links': links if isinstance(links, list) else [links] if links else [],
            'recipient': data.get('recipient') or data.get('to', ''),
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
    
    def _check_phishing_indicators(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for phishing indicators."""
        subject = data.get('subject', '').lower()
        body = data.get('body', '').lower()
        links = data.get('links') or data.get('urls', [])
        
        if isinstance(links, str):
            links = [links]
        
        # Urgency keywords
        urgency_keywords = ['urgent', 'immediate', 'action required', 'verify now', 
                          'suspended', 'locked', 'expired', 'verify account']
        if any(keyword in subject or keyword in body for keyword in urgency_keywords):
            return True
        
        # Suspicious link patterns
        for link in links:
            if self._is_suspicious_link(link):
                return True
        
        return False
    
    def _check_malicious_attachment(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for malicious attachment patterns."""
        attachment_name = data.get('attachment_name') or data.get('attachment', '')
        attachment_type = features.get('attachment_types', '')
        
        # Executable file extensions
        executable_extensions = ['exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar']
        if attachment_type.lower() in executable_extensions:
            return True
        
        # Double extension trick (e.g., .pdf.exe)
        if re.search(r'\.(pdf|doc|jpg|png)\.(exe|bat|cmd|scr|vbs|js)$', attachment_name, re.IGNORECASE):
            return True
        
        # Suspicious attachment names
        suspicious_names = ['invoice', 'payment', 'receipt', 'document', 'scan']
        if any(name in attachment_name.lower() for name in suspicious_names):
            if attachment_type.lower() in executable_extensions:
                return True
        
        return False
    
    def _check_url_obfuscation(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for URL obfuscation techniques."""
        links = data.get('links') or data.get('urls', [])
        if isinstance(links, str):
            links = [links]
        
        for link in links:
            # IP address instead of domain
            if re.search(r'https?://\d+\.\d+\.\d+\.\d+', link):
                return True
            
            # URL shorteners (can be used for obfuscation)
            shortener_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            parsed = urlparse(link)
            if parsed.netloc.lower() in shortener_domains:
                return True
            
            # Punycode domains (can be used for homograph attacks)
            if 'xn--' in link.lower():
                return True
        
        return False
    
    def _check_spoofing(self, data: Dict[str, Any], features: Dict[str, Any]) -> bool:
        """Check for email spoofing indicators."""
        sender = data.get('sender') or data.get('from', '')
        sender_domain = features.get('sender_domains', '')
        display_name = data.get('display_name', '')
        
        # Display name doesn't match sender
        if display_name and sender:
            # Extract name from display name
            if '@' in display_name:
                display_domain = display_name.split('@')[1].lower()
                if display_domain != sender_domain:
                    return True
        
        # SPF/DKIM failures (would need email headers)
        spf_fail = data.get('spf_fail', False)
        dkim_fail = data.get('dkim_fail', False)
        if spf_fail or dkim_fail:
            return True
        
        return False
    
    def _is_suspicious_link(self, link: str) -> bool:
        """Check if a link is suspicious."""
        try:
            parsed = urlparse(link)
            domain = parsed.netloc.lower()
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                return True
            
            # Check for typosquatting patterns
            # (would need domain reputation database for full check)
            
        except:
            pass
        
        return False




