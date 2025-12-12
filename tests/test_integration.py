"""
Integration Tests

Tests the complete end-to-end flow of the proactive agent system.
"""

import unittest
import time
import logging
from datetime import datetime

from agents.router_agent import RouterAgent
from agents.computer_agent import ComputerAgent
from agents.email_agent import EmailAgent
from agents.baseline_learner import BaselineLearner


class TestBaselineLearning(unittest.TestCase):
    """Test baseline learning functionality."""
    
    def test_baseline_learner_creation(self):
        """Test baseline learner creation."""
        learner = BaselineLearner()
        
        # Create numeric baseline
        baseline = learner.create_numeric_baseline("test.numeric")
        self.assertIsNotNone(baseline)
        
        # Update baseline
        for i in range(20):
            baseline.update(float(i))
        
        # Check if ready
        self.assertTrue(baseline.is_ready())
        
        # Check anomaly detection
        anomaly_score = baseline.get_anomaly_score(100.0)  # Should be high
        self.assertGreater(anomaly_score, 0.5)
    
    def test_pattern_baseline(self):
        """Test pattern baseline learning."""
        learner = BaselineLearner()
        baseline = learner.create_pattern_baseline("test.pattern")
        
        # Learn normal patterns
        for _ in range(10):
            baseline.update("normal-pattern")
        
        # Check anomaly
        self.assertFalse(baseline.is_known("unknown-pattern"))
        self.assertTrue(baseline.is_known("normal-pattern"))


class TestAgents(unittest.TestCase):
    """Test agent functionality."""
    
    def test_router_agent(self):
        """Test router agent."""
        agent = RouterAgent()
        agent.start()
        
        # Generate normal traffic
        normal_traffic = {
            "source_ip": "192.168.1.100",
            "dest_ip": "8.8.8.8",
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": 1024,
            "bytes_received": 2048,
            "duration_seconds": 30.5
        }
        
        # Update baseline
        agent.update_baseline(normal_traffic)
        
        # Generate C2 traffic (should be anomalous)
        c2_traffic = {
            "source_ip": "192.168.1.100",
            "dest_ip": "185.220.101.45",  # Suspicious IP
            "protocol": "HTTPS",
            "port": 443,
            "bytes_sent": 10485760,  # Large data transfer
            "bytes_received": 1024,
            "duration_seconds": 3600  # Long connection
        }
        observations = agent.process_data(c2_traffic)
        
        # Should detect anomaly
        self.assertGreater(len(observations), 0)
        
        agent.stop()
    
    def test_computer_agent(self):
        """Test computer agent."""
        agent = ComputerAgent()
        agent.start()
        
        # Generate normal process
        normal_process = {
            "process_name": "chrome.exe",
            "user": "admin",
            "file_path": "C:\\Program Files\\Chrome\\chrome.exe",
            "command_line": "chrome.exe --start-maximized",
            "pid": 1234
        }
        
        # Update baseline
        agent.update_baseline(normal_process)
        
        # Generate suspicious process
        suspicious = {
            "process_name": "powershell.exe",
            "user": "admin",
            "command_line": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAiACwANAA0ADMAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AA==",
            "pid": 9999
        }
        observations = agent.process_data(suspicious)
        
        # Should detect anomaly
        self.assertGreater(len(observations), 0)
        
        agent.stop()
    
    def test_email_agent(self):
        """Test email agent."""
        agent = EmailAgent()
        agent.start()
        
        # Generate normal email
        normal_email = {
            "sender": "noreply@company.com",
            "sender_domain": "company.com",
            "subject": "Weekly Newsletter",
            "recipient": "user@company.com"
        }
        
        # Update baseline
        agent.update_baseline(normal_email)
        
        # Generate phishing email
        phishing = {
            "sender": "attacker@malicious.com",
            "sender_domain": "malicious.com",
            "subject": "Urgent: Verify Your Account",
            "recipient": "user@company.com",
            "attachment_name": "invoice.exe",
            "links": ["http://phishing-site.com"]
        }
        observations = agent.process_data(phishing)
        
        # Should detect anomaly
        self.assertGreater(len(observations), 0)
        
        agent.stop()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
