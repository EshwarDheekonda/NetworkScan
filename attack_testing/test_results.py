"""
Test Results

Structure and analyze test results from attack testing.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime

from knowledge_fusion.interfaces import Observation


@dataclass
class TestResult:
    """Result from a single attack test."""
    
    attack_data: Dict[str, Any]
    agent_id: str
    attack_type: str
    expected_detection: bool = True  # We expect attacks to be detected
    detections: List[Observation] = field(default_factory=list)
    detected: bool = False
    confidence: float = 0.0
    max_anomaly_score: float = 0.0
    false_positive: bool = False
    false_negative: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    execution_time_ms: float = 0.0
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'attack_data': self.attack_data,
            'agent_id': self.agent_id,
            'attack_type': self.attack_type,
            'expected_detection': self.expected_detection,
            'detected': self.detected,
            'confidence': self.confidence,
            'max_anomaly_score': self.max_anomaly_score,
            'false_positive': self.false_positive,
            'false_negative': self.false_negative,
            'detection_count': len(self.detections),
            'timestamp': self.timestamp.isoformat(),
            'execution_time_ms': self.execution_time_ms,
            'error': self.error
        }
    
    def calculate_metrics(self):
        """Calculate result metrics."""
        if self.expected_detection:
            # We expected detection
            if not self.detected:
                self.false_negative = True
            else:
                self.false_negative = False
        else:
            # We didn't expect detection (normal traffic)
            if self.detected:
                self.false_positive = True
            else:
                self.false_positive = False


@dataclass
class SequenceTestResult:
    """Result from a multi-step attack sequence test."""
    
    sequence_id: str
    technique_id: str
    steps: List[TestResult] = field(default_factory=list)
    overall_detected: bool = False
    steps_detected: int = 0
    total_steps: int = 0
    detection_rate: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'sequence_id': self.sequence_id,
            'technique_id': self.technique_id,
            'overall_detected': self.overall_detected,
            'steps_detected': self.steps_detected,
            'total_steps': self.total_steps,
            'detection_rate': self.detection_rate,
            'steps': [step.to_dict() for step in self.steps],
            'timestamp': self.timestamp.isoformat()
        }
    
    def calculate_metrics(self):
        """Calculate sequence metrics."""
        self.total_steps = len(self.steps)
        self.steps_detected = sum(1 for step in self.steps if step.detected)
        self.detection_rate = self.steps_detected / self.total_steps if self.total_steps > 0 else 0.0
        self.overall_detected = self.steps_detected > 0


@dataclass
class TestReport:
    """Comprehensive test report with metrics."""
    
    test_id: str
    total_tests: int = 0
    detected_count: int = 0
    not_detected_count: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_positives: int = 0
    true_negatives: int = 0
    detection_rate: float = 0.0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    results: List[TestResult] = field(default_factory=list)
    sequence_results: List[SequenceTestResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'test_id': self.test_id,
            'total_tests': self.total_tests,
            'detected_count': self.detected_count,
            'not_detected_count': self.not_detected_count,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_positives': self.true_positives,
            'true_negatives': self.true_negatives,
            'detection_rate': self.detection_rate,
            'accuracy': self.accuracy,
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'results_count': len(self.results),
            'sequence_results_count': len(self.sequence_results),
            'timestamp': self.timestamp.isoformat()
        }
    
    def calculate_metrics(self):
        """Calculate comprehensive test metrics."""
        self.total_tests = len(self.results)
        
        if self.total_tests == 0:
            return
        
        # Count detections
        self.detected_count = sum(1 for r in self.results if r.detected)
        self.not_detected_count = self.total_tests - self.detected_count
        
        # Calculate confusion matrix
        for result in self.results:
            result.calculate_metrics()
            if result.false_positive:
                self.false_positives += 1
            elif result.false_negative:
                self.false_negatives += 1
            elif result.detected and result.expected_detection:
                self.true_positives += 1
            elif not result.detected and not result.expected_detection:
                self.true_negatives += 1
        
        # Calculate rates
        self.detection_rate = self.detected_count / self.total_tests if self.total_tests > 0 else 0.0
        
        # Accuracy: (TP + TN) / Total
        self.accuracy = (self.true_positives + self.true_negatives) / self.total_tests if self.total_tests > 0 else 0.0
        
        # Precision: TP / (TP + FP)
        self.precision = self.true_positives / (self.true_positives + self.false_positives) if (self.true_positives + self.false_positives) > 0 else 0.0
        
        # Recall: TP / (TP + FN)
        self.recall = self.true_positives / (self.true_positives + self.false_negatives) if (self.true_positives + self.false_negatives) > 0 else 0.0
        
        # F1 Score: 2 * (Precision * Recall) / (Precision + Recall)
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
    
    def get_summary(self) -> str:
        """Get human-readable summary."""
        summary = f"""
Test Report Summary
===================
Test ID: {self.test_id}
Timestamp: {self.timestamp.isoformat()}

Total Tests: {self.total_tests}
Detected: {self.detected_count} ({self.detection_rate*100:.1f}%)
Not Detected: {self.not_detected_count}

Confusion Matrix:
  True Positives: {self.true_positives}
  True Negatives: {self.true_negatives}
  False Positives: {self.false_positives}
  False Negatives: {self.false_negatives}

Metrics:
  Accuracy: {self.accuracy*100:.1f}%
  Precision: {self.precision*100:.1f}%
  Recall: {self.recall*100:.1f}%
  F1 Score: {self.f1_score*100:.1f}%
"""
        return summary




