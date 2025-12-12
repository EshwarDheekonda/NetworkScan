"""
Baseline Learning Module

Implements statistical baseline models for learning normal patterns
and detecting anomalies through deviation scoring.
"""

import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import deque
import statistics


class BaselineModel:
    """Represents a baseline model for a specific metric."""
    
    def __init__(self, window_size: int = 1000, min_samples: int = 10):
        """
        Initialize a baseline model.
        
        Args:
            window_size: Maximum number of samples to keep in sliding window
            min_samples: Minimum samples required before making predictions
        """
        self.window_size = window_size
        self.min_samples = min_samples
        self.values = deque(maxlen=window_size)
        self.timestamps = deque(maxlen=window_size)
        self.mean = 0.0
        self.std = 0.0
        self.median = 0.0
        self.percentiles = {}
        
    def update(self, value: float, timestamp: Optional[datetime] = None):
        """
        Update the baseline model with a new value.
        
        Args:
            value: New value to add to the baseline
            timestamp: Optional timestamp for the value
        """
        if timestamp is None:
            timestamp = datetime.now()
            
        self.values.append(value)
        self.timestamps.append(timestamp)
        
        if len(self.values) >= self.min_samples:
            values_array = np.array(self.values)
            self.mean = float(np.mean(values_array))
            self.std = float(np.std(values_array)) if len(values_array) > 1 else 0.0
            self.median = float(np.median(values_array))
            
            # Calculate percentiles
            self.percentiles = {
                'p25': float(np.percentile(values_array, 25)),
                'p50': float(np.percentile(values_array, 50)),
                'p75': float(np.percentile(values_array, 75)),
                'p95': float(np.percentile(values_array, 95)),
                'p99': float(np.percentile(values_array, 99))
            }
    
    def get_z_score(self, value: float) -> float:
        """
        Calculate z-score for a value against the baseline.
        
        Args:
            value: Value to score
            
        Returns:
            Z-score (standard deviations from mean)
        """
        if self.std == 0 or len(self.values) < self.min_samples:
            return 0.0
        return (value - self.mean) / self.std
    
    def is_anomaly(self, value: float, threshold: float = 2.0) -> bool:
        """
        Check if a value is an anomaly based on z-score threshold.
        
        Args:
            value: Value to check
            threshold: Z-score threshold (default 2.0 = 2 standard deviations)
            
        Returns:
            True if anomaly detected
        """
        z_score = abs(self.get_z_score(value))
        return z_score > threshold
    
    def get_anomaly_score(self, value: float) -> float:
        """
        Get normalized anomaly score (0.0 to 1.0).
        
        Args:
            value: Value to score
            
        Returns:
            Anomaly score between 0.0 and 1.0
        """
        if len(self.values) < self.min_samples:
            return 0.0
            
        z_score = abs(self.get_z_score(value))
        # Normalize to 0-1 range (assuming 3 std devs = 1.0)
        score = min(1.0, z_score / 3.0)
        return score
    
    def get_percentile_rank(self, value: float) -> float:
        """
        Get percentile rank of a value (0.0 to 1.0).
        
        Args:
            value: Value to rank
            
        Returns:
            Percentile rank (0.0 = minimum, 1.0 = maximum)
        """
        if len(self.values) < self.min_samples:
            return 0.5  # Default to median if not enough samples
            
        values_array = np.array(self.values)
        percentile_rank = (values_array < value).sum() / len(values_array)
        return float(percentile_rank)
    
    def is_ready(self) -> bool:
        """Check if baseline has enough samples to make predictions."""
        return len(self.values) >= self.min_samples
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current baseline statistics."""
        return {
            'sample_count': len(self.values),
            'mean': self.mean,
            'std': self.std,
            'median': self.median,
            'percentiles': self.percentiles,
            'is_ready': self.is_ready()
        }


class TimeWindowedBaseline:
    """Baseline model that maintains separate models for different time windows."""
    
    def __init__(self, window_sizes: Dict[str, int] = None):
        """
        Initialize time-windowed baseline.
        
        Args:
            window_sizes: Dict mapping window names to sizes (e.g., {'hourly': 24, 'daily': 7})
        """
        if window_sizes is None:
            window_sizes = {'hourly': 24, 'daily': 7, 'weekly': 4}
        
        self.window_sizes = window_sizes
        self.models = {name: BaselineModel(window_size=size) 
                      for name, size in window_sizes.items()}
    
    def update(self, value: float, timestamp: Optional[datetime] = None):
        """Update all window models."""
        if timestamp is None:
            timestamp = datetime.now()
            
        for model in self.models.values():
            model.update(value, timestamp)
    
    def get_anomaly_score(self, value: float) -> float:
        """
        Get combined anomaly score across all time windows.
        
        Returns:
            Maximum anomaly score across all windows
        """
        scores = [model.get_anomaly_score(value) 
                 for model in self.models.values() 
                 if model.is_ready()]
        
        if not scores:
            return 0.0
        
        return max(scores)
    
    def is_anomaly(self, value: float, threshold: float = 2.0) -> bool:
        """Check if value is anomalous in any time window."""
        for model in self.models.values():
            if model.is_ready() and model.is_anomaly(value, threshold):
                return True
        return False


class PatternBaseline:
    """Baseline model for categorical/pattern data (e.g., domains, file paths)."""
    
    def __init__(self, min_frequency: int = 3):
        """
        Initialize pattern baseline.
        
        Args:
            min_frequency: Minimum occurrences for a pattern to be considered "normal"
        """
        self.min_frequency = min_frequency
        self.pattern_counts: Dict[str, int] = {}
        self.total_observations = 0
        
    def update(self, pattern: str):
        """
        Update baseline with a new pattern observation.
        
        Args:
            pattern: Pattern string (e.g., domain name, file path)
        """
        self.pattern_counts[pattern] = self.pattern_counts.get(pattern, 0) + 1
        self.total_observations += 1
        
        # Clean up low-frequency patterns periodically
        if self.total_observations % 100 == 0:
            self._cleanup()
    
    def _cleanup(self):
        """Remove patterns that haven't been seen recently."""
        # Keep only patterns that meet minimum frequency
        self.pattern_counts = {
            pattern: count 
            for pattern, count in self.pattern_counts.items() 
            if count >= self.min_frequency
        }
    
    def is_known(self, pattern: str) -> bool:
        """
        Check if a pattern is known (seen frequently enough).
        
        Args:
            pattern: Pattern to check
            
        Returns:
            True if pattern is known/normal
        """
        return self.pattern_counts.get(pattern, 0) >= self.min_frequency
    
    def get_frequency(self, pattern: str) -> int:
        """Get frequency count for a pattern."""
        return self.pattern_counts.get(pattern, 0)
    
    def get_anomaly_score(self, pattern: str) -> float:
        """
        Get anomaly score for a pattern (0.0 = normal, 1.0 = highly anomalous).
        
        Args:
            pattern: Pattern to score
            
        Returns:
            Anomaly score (0.0 to 1.0)
        """
        if self.total_observations == 0:
            return 0.5  # Unknown state
        
        frequency = self.pattern_counts.get(pattern, 0)
        
        if frequency >= self.min_frequency:
            return 0.0  # Known pattern, not anomalous
        
        # Score based on how rare it is
        # If we've seen many patterns but not this one, it's more anomalous
        rarity = 1.0 - (frequency / max(1, self.min_frequency))
        return min(1.0, rarity)
    
    def is_ready(self) -> bool:
        """
        Check if baseline has enough observations to be considered ready.
        
        Returns:
            True if baseline is ready (has enough observations and at least one known pattern)
        """
        # Consider ready if we have at least min_frequency * 2 observations
        # and at least one pattern meets min_frequency
        if self.total_observations < self.min_frequency * 2:
            return False
        return any(count >= self.min_frequency for count in self.pattern_counts.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get baseline statistics."""
        return {
            'total_observations': self.total_observations,
            'unique_patterns': len(self.pattern_counts),
            'known_patterns': sum(1 for count in self.pattern_counts.values() 
                                 if count >= self.min_frequency),
            'is_ready': self.is_ready()
        }


class BaselineLearner:
    """Main baseline learning orchestrator."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize baseline learner.
        
        Args:
            config: Configuration dictionary
        """
        if config is None:
            config = {}
        
        self.config = config
        self.numeric_baselines: Dict[str, BaselineModel] = {}
        self.time_windowed_baselines: Dict[str, TimeWindowedBaseline] = {}
        self.pattern_baselines: Dict[str, PatternBaseline] = {}
        
    def create_numeric_baseline(self, name: str, window_size: int = 1000, 
                                min_samples: int = 10) -> BaselineModel:
        """Create a new numeric baseline model."""
        baseline = BaselineModel(window_size=window_size, min_samples=min_samples)
        self.numeric_baselines[name] = baseline
        return baseline
    
    def create_time_windowed_baseline(self, name: str, 
                                      window_sizes: Optional[Dict[str, int]] = None) -> TimeWindowedBaseline:
        """Create a new time-windowed baseline model."""
        baseline = TimeWindowedBaseline(window_sizes=window_sizes)
        self.time_windowed_baselines[name] = baseline
        return baseline
    
    def create_pattern_baseline(self, name: str, min_frequency: int = 3) -> PatternBaseline:
        """Create a new pattern baseline model."""
        baseline = PatternBaseline(min_frequency=min_frequency)
        self.pattern_baselines[name] = baseline
        return baseline
    
    def get_numeric_baseline(self, name: str) -> Optional[BaselineModel]:
        """Get a numeric baseline by name."""
        return self.numeric_baselines.get(name)
    
    def get_time_windowed_baseline(self, name: str) -> Optional[TimeWindowedBaseline]:
        """Get a time-windowed baseline by name."""
        return self.time_windowed_baselines.get(name)
    
    def get_pattern_baseline(self, name: str) -> Optional[PatternBaseline]:
        """Get a pattern baseline by name."""
        return self.pattern_baselines.get(name)
    
    def update_numeric(self, name: str, value: float, timestamp: Optional[datetime] = None):
        """Update a numeric baseline."""
        if name not in self.numeric_baselines:
            self.create_numeric_baseline(name)
        self.numeric_baselines[name].update(value, timestamp)
    
    def update_pattern(self, name: str, pattern: str):
        """Update a pattern baseline."""
        if name not in self.pattern_baselines:
            self.create_pattern_baseline(name)
        self.pattern_baselines[name].update(pattern)
    
    def check_anomaly(self, name: str, value: Any, threshold: float = 2.0) -> bool:
        """
        Check if a value is anomalous.
        
        Args:
            name: Baseline name
            value: Value to check (numeric or pattern string)
            threshold: Anomaly threshold
            
        Returns:
            True if anomalous
        """
        # Try numeric baseline first
        if name in self.numeric_baselines:
            baseline = self.numeric_baselines[name]
            if isinstance(value, (int, float)):
                return baseline.is_anomaly(float(value), threshold)
        
        # Try pattern baseline
        if name in self.pattern_baselines:
            baseline = self.pattern_baselines[name]
            if isinstance(value, str):
                return not baseline.is_known(value)
        
        return False
    
    def get_anomaly_score(self, name: str, value: Any) -> float:
        """Get anomaly score for a value."""
        # Try numeric baseline
        if name in self.numeric_baselines:
            baseline = self.numeric_baselines[name]
            if isinstance(value, (int, float)):
                return baseline.get_anomaly_score(float(value))
        
        # Try pattern baseline
        if name in self.pattern_baselines:
            baseline = self.pattern_baselines[name]
            if isinstance(value, str):
                return baseline.get_anomaly_score(value)
        
        return 0.0
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all baselines."""
        return {
            'numeric_baselines': {
                name: baseline.get_stats() 
                for name, baseline in self.numeric_baselines.items()
            },
            'pattern_baselines': {
                name: baseline.get_stats() 
                for name, baseline in self.pattern_baselines.items()
            }
        }

