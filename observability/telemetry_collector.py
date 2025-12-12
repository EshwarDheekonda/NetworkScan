"""
Telemetry Collector

Collects metrics from all agents, tracks LLM API calls, monitors message
bus activity, and provides performance metrics.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from collections import defaultdict, deque


class TelemetryCollector:
    """System telemetry collection."""
    
    def __init__(self, max_metrics: int = 10000):
        """
        Initialize the telemetry collector.
        
        Args:
            max_metrics: Maximum metrics to keep in memory
        """
        self.logger = logging.getLogger(__name__)
        self.max_metrics = max_metrics
        
        # Metrics storage
        self.llm_metrics: deque = deque(maxlen=max_metrics)
        self.message_bus_metrics: deque = deque(maxlen=max_metrics)
        self.performance_metrics: deque = deque(maxlen=max_metrics)
        
        # Counters
        self.counters = defaultdict(int)
    
    def record_llm_call(
        self,
        agent_id: str,
        provider: str,
        model: str,
        tokens_used: Optional[int] = None,
        latency_ms: Optional[float] = None,
        success: bool = True
    ):
        """Record an LLM API call."""
        metric = {
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'provider': provider,
            'model': model,
            'tokens_used': tokens_used,
            'latency_ms': latency_ms,
            'success': success
        }
        
        self.llm_metrics.append(metric)
        self.counters['llm_calls_total'] += 1
        
        if success:
            self.counters['llm_calls_success'] += 1
        else:
            self.counters['llm_calls_failed'] += 1
    
    def record_message_bus_event(
        self,
        event_type: str,
        topic: str,
        size_bytes: Optional[int] = None
    ):
        """Record a message bus event."""
        metric = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,  # publish, subscribe, etc.
            'topic': topic,
            'size_bytes': size_bytes
        }
        
        self.message_bus_metrics.append(metric)
        self.counters[f'message_bus_{event_type}'] += 1
    
    def record_performance_metric(
        self,
        metric_name: str,
        value: float,
        agent_id: Optional[str] = None,
        unit: str = 'ms'
    ):
        """Record a performance metric."""
        metric = {
            'timestamp': datetime.now().isoformat(),
            'metric_name': metric_name,
            'value': value,
            'agent_id': agent_id,
            'unit': unit
        }
        
        self.performance_metrics.append(metric)
    
    def get_llm_stats(self) -> Dict[str, Any]:
        """Get LLM usage statistics."""
        if not self.llm_metrics:
            return {'total_calls': 0}
        
        recent_metrics = list(self.llm_metrics)[-1000:]  # Last 1000
        
        total_calls = len(recent_metrics)
        successful = sum(1 for m in recent_metrics if m.get('success', True))
        failed = total_calls - successful
        
        total_tokens = sum(m.get('tokens_used', 0) for m in recent_metrics if m.get('tokens_used'))
        avg_latency = sum(m.get('latency_ms', 0) for m in recent_metrics if m.get('latency_ms')) / max(1, total_calls)
        
        # By provider
        by_provider = defaultdict(int)
        for m in recent_metrics:
            by_provider[m.get('provider', 'unknown')] += 1
        
        return {
            'total_calls': total_calls,
            'successful': successful,
            'failed': failed,
            'success_rate': successful / max(1, total_calls),
            'total_tokens': total_tokens,
            'avg_latency_ms': avg_latency,
            'by_provider': dict(by_provider)
        }
    
    def get_message_bus_stats(self) -> Dict[str, Any]:
        """Get message bus statistics."""
        if not self.message_bus_metrics:
            return {'total_events': 0}
        
        recent_metrics = list(self.message_bus_metrics)[-1000:]
        
        total_events = len(recent_metrics)
        total_bytes = sum(m.get('size_bytes', 0) for m in recent_metrics if m.get('size_bytes'))
        
        # By event type
        by_type = defaultdict(int)
        for m in recent_metrics:
            by_type[m.get('event_type', 'unknown')] += 1
        
        # By topic
        by_topic = defaultdict(int)
        for m in recent_metrics:
            by_topic[m.get('topic', 'unknown')] += 1
        
        return {
            'total_events': total_events,
            'total_bytes': total_bytes,
            'by_event_type': dict(by_type),
            'by_topic': dict(by_topic)
        }
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        if not self.performance_metrics:
            return {}
        
        recent_metrics = list(self.performance_metrics)[-1000:]
        
        # Group by metric name
        by_metric = defaultdict(list)
        for m in recent_metrics:
            by_metric[m.get('metric_name')].append(m.get('value', 0))
        
        stats = {}
        for metric_name, values in by_metric.items():
            if values:
                stats[metric_name] = {
                    'avg': sum(values) / len(values),
                    'min': min(values),
                    'max': max(values),
                    'count': len(values)
                }
        
        return stats
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get all telemetry statistics."""
        return {
            'llm': self.get_llm_stats(),
            'message_bus': self.get_message_bus_stats(),
            'performance': self.get_performance_stats(),
            'counters': dict(self.counters)
        }




