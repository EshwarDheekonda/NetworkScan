"""
Agent Monitor

Real-time agent monitoring that tracks agent status, activity, performance,
LLM usage, baseline learning progress, and active threats.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
from collections import defaultdict


class AgentMonitor:
    """Real-time agent monitoring."""
    
    def __init__(self):
        """Initialize the agent monitor."""
        self.logger = logging.getLogger(__name__)
        self.agents: Dict[str, Any] = {}
        self.metrics_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.max_history = 1000
    
    def register_agent(self, agent_id: str, agent: Any):
        """Register an agent for monitoring."""
        self.agents[agent_id] = {
            'agent': agent,
            'registered_at': datetime.now().isoformat(),
            'last_update': datetime.now().isoformat()
        }
        self.logger.info(f"Registered agent for monitoring: {agent_id}")
    
    def update_agent_status(self, agent_id: str, status: Dict[str, Any]):
        """Update agent status."""
        if agent_id not in self.agents:
            return
        
        self.agents[agent_id]['last_update'] = datetime.now().isoformat()
        self.agents[agent_id]['status'] = status
        
        # Store in history
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'status': status
        }
        self.metrics_history[agent_id].append(history_entry)
        
        # Trim history
        if len(self.metrics_history[agent_id]) > self.max_history:
            self.metrics_history[agent_id] = self.metrics_history[agent_id][-self.max_history:]
    
    def get_agent_status(self, agent_id: str) -> Dict[str, Any]:
        """Get current status of an agent."""
        if agent_id not in self.agents:
            return {'error': f'Agent {agent_id} not registered'}
        
        agent_info = self.agents[agent_id]
        agent = agent_info['agent']
        
        # Get stats from agent
        stats = agent.get_stats() if hasattr(agent, 'get_stats') else {}
        
        return {
            'agent_id': agent_id,
            'registered_at': agent_info['registered_at'],
            'last_update': agent_info['last_update'],
            'is_running': stats.get('is_running', False),
            'stats': stats,
            'recent_status': agent_info.get('status', {})
        }
    
    def get_all_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all registered agents."""
        return {
            agent_id: self.get_agent_status(agent_id)
            for agent_id in self.agents.keys()
        }
    
    def get_agent_metrics(
        self,
        agent_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get metrics history for an agent."""
        return self.metrics_history.get(agent_id, [])[-limit:]
    
    def get_system_summary(self) -> Dict[str, Any]:
        """Get system-wide summary."""
        all_status = self.get_all_agent_status()
        
        total_observations = sum(
            s.get('stats', {}).get('observation_count', 0)
            for s in all_status.values()
        )
        
        total_anomalies = sum(
            s.get('stats', {}).get('anomaly_count', 0)
            for s in all_status.values()
        )
        
        running_agents = sum(
            1 for s in all_status.values()
            if s.get('is_running', False)
        )
        
        total_llm_calls = sum(
            s.get('stats', {}).get('llm_calls', 0)
            for s in all_status.values()
        )
        
        return {
            'total_agents': len(self.agents),
            'running_agents': running_agents,
            'total_observations': total_observations,
            'total_anomalies': total_anomalies,
            'total_llm_calls': total_llm_calls,
            'agents': all_status
        }




