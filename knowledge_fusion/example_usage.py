"""
Example usage of the Knowledge Fusion module.

This demonstrates a complete workflow from agent outputs to enriched threat intelligence.
"""

from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.rag_pipeline import RAGPipeline
from knowledge_fusion.agent_interface import AgentInterface
from knowledge_fusion.interfaces import AgentOutput, Observation
from datetime import datetime


def example_single_agent():
    """Example: Process single agent output."""
    print("=" * 60)
    print("Example 1: Single Agent Processing")
    print("=" * 60)
    
    # Normalize agent output
    agent_interface = AgentInterface()
    agent_data = {
        "agent_id": "router",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "network",
            "description": "Suspicious command and control communication on port 443",
            "indicators": ["192.168.1.100", "c2-server.example.com"],
            "severity": "high"
        }],
        "confidence": 0.85
    }
    
    agent_output = agent_interface.normalize_agent_output(agent_data)
    
    # Run fusion
    knowledge_fusion = KnowledgeFusion()
    enriched = knowledge_fusion.fuse([agent_output])
    
    # Enhance with RAG
    rag_pipeline = RAGPipeline()
    enhanced = rag_pipeline.enhance_with_rag(enriched)
    
    # Display results
    print(f"\nMatched Techniques: {len(enhanced.matched_mitre_techniques)}")
    for tech in enhanced.matched_mitre_techniques[:3]:
        print(f"  - {tech.name} ({tech.external_id or 'N/A'})")
    
    print(f"\nMatched Tactics: {len(enhanced.matched_mitre_tactics)}")
    for tactic in enhanced.matched_mitre_tactics[:3]:
        print(f"  - {tactic.name}")
    
    print(f"\nConfidence: {enhanced.confidence_scores['overall']:.3f}")
    print(f"\nThreat Context Preview:\n{enhanced.threat_context[:300]}...")


def example_multi_agent():
    """Example: Process multiple agent outputs with correlation."""
    print("\n" + "=" * 60)
    print("Example 2: Multi-Agent Correlation")
    print("=" * 60)
    
    agent_interface = AgentInterface()
    
    # Router agent
    router_data = {
        "agent_id": "router",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "network",
            "description": "Outbound connection to suspicious IP",
            "indicators": ["192.168.1.100"],
            "severity": "high"
        }],
        "confidence": 0.85
    }
    
    # Computer agent
    computer_data = {
        "agent_id": "computer",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "process",
            "description": "PowerShell script execution with network activity",
            "indicators": ["192.168.1.100", "powershell.exe"],
            "severity": "critical"
        }],
        "confidence": 0.90
    }
    
    router_output = agent_interface.normalize_agent_output(router_data)
    computer_output = agent_interface.normalize_agent_output(computer_data)
    
    # Run fusion
    knowledge_fusion = KnowledgeFusion()
    enriched = knowledge_fusion.fuse([router_output, computer_output])
    
    # Check correlation
    correlation = enriched.attribution.get("correlation", {})
    print(f"\nCross-Agent Correlation: {correlation.get('correlated', False)}")
    if correlation.get('correlated'):
        print(f"  Correlation Score: {correlation.get('correlation_score', 0):.3f}")
    
    print(f"\nTotal Matched Techniques: {len(enriched.matched_mitre_techniques)}")
    print(f"Total Mitigations: {len(enriched.mitigations)}")
    print(f"Overall Confidence: {enriched.confidence_scores['overall']:.3f}")


if __name__ == "__main__":
    # Run examples
    example_single_agent()
    example_multi_agent()
    
    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)


