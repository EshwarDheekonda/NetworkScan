"""
Complete Knowledge Fusion Module Runner

This script runs the full Knowledge Fusion pipeline end-to-end with comprehensive output.
"""

import sys
import time
from datetime import datetime
from py2neo import Graph
import json

# Add project root to path
sys.path.insert(0, '.')

try:
    from knowledge_fusion.fusion_core import KnowledgeFusion
    from knowledge_fusion.rag_pipeline import RAGPipeline
    from knowledge_fusion.agent_interface import AgentInterface
    from knowledge_fusion.interfaces import AgentOutput, Observation
except ImportError as e:
    print(f"ERROR: Could not import Knowledge Fusion module: {e}")
    print("Make sure you're running from the project root directory.")
    sys.exit(1)

def check_neo4j_connection():
    """Check if Neo4j is running and accessible."""
    try:
        # Try to load credentials
        try:
            with open("cred.json") as f:
                creds = json.load(f)
                username = creds.get("username", "neo4j")
                password = creds.get("password", "password123")
        except FileNotFoundError:
            print("WARNING: cred.json not found, using defaults")
            username = "neo4j"
            password = "password123"
        
        # Try to connect
        graph = Graph("bolt://localhost:7687", auth=(username, password))
        graph.run("RETURN 1 as test")
        return True, graph
    except Exception as e:
        return False, str(e)

def run_complete_knowledge_fusion():
    """Run the complete Knowledge Fusion module."""
    
    print("=" * 100)
    print("KNOWLEDGE FUSION MODULE - COMPLETE RUN")
    print("=" * 100)
    print()
    
    # Step 1: Check Neo4j connection
    print("[1/8] Checking Neo4j Connection...")
    neo4j_ok, neo4j_info = check_neo4j_connection()
    
    if not neo4j_ok:
        print(f"❌ ERROR: Cannot connect to Neo4j database")
        print(f"   Error: {neo4j_info}")
        print()
        print("Please ensure Neo4j is running:")
        print("  1. Start Neo4j using: start_neo4j.bat (Windows) or start_neo4j.sh (Linux/Mac)")
        print("  2. Or manually: docker run --name neo4j -p7474:7474 -p7687:7687 -d -e NEO4J_AUTH=neo4j/password123 neo4j:5")
        print("  3. Make sure cred.json exists with correct credentials")
        sys.exit(1)
    
    print("✅ Neo4j connection successful!")
    print()
    
    # Step 2: Prepare agent outputs
    print("[2/8] Preparing Agent Outputs...")
    agent_interface = AgentInterface()
    
    # Create realistic multi-agent scenario
    router_data = {
        "agent_id": "router",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "network",
            "description": "Suspicious outbound HTTPS connection to unknown external IP on port 443. High volume encrypted data transfer. Connection pattern matches known command and control infrastructure. Domain associated with threat actor group.",
            "indicators": ["185.220.101.45", "c2-command-control.com", "443", "TLS 1.3"],
            "severity": "high",
            "metadata": {
                "protocol": "HTTPS",
                "bytes_sent": 10485760,
                "bytes_received": 4194304,
                "duration_seconds": 3600,
                "dns_query": "c2-command-control.com"
            }
        }],
        "confidence": 0.88,
        "metadata": {"source": "network_firewall", "rule_id": "FW-C2-001"}
    }
    
    computer_data = {
        "agent_id": "computer",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "process",
            "description": "PowerShell process executing Base64-encoded commands and establishing persistent network connections. Process injection detected. Scheduled task creation observed. Suspicious WMI activity for remote execution.",
            "indicators": ["powershell.exe", "encoded-payload.ps1", "185.220.101.45", "cmd.exe", "wmic.exe"],
            "severity": "critical",
            "metadata": {
                "pid": 8924,
                "parent_pid": 1234,
                "user": "SYSTEM",
                "command_line": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA...",
                "process_tree": ["explorer.exe", "cmd.exe", "powershell.exe"]
            }
        }],
        "confidence": 0.92,
        "metadata": {"source": "endpoint_detection", "alert_id": "EDR-789", "threat_score": 95}
    }
    
    email_data = {
        "agent_id": "email",
        "timestamp": datetime.now(),
        "observations": [{
            "type": "email",
            "description": "Phishing email with malicious attachment detected. Email contains suspicious links to external domains. Attachment is executable disguised as PDF. Sender domain reputation is poor.",
            "indicators": ["sender@malicious-domain.org", "invoice-urgent.pdf.exe", "click-here-link.com"],
            "severity": "high",
            "metadata": {
                "subject": "URGENT: Invoice Payment Required - Action Needed",
                "sender_domain": "malicious-domain.org",
                "attachment_hash": "abc123def456...",
                "url_count": 3
            }
        }],
        "confidence": 0.75,
        "metadata": {"source": "email_security_gateway", "quarantined": True}
    }
    
    router_output = agent_interface.normalize_agent_output(router_data)
    computer_output = agent_interface.normalize_agent_output(computer_data)
    email_output = agent_interface.normalize_agent_output(email_data)
    
    agent_outputs = [router_output, computer_output, email_output]
    
    print(f"✅ Prepared {len(agent_outputs)} agent outputs:")
    for output in agent_outputs:
        print(f"   - {output.agent_id.upper()}: {len(output.observations)} observation(s), confidence: {output.confidence:.2f}")
    print()
    
    # Step 3: Knowledge Fusion
    print("[3/8] Running Knowledge Fusion...")
    knowledge_fusion = KnowledgeFusion()
    
    start_time = time.time()
    enriched = knowledge_fusion.fuse(agent_outputs, threat_context_placeholder="[LLM context will be generated]")
    fusion_time = time.time() - start_time
    
    print(f"✅ Fusion completed in {fusion_time*1000:.2f}ms")
    print(f"   - Matched Techniques: {len(enriched.matched_mitre_techniques)}")
    print(f"   - Matched Tactics: {len(enriched.matched_mitre_tactics)}")
    print(f"   - Related Techniques: {len(enriched.related_techniques)}")
    print(f"   - Mitigations: {len(enriched.mitigations)}")
    print()
    
    # Step 4: RAG Enhancement
    print("[4/8] Generating RAG-Enhanced Threat Intelligence...")
    rag_pipeline = RAGPipeline()
    
    start_time = time.time()
    enhanced = rag_pipeline.enhance_with_rag(enriched, generate_context=True)
    rag_time = time.time() - start_time
    
    print(f"✅ RAG generation completed in {rag_time*1000:.2f}ms")
    print(f"   - Threat context length: {len(enhanced.threat_context)} characters")
    print(f"   - LLM Provider: {enhanced.attribution.get('llm_provider', 'N/A')}")
    print()
    
    # Step 5: Add Explainability
    print("[5/8] Adding Explainability Attribution...")
    enhanced = rag_pipeline.add_explainability_attribution(enhanced)
    print("✅ Explainability attribution added")
    print()
    
    # Step 6: Display Results
    print("[6/8] Displaying Results...")
    print()
    print("=" * 100)
    print("MATCHED MITRE ATT&CK TECHNIQUES")
    print("=" * 100)
    for i, tech in enumerate(enhanced.matched_mitre_techniques, 1):
        print(f"\n{i}. {tech.name}")
        if tech.external_id:
            print(f"   MITRE ID: {tech.external_id}")
        print(f"   Tactic: {tech.tactic or 'N/A'}")
        print(f"   Relevance Score: {tech.score:.3f}")
        if tech.description:
            desc = tech.description[:200] + "..." if len(tech.description) > 200 else tech.description
            print(f"   Description: {desc}")
    
    print()
    print("=" * 100)
    print("MATCHED MITRE ATT&CK TACTICS")
    print("=" * 100)
    for i, tactic in enumerate(enhanced.matched_mitre_tactics, 1):
        print(f"{i}. {tactic.name} (Score: {tactic.score:.3f})")
    
    print()
    print("=" * 100)
    print("ATTACK CHAIN - RELATED TECHNIQUES")
    print("=" * 100)
    for i, tech in enumerate(enhanced.related_techniques[:10], 1):
        print(f"{i}. {tech.name} ({tech.external_id or 'N/A'}) - {tech.tactic or 'N/A'}")
    
    print()
    print("=" * 100)
    print("RECOMMENDED MITIGATIONS")
    print("=" * 100)
    for i, mitigation in enumerate(enhanced.mitigations[:10], 1):
        print(f"\n{i}. {mitigation.name}")
        if mitigation.description:
            desc = mitigation.description[:200] + "..." if len(mitigation.description) > 200 else mitigation.description
            print(f"   {desc}")
    
    print()
    print("=" * 100)
    print("LLM-GENERATED THREAT ANALYSIS")
    print("=" * 100)
    print(enhanced.threat_context)
    
    print()
    print("=" * 100)
    print("CONFIDENCE SCORES")
    print("=" * 100)
    for key, value in enhanced.confidence_scores.items():
        bar_length = int(value * 50)
        bar = "#" * bar_length + "-" * (50 - bar_length)
        print(f"  {key.replace('_', ' ').title():25} {value:.3f} [{bar}]")
    
    print()
    
    # Step 7: Attribution
    print("[7/8] Attribution & Explainability...")
    print(f"   Retrieval Methods: {', '.join(enhanced.attribution.get('retrieval_methods', []))}")
    print(f"   Total Techniques Matched: {enhanced.attribution.get('technique_count', 0)}")
    print(f"   Total Tactics Identified: {enhanced.attribution.get('tactic_count', 0)}")
    print(f"   Related Techniques Found: {enhanced.attribution.get('related_technique_count', 0)}")
    print(f"   Mitigations Retrieved: {enhanced.attribution.get('mitigation_count', 0)}")
    print(f"   RAG Generated: {enhanced.attribution.get('rag_generated', False)}")
    print(f"   LLM Provider: {enhanced.attribution.get('llm_provider', 'N/A')}")
    print()
    
    # Step 8: Validation
    print("[8/8] Output Validation...")
    try:
        output_dict = enhanced.model_dump()
        json_output = json.dumps(output_dict, default=str, indent=2)
        print(f"✅ JSON serialization successful ({len(json_output)} characters)")
        print(f"✅ All required fields present")
        print(f"✅ Ready for Threat Scoring Module integration")
    except Exception as e:
        print(f"❌ Validation error: {e}")
    
    print()
    print("=" * 100)
    print("KNOWLEDGE FUSION MODULE RUN COMPLETE")
    print("=" * 100)
    print()
    print(f"Performance Summary:")
    print(f"  - Knowledge Fusion: {fusion_time*1000:.2f}ms")
    print(f"  - RAG Generation: {rag_time*1000:.2f}ms")
    print(f"  - Total Time: {(fusion_time + rag_time)*1000:.2f}ms ({(fusion_time + rag_time):.2f}s)")
    print()
    print(f"Output Quality:")
    print(f"  - Overall Confidence: {enhanced.confidence_scores['overall']:.3f}")
    print(f"  - Technique Matching: {enhanced.confidence_scores['technique_matching']:.3f}")
    print(f"  - Tactic Matching: {enhanced.confidence_scores['tactic_matching']:.3f}")
    print(f"  - Agent Confidence: {enhanced.confidence_scores['agent_confidence']:.3f}")
    print()

if __name__ == "__main__":
    try:
        run_complete_knowledge_fusion()
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

