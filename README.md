# Modern AI-Powered Security Agent System

A next-generation, LLM-powered cybersecurity threat detection system that combines statistical baseline learning with AI reasoning for proactive threat detection. The system uses CrewAI framework for agentic orchestration, implements comprehensive guardrails for all actions, and provides full observability and user control.

---

## Architecture Overview

### 1. **Modern LLM-Powered Agents**
Three specialized security agents powered by LLMs and statistical baselines:

- **Router LLM Agent** (`agents/llm_agents/router_llm_agent.py`)  
  Monitors network traffic with LLM reasoning for C2 detection, data exfiltration, and network anomalies.

- **Computer LLM Agent** (`agents/llm_agents/computer_llm_agent.py`)  
  Analyzes system logs with LLM to identify attack chains, process injection, privilege escalation, and persistence.

- **Email LLM Agent** (`agents/llm_agents/email_llm_agent.py`)  
  Detects phishing, malicious attachments, and email-based attacks using LLM content analysis.

### 2. **LLM Reasoning Layer** (`agents/reasoning/`)
- **ThreatAnalyzer**: LLM-powered threat analysis that determines if anomalies are real threats
- **PatternRecognizer**: Identifies multi-stage attack sequences and predicts next steps
- **ContextBuilder**: Builds rich context from historical data, MITRE ATT&CK, and cross-agent correlation

### 3. **Agent Guardrails System** (`guardrails/`)
- **ActionGuard**: Intercepts all agent actions and requires user approval
- **PolicyEngine**: Defines and enforces action policies
- **ApprovalManager**: Manages approval workflow and tracks decisions
- **ActionLogger**: Maintains complete audit trail of all actions

### 4. **Observability & Visibility** (`observability/`)
- **AgentMonitor**: Real-time monitoring of agent status, activity, and performance
- **ActionDashboard**: User-facing dashboard showing pending approvals and agent activity
- **TelemetryCollector**: Tracks LLM usage, message bus activity, and performance metrics
- **NotificationSystem**: Real-time notifications for approvals and critical threats

### 5. **Knowledge Fusion & RAG**
- **MITRE ATT&CK Graph DB**: Structured threat intelligence in Neo4j
- **Hybrid RAG Pipeline**: Combines graph and vector search for MITRE technique matching
- **Agent-Aware RAG**: Incorporates agent reasoning into threat intelligence
- **Proactive RAG**: Pre-fetches related techniques for early warning

### 6. **CrewAI Orchestration** (`agents/crew_orchestrator.py`)
- Coordinates all three agents using CrewAI framework
- Manages agent collaboration and cross-agent correlation
- Handles inter-agent communication and shared context

---

## Key Features

### LLM-Powered Reasoning
- **Hybrid Detection**: Statistical baselines identify anomalies, LLM determines threat significance
- **Contextual Analysis**: LLM provides rich context and reasoning for detections
- **Pattern Recognition**: Identifies complex attack patterns and sequences
- **Proactive Prediction**: Predicts likely next attack steps

### Comprehensive Guardrails
- **Action Interception**: All agent actions intercepted and validated
- **User Approval Required**: All actions require explicit user approval
- **Policy Enforcement**: Configurable policies for different action types
- **Complete Audit Trail**: Full logging of all actions and approvals

### Full User Visibility
- **Real-Time Monitoring**: Live view of agent activity and status
- **Action Dashboard**: Pending approvals and action history
- **Telemetry**: Comprehensive metrics and performance data
- **Notifications**: Real-time alerts for approvals and critical threats

### Enhanced Communication
- **Intelligent Routing**: LLM-based message routing
- **Agent Collaboration**: Structured protocols for multi-agent investigations
- **Shared Context**: Agents share threat context and knowledge
- **Cross-Agent Correlation**: Automatic correlation of related events

---

## Quick Start

### Prerequisites
- Python 3.8+
- Redis (for message bus)
- Neo4j (for MITRE ATT&CK knowledge base)
- OpenAI API key (or other LLM provider)

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Start Redis
redis-server

# Start Neo4j (using Docker)
docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest
```

### Basic Usage

```python
from agents.crew_orchestrator import CrewOrchestrator
from guardrails.action_guard import ActionGuard
from observability.agent_monitor import AgentMonitor

# Initialize orchestrator
orchestrator = CrewOrchestrator()

# Set up guardrails
action_guard = ActionGuard()
orchestrator.set_action_guard(action_guard)

# Set up monitoring
monitor = AgentMonitor()
for agent_id, agent in orchestrator.agents.items():
    monitor.register_agent(agent_id, agent)

# Start agents
orchestrator.start()

# Process data
network_data = {
    "source_ip": "192.168.1.100",
    "dest_ip": "185.220.101.45",
    "protocol": "HTTPS",
    "port": 443,
    "bytes_sent": 10485760
}

output = orchestrator.process_data("router", network_data)
```

---

## System Capabilities

- **Proactive Threat Detection**: Detects threats before damage occurs using baseline learning and LLM reasoning
- **LLM-Enhanced Analysis**: Statistical detection enhanced with AI reasoning for better accuracy
- **Complete User Control**: All actions require approval with full visibility
- **Cross-Agent Correlation**: Identifies coordinated attacks across network, endpoint, and email
- **Explainable AI**: All detections include LLM-generated reasoning and context
- **Scalable Architecture**: Modular design allows independent tuning and replacement of components
- **Audit Trail**: Complete logging of all actions, approvals, and decisions

---

## Documentation

- **[System Example](SYSTEM_EXAMPLE.md)**: Detailed walkthrough of how the system works with a concrete C2 attack scenario
- **[System Flowcharts](SYSTEM_FLOWCHART.md)**: Visual flowcharts showing system architecture and data flow
