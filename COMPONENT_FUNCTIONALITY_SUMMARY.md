# Backend Component Functionality Summary

This document provides a quick reference for each backend component's functionality and status.

## Component Overview

### 1. MessageBus ✅
**Location:** `communication/message_bus.py`  
**Status:** Fully Functional

**Purpose:** Real-time communication infrastructure using Redis Pub/Sub

**Key Features:**
- Publishes messages to topics
- Subscribes to topics with callbacks
- Graceful degradation when Redis unavailable
- Publisher/Subscriber pattern implementation

**Usage:**
```python
from communication.message_bus import MessageBus, MessageBusPublisher

# Initialize
message_bus = MessageBus(host='localhost', port=6379)

# Publish
publisher = MessageBusPublisher(message_bus, "agent.router.observations")
publisher.publish({'data': 'observation'})

# Subscribe
subscriber = MessageBusSubscriber(message_bus, ["agent.*.observations"], callback)
subscriber.start()
```

---

### 2. BaselineLearner ✅
**Location:** `agents/baseline_learner.py`  
**Status:** Fully Functional

**Purpose:** Statistical baseline learning for anomaly detection

**Key Features:**
- Numeric baselines (mean, std, percentiles)
- Pattern baselines (frequency-based)
- Time-windowed baselines
- Z-score calculation
- Anomaly scoring (0.0 to 1.0)

**Usage:**
```python
from agents.baseline_learner import BaselineLearner

learner = BaselineLearner()
learner.create_numeric_baseline("router.data_volume")
learner.update_numeric("router.data_volume", 1000.0)
is_anomaly = learner.check_anomaly("router.data_volume", 50000.0, threshold=2.0)
```

---

### 3. CrewOrchestrator ⚠️
**Location:** `agents/crew_orchestrator.py`  
**Status:** Functional (with notes)

**Purpose:** Orchestrates three security agents using CrewAI framework

**Key Features:**
- Manages Router, Computer, Email agents
- Processes data through agents
- Cross-agent correlation
- CrewAI crew initialization
- Statistics collection

**Usage:**
```python
from agents.crew_orchestrator import CrewOrchestrator

orchestrator = CrewOrchestrator()
result = orchestrator.process_data('router', network_data)
stats = orchestrator.get_stats()
```

**Note:** Agents may return empty results if no anomalies detected (expected behavior).

---

### 4. Guardrails ⚠️
**Location:** `guardrails/action_guard.py`  
**Status:** Functional (with notes)

**Purpose:** Intercepts and validates all agent actions

**Key Features:**
- Action interception
- Policy enforcement
- Approval workflow
- Action logging
- Statistics tracking

**Usage:**
```python
from guardrails.action_guard import ActionGuard

action_guard = ActionGuard()
result = action_guard.intercept_action({
    'type': 'observation',
    'agent_id': 'router',
    'data': {...}
})

if result['requires_approval']:
    approval_id = result['approval_id']
    action_guard.approve_action(approval_id, True, user='admin')
```

---

### 5. KnowledgeFusion ✅
**Location:** `knowledge_fusion/fusion_core.py`  
**Status:** Structure Validated (requires Neo4j)

**Purpose:** Enriches observations with MITRE ATT&CK knowledge

**Key Features:**
- Observation-to-technique mapping
- Related technique retrieval
- Mitigation suggestions
- Context assembly
- RAG pipeline integration

**Dependencies:** Neo4j database, LLM API

---

### 6. TestOrchestrator ✅
**Location:** `attack_testing/test_orchestrator.py`  
**Status:** Fully Functional

**Purpose:** Orchestrates attack testing workflow

**Key Features:**
- Training status checking
- Attack test execution
- Result storage and retrieval
- Test report generation
- Sequence testing

**Usage:**
```python
from attack_testing.test_orchestrator import TestOrchestrator

test_orch = TestOrchestrator(agents=agents)
result = test_orch.run_attack_test(attack_data, 'router')
report = test_orch.generate_test_report()
```

---

### 7. TrainingOrchestrator ✅
**Location:** `baseline_training/training_orchestrator.py`  
**Status:** Fully Functional

**Purpose:** Manages baseline training for agents

**Key Features:**
- Training data ingestion
- Feature extraction
- Baseline updates
- Training status tracking
- Mode switching (training/inference/hybrid)

**Usage:**
```python
from baseline_training.training_orchestrator import TrainingOrchestrator

trainer = TrainingOrchestrator()
result = trainer.start_training('router', training_data)
status = trainer.get_training_status('router')
```

---

### 8. AttackGenerator ✅
**Location:** `attack_testing/attack_generator.py`  
**Status:** Structure Validated (requires LLM API)

**Purpose:** LLM-powered attack data generation

**Key Features:**
- Attack scenario generation
- Structured attack data
- Hacker simulation
- Random attack generation

**Dependencies:** LLM API

---

### 9. API Layer ✅
**Location:** `attack_testing/api.py`  
**Status:** Fully Functional

**Purpose:** Flask REST API with WebSocket support

**Key Endpoints:**
- `GET /health` - Health check
- `GET /api/test/status` - Test status
- `POST /api/test/chat` - Chat processing
- `POST /api/test/generate-attack` - Attack generation
- `POST /api/test/run-test` - Run attack test
- `GET /api/test/results` - Get test results
- `POST /api/training/upload` - Upload training data
- `GET /api/training/status/<agent_id>` - Training status
- `POST /api/system/start` - Start system
- `POST /api/system/stop` - Stop system

**WebSocket Events:**
- `router-observation`
- `computer-observation`
- `email-observation`

---

### 10. Observability ✅
**Location:** `observability/agent_monitor.py`  
**Status:** Fully Functional

**Purpose:** Real-time agent monitoring and telemetry

**Key Features:**
- Agent registration
- Status tracking
- Metrics collection
- System summary
- Performance monitoring

**Usage:**
```python
from observability.agent_monitor import AgentMonitor

monitor = AgentMonitor()
monitor.register_agent('router', router_agent)
monitor.update_agent_status('router', {'status': 'active'})
summary = monitor.get_system_summary()
```

---

## Component Interaction Flow

```
Data Input
    ↓
CrewOrchestrator (routes to agents)
    ↓
Individual Agents (Router/Computer/Email)
    ↓
BaselineLearner (anomaly detection)
    ↓
Threat Analyzer (LLM reasoning)
    ↓
ActionGuard (interception)
    ↓
ApprovalManager (if required)
    ↓
MessageBus (publish observations)
    ↓
KnowledgeFusion (MITRE enrichment)
    ↓
Observability (monitoring)
```

---

## Dependencies Summary

| Component | Required Dependencies | Optional Dependencies |
|-----------|----------------------|----------------------|
| MessageBus | - | Redis |
| BaselineLearner | numpy | - |
| CrewOrchestrator | - | CrewAI, LLM API |
| Guardrails | - | - |
| KnowledgeFusion | - | Neo4j, LLM API |
| TestOrchestrator | - | LLM API |
| TrainingOrchestrator | - | - |
| AttackGenerator | - | LLM API |
| API Layer | Flask | Redis (for WebSocket) |
| Observability | - | - |

---

## Testing Status

- **Total Components:** 10
- **Fully Tested:** 8
- **Partially Tested:** 2 (require external dependencies)
- **Test Pass Rate:** 94.4%

---

## Quick Reference

### Starting the System
```python
from start_backend_server import main
main()
```

### Testing Components
```bash
python test_backend_components.py
```

### Viewing Test Report
```bash
cat BACKEND_COMPONENT_TEST_REPORT.md
```

---

**Last Updated:** 2025-12-09  
**Test Coverage:** 72 tests across 10 components


