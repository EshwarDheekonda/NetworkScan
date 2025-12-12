# System Flow Example

This document demonstrates how the modern AI-powered security agent system works with a concrete example.

## Scenario: Detecting a Command & Control (C2) Attack

### Step-by-Step Flow

#### 1. **Data Input: Network Traffic Anomaly**

```python
# Network traffic data arrives at the Router LLM Agent
network_data = {
    "source_ip": "192.168.1.100",
    "dest_ip": "185.220.101.45",  # Suspicious external IP
    "protocol": "HTTPS",
    "port": 443,
    "bytes_sent": 10485760,  # 10MB outbound
    "bytes_received": 1024,  # Very little inbound (asymmetric)
    "duration_seconds": 3600,  # Long-lived connection (1 hour)
    "timestamp": "2024-12-05T10:30:00Z"
}
```

#### 2. **Statistical Baseline Detection**

The Router LLM Agent first uses statistical baselines:

```python
# Agent extracts features
features = {
    'destinations': '185.220.101.45',
    'protocols': 'HTTPS',
    'ports': '443',
    'data_volume': 10485760 + 1024,
    'connection_duration': 3600
}

# Checks against learned baselines
anomaly_scores = {
    'destinations': 0.85,  # High - never seen this destination before
    'data_volume': 0.92,   # Very high - unusual data volume
    'connection_duration': 0.88,  # High - unusually long connection
    'protocols': 0.15,     # Low - HTTPS is normal
    'ports': 0.20          # Low - port 443 is normal
}

# Max anomaly score: 0.92 > threshold (0.4) → Anomaly detected!
```

#### 3. **Initial Observation Generation**

```python
# Agent generates initial observation from statistical detection
initial_observation = Observation(
    type="router",
    description="Unusual destination: 185.220.101.45. Unusual data volume: 10485760 bytes. Unusual connection duration: 3600.0s. Pattern suggests potential data exfiltration.",
    indicators=["185.220.101.45", "192.168.1.100", "HTTPS", "port:443"],
    severity="high",
    metadata={
        'anomaly_scores': anomaly_scores,
        'max_anomaly_score': 0.92,
        'source_ip': '192.168.1.100',
        'dest_ip': '185.220.101.45',
        'bytes_sent': 10485760,
        'bytes_received': 1024
    }
)
```

#### 4. **LLM Threat Analysis**

The ThreatAnalyzer uses LLM to analyze if this is a real threat:

```python
# Context is built including:
context = {
    'current_observations': [initial_observation],
    'temporal': {
        'recent_observation_count': 5,  # 5 observations in last 24h
        'type_distribution': {'router': 3, 'computer': 2}
    },
    'correlation': {
        'correlated_agents': [],  # No correlation yet
        'common_indicators': []
    },
    'mitre': {
        'techniques': [
            {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'score': 0.89},
            {'id': 'T1071', 'name': 'Application Layer Protocol', 'score': 0.85}
        ],
        'tactics': [
            {'name': 'Exfiltration', 'score': 0.87},
            {'name': 'Command and Control', 'score': 0.82}
        ]
    }
}

# LLM analyzes and returns:
threat_analysis = {
    'is_threat': True,
    'threat_level': 'critical',
    'confidence': 0.91,
    'reasoning': 'This traffic pattern strongly indicates data exfiltration over a C2 channel. The asymmetric traffic (large outbound, minimal inbound), long connection duration, and unknown destination are classic indicators of C2 communication.',
    'attack_scenario': 'An attacker has established a C2 channel and is exfiltrating data. The long-lived HTTPS connection to an unknown external IP with 10MB of outbound data suggests sensitive information is being transmitted.',
    'recommended_actions': [
        'Immediately block outbound traffic to 185.220.101.45',
        'Investigate source host 192.168.1.100 for compromise',
        'Review recent file access and process execution on source host',
        'Check for related email communications to this IP'
    ]
}
```

#### 5. **Pattern Recognition**

The PatternRecognizer identifies attack patterns:

```python
pattern_analysis = {
    'patterns_detected': [
        'Data exfiltration pattern',
        'C2 channel establishment',
        'Asymmetric network traffic'
    ],
    'attack_sequence': [
        'Initial compromise',
        'C2 channel establishment',
        'Data collection',
        'Data exfiltration'  # ← We are here
    ],
    'likely_next_steps': [
        'Continued data exfiltration',
        'Lateral movement from compromised host',
        'Additional C2 channels',
        'Cleanup and persistence'
    ],
    'mitre_tactics': ['Exfiltration', 'Command and Control', 'Collection'],
    'confidence': 0.88
}
```

#### 6. **Enhanced Observation**

The observation is enhanced with LLM analysis:

```python
enhanced_observation = Observation(
    type="router",
    description="Critical threat: Data exfiltration over C2 channel detected. 10MB of data transmitted to unknown external IP 185.220.101.45 over long-lived HTTPS connection.",
    indicators=["185.220.101.45", "192.168.1.100", "HTTPS", "port:443"],
    severity="critical",  # Upgraded from "high" based on LLM analysis
    metadata={
        'anomaly_scores': anomaly_scores,
        'max_anomaly_score': 0.92,
        'llm_analysis': {
            'is_threat': True,
            'threat_level': 'critical',
            'confidence': 0.91,
            'reasoning': '...',
            'attack_scenario': '...',
            'recommended_actions': [...]
        },
        'pattern_metadata': {
            'patterns_detected': [...],
            'attack_sequence': [...],
            'likely_next_steps': [...]
        },
        'mitre_techniques': ['T1041', 'T1071'],
        'mitre_tactics': ['Exfiltration', 'Command and Control']
    }
)
```

#### 7. **Action Guardrails - Approval Required**

Before the observation can be published, it must go through guardrails:

```python
# Action guard intercepts
action = {
    'type': 'observation',
    'agent_id': 'router',
    'observation': enhanced_observation,
    'timestamp': '2024-12-05T10:30:15Z'
}

# Policy check: All observations require approval
approval_result = action_guard.intercept_action(action)
# Returns:
{
    'allowed': False,
    'requires_approval': True,
    'action_id': 'observation_20241205103015_a1b2c3d4',
    'approval_id': 'approval_xyz789',
    'message': 'Action requires user approval'
}
```

#### 8. **User Approval**

The action appears in the dashboard:

```
╔══════════════════════════════════════════════════════════╗
║              PENDING APPROVAL REQUIRED                    ║
╠══════════════════════════════════════════════════════════╣
║ Approval ID: approval_xyz789                              ║
║ Agent: router                                             ║
║ Type: observation                                         ║
║ Severity: CRITICAL                                        ║
║                                                           ║
║ Description:                                              ║
║ Critical threat: Data exfiltration over C2 channel       ║
║ detected. 10MB of data transmitted to unknown external   ║
║ IP 185.220.101.45 over long-lived HTTPS connection.      ║
║                                                           ║
║ LLM Analysis:                                             ║
║ Confidence: 91%                                           ║
║ Threat Level: Critical                                    ║
║                                                           ║
║ Recommended Actions:                                      ║
║ • Block outbound traffic to 185.220.101.45                ║
║ • Investigate source host 192.168.1.100                   ║
║                                                           ║
║ [Approve] [Reject] [View Details]                         ║
╚══════════════════════════════════════════════════════════╝
```

User clicks "Approve":

```python
action_guard.approve_action(
    approval_id='approval_xyz789',
    approved=True,
    user='security_analyst_01',
    reason='Confirmed threat - proceeding with investigation'
)
```

#### 9. **Observation Published to Message Bus**

Once approved, the observation is published:

```python
agent_output = AgentOutput(
    agent_id='router',
    timestamp=datetime.now(),
    observations=[enhanced_observation],
    confidence=0.91,
    metadata={
        'llm_enhanced': True,
        'llm_calls': 2,  # Threat analysis + pattern recognition
        'approved_by': 'security_analyst_01'
    }
)

# Published to Redis message bus
message_bus.publish('agent.router.observations', agent_output)
```

#### 10. **Cross-Agent Correlation**

The Computer Agent detects related activity:

```python
# Computer Agent detects suspicious process on same source IP
computer_observation = Observation(
    type="computer",
    description="Unusual process: powershell.exe with obfuscated command line",
    indicators=["powershell.exe", "user:admin", "192.168.1.100"],
    severity="high",
    metadata={
        'process_name': 'powershell.exe',
        'command_line': 'powershell -enc <base64_encoded>',
        'source_ip': '192.168.1.100'  # Same as network traffic!
    }
)

# Cross-agent correlation identifies common indicator
correlation = {
    'common_indicators': ['192.168.1.100'],
    'correlated_agents': ['router', 'computer'],
    'correlation_score': 0.95
}
```

#### 11. **Knowledge Fusion**

Both observations are sent to Knowledge Fusion:

```python
# Knowledge Fusion enriches with MITRE ATT&CK
enriched_intelligence = knowledge_fusion.fuse([
    router_agent_output,
    computer_agent_output
])

# Returns:
{
    'matched_mitre_techniques': [
        {'id': 'T1041', 'name': 'Exfiltration Over C2 Channel', 'score': 0.92},
        {'id': 'T1059.001', 'name': 'PowerShell', 'score': 0.88},
        {'id': 'T1071', 'name': 'Application Layer Protocol', 'score': 0.85}
    ],
    'matched_mitre_tactics': [
        {'name': 'Exfiltration', 'score': 0.90},
        {'name': 'Command and Control', 'score': 0.87},
        {'name': 'Execution', 'score': 0.82}
    ],
    'threat_context': 'LLM-generated comprehensive threat analysis...',
    'confidence_scores': {
        'overall': 0.89,
        'correlation': 0.95
    }
}
```

#### 12. **Notification & Dashboard Update**

```python
# Notification sent
notification_system.notify_critical_threat({
    'description': 'Multi-agent threat detected: C2 and data exfiltration',
    'agents': ['router', 'computer'],
    'severity': 'critical',
    'mitre_techniques': ['T1041', 'T1059.001', 'T1071']
})

# Dashboard updates in real-time
dashboard.display_agent_activity()
# Shows:
# - Router Agent: 1 critical observation
# - Computer Agent: 1 high observation
# - Correlation: 95% confidence
```

#### 13. **Action Logging & Audit Trail**

All actions are logged:

```python
action_logger.get_audit_trail('observation_20241205103015_a1b2c3d4')
# Returns:
[
    {
        'timestamp': '2024-12-05T10:30:15Z',
        'status': 'intercepted',
        'action_type': 'observation',
        'agent_id': 'router'
    },
    {
        'timestamp': '2024-12-05T10:30:16Z',
        'status': 'pending_approval',
        'approval_id': 'approval_xyz789'
    },
    {
        'timestamp': '2024-12-05T10:30:45Z',
        'status': 'approved',
        'approved_by': 'security_analyst_01',
        'reason': 'Confirmed threat - proceeding with investigation'
    },
    {
        'timestamp': '2024-12-05T10:30:46Z',
        'status': 'published',
        'message_bus_topic': 'agent.router.observations'
    }
]
```

## Complete Flow Summary

1. **Data Input** → Network traffic arrives
2. **Statistical Detection** → Baseline learning identifies anomaly
3. **LLM Analysis** → Threat analyzer determines if real threat
4. **Pattern Recognition** → Identifies attack sequence
5. **Guardrails** → Action requires user approval
6. **User Approval** → Security analyst reviews and approves
7. **Publish** → Observation sent to message bus
8. **Correlation** → Other agents detect related activity
9. **Knowledge Fusion** → Enriched with MITRE ATT&CK
10. **Notification** → User alerted to critical threat
11. **Audit Trail** → Complete log of all actions

## Key Benefits

- **Proactive**: Detects threats before full damage
- **Intelligent**: LLM provides context and reasoning
- **Controlled**: All actions require approval
- **Transparent**: Complete visibility and audit trail
- **Correlated**: Multi-agent detection for coordinated attacks




