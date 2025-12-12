# System Architecture Flowchart

This document contains visual flowcharts showing how the modern AI-powered security agent system works.

## Main System Flow

```mermaid
graph TB
    Start([Data Input]) --> Router[Router LLM Agent]
    Start --> Computer[Computer LLM Agent]
    Start --> Email[Email LLM Agent]
    
    Router --> Baseline1[Statistical Baseline<br/>Learning]
    Computer --> Baseline2[Statistical Baseline<br/>Learning]
    Email --> Baseline3[Statistical Baseline<br/>Learning]
    
    Baseline1 --> Anomaly1{Anomaly<br/>Detected?}
    Baseline2 --> Anomaly2{Anomaly<br/>Detected?}
    Baseline3 --> Anomaly3{Anomaly<br/>Detected?}
    
    Anomaly1 -->|Yes| LLM1[LLM Threat Analyzer]
    Anomaly2 -->|Yes| LLM2[LLM Threat Analyzer]
    Anomaly3 -->|Yes| LLM3[LLM Threat Analyzer]
    
    Anomaly1 -->|No| Learn1[Update Baseline]
    Anomaly2 -->|No| Learn2[Update Baseline]
    Anomaly3 -->|No| Learn3[Update Baseline]
    
    LLM1 --> Pattern1[Pattern Recognizer]
    LLM2 --> Pattern2[Pattern Recognizer]
    LLM3 --> Pattern3[Pattern Recognizer]
    
    Pattern1 --> Guard1[Action Guardrails]
    Pattern2 --> Guard2[Action Guardrails]
    Pattern3 --> Guard3[Action Guardrails]
    
    Guard1 --> Approval1{User<br/>Approval}
    Guard2 --> Approval2{User<br/>Approval}
    Guard3 --> Approval3{User<br/>Approval}
    
    Approval1 -->|Approved| Publish1[Publish to<br/>Message Bus]
    Approval2 -->|Approved| Publish2[Publish to<br/>Message Bus]
    Approval3 -->|Approved| Publish3[Publish to<br/>Message Bus]
    
    Approval1 -->|Rejected| Log1[Log Action]
    Approval2 -->|Rejected| Log2[Log Action]
    Approval3 -->|Rejected| Log3[Log Action]
    
    Publish1 --> Correlation[Cross-Agent<br/>Correlation]
    Publish2 --> Correlation
    Publish3 --> Correlation
    
    Correlation --> KnowledgeFusion[Knowledge Fusion<br/>+ MITRE ATT&CK]
    
    KnowledgeFusion --> Enriched[Enriched Threat<br/>Intelligence]
    
    Enriched --> Dashboard[Action Dashboard]
    Enriched --> Notification[Notification System]
    Enriched --> Telemetry[Telemetry Collector]
    
    Dashboard --> End([User View])
    Notification --> End
    Telemetry --> End
    
    style Start fill:#e1f5ff
    style End fill:#e1f5ff
    style Guard1 fill:#fff4e1
    style Guard2 fill:#fff4e1
    style Guard3 fill:#fff4e1
    style Approval1 fill:#ffe1e1
    style Approval2 fill:#ffe1e1
    style Approval3 fill:#ffe1e1
    style KnowledgeFusion fill:#e1ffe1
    style Enriched fill:#e1ffe1
```

## Agent Processing Flow (Detailed)

```mermaid
graph LR
    A[Raw Data] --> B[Extract Features]
    B --> C[Update Baselines]
    C --> D[Calculate Anomaly Scores]
    D --> E{Max Score ><br/>Threshold?}
    
    E -->|No| F[Continue Learning]
    E -->|Yes| G[Generate Initial<br/>Observation]
    
    G --> H[Build Context]
    H --> I[LLM Threat Analysis]
    I --> J{Is Real<br/>Threat?}
    
    J -->|No| F
    J -->|Yes| K[Pattern Recognition]
    
    K --> L[Enhance Observation<br/>with LLM Analysis]
    L --> M[Action Guardrails]
    M --> N{Requires<br/>Approval?}
    
    N -->|Yes| O[Queue for Approval]
    N -->|No| P[Publish Observation]
    
    O --> Q{User<br/>Approves?}
    Q -->|Yes| P
    Q -->|No| R[Log Rejection]
    
    P --> S[Message Bus]
    S --> T[Knowledge Fusion]
    
    style A fill:#e1f5ff
    style I fill:#fff4e1
    style K fill:#fff4e1
    style M fill:#ffe1e1
    style Q fill:#ffe1e1
    style T fill:#e1ffe1
```

## Guardrails & Approval Flow

```mermaid
graph TB
    Action[Agent Action] --> Intercept[Action Guard<br/>Intercepts]
    Intercept --> Policy[Policy Engine<br/>Check]
    
    Policy --> Blocked{Blocked by<br/>Policy?}
    Blocked -->|Yes| LogBlock[Log Blocked Action]
    Blocked -->|No| Approval{Requires<br/>Approval?}
    
    Approval -->|No| Allow[Allow Action]
    Approval -->|Yes| Queue[Queue for Approval]
    
    Queue --> Dashboard[Show in Dashboard]
    Dashboard --> User[User Reviews]
    
    User --> Decision{User<br/>Decision}
    Decision -->|Approve| Approve[Approve Action]
    Decision -->|Reject| Reject[Reject Action]
    
    Approve --> Execute[Execute Action]
    Reject --> LogReject[Log Rejection]
    
    Execute --> Publish[Publish/Execute]
    LogBlock --> Audit[Audit Trail]
    LogReject --> Audit
    Publish --> Audit
    
    Audit --> Complete([Complete])
    
    style Action fill:#e1f5ff
    style Intercept fill:#fff4e1
    style Policy fill:#fff4e1
    style Blocked fill:#ffe1e1
    style Approval fill:#ffe1e1
    style Decision fill:#ffe1e1
    style Audit fill:#e1ffe1
```

## Cross-Agent Correlation Flow

```mermaid
graph TB
    Router[Router Agent<br/>Observation] --> Bus[Message Bus]
    Computer[Computer Agent<br/>Observation] --> Bus
    Email[Email Agent<br/>Observation] --> Bus
    
    Bus --> Extract[Extract Indicators]
    Extract --> Compare[Compare Indicators<br/>Across Agents]
    
    Compare --> Common{Common<br/>Indicators?}
    
    Common -->|Yes| Correlate[Correlation Detected]
    Common -->|No| Separate[Separate Events]
    
    Correlate --> Context[Build Shared Context]
    Context --> Fusion[Knowledge Fusion]
    
    Separate --> Fusion
    
    Fusion --> MITRE[MITRE ATT&CK<br/>Enrichment]
    MITRE --> Enriched[Enriched Intelligence]
    
    Enriched --> Notify[Notification System]
    Enriched --> Dashboard[Dashboard Update]
    
    Notify --> User([User Alerted])
    Dashboard --> User
    
    style Router fill:#e1f5ff
    style Computer fill:#e1f5ff
    style Email fill:#e1f5ff
    style Correlate fill:#fff4e1
    style Fusion fill:#e1ffe1
    style Enriched fill:#e1ffe1
```

## LLM Reasoning Flow

```mermaid
graph TB
    Observation[Observation from<br/>Statistical Detection] --> Context[Context Builder]
    
    Context --> Historical[Historical Context]
    Context --> Temporal[Temporal Patterns]
    Context --> Correlation[Cross-Agent Correlation]
    Context --> MITRE[MITRE Context]
    
    Historical --> Threat[Threat Analyzer]
    Temporal --> Threat
    Correlation --> Threat
    MITRE --> Threat
    
    Threat --> LLM1[LLM Analysis]
    LLM1 --> Analysis{Is Real<br/>Threat?}
    
    Analysis -->|No| Filter[Filter Out]
    Analysis -->|Yes| Pattern[Pattern Recognizer]
    
    Pattern --> LLM2[LLM Pattern Analysis]
    LLM2 --> Sequence[Attack Sequence]
    LLM2 --> Predict[Predict Next Steps]
    
    Sequence --> Enhance[Enhance Observation]
    Predict --> Enhance
    
    Enhance --> Final[Final Observation<br/>with LLM Reasoning]
    
    style Observation fill:#e1f5ff
    style LLM1 fill:#fff4e1
    style LLM2 fill:#fff4e1
    style Analysis fill:#ffe1e1
    style Final fill:#e1ffe1
```

## Observability & Monitoring Flow

```mermaid
graph TB
    Agents[All Agents] --> Monitor[Agent Monitor]
    Guardrails[Action Guardrails] --> Monitor
    MessageBus[Message Bus] --> Telemetry[Telemetry Collector]
    LLMCalls[LLM API Calls] --> Telemetry
    
    Monitor --> Dashboard[Action Dashboard]
    Guardrails --> Dashboard
    Telemetry --> Dashboard
    
    Dashboard --> Display[Real-Time Display]
    
    Guardrails --> Notify[Notification System]
    Critical[Critical Threats] --> Notify
    
    Notify --> Alert[User Alerts]
    Display --> View[User View]
    Alert --> View
    
    Monitor --> Stats[Statistics]
    Telemetry --> Stats
    Stats --> View
    
    style Agents fill:#e1f5ff
    style Monitor fill:#fff4e1
    style Telemetry fill:#fff4e1
    style Dashboard fill:#e1ffe1
    style Notify fill:#ffe1e1
    style View fill:#e1f5ff
```

## Complete System Architecture

```mermaid
graph TB
    subgraph "Data Sources"
        Network[Network Traffic]
        Logs[System Logs]
        Emails[Email Traffic]
    end
    
    subgraph "LLM-Powered Agents"
        Router[Router LLM Agent]
        Computer[Computer LLM Agent]
        Email[Email LLM Agent]
    end
    
    subgraph "Reasoning Layer"
        Threat[Threat Analyzer]
        Pattern[Pattern Recognizer]
        Context[Context Builder]
    end
    
    subgraph "Guardrails"
        Guard[Action Guard]
        Policy[Policy Engine]
        Approval[Approval Manager]
        Logger[Action Logger]
    end
    
    subgraph "Communication"
        Bus[Message Bus]
        RouterMsg[LLM Router]
        Collab[Agent Collaboration]
    end
    
    subgraph "Knowledge Fusion"
        Fusion[Knowledge Fusion]
        RAG[RAG Pipeline]
        MITRE[MITRE ATT&CK DB]
    end
    
    subgraph "Observability"
        Monitor[Agent Monitor]
        Dashboard[Action Dashboard]
        Telemetry[Telemetry]
        Notify[Notifications]
    end
    
    Network --> Router
    Logs --> Computer
    Emails --> Email
    
    Router --> Threat
    Computer --> Threat
    Email --> Threat
    
    Threat --> Pattern
    Pattern --> Context
    
    Router --> Guard
    Computer --> Guard
    Email --> Guard
    
    Guard --> Policy
    Guard --> Approval
    Guard --> Logger
    
    Router --> Bus
    Computer --> Bus
    Email --> Bus
    
    Bus --> RouterMsg
    RouterMsg --> Collab
    
    Bus --> Fusion
    Fusion --> RAG
    RAG --> MITRE
    
    Router --> Monitor
    Computer --> Monitor
    Email --> Monitor
    
    Guard --> Dashboard
    Monitor --> Dashboard
    Telemetry --> Dashboard
    
    Approval --> Notify
    Fusion --> Notify
    
    style Router fill:#e1f5ff
    style Computer fill:#e1f5ff
    style Email fill:#e1f5ff
    style Threat fill:#fff4e1
    style Pattern fill:#fff4e1
    style Guard fill:#ffe1e1
    style Fusion fill:#e1ffe1
    style Dashboard fill:#e1ffe1
```




