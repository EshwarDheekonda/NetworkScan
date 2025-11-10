# Knowledge Fusion Module

A RAG-based module that fuses agent outputs with MITRE ATT&CK knowledge for contextual threat intelligence enrichment.

## Overview

The Knowledge Fusion module integrates structured agent observations with MITRE ATT&CK framework knowledge stored in Neo4j, using hybrid retrieval (graph + vector search) and LLM-based generation to produce enriched threat intelligence.

## Quick Start

### Basic Usage

```python
from knowledge_fusion.fusion_core import KnowledgeFusion
from knowledge_fusion.rag_pipeline import RAGPipeline
from knowledge_fusion.agent_interface import AgentInterface
from knowledge_fusion.interfaces import AgentOutput, Observation
from datetime import datetime

# 1. Create agent outputs
agent_interface = AgentInterface()

agent_data = {
    "agent_id": "router",
    "timestamp": datetime.now(),
    "observations": [{
        "type": "network",
        "description": "Suspicious outbound connection detected",
        "indicators": ["192.168.1.100", "malicious-domain.com"],
        "severity": "high"
    }],
    "confidence": 0.85
}

agent_output = agent_interface.normalize_agent_output(agent_data)

# 2. Run Knowledge Fusion
knowledge_fusion = KnowledgeFusion()
enriched = knowledge_fusion.fuse([agent_output])

# 3. Enhance with RAG
rag_pipeline = RAGPipeline()
enhanced = rag_pipeline.enhance_with_rag(enriched)
enhanced = rag_pipeline.add_explainability_attribution(enhanced)

# 4. Access results
print(f"Matched {len(enhanced.matched_mitre_techniques)} MITRE techniques")
print(f"Threat context: {enhanced.threat_context[:200]}...")
```

## Architecture

### Components

1. **Agent Interface** (`agent_interface.py`)
   - Normalizes and validates agent outputs
   - Supports router, computer, and email agents

2. **Retrieval Engine** (`retrieval_engine.py`)
   - Graph-based retrieval from Neo4j
   - Vector-based semantic search
   - Hybrid fusion algorithm

3. **Knowledge Fusion Core** (`fusion_core.py`)
   - Context assembly
   - Observation to MITRE mapping
   - Threat enrichment
   - Cross-agent correlation

4. **RAG Pipeline** (`rag_pipeline.py`)
   - LLM integration (OpenAI, Ollama, Anthropic)
   - Threat context generation
   - Explainability and attribution

## Configuration

### Environment Variables

```bash
# Neo4j (or use cred.json)
NEO4J_URI=bolt://localhost:7687

# LLM Configuration
OPENAI_API_KEY=your_key_here
LLM_PROVIDER=openai
LLM_MODEL=gpt-3.5-turbo
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=1000
```

### Configuration File

Create `cred.json`:
```json
{
    "username": "neo4j",
    "password": "your_password"
}
```

## Input Format

### Agent Output Schema

```python
AgentOutput {
    agent_id: str          # "router", "computer", or "email"
    timestamp: datetime
    observations: List[Observation]
    confidence: float      # 0.0 to 1.0
    metadata: dict
}

Observation {
    type: str              # Observation category
    description: str        # Detailed description
    indicators: List[str]   # IPs, domains, hashes, etc.
    severity: str          # "low", "medium", "high", "critical"
    metadata: dict
}
```

## Output Format

### Enriched Threat Intelligence

```python
EnrichedThreatIntelligence {
    original_observations: List[AgentOutput]
    matched_mitre_techniques: List[MITRETechnique]
    matched_mitre_tactics: List[MITRETactic]
    related_techniques: List[MITRETechnique]
    mitigations: List[Mitigation]
    threat_context: str                    # LLM-generated analysis
    confidence_scores: {
        "overall": float,
        "technique_matching": float,
        "tactic_matching": float,
        "agent_confidence": float,
        "correlation": float
    }
    attribution: {
        "retrieval_methods": List[str],
        "rag_generated": bool,
        "llm_provider": str,
        "technique_explanations": dict
    }
    timestamp: datetime
}
```

## Advanced Usage

### Custom Retrieval Configuration

```python
from knowledge_fusion.config import RetrievalConfig, get_config
from knowledge_fusion.retrieval_engine import HybridRetriever

# Custom retrieval weights
retrieval_config = RetrievalConfig(
    graph_weight=0.8,
    vector_weight=0.2,
    top_k_graph=15,
    top_k_vector=10,
    similarity_threshold=0.65
)

hybrid_retriever = HybridRetriever(config=retrieval_config)
```

### Using Different LLM Providers

```python
from knowledge_fusion.config import LLMConfig
from knowledge_fusion.rag_pipeline import LLMProvider

# OpenAI
openai_config = LLMConfig(
    provider="openai",
    model_name="gpt-4",
    api_key="your_key",
    temperature=0.3
)

# Ollama (local)
ollama_config = LLMConfig(
    provider="ollama",
    model_name="llama2",
    temperature=0.3
)

llm_provider = LLMProvider(config=openai_config)
rag_pipeline = RAGPipeline(llm_provider=llm_provider)
```

### Batch Processing

```python
# Process multiple agent outputs
agent_outputs = [router_output, computer_output, email_output]
enriched = knowledge_fusion.fuse(agent_outputs)
```

### Accessing Individual Components

```python
from knowledge_fusion.retrieval_engine import GraphRetriever, VectorRetriever
from knowledge_fusion.fusion_core import ContextAssembler

# Graph-only retrieval
graph_retriever = GraphRetriever()
techniques = graph_retriever.retrieve_by_keywords(["command", "control"], top_k=10)

# Vector-only retrieval
vector_retriever = VectorRetriever()
semantic_results = vector_retriever.retrieve_semantic("suspicious network activity", top_k=10)

# Context assembly
context_assembler = ContextAssembler()
context = context_assembler.assemble_technique_context(technique)
```

## Performance Optimization

### Caching

Embedding cache is enabled by default:
```python
from knowledge_fusion.mitre_embedder import MITREEmbedder

embedder = MITREEmbedder()
# First call: generates embedding
embedding1 = embedder.embed_text("command and control")

# Subsequent calls: uses cache
embedding2 = embedder.embed_text("command and control")  # Fast!
```

### Batch Embeddings

Use batch processing for multiple texts:
```python
texts = ["text1", "text2", "text3", ...]
embeddings = embedder.embed_batch(texts, batch_size=32)  # Faster than individual calls
```

## Error Handling

The module includes robust error handling:

- **LLM failures**: Automatically falls back to structured summaries
- **Neo4j connection**: Raises clear error messages
- **Validation**: Comprehensive output validation
- **Retries**: LLM calls retry up to 3 times

```python
# Validation
from knowledge_fusion.rag_pipeline import RAGPipeline

rag_pipeline = RAGPipeline()
validation = rag_pipeline.validate_output(enriched)

if not validation['valid']:
    print(f"Errors: {validation['errors']}")
if validation['warnings']:
    print(f"Warnings: {validation['warnings']}")
```

## Integration with Threat Scoring Module

The output is designed for direct integration:

```python
# Output is JSON-serializable
import json

json_output = json.dumps(enriched.model_dump(), default=str)

# All required fields for Threat Scoring Module
assert "matched_mitre_techniques" in enriched.model_dump()
assert "confidence_scores" in enriched.model_dump()
assert enriched.confidence_scores["overall"] is not None
```

## Troubleshooting

### Neo4j Connection Issues

```python
# Test connection
from py2neo import Graph
from knowledge_fusion.config import get_config

config = get_config()
graph = Graph(config.neo4j.uri, auth=(config.neo4j.username, config.neo4j.password))
result = graph.run("RETURN 1 as test").data()
print(f"Connected: {result[0]['test']}")
```

### LLM API Key Issues

```python
import os

# Check if API key is set
if not os.getenv("OPENAI_API_KEY"):
    print("Warning: OPENAI_API_KEY not set. LLM will use fallback mode.")
```

### Embedding Model Loading

```python
# Check if model loads correctly
from knowledge_fusion.mitre_embedder import MITREEmbedder

try:
    embedder = MITREEmbedder()
    print(f"Model loaded: {embedder.get_model_name()}")
except Exception as e:
    print(f"Model loading failed: {e}")
```

## Examples

See the module source code for comprehensive examples. The end-to-end flow demonstrates:

1. Agent output normalization
2. Knowledge fusion
3. RAG enhancement
4. Output validation

## Dependencies

See `requirements.txt` for full dependency list. Key dependencies:

- `py2neo`: Neo4j connectivity
- `sentence-transformers`: Embedding generation
- `langchain`: LLM orchestration
- `pydantic`: Schema validation
- `numpy`: Vector operations

## License

See project LICENSE file.


