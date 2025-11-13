"""
Input/output schemas (Pydantic models) for Knowledge Fusion module.

Defines standardized data structures for:
- Agent outputs (input to Knowledge Fusion)
- Enriched threat intelligence (output to Threat Scoring Module)
"""

from datetime import datetime
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, ConfigDict


class Observation(BaseModel):
    """Represents a single observation from an agent."""
    model_config = ConfigDict(frozen=False)
    
    type: str = Field(..., description="Type/category of observation")
    description: str = Field(..., description="Detailed description of the observation")
    indicators: List[str] = Field(default_factory=list, description="List of indicators (IPs, domains, hashes, etc.)")
    severity: str = Field(..., description="Severity level (low, medium, high, critical)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata about the observation")


class AgentOutput(BaseModel):
    """Standardized format for agent outputs (Router, Computer, Email agents)."""
    model_config = ConfigDict(frozen=False)
    
    agent_id: str = Field(..., description="Agent identifier (router, computer, email)")
    timestamp: datetime = Field(..., description="Timestamp when observation was made")
    observations: List[Observation] = Field(..., description="List of observations from the agent")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence score (0.0 to 1.0)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional agent-specific metadata")


class MITRETechnique(BaseModel):
    """Represents a MITRE ATT&CK technique."""
    model_config = ConfigDict(frozen=False)
    
    id: str = Field(..., description="MITRE technique ID (e.g., T1059.003)")
    external_id: Optional[str] = Field(None, description="External ID from MITRE")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    tactic: Optional[str] = Field(None, description="Associated tactic name")
    score: float = Field(..., ge=0.0, le=1.0, description="Relevance score for this observation")


class MITRETactic(BaseModel):
    """Represents a MITRE ATT&CK tactic."""
    model_config = ConfigDict(frozen=False)
    
    name: str = Field(..., description="Tactic name (e.g., 'Execution', 'Persistence')")
    description: Optional[str] = Field(None, description="Tactic description")
    score: float = Field(..., ge=0.0, le=1.0, description="Relevance score for this observation")


class Mitigation(BaseModel):
    """Represents a MITRE ATT&CK mitigation strategy."""
    model_config = ConfigDict(frozen=False)
    
    id: str = Field(..., description="Mitigation ID")
    name: str = Field(..., description="Mitigation name")
    description: str = Field(..., description="Mitigation description")
    techniques: List[str] = Field(default_factory=list, description="List of technique IDs this mitigates")


class EnrichedThreatIntelligence(BaseModel):
    """Output schema for enriched threat intelligence sent to Threat Scoring Module."""
    model_config = ConfigDict(frozen=False)
    
    original_observations: List[AgentOutput] = Field(..., description="Original agent outputs that were analyzed")
    matched_mitre_techniques: List[MITRETechnique] = Field(default_factory=list, description="Matched MITRE techniques")
    matched_mitre_tactics: List[MITRETactic] = Field(default_factory=list, description="Matched MITRE tactics")
    related_techniques: List[MITRETechnique] = Field(default_factory=list, description="Related techniques via graph relationships")
    mitigations: List[Mitigation] = Field(default_factory=list, description="Recommended mitigation strategies")
    threat_context: str = Field(..., description="LLM-generated contextual threat analysis")
    confidence_scores: Dict[str, float] = Field(default_factory=dict, description="Confidence scores for different aspects")
    attribution: Dict[str, Any] = Field(default_factory=dict, description="Traceability information (source MITRE knowledge, retrieval methods)")
    timestamp: datetime = Field(default_factory=datetime.now, description="Timestamp when enrichment was performed")
