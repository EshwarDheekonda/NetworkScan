"""
Configuration management for Knowledge Fusion module.

Handles environment variables, Neo4j connection, embedding model settings,
LLM configuration, and retrieval parameters.
"""

import os
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()


class Neo4jConfig(BaseModel):
    """Neo4j database configuration."""
    uri: str = Field(default="bolt://localhost:7687", description="Neo4j connection URI")
    username: str = Field(..., description="Neo4j username")
    password: str = Field(..., description="Neo4j password")
    
    @classmethod
    def from_cred_file(cls, cred_file: str = "cred.json") -> "Neo4jConfig":
        """Load Neo4j credentials from cred.json file."""
        import json
        cred_path = Path(cred_file)
        if cred_path.exists():
            with open(cred_path) as f:
                creds = json.load(f)
            return cls(
                uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
                username=creds.get("username"),
                password=creds.get("password")
            )
        raise FileNotFoundError(f"Credentials file not found: {cred_file}")


class EmbeddingConfig(BaseModel):
    """Embedding model configuration."""
    model_name: str = Field(default="sentence-transformers/all-MiniLM-L6-v2", description="Embedding model name")
    device: str = Field(default="cpu", description="Device to run model on (cpu/cuda)")
    batch_size: int = Field(default=32, description="Batch size for embedding generation")
    dimension: int = Field(default=384, description="Embedding dimension")


class LLMConfig(BaseModel):
    """LLM provider configuration."""
    model_config = {"protected_namespaces": ()}
    
    provider: str = Field(default="openai", description="LLM provider (openai, ollama, anthropic)")
    model_name: str = Field(default="gpt-3.5-turbo", description="LLM model name")
    api_key: Optional[str] = Field(default=None, description="API key for LLM provider")
    temperature: float = Field(default=0.3, ge=0.0, le=2.0, description="Temperature for generation")
    max_tokens: int = Field(default=1000, description="Maximum tokens in response")
    
    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Load LLM configuration from environment variables."""
        return cls(
            provider=os.getenv("LLM_PROVIDER", "openai"),
            model_name=os.getenv("LLM_MODEL", "gpt-3.5-turbo"),
            api_key=os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.3")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "1000"))
        )


class RetrievalConfig(BaseModel):
    """Retrieval engine configuration."""
    graph_weight: float = Field(default=0.7, ge=0.0, le=1.0, description="Weight for graph retrieval (hybrid mode)")
    vector_weight: float = Field(default=0.3, ge=0.0, le=1.0, description="Weight for vector retrieval (hybrid mode)")
    top_k_graph: int = Field(default=10, description="Number of top results from graph retrieval")
    top_k_vector: int = Field(default=10, description="Number of top results from vector retrieval")
    similarity_threshold: float = Field(default=0.6, ge=0.0, le=1.0, description="Minimum similarity threshold for vector search")
    
    def __post_init__(self):
        """Ensure weights sum to 1.0."""
        total_weight = self.graph_weight + self.vector_weight
        if total_weight != 1.0:
            # Normalize weights
            self.graph_weight = self.graph_weight / total_weight
            self.vector_weight = self.vector_weight / total_weight


class KnowledgeFusionConfig(BaseModel):
    """Main configuration class for Knowledge Fusion module."""
    neo4j: Neo4jConfig
    embedding: EmbeddingConfig = Field(default_factory=EmbeddingConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig.from_env)
    retrieval: RetrievalConfig = Field(default_factory=RetrievalConfig)
    vector_index_name: str = Field(default="mitre_techniques", description="Name of vector index in Neo4j")
    cache_enabled: bool = Field(default=True, description="Enable embedding cache")
    cache_dir: str = Field(default=".cache/knowledge_fusion", description="Directory for cache files")
    
    @classmethod
    def load(cls, cred_file: str = "cred.json") -> "KnowledgeFusionConfig":
        """Load complete configuration from files and environment."""
        return cls(
            neo4j=Neo4jConfig.from_cred_file(cred_file),
            embedding=EmbeddingConfig(),
            llm=LLMConfig.from_env(),
            retrieval=RetrievalConfig()
        )
    
    def validate(self):
        """Validate configuration settings."""
        # Ensure retrieval weights sum to 1.0
        total_weight = self.retrieval.graph_weight + self.retrieval.vector_weight
        if abs(total_weight - 1.0) > 0.01:
            raise ValueError(f"Retrieval weights must sum to 1.0, got {total_weight}")


# Global configuration instance (lazy loaded)
_config: Optional[KnowledgeFusionConfig] = None


def get_config(cred_file: str = "cred.json") -> KnowledgeFusionConfig:
    """Get or create global configuration instance."""
    global _config
    if _config is None:
        _config = KnowledgeFusionConfig.load(cred_file)
        _config.validate()
    return _config


def reset_config():
    """Reset global configuration (useful for testing)."""
    global _config
    _config = None
