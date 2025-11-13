"""
MITRE content embedding generation.

Handles loading embedding models and generating embeddings for MITRE ATT&CK content.
Uses sentence-transformers with a model abstraction layer for easy swapping.
"""

from typing import List, Union, Optional
import numpy as np
from sentence_transformers import SentenceTransformer

from knowledge_fusion.config import EmbeddingConfig, get_config


class MITREEmbedder:
    """Generates embeddings for MITRE ATT&CK content using sentence-transformers."""
    
    def __init__(self, config: Optional[EmbeddingConfig] = None):
        """
        Initialize the embedder with configuration.
        
        Args:
            config: EmbeddingConfig object. If None, uses default config.
        """
        if config is None:
            config = get_config().embedding
        
        self.config = config
        self.model: Optional[SentenceTransformer] = None
        self._load_model()
    
    def _load_model(self):
        """Load the sentence-transformers model."""
        try:
            print(f"Loading embedding model: {self.config.model_name}")
            self.model = SentenceTransformer(
                self.config.model_name,
                device=self.config.device
            )
            print(f"[OK] Model loaded successfully on {self.config.device}")
        except Exception as e:
            raise RuntimeError(f"Failed to load embedding model: {e}")
    
    def embed_text(self, text: str, use_cache: bool = True) -> np.ndarray:
        """
        Generate embedding for a single text string.
        
        Args:
            text: Input text to embed
            use_cache: Whether to use LRU cache (default: True)
            
        Returns:
            NumPy array of embeddings (shape: [dimension])
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        if not text or not text.strip():
            # Return zero vector for empty text
            return np.zeros(self.config.dimension)
        
        # Use caching for repeated queries
        if use_cache:
            cache_key = f"embed_{hash(text)}"
            if not hasattr(self, '_embed_cache'):
                self._embed_cache = {}
            
            if cache_key in self._embed_cache:
                return self._embed_cache[cache_key]
        
        embedding = self.model.encode(
            text,
            convert_to_numpy=True,
            show_progress_bar=False
        )
        
        if use_cache and hasattr(self, '_embed_cache'):
            # Limit cache size to prevent memory issues
            if len(self._embed_cache) < 1000:
                self._embed_cache[cache_key] = embedding
        
        return embedding
    
    def embed_batch(self, texts: List[str], batch_size: Optional[int] = None) -> np.ndarray:
        """
        Generate embeddings for a batch of texts.
        
        Args:
            texts: List of text strings to embed
            batch_size: Batch size for processing. If None, uses config default.
            
        Returns:
            NumPy array of embeddings (shape: [num_texts, dimension])
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        if not texts:
            return np.array([]).reshape(0, self.config.dimension)
        
        # Filter out empty texts
        non_empty_texts = [t if t and t.strip() else "" for t in texts]
        
        batch_size = batch_size or self.config.batch_size
        
        embeddings = self.model.encode(
            non_empty_texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=True
        )
        
        return embeddings
    
    def embed_query(self, query: str) -> np.ndarray:
        """
        Generate embedding for a search query.
        Same as embed_text, but with semantic naming for clarity.
        
        Args:
            query: Search query text
            
        Returns:
            NumPy array of embeddings (shape: [dimension])
        """
        return self.embed_text(query)
    
    def get_dimension(self) -> int:
        """Get the embedding dimension."""
        return self.config.dimension
    
    def get_model_name(self) -> str:
        """Get the model name."""
        return self.config.model_name
