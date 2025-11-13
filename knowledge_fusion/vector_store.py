"""
Vector database abstraction layer.

Handles extraction and chunking of MITRE content from Neo4j
for embedding and vector search.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import numpy as np
from py2neo import Graph

from knowledge_fusion.config import get_config
from knowledge_fusion.utils.graph_queries import GraphQueries
from knowledge_fusion.mitre_embedder import MITREEmbedder


@dataclass
class MITREContentChunk:
    """Represents a chunk of MITRE content ready for embedding."""
    content_type: str  # 'technique', 'tactic', 'mitigation'
    content_id: str
    external_id: Optional[str]
    name: str
    description: str
    text: str  # Combined text for embedding (name + description)
    metadata: Dict[str, Any]  # Additional context (tactics, relationships, etc.)
    embedding: Optional[np.ndarray] = None  # Vector embedding (added after generation)


class MITREContentExtractor:
    """Extracts and chunks MITRE content from Neo4j."""
    
    def __init__(self, graph: Optional[Graph] = None):
        """
        Initialize the extractor.
        
        Args:
            graph: Neo4j Graph instance. If None, creates connection from config.
        """
        if graph is None:
            config = get_config()
            self.graph = Graph(
                config.neo4j.uri,
                auth=(config.neo4j.username, config.neo4j.password)
            )
        else:
            self.graph = graph
        
        self.queries = GraphQueries()
    
    def extract_all_techniques(self) -> List[MITREContentChunk]:
        """
        Extract all techniques from Neo4j and chunk them.
        
        Returns:
            List of MITREContentChunk objects for techniques
        """
        query = self.queries.get_all_techniques()
        results = self.graph.run(query).data()
        
        chunks = []
        for record in results:
            # Combine name and description for embedding
            description = record.get("description", "") or ""
            name = record.get("name", "") or ""
            tactics = record.get("tactics", []) or []
            
            # Create searchable text
            text_parts = [name]
            if description:
                text_parts.append(description)
            
            # Add tactic context
            if tactics:
                text_parts.append(f"Associated with tactics: {', '.join([t for t in tactics if t])}")
            
            text = " ".join(text_parts)
            
            chunk = MITREContentChunk(
                content_type="technique",
                content_id=record.get("id", ""),
                external_id=record.get("external_id"),
                name=name,
                description=description,
                text=text,
                metadata={
                    "tactics": tactics,
                    "external_id": record.get("external_id")
                }
            )
            chunks.append(chunk)
        
        return chunks
    
    def extract_all_tactics(self) -> List[MITREContentChunk]:
        """
        Extract all tactics from Neo4j and chunk them.
        
        Returns:
            List of MITRECentChunk objects for tactics
        """
        query = self.queries.get_all_tactics()
        results = self.graph.run(query).data()
        
        chunks = []
        for record in results:
            name = record.get("name", "") or ""
            description = record.get("description", "") or ""
            
            # Create searchable text
            text_parts = [name]
            if description:
                text_parts.append(description)
            
            text = " ".join(text_parts)
            
            chunk = MITREContentChunk(
                content_type="tactic",
                content_id=name,  # Use name as ID for tactics
                external_id=None,
                name=name,
                description=description,
                text=text,
                metadata={}
            )
            chunks.append(chunk)
        
        return chunks
    
    def extract_all_mitigations(self) -> List[MITREContentChunk]:
        """
        Extract all mitigations from Neo4j and chunk them.
        
        Returns:
            List of MITREContentChunk objects for mitigations
        """
        query = self.queries.get_all_mitigations()
        results = self.graph.run(query).data()
        
        chunks = []
        for record in results:
            content_id = record.get("id", "")
            name = record.get("name", "") or ""
            description = record.get("description", "") or ""
            
            # Create searchable text
            text_parts = [name]
            if description:
                text_parts.append(description)
            
            text = " ".join(text_parts)
            
            chunk = MITREContentChunk(
                content_type="mitigation",
                content_id=content_id,
                external_id=None,
                name=name,
                description=description,
                text=text,
                metadata={}
            )
            chunks.append(chunk)
        
        return chunks
    
    def extract_all_content(self) -> Dict[str, List[MITREContentChunk]]:
        """
        Extract all MITRE content (techniques, tactics, mitigations).
        
        Returns:
            Dictionary with keys 'techniques', 'tactics', 'mitigations'
        """
        print("Extracting MITRE techniques...")
        techniques = self.extract_all_techniques()
        print(f"  Extracted {len(techniques)} techniques")
        
        print("Extracting MITRE tactics...")
        tactics = self.extract_all_tactics()
        print(f"  Extracted {len(tactics)} tactics")
        
        print("Extracting MITRE mitigations...")
        mitigations = self.extract_all_mitigations()
        print(f"  Extracted {len(mitigations)} mitigations")
        
        return {
            "techniques": techniques,
            "tactics": tactics,
            "mitigations": mitigations
        }
    
    def get_chunk_statistics(self, chunks: List[MITREContentChunk]) -> Dict[str, Any]:
        """
        Get statistics about extracted chunks.
        
        Args:
            chunks: List of content chunks
            
        Returns:
            Dictionary with statistics
        """
        if not chunks:
            return {
                "total": 0,
                "avg_text_length": 0,
                "with_description": 0,
                "with_embeddings": 0
            }
        
        text_lengths = [len(chunk.text) for chunk in chunks]
        with_description = sum(1 for chunk in chunks if chunk.description)
        with_embeddings = sum(1 for chunk in chunks if chunk.embedding is not None)
        
        stats = {
            "total": len(chunks),
            "avg_text_length": sum(text_lengths) / len(text_lengths) if text_lengths else 0,
            "min_text_length": min(text_lengths) if text_lengths else 0,
            "max_text_length": max(text_lengths) if text_lengths else 0,
            "with_description": with_description,
            "with_description_percent": (with_description / len(chunks)) * 100 if chunks else 0,
            "with_embeddings": with_embeddings,
            "with_embeddings_percent": (with_embeddings / len(chunks)) * 100 if chunks else 0
        }
        
        return stats


class MITREEmbeddingGenerator:
    """Generates embeddings for MITRE content chunks."""
    
    def __init__(self, embedder: Optional[MITREEmbedder] = None):
        """
        Initialize the embedding generator.
        
        Args:
            embedder: MITREEmbedder instance. If None, creates a new one.
        """
        if embedder is None:
            self.embedder = MITREEmbedder()
        else:
            self.embedder = embedder
    
    def generate_embeddings(self, chunks: List[MITREContentChunk], batch_size: Optional[int] = None) -> List[MITREContentChunk]:
        """
        Generate embeddings for a list of content chunks.
        
        Args:
            chunks: List of MITREContentChunk objects
            batch_size: Batch size for embedding generation
            
        Returns:
            List of chunks with embeddings populated
        """
        if not chunks:
            return chunks
        
        print(f"Generating embeddings for {len(chunks)} chunks...")
        
        # Extract texts for batch embedding
        texts = [chunk.text for chunk in chunks]
        
        # Generate embeddings in batches
        embeddings = self.embedder.embed_batch(texts, batch_size=batch_size)
        
        # Assign embeddings to chunks
        for i, chunk in enumerate(chunks):
            chunk.embedding = embeddings[i]
        
        print(f"  Generated {len([c for c in chunks if c.embedding is not None])} embeddings")
        
        return chunks
    
    def generate_embeddings_for_all_content(self, content: Dict[str, List[MITREContentChunk]]) -> Dict[str, List[MITREContentChunk]]:
        """
        Generate embeddings for all content types.
        
        Args:
            content: Dictionary with 'techniques', 'tactics', 'mitigations' keys
            
        Returns:
            Dictionary with embeddings populated in chunks
        """
        result = {}
        
        for content_type, chunks in content.items():
            print(f"\nGenerating embeddings for {content_type}...")
            result[content_type] = self.generate_embeddings(chunks)
        
        return result


class Neo4jVectorStore:
    """Manages vector embeddings in Neo4j for semantic search."""
    
    def __init__(self, graph: Optional[Graph] = None, index_name: str = "mitre_techniques"):
        """
        Initialize the vector store.
        
        Args:
            graph: Neo4j Graph instance. If None, creates connection from config.
            index_name: Name of the vector index to create/use.
        """
        if graph is None:
            config = get_config()
            self.graph = Graph(
                config.neo4j.uri,
                auth=(config.neo4j.username, config.neo4j.password)
            )
            self.index_name = config.vector_index_name
        else:
            self.graph = graph
            self.index_name = index_name
        
        self.embedding_dimension = 384  # From all-MiniLM-L6-v2
    
    def store_embeddings(self, chunks: List[MITREContentChunk], content_type: str):
        """
        Store embeddings in Neo4j nodes.
        
        Args:
            chunks: List of chunks with embeddings
            content_type: Type of content ('technique', 'tactic', 'mitigation')
        """
        if not chunks:
            return
        
        print(f"Storing {len(chunks)} {content_type} embeddings in Neo4j...")
        
        stored = 0
        for chunk in chunks:
            if chunk.embedding is None:
                continue
            
            # Convert numpy array to list for Neo4j
            embedding_list = chunk.embedding.tolist()
            
            # Update node with embedding based on content type
            if content_type == "technique":
                query = """
                MATCH (t:Technique {id: $content_id})
                SET t.embedding = $embedding,
                    t.embedding_text = $text,
                    t.embedding_name = $name
                RETURN t.id as id
                """
                params = {
                    "content_id": chunk.content_id,
                    "embedding": embedding_list,
                    "text": chunk.text,
                    "name": chunk.name
                }
            elif content_type == "tactic":
                query = """
                MATCH (t:Tactic {name: $content_id})
                SET t.embedding = $embedding,
                    t.embedding_text = $text,
                    t.embedding_name = $name
                RETURN t.name as name
                """
                params = {
                    "content_id": chunk.content_id,
                    "embedding": embedding_list,
                    "text": chunk.text,
                    "name": chunk.name
                }
            elif content_type == "mitigation":
                query = """
                MATCH (m:Mitigation {id: $content_id})
                SET m.embedding = $embedding,
                    m.embedding_text = $text,
                    m.embedding_name = $name
                RETURN m.id as id
                """
                params = {
                    "content_id": chunk.content_id,
                    "embedding": embedding_list,
                    "text": chunk.text,
                    "name": chunk.name
                }
            else:
                continue
            
            try:
                result = self.graph.run(query, params).data()
                if result:
                    stored += 1
            except Exception as e:
                print(f"  Warning: Failed to store embedding for {chunk.content_id}: {e}")
        
        print(f"  Stored {stored}/{len(chunks)} embeddings")
    
    def create_vector_index(self, node_label: str, property_name: str = "embedding", dimension: int = 384):
        """
        Create a vector index in Neo4j for similarity search.
        
        Note: Neo4j 5.x supports vector indexes using the 'db.index.vector' procedure.
        This requires Neo4j 5.11+ with vector index support.
        
        Args:
            node_label: Label of nodes to index (e.g., 'Technique')
            property_name: Property containing the vector (default: 'embedding')
            dimension: Dimension of the vectors (default: 384)
        """
        # Check if index already exists
        check_query = """
        SHOW INDEXES
        WHERE name = $index_name
        """
        existing = self.graph.run(check_query, {"index_name": self.index_name}).data()
        
        if existing:
            print(f"Vector index '{self.index_name}' already exists")
            return
        
        # Create vector index (Neo4j 5.11+ syntax)
        # Note: This may fail on older Neo4j versions that don't support vector indexes
        create_query = f"""
        CREATE VECTOR INDEX {self.index_name}
        IF NOT EXISTS
        FOR (n:{node_label})
        ON n.{property_name}
        OPTIONS {{
            indexConfig: {{
                `vector.dimensions`: {dimension},
                `vector.similarity_function`: 'cosine'
            }}
        }}
        """
        
        try:
            self.graph.run(create_query).data()
            print(f"[OK] Created vector index '{self.index_name}' for {node_label}")
        except Exception as e:
            print(f"[WARNING] Could not create vector index (Neo4j version may not support it): {e}")
            print("  Falling back to manual cosine similarity search")
    
    def search_similar(self, query_embedding: np.ndarray, node_label: str, top_k: int = 10, threshold: float = 0.6) -> List[Dict[str, Any]]:
        """
        Search for similar nodes using vector similarity.
        
        Uses cosine similarity if vector index is available, otherwise manual calculation.
        
        Args:
            query_embedding: Query embedding vector
            node_label: Label of nodes to search (e.g., 'Technique')
            top_k: Number of results to return
            threshold: Minimum similarity threshold
            
        Returns:
            List of dictionaries with node data and similarity scores
        """
        query_embedding_list = query_embedding.tolist()
        
        # Try using vector index first (Neo4j 5.11+)
        vector_index_query = f"""
        CALL db.index.vector.queryNodes(
            '{self.index_name}',
            {top_k},
            $query_embedding
        )
        YIELD node, score
        WHERE node:{node_label} AND score >= $threshold
        RETURN node.id as id,
               node.name as name,
               node.description as description,
               node.external_id as external_id,
               node.embedding_text as text,
               score as similarity
        ORDER BY score DESC
        LIMIT {top_k}
        """
        
        try:
            results = self.graph.run(vector_index_query, {
                "query_embedding": query_embedding_list,
                "threshold": threshold
            }).data()
            
            if results:
                return results
        except Exception as e:
            # Fallback to manual cosine similarity if index doesn't exist
            print(f"  Vector index search failed, using manual similarity: {e}")
        
        # Manual cosine similarity calculation
        manual_query = f"""
        MATCH (n:{node_label})
        WHERE n.embedding IS NOT NULL
        WITH n, n.embedding as embedding
        WITH n, embedding,
             reduce(s = 0.0, i in range(0, size(embedding)-1) | 
               s + embedding[i] * $query_embedding[i]) as dot_product
        WITH n, dot_product,
             reduce(s = 0.0, i in range(0, size(embedding)-1) | 
               s + embedding[i] * embedding[i]) as embedding_norm,
             reduce(s = 0.0, i in range(0, size($query_embedding)-1) | 
               s + $query_embedding[i] * $query_embedding[i]) as query_norm
        WITH n, dot_product / (sqrt(embedding_norm) * sqrt(query_norm)) as similarity
        WHERE similarity >= $threshold
        RETURN n.id as id,
               n.name as name,
               n.description as description,
               n.external_id as external_id,
               n.embedding_text as text,
               similarity
        ORDER BY similarity DESC
        LIMIT {top_k}
        """
        
        try:
            results = self.graph.run(manual_query, {
                "query_embedding": query_embedding_list,
                "threshold": threshold
            }).data()
            return results
        except Exception as e:
            print(f"  Manual similarity search failed: {e}")
            return []
