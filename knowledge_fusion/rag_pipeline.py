"""
RAG generation orchestration pipeline.

Implements the RAG (Retrieval-Augmented Generation) pipeline that:
- Generates contextual threat analysis using LLMs
- Integrates with multiple LLM providers (OpenAI, Ollama, etc.)
- Provides structured output generation
- Handles errors and fallbacks gracefully
"""

from typing import List, Dict, Any, Optional, Callable
import os
import time
from langchain.llms.base import BaseLLM
from langchain_openai import ChatOpenAI
try:
    from langchain_core.messages import HumanMessage, SystemMessage
except ImportError:
    from langchain.schema import HumanMessage, SystemMessage

from knowledge_fusion.config import get_config, LLMConfig
from knowledge_fusion.interfaces import (
    AgentOutput, EnrichedThreatIntelligence,
    MITRETechnique, MITRETactic, Mitigation
)
from knowledge_fusion.utils.prompt_templates import PromptTemplates


class LLMProvider:
    """LLM provider abstraction layer."""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Initialize LLM provider.
        
        Args:
            config: LLMConfig object. If None, loads from environment.
        """
        if config is None:
            self.config = get_config().llm
        else:
            self.config = config
        
        self.llm: Optional[BaseLLM] = None
        self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize the LLM based on provider configuration."""
        provider = self.config.provider.lower()
        
        if provider == "openai":
            api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable or configure in LLMConfig.")
            
            self.llm = ChatOpenAI(
                model_name=self.config.model_name,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                openai_api_key=api_key
            )
            print(f"[OK] Initialized OpenAI LLM: {self.config.model_name}")
        
        elif provider == "ollama":
            # Ollama integration (for local testing)
            try:
                from langchain_community.llms import Ollama
                self.llm = Ollama(
                    model=self.config.model_name,
                    temperature=self.config.temperature
                )
                print(f"[OK] Initialized Ollama LLM: {self.config.model_name}")
            except ImportError:
                raise ImportError("langchain_community not installed. Install with: pip install langchain-community")
        
        elif provider == "anthropic":
            # Anthropic Claude integration
            try:
                from langchain_anthropic import ChatAnthropic
                api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
                if not api_key:
                    raise ValueError("Anthropic API key not found.")
                
                self.llm = ChatAnthropic(
                    model=self.config.model_name,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                    anthropic_api_key=api_key
                )
                print(f"[OK] Initialized Anthropic LLM: {self.config.model_name}")
            except ImportError:
                raise ImportError("langchain-anthropic not installed. Install with: pip install langchain-anthropic")
        
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
    
    def generate(
        self, 
        prompt: str, 
        system_message: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0
    ) -> str:
        """
        Generate text using the LLM with retry logic.
        
        Args:
            prompt: User prompt/query
            system_message: Optional system message for context
            max_retries: Maximum number of retry attempts
            retry_delay: Delay between retries in seconds
            
        Returns:
            Generated text response
            
        Raises:
            RuntimeError: If generation fails after retries
        """
        if self.llm is None:
            raise RuntimeError("LLM not initialized")
        
        last_error = None
        for attempt in range(max_retries):
            try:
                messages = []
                if system_message:
                    messages.append(SystemMessage(content=system_message))
                messages.append(HumanMessage(content=prompt))
                
                # Use invoke instead of __call__ (LangChain 0.1.7+)
                if hasattr(self.llm, 'invoke'):
                    response = self.llm.invoke(messages)
                else:
                    response = self.llm(messages)
                
                # Handle different response types
                if hasattr(response, 'content'):
                    return response.content
                elif isinstance(response, str):
                    return response
                else:
                    return str(response)
            
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    print(f"[WARNING] LLM generation attempt {attempt + 1} failed: {e}. Retrying...")
                    time.sleep(retry_delay)
                else:
                    raise RuntimeError(f"LLM generation failed after {max_retries} attempts: {e}")
        
        raise RuntimeError(f"LLM generation failed: {last_error}")
    
    def generate_with_fallback(self, prompt: str, system_message: Optional[str] = None, fallback: str = "") -> str:
        """
        Generate text with fallback on error.
        
        Args:
            prompt: User prompt/query
            system_message: Optional system message
            fallback: Fallback text if generation fails
            
        Returns:
            Generated text or fallback
        """
        try:
            return self.generate(prompt, system_message)
        except Exception as e:
            print(f"[WARNING] LLM generation failed, using fallback: {e}")
            return fallback


class RAGPipeline:
    """Main RAG pipeline for threat intelligence synthesis."""
    
    def __init__(
        self,
        llm_provider: Optional[LLMProvider] = None,
        prompt_templates: Optional[PromptTemplates] = None
    ):
        """
        Initialize the RAG pipeline.
        
        Args:
            llm_provider: LLMProvider instance. If None, creates a new one.
            prompt_templates: PromptTemplates instance. If None, creates a new one.
        """
        self.llm_provider = llm_provider or LLMProvider()
        self.prompt_templates = prompt_templates or PromptTemplates()
        self.enable_fallback = True
        self.fallback_context = "Threat intelligence analysis generated from MITRE ATT&CK framework matching."
    
    def generate_threat_context(
        self,
        enriched_intelligence: EnrichedThreatIntelligence
    ) -> str:
        """
        Generate contextual threat analysis from enriched intelligence.
        
        Args:
            enriched_intelligence: EnrichedThreatIntelligence object
            
        Returns:
            Generated threat context string
        """
        # Build prompt
        prompt = self.prompt_templates.threat_analysis_prompt(
            agent_outputs=enriched_intelligence.original_observations,
            matched_techniques=enriched_intelligence.matched_mitre_techniques,
            matched_tactics=enriched_intelligence.matched_mitre_tactics,
            related_techniques=enriched_intelligence.related_techniques,
            mitigations=enriched_intelligence.mitigations,
            confidence_scores=enriched_intelligence.confidence_scores
        )
        
        # System message
        system_message = """You are an expert cybersecurity threat intelligence analyst specializing in MITRE ATT&CK framework analysis. 
Your role is to provide clear, actionable, and technically accurate threat assessments based on security observations and MITRE ATT&CK mappings."""
        
        # Generate
        if self.enable_fallback:
            threat_context = self.llm_provider.generate_with_fallback(
                prompt,
                system_message,
                fallback=self._generate_fallback_context(enriched_intelligence)
            )
        else:
            threat_context = self.llm_provider.generate(prompt, system_message)
        
        return threat_context
    
    def generate_explainability(
        self,
        technique: MITRETechnique,
        observation: Any,
        score: float
    ) -> str:
        """
        Generate explainability text for why a technique was matched.
        
        Args:
            technique: Matched MITRE technique
            observation: Agent observation
            score: Relevance score
            
        Returns:
            Explanation text
        """
        prompt = self.prompt_templates.explainability_prompt(technique, observation, score)
        
        system_message = "You are a cybersecurity analyst explaining MITRE ATT&CK technique matches. Provide clear, concise explanations."
        
        if self.enable_fallback:
            explanation = self.llm_provider.generate_with_fallback(
                prompt,
                system_message,
                fallback=f"Technique {technique.name} matched with relevance score {score:.2f} based on observation characteristics."
            )
        else:
            explanation = self.llm_provider.generate(prompt, system_message)
        
        return explanation
    
    def _generate_fallback_context(self, enriched: EnrichedThreatIntelligence) -> str:
        """Generate a basic fallback context when LLM is unavailable."""
        techniques_summary = ", ".join([
            f"{tech.name} ({tech.external_id})" 
            for tech in enriched.matched_mitre_techniques[:3]
            if tech.external_id
        ])
        
        tactics_summary = ", ".join([t.name for t in enriched.matched_mitre_tactics[:3]])
        
        fallback = f"""THREAT ANALYSIS SUMMARY

Based on security observations from {len(enriched.original_observations)} agent(s), the following MITRE ATT&CK techniques were identified: {techniques_summary or 'Multiple techniques detected'}.

Primary tactics involved: {tactics_summary or 'Multiple tactics detected'}.

Confidence Score: {enriched.confidence_scores.get('overall', 0):.2f}

RECOMMENDED ACTIONS:
1. Review matched MITRE techniques for attack patterns
2. Implement suggested mitigations
3. Monitor related indicators across network
4. Correlate with other security events

[Note: Detailed LLM analysis unavailable. This is a fallback summary.]"""
        
        return fallback
    
    def enhance_with_rag(
        self,
        enriched_intelligence: EnrichedThreatIntelligence,
        generate_context: bool = True
    ) -> EnrichedThreatIntelligence:
        """
        Enhance enriched threat intelligence with RAG-generated context.
        
        Args:
            enriched_intelligence: EnrichedThreatIntelligence object (may have placeholder context)
            generate_context: Whether to generate new context or use existing
            
        Returns:
            Enhanced EnrichedThreatIntelligence with LLM-generated context
        """
        # Check if context needs generation
        if generate_context or not enriched_intelligence.threat_context or enriched_intelligence.threat_context.startswith("[LLM"):
            try:
                threat_context = self.generate_threat_context(enriched_intelligence)
                enriched_intelligence.threat_context = threat_context
                
                # Update attribution to include RAG generation
                enriched_intelligence.attribution["rag_generated"] = True
                enriched_intelligence.attribution["llm_provider"] = self.llm_provider.config.provider
                enriched_intelligence.attribution["llm_model"] = self.llm_provider.config.model_name
            except Exception as e:
                print(f"[WARNING] RAG generation failed: {e}")
                if not enriched_intelligence.threat_context:
                    enriched_intelligence.threat_context = self._generate_fallback_context(enriched_intelligence)
                enriched_intelligence.attribution["rag_generated"] = False
                enriched_intelligence.attribution["rag_error"] = str(e)
        
        return enriched_intelligence
    
    def add_explainability_attribution(
        self,
        enriched_intelligence: EnrichedThreatIntelligence
    ) -> EnrichedThreatIntelligence:
        """
        Add explainability and attribution information to enriched intelligence.
        
        Args:
            enriched_intelligence: EnrichedThreatIntelligence object
            
        Returns:
            Enhanced object with explainability metadata
        """
        # Add technique matching explanations
        technique_explanations = {}
        for tech in enriched_intelligence.matched_mitre_techniques[:5]:  # Top 5 only
            # Find matching observation
            for agent_output in enriched_intelligence.original_observations:
                for obs in agent_output.observations:
                    # Generate simple explanation
                    explanation = f"Matched based on observation type '{obs.type}' and relevance score {tech.score:.2f}"
                    technique_explanations[tech.id] = explanation
                    break
                if tech.id in technique_explanations:
                    break
        
        # Add attribution details
        enriched_intelligence.attribution["technique_explanations"] = technique_explanations
        enriched_intelligence.attribution["explainability_method"] = "hybrid_retrieval"
        enriched_intelligence.attribution["retrieval_weights"] = {
            "graph": 0.7,
            "vector": 0.3
        }
        
        # Add MITRE source attribution
        enriched_intelligence.attribution["mitre_source"] = "MITRE ATT&CK Framework"
        enriched_intelligence.attribution["mitre_version"] = "Enterprise (from Neo4j)"
        
        return enriched_intelligence
    
    def validate_output(self, enriched_intelligence: EnrichedThreatIntelligence) -> Dict[str, Any]:
        """
        Validate the enriched threat intelligence output.
        
        Args:
            enriched_intelligence: EnrichedThreatIntelligence object
            
        Returns:
            Dictionary with validation results
        """
        validation_results = {
            "valid": True,
            "warnings": [],
            "errors": []
        }
        
        # Check required fields
        if not enriched_intelligence.original_observations:
            validation_results["valid"] = False
            validation_results["errors"].append("No original observations")
        
        if not enriched_intelligence.threat_context or enriched_intelligence.threat_context.strip() == "":
            validation_results["warnings"].append("Threat context is empty")
        
        # Check MITRE matches
        if not enriched_intelligence.matched_mitre_techniques:
            validation_results["warnings"].append("No MITRE techniques matched")
        
        if not enriched_intelligence.matched_mitre_tactics:
            validation_results["warnings"].append("No MITRE tactics matched")
        
        # Check confidence scores
        if enriched_intelligence.confidence_scores.get("overall", 0) < 0.3:
            validation_results["warnings"].append("Low overall confidence score")
        
        # Check attribution
        if not enriched_intelligence.attribution:
            validation_results["warnings"].append("No attribution information")
        
        return validation_results
