"""
Attack Generator

LLM-powered attack data generator for testing security detection systems.
"""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
import logging

from knowledge_fusion.rag_pipeline import LLMProvider
from attack_testing.attack_scenarios import (
    get_mitre_techniques,
    get_attack_templates,
    get_attack_characteristics
)
from attack_testing.prompts.attack_generation import (
    get_attack_generation_prompt,
    get_attack_sequence_prompt,
    get_structured_output_prompt
)
from attack_testing.prompts.hacker_simulation import (
    get_hacker_system_prompt,
    get_hacker_attack_prompt,
    get_random_attack_prompt
)

logger = logging.getLogger(__name__)


@dataclass
class AttackData:
    """Structured attack data."""
    agent_type: str
    attack_type: str
    data: Dict[str, Any]
    description: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    explanation: Optional[str] = None
    indicators: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []


@dataclass
class HackerScenario:
    """Hacker-generated attack scenario."""
    agent_type: str
    attack_data: AttackData
    strategy: str
    objectives: List[str]
    expected_detection: bool = True


class AttackGenerator:
    """LLM-powered attack data generator."""
    
    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        """
        Initialize attack generator.
        
        Args:
            llm_provider: Optional LLMProvider instance
        """
        self.llm_provider = llm_provider or LLMProvider()
        self.logger = logging.getLogger(__name__)
    
    def generate_attack(
        self,
        attack_type: str,
        agent_type: str,
        description: Optional[str] = None,
        technique_id: Optional[str] = None
    ) -> AttackData:
        """
        Generate attack data for a specific attack type.
        
        Args:
            attack_type: Attack type identifier
            agent_type: Agent type ('router', 'computer', 'email')
            description: Optional user description
            technique_id: Optional MITRE technique ID
            
        Returns:
            AttackData object
        """
        # Get attack template and technique info
        template = get_attack_templates(attack_type, agent_type)
        technique_info = None
        
        if technique_id:
            techniques = get_mitre_techniques(agent_type)
            technique_info = next((t for t in techniques if t['id'] == technique_id), None)
        elif template and template.get('techniques'):
            # Use first technique from template
            technique_id = template['techniques'][0]
            techniques = get_mitre_techniques(agent_type)
            technique_info = next((t for t in techniques if t['id'] == technique_id), None)
        
        # Build prompt
        prompt = get_attack_generation_prompt(
            attack_type=attack_type,
            agent_type=agent_type,
            description=description,
            technique_info=technique_info
        )
        
        system_prompt = get_structured_output_prompt(agent_type)
        
        # Generate with LLM
        try:
            response = self.llm_provider.generate(prompt, system_prompt)
            
            # Parse JSON from response
            attack_data_dict = self._parse_json_response(response)
            
            # Get characteristics
            characteristics = get_attack_characteristics(attack_type, agent_type)
            
            return AttackData(
                agent_type=agent_type,
                attack_type=attack_type,
                data=attack_data_dict,
                description=description or template.get('description', '') if template else '',
                technique_id=technique_id,
                technique_name=technique_info.get('name') if technique_info else None,
                explanation=response,  # Full LLM response as explanation
                indicators=characteristics
            )
        
        except Exception as e:
            self.logger.error(f"Error generating attack: {e}", exc_info=True)
            # Fallback: generate basic attack data
            return self._generate_fallback_attack(attack_type, agent_type)
    
    def generate_attack_sequence(
        self,
        technique_id: str,
        agent_types: List[str]
    ) -> List[AttackData]:
        """
        Generate multi-step attack sequence.
        
        Args:
            technique_id: MITRE technique ID
            agent_types: List of agent types in sequence
            
        Returns:
            List of AttackData objects
        """
        from attack_testing.attack_scenarios import build_attack_sequence
        
        sequence_steps = build_attack_sequence(technique_id, agent_types)
        
        if not sequence_steps:
            self.logger.warning(f"No sequence template for technique {technique_id}")
            return []
        
        prompt = get_attack_sequence_prompt(technique_id, agent_types, sequence_steps)
        system_prompt = "You are a cybersecurity expert. Generate realistic attack data in JSON format."
        
        try:
            response = self.llm_provider.generate(prompt, system_prompt)
            
            # Parse sequence from response
            sequence_data = self._parse_json_response(response)
            
            # Convert to AttackData objects
            attack_sequence = []
            if isinstance(sequence_data, list):
                for step_data in sequence_data:
                    if isinstance(step_data, dict) and 'data' in step_data:
                        attack_sequence.append(AttackData(
                            agent_type=step_data.get('agent', agent_types[0]),
                            attack_type=step_data.get('action', 'unknown'),
                            data=step_data['data'],
                            description=step_data.get('description', ''),
                            explanation=step_data.get('explanation', '')
                        ))
            
            return attack_sequence
        
        except Exception as e:
            self.logger.error(f"Error generating attack sequence: {e}", exc_info=True)
            return []
    
    def generate_random_attack(self, agent_type: str) -> AttackData:
        """
        Generate a random attack without user specification.
        
        Args:
            agent_type: Agent type
            
        Returns:
            AttackData object
        """
        prompt = get_random_attack_prompt(agent_type)
        system_prompt = get_hacker_system_prompt()
        
        try:
            response = self.llm_provider.generate(prompt, system_prompt)
            
            # Parse JSON from response
            attack_data_dict = self._parse_json_response(response)
            
            # Extract attack type from response if possible
            attack_type = "random"
            if "attack type" in response.lower() or "technique" in response.lower():
                # Try to extract attack type
                pass
            
            return AttackData(
                agent_type=agent_type,
                attack_type=attack_type,
                data=attack_data_dict,
                description="Randomly generated attack",
                explanation=response
            )
        
        except Exception as e:
            self.logger.error(f"Error generating random attack: {e}", exc_info=True)
            return self._generate_fallback_attack("random", agent_type)
    
    def generate_hacker_scenario(self, agent_type: str, context: Optional[Dict] = None) -> HackerScenario:
        """
        Generate attack scenario where LLM acts as a hacker.
        
        Args:
            agent_type: Agent type
            context: Optional context about target environment
            
        Returns:
            HackerScenario object
        """
        prompt = get_hacker_attack_prompt(agent_type, context)
        system_prompt = get_hacker_system_prompt()
        
        try:
            response = self.llm_provider.generate(prompt, system_prompt)
            
            # Parse structured data from response
            attack_data_dict = self._parse_json_response(response)
            
            # Extract strategy and objectives from response
            strategy = self._extract_strategy(response)
            objectives = self._extract_objectives(response)
            
            attack_data = AttackData(
                agent_type=agent_type,
                attack_type="hacker_generated",
                data=attack_data_dict,
                description=strategy,
                explanation=response
            )
            
            return HackerScenario(
                agent_type=agent_type,
                attack_data=attack_data,
                strategy=strategy,
                objectives=objectives
            )
        
        except Exception as e:
            self.logger.error(f"Error generating hacker scenario: {e}", exc_info=True)
            # Fallback
            attack_data = self._generate_fallback_attack("hacker", agent_type)
            return HackerScenario(
                agent_type=agent_type,
                attack_data=attack_data,
                strategy="Fallback attack scenario",
                objectives=["Test system detection"]
            )
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """
        Parse JSON from LLM response.
        
        Args:
            response: LLM response text
            
        Returns:
            Parsed JSON dictionary
        """
        # Try to extract JSON from response
        # Remove markdown code blocks if present
        response = re.sub(r'```json\s*', '', response)
        response = re.sub(r'```\s*', '', response)
        response = response.strip()
        
        # Try to find JSON object
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass
        
        # Try parsing entire response
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # If no valid JSON, return empty dict
            self.logger.warning("Could not parse JSON from LLM response")
            return {}
    
    def _extract_strategy(self, response: str) -> str:
        """Extract attack strategy from LLM response."""
        # Look for strategy description
        strategy_patterns = [
            r'strategy[:\s]+([^.\n]+)',
            r'attack[:\s]+([^.\n]+)',
            r'plan[:\s]+([^.\n]+)'
        ]
        
        for pattern in strategy_patterns:
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Hacker-generated attack scenario"
    
    def _extract_objectives(self, response: str) -> List[str]:
        """Extract attack objectives from LLM response."""
        objectives = []
        
        # Look for objectives list
        obj_patterns = [
            r'objectives?[:\s]+(.*?)(?:\n\n|\Z)',
            r'goals?[:\s]+(.*?)(?:\n\n|\Z)'
        ]
        
        for pattern in obj_patterns:
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                obj_text = match.group(1)
                # Split by bullets or numbers
                objectives = re.split(r'[•\-\d+\.]\s*', obj_text)
                objectives = [obj.strip() for obj in objectives if obj.strip()]
                break
        
        if not objectives:
            objectives = ["Test security detection capabilities"]
        
        return objectives
    
    def _generate_fallback_attack(self, attack_type: str, agent_type: str) -> AttackData:
        """
        Generate fallback attack data when LLM fails.
        
        Args:
            attack_type: Attack type
            agent_type: Agent type
            
        Returns:
            AttackData object with basic attack data
        """
        # Basic fallback data structures
        fallback_data = {
            'router': {
                'dest_ip': '185.220.101.45',
                'protocol': 'HTTPS',
                'port': 443,
                'bytes_sent': 10485760,
                'bytes_received': 1024,
                'duration_seconds': 3600
            },
            'computer': {
                'process_name': 'powershell.exe',
                'user': 'admin',
                'command_line': 'powershell -enc <base64>',
                'pid': 9999
            },
            'email': {
                'sender': 'attacker@malicious.com',
                'subject': 'Urgent: Verify Your Account',
                'links': ['http://phishing-site.com']
            }
        }
        
        return AttackData(
            agent_type=agent_type,
            attack_type=attack_type,
            data=fallback_data.get(agent_type, {}),
            description=f"Fallback {attack_type} attack for {agent_type}",
            explanation="Generated using fallback method (LLM unavailable)"
        )

