"""
Chat Interface

Chat-based interface for attack specification and hacker simulation.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

from attack_testing.attack_generator import AttackGenerator, AttackData, HackerScenario
from attack_testing.attack_scenarios import (
    get_all_attack_types,
    get_attack_templates
)
from attack_testing.prompts.hacker_simulation import get_chat_attack_prompt
from knowledge_fusion.rag_pipeline import LLMProvider

logger = logging.getLogger(__name__)


@dataclass
class AttackIntent:
    """Parsed attack intent from user message."""
    agent_type: Optional[str] = None
    attack_type: Optional[str] = None
    technique_id: Optional[str] = None
    description: Optional[str] = None
    mode: str = "specified"  # 'specified', 'hacker', 'random'
    confidence: float = 0.0


@dataclass
class ChatResponse:
    """Response from chat interface."""
    message: str
    attack_data: Optional[AttackData] = None
    hacker_scenario: Optional[HackerScenario] = None
    intent: Optional[AttackIntent] = None
    requires_clarification: bool = False
    clarification_questions: List[str] = None
    
    def __post_init__(self):
        if self.clarification_questions is None:
            self.clarification_questions = []


class ChatInterface:
    """Chat interface for attack specification."""
    
    def __init__(self, attack_generator: Optional[AttackGenerator] = None, llm_provider: Optional[LLMProvider] = None):
        """
        Initialize chat interface.
        
        Args:
            attack_generator: Optional AttackGenerator instance
            llm_provider: Optional LLMProvider instance
        """
        self.attack_generator = attack_generator or AttackGenerator(llm_provider)
        self.llm_provider = llm_provider or LLMProvider()
        self.conversation_history: List[Dict[str, str]] = []
        self.logger = logging.getLogger(__name__)
        # Execution state tracking to prevent looping
        self.execution_state: Dict[str, Any] = {
            'is_executing': False,
            'current_execution_id': None,
            'last_request_time': 0.0
        }
    
    def process_message(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
        agent_type: Optional[str] = None
    ) -> ChatResponse:
        """
        Process user message and generate response.
        
        Args:
            message: User message
            context: Optional context dictionary
            agent_type: Optional agent type hint
            
        Returns:
            ChatResponse object
        """
        # Parse attack intent
        intent = self.parse_attack_intent(message, agent_type)
        
        # Check for hacker mode
        if intent.mode == "hacker":
            return self._handle_hacker_mode(intent, context)
        
        # Check for random attack
        if intent.mode == "random":
            return self._handle_random_attack(intent)
        
        # Check if clarification needed
        if intent.agent_type is None or intent.attack_type is None:
            return self._request_clarification(intent, message)
        
        # Generate attack
        try:
            attack_data = self.attack_generator.generate_attack(
                attack_type=intent.attack_type,
                agent_type=intent.agent_type,
                description=intent.description or message,
                technique_id=intent.technique_id
            )
            
            response_message = f"I've generated a {intent.attack_type} attack for {intent.agent_type} agent.\n\n"
            response_message += f"Description: {attack_data.description}\n"
            if attack_data.technique_name:
                response_message += f"MITRE Technique: {attack_data.technique_name} ({attack_data.technique_id})\n"
            response_message += "\nAttack data has been generated and is ready for testing."
            
            # Update conversation history
            self.conversation_history.append({
                'user': message,
                'assistant': response_message,
                'timestamp': datetime.now().isoformat()
            })
            
            return ChatResponse(
                message=response_message,
                attack_data=attack_data,
                intent=intent
            )
        
        except Exception as e:
            self.logger.error(f"Error processing message: {e}", exc_info=True)
            return ChatResponse(
                message=f"Error generating attack: {str(e)}",
                intent=intent,
                requires_clarification=True
            )
    
    def parse_attack_intent(self, message: str, agent_type_hint: Optional[str] = None) -> AttackIntent:
        """
        Parse attack intent from user message.
        
        Args:
            message: User message
            agent_type_hint: Optional agent type hint
            
        Returns:
            AttackIntent object
        """
        message_lower = message.lower()
        
        # Check for hacker mode keywords
        hacker_keywords = ['act as hacker', 'be a hacker', 'hacker mode', 'simulate hacker', 'as a hacker']
        if any(keyword in message_lower for keyword in hacker_keywords):
            return AttackIntent(
                mode="hacker",
                agent_type=agent_type_hint,
                confidence=0.9
            )
        
        # Check for random attack keywords
        random_keywords = ['random attack', 'surprise me', 'any attack', 'random']
        if any(keyword in message_lower for keyword in random_keywords):
            return AttackIntent(
                mode="random",
                agent_type=agent_type_hint,
                confidence=0.8
            )
        
        # Detect agent type
        detected_agent_type = agent_type_hint
        if not detected_agent_type:
            if any(word in message_lower for word in ['router', 'network', 'traffic', 'connection']):
                detected_agent_type = 'router'
            elif any(word in message_lower for word in ['computer', 'endpoint', 'process', 'system']):
                detected_agent_type = 'computer'
            elif any(word in message_lower for word in ['email', 'phishing', 'mail']):
                detected_agent_type = 'email'
        
        # Detect attack type
        detected_attack_type = None
        if detected_agent_type:
            attack_types = get_all_attack_types(detected_agent_type)
            for attack_type in attack_types:
                template = get_attack_templates(attack_type, detected_agent_type)
                if template:
                    attack_name = template['name'].lower()
                    attack_desc = template['description'].lower()
                    if attack_name in message_lower or attack_desc in message_lower:
                        detected_attack_type = attack_type
                        break
        
        # Extract description
        description = message if len(message) > 20 else None
        
        return AttackIntent(
            agent_type=detected_agent_type,
            attack_type=detected_attack_type,
            description=description,
            mode="specified",
            confidence=0.7 if detected_agent_type and detected_attack_type else 0.3
        )
    
    def generate_hacker_attack(self, agent_type: str, context: Optional[Dict] = None) -> HackerScenario:
        """
        Generate attack where LLM acts as hacker.
        
        Args:
            agent_type: Agent type
            context: Optional context
            
        Returns:
            HackerScenario object
        """
        return self.attack_generator.generate_hacker_scenario(agent_type, context)
    
    def _handle_hacker_mode(self, intent: AttackIntent, context: Optional[Dict]) -> ChatResponse:
        """Handle hacker mode request."""
        agent_type = intent.agent_type or 'router'  # Default to router
        
        try:
            scenario = self.generate_hacker_attack(agent_type, context)
            
            response_message = "🔴 HACKER MODE ACTIVATED 🔴\n\n"
            response_message += f"Attack Strategy: {scenario.strategy}\n"
            response_message += f"Objectives: {', '.join(scenario.objectives)}\n"
            response_message += f"\nAttack data generated for {agent_type} agent."
            
            self.conversation_history.append({
                'user': 'hacker mode',
                'assistant': response_message,
                'timestamp': datetime.now().isoformat()
            })
            
            return ChatResponse(
                message=response_message,
                hacker_scenario=scenario,
                intent=intent
            )
        
        except Exception as e:
            self.logger.error(f"Error in hacker mode: {e}", exc_info=True)
            return ChatResponse(
                message=f"Error in hacker mode: {str(e)}",
                intent=intent
            )
    
    def _handle_random_attack(self, intent: AttackIntent) -> ChatResponse:
        """Handle random attack request."""
        agent_type = intent.agent_type or 'router'  # Default to router
        
        try:
            attack_data = self.attack_generator.generate_random_attack(agent_type)
            
            response_message = "🎲 Generating random attack...\n\n"
            response_message += f"Attack Type: {attack_data.attack_type}\n"
            response_message += f"Description: {attack_data.description}\n"
            response_message += "\nRandom attack data generated and ready for testing."
            
            self.conversation_history.append({
                'user': 'random attack',
                'assistant': response_message,
                'timestamp': datetime.now().isoformat()
            })
            
            return ChatResponse(
                message=response_message,
                attack_data=attack_data,
                intent=intent
            )
        
        except Exception as e:
            self.logger.error(f"Error generating random attack: {e}", exc_info=True)
            return ChatResponse(
                message=f"Error generating random attack: {str(e)}",
                intent=intent
            )
    
    def _request_clarification(self, intent: AttackIntent, original_message: str) -> ChatResponse:
        """Request clarification from user."""
        questions = []
        
        if not intent.agent_type:
            questions.append("Which agent type should I target? (router, computer, or email)")
        
        if intent.agent_type and not intent.attack_type:
            attack_types = get_all_attack_types(intent.agent_type)
            questions.append(f"What type of attack? Available: {', '.join(attack_types)}")
        
        response_message = "I need a bit more information to generate the attack:\n"
        response_message += "\n".join(f"- {q}" for q in questions)
        
        return ChatResponse(
            message=response_message,
            intent=intent,
            requires_clarification=True,
            clarification_questions=questions
        )
    
    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history."""
        return self.conversation_history.copy()
    
    def initialize_hacker_assistant(self) -> ChatResponse:
        """
        Initialize hacker assistant with greeting and mode selection.
        
        Returns:
            ChatResponse with hacker assistant greeting
        """
        message = """🔴 **HACKER ASSISTANT ACTIVATED** 🔴

I'm your virtual hacker assistant, ready to test your security system. I can behave like a real attacker and help you evaluate how well your agents detect threats.

**Choose your attack mode:**

1. **Predefined Scenarios** - Select from a list of known attack types
2. **Dynamic Hacker Mode** - I'll act like a real hacker and dynamically generate attacks

Which mode would you like to use? Select an agent type first, then choose your mode."""
        
        return ChatResponse(
            message=message,
            intent=AttackIntent(mode="hacker_assistant_init")
        )
    
    def get_predefined_scenarios(self, agent_type: str) -> List[Dict[str, Any]]:
        """
        Get list of predefined attack scenarios for an agent type.
        
        Args:
            agent_type: Agent type ('router', 'computer', 'email')
            
        Returns:
            List of scenario dictionaries
        """
        attack_types = get_all_attack_types(agent_type)
        scenarios = []
        
        for attack_type in attack_types:
            template = get_attack_templates(attack_type, agent_type)
            if template:
                scenarios.append({
                    'attack_type': attack_type,
                    'name': template.get('name', attack_type),
                    'description': template.get('description', ''),
                    'techniques': template.get('techniques', []),
                    'characteristics': template.get('characteristics', [])
                })
        
        return scenarios
    
    def format_predefined_scenarios_response(self, agent_type: str) -> ChatResponse:
        """
        Format predefined scenarios as a chat response.
        
        Args:
            agent_type: Agent type
            
        Returns:
            ChatResponse with scenarios list
        """
        scenarios = self.get_predefined_scenarios(agent_type)
        
        if not scenarios:
            message = f"No predefined scenarios available for {agent_type} agent."
            return ChatResponse(
                message=message,
                intent=AttackIntent(agent_type=agent_type, mode="predefined")
            )
        
        message = f"**Available Predefined Attack Scenarios for {agent_type.upper()} Agent:**\n\n"
        
        for i, scenario in enumerate(scenarios, 1):
            message += f"**{i}. {scenario['name']}**\n"
            message += f"   - Type: `{scenario['attack_type']}`\n"
            message += f"   - Description: {scenario['description']}\n"
            if scenario.get('techniques'):
                message += f"   - MITRE Techniques: {', '.join(scenario['techniques'])}\n"
            message += "\n"
        
        message += "Select a scenario number to execute it, or type the attack type name."
        
        return ChatResponse(
            message=message,
            intent=AttackIntent(agent_type=agent_type, mode="predefined"),
            requires_clarification=False
        )
    
    def check_execution_state(self) -> bool:
        """
        Check if execution is in progress to prevent looping.
        
        Returns:
            True if execution is in progress
        """
        import time
        current_time = time.time()
        
        # Reset state if last request was more than 30 seconds ago
        if current_time - self.execution_state['last_request_time'] > 30:
            self.execution_state['is_executing'] = False
            self.execution_state['current_execution_id'] = None
        
        return self.execution_state['is_executing']
    
    def set_execution_state(self, is_executing: bool, execution_id: Optional[str] = None):
        """
        Set execution state to prevent duplicate requests.
        
        Args:
            is_executing: Whether execution is in progress
            execution_id: Optional execution ID
        """
        import time
        self.execution_state['is_executing'] = is_executing
        self.execution_state['current_execution_id'] = execution_id
        self.execution_state['last_request_time'] = time.time()



