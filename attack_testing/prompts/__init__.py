"""
LLM Prompt Templates

Structured prompts for attack generation and hacker simulation.
"""

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

__all__ = [
    'get_attack_generation_prompt',
    'get_attack_sequence_prompt',
    'get_structured_output_prompt',
    'get_hacker_system_prompt',
    'get_hacker_attack_prompt',
    'get_random_attack_prompt',
]




