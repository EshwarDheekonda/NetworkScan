"""
Attack Generation Prompts

LLM prompts for generating attack data in structured formats.
"""

from typing import Dict, Any, Optional


def get_attack_generation_prompt(
    attack_type: str,
    agent_type: str,
    description: Optional[str] = None,
    technique_info: Optional[Dict[str, Any]] = None
) -> str:
    """
    Get prompt for generating single attack data.
    
    Args:
        attack_type: Type of attack (e.g., 'c2_channel', 'phishing')
        agent_type: Agent type ('router', 'computer', 'email')
        description: Optional user description
        technique_info: Optional MITRE technique information
        
    Returns:
        Prompt string for LLM
    """
    agent_descriptions = {
        'router': 'network traffic data (source_ip, dest_ip, protocol, port, bytes_sent, bytes_received, duration_seconds)',
        'computer': 'system log data (process_name, user, file_path, command_line, pid, event_type)',
        'email': 'email data (sender, sender_domain, subject, attachment_name, attachment_size, links)'
    }
    
    data_format = agent_descriptions.get(agent_type.lower(), 'data')
    
    technique_context = ""
    if technique_info:
        technique_context = f"""
MITRE ATT&CK Technique: {technique_info.get('name', '')} ({technique_info.get('id', '')})
Description: {technique_info.get('description', '')}
Tactic: {technique_info.get('tactic', '')}
Indicators: {', '.join(technique_info.get('indicators', []))}
"""
    
    user_context = ""
    if description:
        user_context = f"\nUser Description: {description}\n"
    
    prompt = f"""You are a cybersecurity expert generating realistic attack data for testing security detection systems.

TASK: Generate realistic {attack_type} attack data for {agent_type} agent monitoring.

{technique_context}
{user_context}

The attack data must:
1. Be realistic and match real-world attack patterns
2. Be formatted as valid JSON matching the {agent_type} agent data format
3. Include characteristics that would trigger security alerts
4. Be subtle enough to potentially evade basic detection but detectable by advanced systems

Generate the attack data as a JSON object with the following structure for {agent_type}:
{data_format}

IMPORTANT: 
- Output ONLY valid JSON, no additional text
- Make the data realistic and consistent
- Include suspicious but realistic values
- The data should represent an actual {attack_type} attack

Generate the attack data now:"""
    
    return prompt


def get_attack_sequence_prompt(
    technique_id: str,
    agent_types: list,
    sequence_steps: list
) -> str:
    """
    Get prompt for generating multi-step attack sequence.
    
    Args:
        technique_id: MITRE technique ID
        agent_types: List of agent types in sequence
        sequence_steps: List of attack step descriptions
        
    Returns:
        Prompt string for LLM
    """
    steps_text = "\n".join([
        f"Step {step['step']} ({step['agent']}): {step['description']}"
        for step in sequence_steps
    ])
    
    prompt = f"""You are a cybersecurity expert generating a realistic multi-step attack sequence.

TASK: Generate a complete attack sequence based on MITRE ATT&CK technique {technique_id}.

Attack Sequence:
{steps_text}

The sequence involves these agent types: {', '.join(agent_types)}

For each step, generate realistic attack data that:
1. Represents the attack action described
2. Is formatted as valid JSON for the corresponding agent type
3. Shows progression through the attack chain
4. Includes realistic timing and relationships between steps

Generate the complete attack sequence as a JSON array, where each element is an attack data object for the corresponding step.

Output format:
[
  {{"step": 1, "agent": "agent_type", "data": {{...attack data...}}, "description": "..."}},
  {{"step": 2, "agent": "agent_type", "data": {{...attack data...}}, "description": "..."}},
  ...
]

Generate the attack sequence now:"""
    
    return prompt


def get_structured_output_prompt(agent_type: str) -> str:
    """
    Get system prompt for structured JSON output.
    
    Args:
        agent_type: Agent type
        
    Returns:
        System prompt for ensuring structured output
    """
    formats = {
        'router': {
            'required': ['dest_ip or dest_domain', 'protocol'],
            'optional': ['source_ip', 'port', 'bytes_sent', 'bytes_received', 'duration_seconds'],
            'example': {
                'dest_ip': '185.220.101.45',
                'protocol': 'HTTPS',
                'port': 443,
                'bytes_sent': 10485760,
                'bytes_received': 1024,
                'duration_seconds': 3600
            }
        },
        'computer': {
            'required': ['process_name'],
            'optional': ['user', 'file_path', 'command_line', 'pid', 'parent_pid', 'event_type'],
            'example': {
                'process_name': 'powershell.exe',
                'user': 'admin',
                'command_line': 'powershell -enc <base64>',
                'pid': 1234
            }
        },
        'email': {
            'required': ['sender'],
            'optional': ['sender_domain', 'subject', 'attachment_name', 'attachment_size', 'links'],
            'example': {
                'sender': 'attacker@malicious.com',
                'subject': 'Urgent: Verify Your Account',
                'links': ['http://phishing-site.com']
            }
        }
    }
    
    format_info = formats.get(agent_type.lower(), {})
    
    prompt = f"""You must output ONLY valid JSON matching the {agent_type} agent data format.

Required fields: {', '.join(format_info.get('required', []))}
Optional fields: {', '.join(format_info.get('optional', []))}

Example format:
{format_info.get('example', {})}

CRITICAL: Output ONLY the JSON object, no markdown, no code blocks, no explanations. Just the raw JSON."""
    
    return prompt




