"""
Attack Scenarios

Predefined attack scenarios, MITRE ATT&CK technique mappings, and attack templates.
"""

from typing import Dict, List, Any, Optional


# MITRE ATT&CK Techniques by Agent Type
ROUTER_TECHNIQUES = {
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "Data exfiltration over command and control channel",
        "tactic": "Exfiltration",
        "indicators": ["large outbound data", "asymmetric traffic", "unknown destination"]
    },
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "description": "Command and control using application layer protocols",
        "tactic": "Command and Control",
        "indicators": ["HTTPS to unknown IP", "long-lived connections", "beacon traffic"]
    },
    "T1048": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "description": "Data exfiltration using non-standard protocols",
        "tactic": "Exfiltration",
        "indicators": ["unusual protocol", "large data transfer", "non-standard port"]
    },
    "T1021": {
        "id": "T1021",
        "name": "Remote Services",
        "description": "Lateral movement using remote services",
        "tactic": "Lateral Movement",
        "indicators": ["RDP/SSH connections", "unusual source", "privileged access"]
    },
    "T1043": {
        "id": "T1043",
        "name": "Commonly Used Port",
        "description": "Communication over commonly used ports",
        "tactic": "Command and Control",
        "indicators": ["C2 over port 80/443", "encrypted traffic", "beacon patterns"]
    }
}

COMPUTER_TECHNIQUES = {
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "description": "Command and script interpreter using PowerShell",
        "tactic": "Execution",
        "indicators": ["obfuscated PowerShell", "encoded commands", "suspicious scripts"]
    },
    "T1055": {
        "id": "T1055",
        "name": "Process Injection",
        "description": "Injection of malicious code into running processes",
        "tactic": "Defense Evasion",
        "indicators": ["unusual process relationships", "injected code", "memory manipulation"]
    },
    "T1547.001": {
        "id": "T1547.001",
        "name": "Boot or Logon Autostart Execution",
        "description": "Persistence through startup programs",
        "tactic": "Persistence",
        "indicators": ["startup folder modifications", "registry changes", "scheduled tasks"]
    },
    "T1134": {
        "id": "T1134",
        "name": "Access Token Manipulation",
        "description": "Privilege escalation through token manipulation",
        "tactic": "Privilege Escalation",
        "indicators": ["token duplication", "privilege changes", "unusual user context"]
    },
    "T1053": {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "description": "Persistence through scheduled tasks",
        "tactic": "Persistence",
        "indicators": ["scheduled task creation", "suspicious task names", "unusual timing"]
    }
}

EMAIL_TECHNIQUES = {
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "description": "Phishing attacks via email",
        "tactic": "Initial Access",
        "indicators": ["suspicious sender", "urgent language", "malicious links"]
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "description": "Phishing with malicious attachments",
        "tactic": "Initial Access",
        "indicators": ["malicious attachment", "executable files", "double extensions"]
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "description": "Phishing with malicious links",
        "tactic": "Initial Access",
        "indicators": ["suspicious URLs", "URL shortening", "obfuscated links"]
    },
    "T1534": {
        "id": "T1534",
        "name": "Internal Spearphishing",
        "description": "Spearphishing using internal email systems",
        "tactic": "Lateral Movement",
        "indicators": ["internal sender spoofing", "credential harvesting", "internal links"]
    }
}

# Common Attack Types
COMMON_ATTACKS = {
    "router": {
        "c2_channel": {
            "name": "Command & Control Channel",
            "description": "Establish C2 communication channel",
            "techniques": ["T1071", "T1043"],
            "characteristics": ["long-lived connection", "encrypted traffic", "beacon pattern"]
        },
        "data_exfiltration": {
            "name": "Data Exfiltration",
            "description": "Steal and exfiltrate data",
            "techniques": ["T1041", "T1048"],
            "characteristics": ["large outbound data", "asymmetric traffic", "unknown destination"]
        },
        "port_scanning": {
            "name": "Port Scanning",
            "description": "Scan network for open ports",
            "techniques": ["T1046"],
            "characteristics": ["multiple connection attempts", "sequential ports", "short connections"]
        },
        "lateral_movement": {
            "name": "Lateral Movement",
            "description": "Move through network",
            "techniques": ["T1021", "T1071"],
            "characteristics": ["internal connections", "privileged access", "multiple hops"]
        }
    },
    "computer": {
        "process_injection": {
            "name": "Process Injection",
            "description": "Inject malicious code into processes",
            "techniques": ["T1055"],
            "characteristics": ["unusual process relationships", "memory manipulation", "defense evasion"]
        },
        "privilege_escalation": {
            "name": "Privilege Escalation",
            "description": "Gain higher privileges",
            "techniques": ["T1134", "T1548"],
            "characteristics": ["token manipulation", "UAC bypass", "admin access"]
        },
        "persistence": {
            "name": "Persistence",
            "description": "Maintain access after reboot",
            "techniques": ["T1547.001", "T1053"],
            "characteristics": ["startup programs", "scheduled tasks", "registry modifications"]
        },
        "powershell_attack": {
            "name": "PowerShell Attack",
            "description": "Execute malicious PowerShell commands",
            "techniques": ["T1059.001"],
            "characteristics": ["obfuscated commands", "encoded scripts", "suspicious execution"]
        }
    },
    "email": {
        "phishing": {
            "name": "Phishing",
            "description": "Phishing email attack",
            "techniques": ["T1566"],
            "characteristics": ["suspicious sender", "urgent language", "malicious links"]
        },
        "malicious_attachment": {
            "name": "Malicious Attachment",
            "description": "Email with malicious attachment",
            "techniques": ["T1566.001"],
            "characteristics": ["executable files", "double extensions", "suspicious file types"]
        },
        "email_spoofing": {
            "name": "Email Spoofing",
            "description": "Spoofed sender address",
            "techniques": ["T1534"],
            "characteristics": ["display name spoofing", "domain spoofing", "internal sender"]
        },
        "credential_harvesting": {
            "name": "Credential Harvesting",
            "description": "Steal credentials via email",
            "techniques": ["T1566.002"],
            "characteristics": ["fake login pages", "suspicious links", "credential requests"]
        }
    }
}


def get_mitre_techniques(agent_type: str) -> List[Dict[str, Any]]:
    """
    Get MITRE ATT&CK techniques for an agent type.
    
    Args:
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        List of MITRE technique dictionaries
    """
    technique_map = {
        'router': ROUTER_TECHNIQUES,
        'computer': COMPUTER_TECHNIQUES,
        'email': EMAIL_TECHNIQUES
    }
    
    techniques = technique_map.get(agent_type.lower(), {})
    return list(techniques.values())


def get_attack_templates(attack_type: str, agent_type: str) -> Optional[Dict[str, Any]]:
    """
    Get attack template for a specific attack type.
    
    Args:
        attack_type: Attack type identifier
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        Attack template dictionary or None
    """
    agent_attacks = COMMON_ATTACKS.get(agent_type.lower(), {})
    return agent_attacks.get(attack_type)


def get_all_attack_types(agent_type: str) -> List[str]:
    """
    Get all available attack types for an agent.
    
    Args:
        agent_type: Agent type
        
    Returns:
        List of attack type identifiers
    """
    agent_attacks = COMMON_ATTACKS.get(agent_type.lower(), {})
    return list(agent_attacks.keys())


def build_attack_sequence(technique_id: str, agent_types: List[str]) -> List[Dict[str, Any]]:
    """
    Build a multi-step attack sequence from a MITRE technique.
    
    Args:
        technique_id: MITRE technique ID
        agent_types: List of agent types involved
        
    Returns:
        List of attack step dictionaries
    """
    # Map technique to attack steps
    sequence_templates = {
        "T1041": [  # Exfiltration Over C2 Channel
            {"step": 1, "agent": "router", "action": "establish_c2", "description": "Establish C2 channel"},
            {"step": 2, "agent": "computer", "action": "collect_data", "description": "Collect sensitive data"},
            {"step": 3, "agent": "router", "action": "exfiltrate", "description": "Exfiltrate data over C2"}
        ],
        "T1059.001": [  # PowerShell
            {"step": 1, "agent": "email", "action": "deliver", "description": "Deliver malicious email"},
            {"step": 2, "agent": "computer", "action": "execute_powershell", "description": "Execute PowerShell payload"},
            {"step": 3, "agent": "router", "action": "establish_c2", "description": "Establish C2 connection"}
        ],
        "T1566": [  # Phishing
            {"step": 1, "agent": "email", "action": "send_phishing", "description": "Send phishing email"},
            {"step": 2, "agent": "computer", "action": "user_interaction", "description": "User clicks link"},
            {"step": 3, "agent": "router", "action": "malicious_traffic", "description": "Malicious network traffic"}
        ]
    }
    
    return sequence_templates.get(technique_id, [])


def get_attack_description(attack_type: str, agent_type: str) -> str:
    """
    Get human-readable description of an attack type.
    
    Args:
        attack_type: Attack type identifier
        agent_type: Agent type
        
    Returns:
        Attack description string
    """
    template = get_attack_templates(attack_type, agent_type)
    if template:
        return f"{template['name']}: {template['description']}"
    return f"Unknown attack type: {attack_type}"


def get_attack_characteristics(attack_type: str, agent_type: str) -> List[str]:
    """
    Get characteristics/indicators for an attack type.
    
    Args:
        attack_type: Attack type identifier
        agent_type: Agent type
        
    Returns:
        List of attack characteristics
    """
    template = get_attack_templates(attack_type, agent_type)
    if template:
        return template.get('characteristics', [])
    return []

