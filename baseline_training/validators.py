"""
Data Validators

Validate training data format for each agent type (Router, Computer, Email).
"""

from typing import Dict, List, Tuple, Optional, Any
import re
from urllib.parse import urlparse


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_router_data(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate Router agent data format.
    
    Args:
        data: Data dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    # Check for required fields (at least one destination identifier)
    has_dest = bool(data.get('dest_ip') or data.get('dest_domain') or data.get('destination'))
    if not has_dest:
        return False, "Missing required field: 'dest_ip', 'dest_domain', or 'destination'"
    
    # Check for required protocol field
    if not data.get('protocol'):
        return False, "Missing required field: 'protocol'"
    
    # Validate protocol is a string
    protocol = data.get('protocol', '')
    if not isinstance(protocol, str):
        return False, "Field 'protocol' must be a string"
    
    # Validate port if provided
    port = data.get('port') or data.get('dest_port')
    if port is not None:
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                return False, f"Port must be between 1 and 65535, got {port_int}"
        except (ValueError, TypeError):
            return False, f"Port must be an integer, got {type(port).__name__}"
    
    # Validate bytes_sent if provided
    if 'bytes_sent' in data and data['bytes_sent'] is not None:
        try:
            bytes_sent = int(data['bytes_sent'])
            if bytes_sent < 0:
                return False, "bytes_sent must be non-negative"
        except (ValueError, TypeError):
            return False, "bytes_sent must be an integer"
    
    # Validate bytes_received if provided
    if 'bytes_received' in data and data['bytes_received'] is not None:
        try:
            bytes_received = int(data['bytes_received'])
            if bytes_received < 0:
                return False, "bytes_received must be non-negative"
        except (ValueError, TypeError):
            return False, "bytes_received must be an integer"
    
    # Validate duration if provided
    duration = data.get('duration_seconds') or data.get('duration')
    if duration is not None:
        try:
            duration_float = float(duration)
            if duration_float < 0:
                return False, "duration must be non-negative"
        except (ValueError, TypeError):
            return False, "duration must be a number"
    
    # Validate IP address format if provided
    dest_ip = data.get('dest_ip')
    if dest_ip:
        if not isinstance(dest_ip, str):
            return False, "dest_ip must be a string"
        # Basic IP validation (IPv4)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, dest_ip):
            # Might be IPv6 or domain, so just check it's a string
            pass
    
    return True, None


def validate_computer_data(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate Computer agent data format.
    
    Args:
        data: Data dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    # Check for required fields (at least one process identifier)
    has_process = bool(data.get('process_name') or data.get('process'))
    if not has_process:
        return False, "Missing required field: 'process_name' or 'process'"
    
    # Validate process_name is a string
    process_name = data.get('process_name') or data.get('process', '')
    if not isinstance(process_name, str):
        return False, "Field 'process_name' or 'process' must be a string"
    
    # Validate user if provided
    user = data.get('user') or data.get('username')
    if user is not None and not isinstance(user, str):
        return False, "Field 'user' or 'username' must be a string"
    
    # Validate file_path if provided
    file_path = data.get('file_path') or data.get('file')
    if file_path is not None and not isinstance(file_path, str):
        return False, "Field 'file_path' or 'file' must be a string"
    
    # Validate command_line if provided
    command_line = data.get('command_line') or data.get('command')
    if command_line is not None and not isinstance(command_line, str):
        return False, "Field 'command_line' or 'command' must be a string"
    
    # Validate pid if provided
    pid = data.get('pid')
    if pid is not None:
        try:
            pid_int = int(pid)
            if pid_int < 0:
                return False, "pid must be non-negative"
        except (ValueError, TypeError):
            return False, "pid must be an integer"
    
    # Validate parent_pid if provided
    parent_pid = data.get('parent_pid')
    if parent_pid is not None:
        try:
            parent_pid_int = int(parent_pid)
            if parent_pid_int < 0:
                return False, "parent_pid must be non-negative"
        except (ValueError, TypeError):
            return False, "parent_pid must be an integer"
    
    # Validate event_type if provided
    event_type = data.get('event_type')
    if event_type is not None and not isinstance(event_type, str):
        return False, "Field 'event_type' must be a string"
    
    return True, None


def validate_email_data(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate Email agent data format.
    
    Args:
        data: Data dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    # Check for required fields (at least one sender identifier)
    has_sender = bool(data.get('sender') or data.get('from'))
    if not has_sender:
        return False, "Missing required field: 'sender' or 'from'"
    
    # Validate sender is a string
    sender = data.get('sender') or data.get('from', '')
    if not isinstance(sender, str):
        return False, "Field 'sender' or 'from' must be a string"
    
    # Validate email format (basic check)
    if '@' not in sender:
        return False, "Sender must be a valid email address (contain '@')"
    
    # Validate subject if provided
    subject = data.get('subject')
    if subject is not None and not isinstance(subject, str):
        return False, "Field 'subject' must be a string"
    
    # Validate attachment_name if provided
    attachment_name = data.get('attachment_name') or data.get('attachment')
    if attachment_name is not None and not isinstance(attachment_name, str):
        return False, "Field 'attachment_name' or 'attachment' must be a string"
    
    # Validate attachment_size if provided
    attachment_size = data.get('attachment_size') or data.get('size')
    if attachment_size is not None:
        try:
            size_int = int(attachment_size)
            if size_int < 0:
                return False, "attachment_size must be non-negative"
        except (ValueError, TypeError):
            return False, "attachment_size must be an integer"
    
    # Validate links/urls if provided
    links = data.get('links') or data.get('urls')
    if links is not None:
        if isinstance(links, str):
            links = [links]
        if not isinstance(links, list):
            return False, "Field 'links' or 'urls' must be a list or string"
        
        for link in links:
            if not isinstance(link, str):
                return False, "All links must be strings"
            # Basic URL validation
            try:
                parsed = urlparse(link)
                if not parsed.scheme and not parsed.netloc:
                    # Allow relative URLs
                    pass
            except Exception:
                return False, f"Invalid URL format: {link}"
    
    # Validate sender_domain if provided
    sender_domain = data.get('sender_domain')
    if sender_domain is not None and not isinstance(sender_domain, str):
        return False, "Field 'sender_domain' must be a string"
    
    return True, None


def validate_batch(data_list: List[Dict], agent_type: str) -> Tuple[bool, List[str]]:
    """
    Validate a batch of data records.
    
    Args:
        data_list: List of data dictionaries to validate
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        Tuple of (all_valid, list_of_errors)
    """
    if not isinstance(data_list, list):
        return False, ["Data must be a list of dictionaries"]
    
    errors = []
    validator_map = {
        'router': validate_router_data,
        'computer': validate_computer_data,
        'email': validate_email_data
    }
    
    validator = validator_map.get(agent_type.lower())
    if not validator:
        return False, [f"Unknown agent type: {agent_type}"]
    
    for i, data in enumerate(data_list):
        is_valid, error_msg = validator(data)
        if not is_valid:
            errors.append(f"Record {i+1}: {error_msg}")
    
    return len(errors) == 0, errors


def get_required_fields(agent_type: str) -> List[str]:
    """
    Get list of required fields for an agent type.
    
    Args:
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        List of required field names
    """
    required_fields = {
        'router': ['dest_ip or dest_domain', 'protocol'],
        'computer': ['process_name or process'],
        'email': ['sender or from']
    }
    
    return required_fields.get(agent_type.lower(), [])




