"""
Data Ingestion Module

Parse and normalize training data from multiple formats (JSON, CSV, JSONL).
"""

import json
import csv
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


def parse_json_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse JSON file containing training data.
    
    Supports:
    - Single JSON object (will be wrapped in list)
    - Array of JSON objects
    - File with 'data' key containing array
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        List of data dictionaries
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file is not valid JSON
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = json.load(f)
    
    # Handle different JSON structures
    if isinstance(content, list):
        # Already a list of records
        return content
    elif isinstance(content, dict):
        # Check if it has a 'data' key
        if 'data' in content and isinstance(content['data'], list):
            return content['data']
        elif 'agent' in content:
            # Single record with agent info, return as list
            return [content]
        else:
            # Single record, wrap in list
            return [content]
    else:
        raise ValueError(f"Unexpected JSON structure: {type(content)}")


def parse_jsonl_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse JSONL file (one JSON object per line).
    
    Args:
        file_path: Path to JSONL file
        
    Returns:
        List of data dictionaries
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If any line is not valid JSON
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    records = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:  # Skip empty lines
                continue
            
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON on line {line_num}: {e}")
                raise ValueError(f"Invalid JSON on line {line_num}: {e}")
    
    return records


def parse_csv_file(file_path: str, agent_type: str) -> List[Dict[str, Any]]:
    """
    Parse CSV file with column mapping for agent type.
    
    Args:
        file_path: Path to CSV file
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        List of data dictionaries
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Column mappings for each agent type
    column_mappings = {
        'router': {
            'source_ip': ['source_ip', 'source', 'src_ip'],
            'dest_ip': ['dest_ip', 'destination', 'dest', 'dest_ip_address'],
            'dest_domain': ['dest_domain', 'destination_domain', 'domain'],
            'protocol': ['protocol', 'proto'],
            'port': ['port', 'dest_port', 'destination_port'],
            'bytes_sent': ['bytes_sent', 'bytes_out', 'out_bytes'],
            'bytes_received': ['bytes_received', 'bytes_in', 'in_bytes'],
            'duration_seconds': ['duration_seconds', 'duration', 'time', 'connection_time']
        },
        'computer': {
            'process_name': ['process_name', 'process', 'exe', 'executable'],
            'user': ['user', 'username', 'user_name'],
            'file_path': ['file_path', 'file', 'path', 'filepath'],
            'command_line': ['command_line', 'command', 'cmd', 'cmdline'],
            'pid': ['pid', 'process_id'],
            'parent_pid': ['parent_pid', 'ppid', 'parent_process_id'],
            'event_type': ['event_type', 'event', 'type']
        },
        'email': {
            'sender': ['sender', 'from', 'from_address', 'sender_email'],
            'sender_domain': ['sender_domain', 'domain', 'from_domain'],
            'subject': ['subject', 'email_subject'],
            'attachment_name': ['attachment_name', 'attachment', 'filename'],
            'attachment_type': ['attachment_type', 'file_type', 'file_extension'],
            'attachment_size': ['attachment_size', 'size', 'file_size'],
            'links': ['links', 'urls', 'url', 'link']
        }
    }
    
    mapping = column_mappings.get(agent_type.lower(), {})
    records = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            record = {}
            
            # Map CSV columns to standard field names
            for standard_field, possible_columns in mapping.items():
                for col_name in possible_columns:
                    if col_name in row and row[col_name]:
                        value = row[col_name].strip()
                        if value:
                            # Try to convert numeric fields
                            if standard_field in ['port', 'bytes_sent', 'bytes_received', 
                                                  'pid', 'parent_pid', 'attachment_size']:
                                try:
                                    record[standard_field] = int(value)
                                except ValueError:
                                    try:
                                        record[standard_field] = float(value)
                                    except ValueError:
                                        record[standard_field] = value
                            elif standard_field in ['duration_seconds', 'duration']:
                                try:
                                    record[standard_field] = float(value)
                                except ValueError:
                                    record[standard_field] = value
                            elif standard_field == 'links':
                                # Handle comma-separated links
                                if ',' in value:
                                    record[standard_field] = [link.strip() for link in value.split(',')]
                                else:
                                    record[standard_field] = [value]
                            else:
                                record[standard_field] = value
                            break
            
            if record:  # Only add non-empty records
                records.append(record)
    
    return records


def normalize_data(data: List[Dict[str, Any]], agent_type: str) -> List[Dict[str, Any]]:
    """
    Normalize data to agent-specific format.
    
    Handles alternative field names and auto-extracts missing fields.
    
    Args:
        data: List of data dictionaries
        agent_type: Agent type ('router', 'computer', 'email')
        
    Returns:
        List of normalized data dictionaries
    """
    normalized = []
    
    for record in data:
        normalized_record = record.copy()
        
        if agent_type.lower() == 'router':
            # Handle alternative field names
            if 'destination' in normalized_record and 'dest_ip' not in normalized_record:
                normalized_record['dest_ip'] = normalized_record.pop('destination')
            
            if 'dest_port' in normalized_record and 'port' not in normalized_record:
                normalized_record['port'] = normalized_record['dest_port']
            
            if 'duration' in normalized_record and 'duration_seconds' not in normalized_record:
                normalized_record['duration_seconds'] = normalized_record['duration']
            
            # Ensure at least one destination identifier
            if not normalized_record.get('dest_ip') and not normalized_record.get('dest_domain'):
                if 'dest' in normalized_record:
                    normalized_record['dest_ip'] = normalized_record.pop('dest')
        
        elif agent_type.lower() == 'computer':
            # Handle alternative field names
            if 'process' in normalized_record and 'process_name' not in normalized_record:
                normalized_record['process_name'] = normalized_record.pop('process')
            
            if 'username' in normalized_record and 'user' not in normalized_record:
                normalized_record['user'] = normalized_record.pop('username')
            
            if 'file' in normalized_record and 'file_path' not in normalized_record:
                normalized_record['file_path'] = normalized_record.pop('file')
            
            if 'command' in normalized_record and 'command_line' not in normalized_record:
                normalized_record['command_line'] = normalized_record.pop('command')
        
        elif agent_type.lower() == 'email':
            # Handle alternative field names
            if 'from' in normalized_record and 'sender' not in normalized_record:
                normalized_record['sender'] = normalized_record.pop('from')
            
            if 'attachment' in normalized_record and 'attachment_name' not in normalized_record:
                normalized_record['attachment_name'] = normalized_record.pop('attachment')
            
            if 'size' in normalized_record and 'attachment_size' not in normalized_record:
                normalized_record['attachment_size'] = normalized_record.pop('size')
            
            if 'urls' in normalized_record and 'links' not in normalized_record:
                normalized_record['links'] = normalized_record.pop('urls')
            
            # Auto-extract sender_domain if not provided
            if 'sender_domain' not in normalized_record and 'sender' in normalized_record:
                sender = normalized_record['sender']
                if '@' in sender:
                    normalized_record['sender_domain'] = sender.split('@')[1].lower()
            
            # Auto-extract attachment_type if not provided
            if 'attachment_type' not in normalized_record and 'attachment_name' in normalized_record:
                att_name = normalized_record['attachment_name']
                if '.' in att_name:
                    normalized_record['attachment_type'] = att_name.split('.')[-1].lower()
        
        normalized.append(normalized_record)
    
    return normalized


def load_training_data(file_path: str, agent_type: str, format: str = None) -> List[Dict[str, Any]]:
    """
    Load training data from file, auto-detecting format if not specified.
    
    Args:
        file_path: Path to data file
        agent_type: Agent type ('router', 'computer', 'email')
        format: File format ('json', 'csv', 'jsonl'). If None, auto-detect from extension.
        
    Returns:
        List of normalized data dictionaries
        
    Raises:
        ValueError: If format is not supported or cannot be detected
        FileNotFoundError: If file doesn't exist
    """
    file_path = Path(file_path)
    
    # Auto-detect format from extension if not provided
    if format is None:
        ext = file_path.suffix.lower()
        if ext == '.json':
            format = 'json'
        elif ext == '.csv':
            format = 'csv'
        elif ext == '.jsonl':
            format = 'jsonl'
        else:
            raise ValueError(f"Cannot auto-detect format from extension: {ext}")
    
    format = format.lower()
    
    # Parse based on format
    if format == 'json':
        data = parse_json_file(str(file_path))
    elif format == 'jsonl':
        data = parse_jsonl_file(str(file_path))
    elif format == 'csv':
        data = parse_csv_file(str(file_path), agent_type)
    else:
        raise ValueError(f"Unsupported format: {format}. Supported formats: json, csv, jsonl")
    
    # Normalize data
    normalized_data = normalize_data(data, agent_type)
    
    logger.info(f"Loaded {len(normalized_data)} records from {file_path} (format: {format})")
    
    return normalized_data




