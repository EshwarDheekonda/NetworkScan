"""
Utility functions for the Knowledge Fusion module.
"""

from functools import lru_cache
import hashlib
import json

def cache_key_from_data(data):
    """Generate a cache key from data."""
    if isinstance(data, dict):
        data_str = json.dumps(data, sort_keys=True, default=str)
    elif isinstance(data, str):
        data_str = data
    else:
        data_str = str(data)
    
    return hashlib.md5(data_str.encode()).hexdigest()
