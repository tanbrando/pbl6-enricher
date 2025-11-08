"""
Utility Functions
Common helper functions used across the application
"""

import re
import hashlib
from typing import Optional, Any, Dict
from datetime import datetime
from functools import wraps
import time

from shared.logger import get_logger

logger = get_logger(__name__)


def sanitize_string(text: str) -> str:
    """Remove potentially dangerous characters from string"""
    return re.sub(r'[^\w\s\-\.\@\:]', '', text)


def truncate_string(text: str, max_length: int = 1000) -> str:
    """Truncate string to max length"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def hash_string(text: str) -> str:
    """Generate SHA256 hash of string"""
    return hashlib.sha256(text.encode()).hexdigest()


def parse_timestamp(ts: Any) -> Optional[datetime]:
    """
    Parse various timestamp formats to datetime
    
    Supports:
    - Unix timestamp (seconds or milliseconds)
    - ISO 8601 string
    - datetime object
    """
    if isinstance(ts, datetime):
        return ts
    
    if isinstance(ts, (int, float)):
        # Unix timestamp
        if ts > 1e10:  # Milliseconds
            ts = ts / 1000
        return datetime.fromtimestamp(ts)
    
    if isinstance(ts, str):
        # Try ISO 8601
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except ValueError:
            pass
        
        # Try common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
    
    return None


def format_bytes(bytes_value: int) -> str:
    """Format bytes to human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def timing_decorator(func):
    """Decorator to measure function execution time"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        logger.debug(f"{func.__name__} took {duration:.3f}s")
        return result
    return wrapper


def safe_get(dictionary: Dict, *keys, default=None) -> Any:
    """
    Safely get nested dictionary value
    
    Usage:
        data = {"a": {"b": {"c": 123}}}
        value = safe_get(data, "a", "b", "c")  # Returns 123
        value = safe_get(data, "a", "x", "y", default=0)  # Returns 0
    """
    result = dictionary
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        else:
            return default
        if result is None:
            return default
    return result


def extract_ip_from_log(log_line: str) -> Optional[str]:
    """Extract IP address from log line using regex"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    match = re.search(ip_pattern, log_line)
    return match.group(0) if match else None


def merge_dicts(*dicts: Dict) -> Dict:
    """Merge multiple dictionaries"""
    result = {}
    for d in dicts:
        result.update(d)
    return result