"""
Centralized Logging Configuration
Supports both JSON and text formats
"""

import logging
import sys
from pathlib import Path
from typing import Optional
from pythonjsonlogger import jsonlogger

from shared.config import get_settings


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields"""
    
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        
        # Add custom fields
        log_record['timestamp'] = record.created
        log_record['level'] = record.levelname
        log_record['logger'] = record.name
        log_record['module'] = record.module
        log_record['function'] = record.funcName
        log_record['line'] = record.lineno
        
        # Add exception info if present
        if record.exc_info:
            log_record['exception'] = self.formatException(record.exc_info)


def setup_logger(
    name: str,
    settings: Optional[object] = None
) -> logging.Logger:
    """
    Setup logger with configuration from settings
    
    Args:
        name: Logger name (usually __name__)
        settings: Settings object (if None, will load from get_settings())
    
    Returns:
        Configured logger instance
    """
    if settings is None:
        settings = get_settings()
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, settings.log_level.upper()))
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, settings.log_level.upper()))
    
    # Formatter
    if settings.log_format.lower() == "json":
        formatter = CustomJsonFormatter(
            '%(timestamp)s %(level)s %(name)s %(message)s'
        )
    else:
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (if log_file is configured)
    if settings.log_file:
        log_file = Path(settings.log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, settings.log_level.upper()))
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get or create logger for module
    
    Usage:
        from shared.logger import get_logger
        logger = get_logger(__name__)
        logger.info("Hello world")
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Logger instance
    """
    return setup_logger(name)