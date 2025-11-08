"""
Unit Tests for Foundation Layer
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta, timezone

from shared.config import get_settings
from shared.logger import get_logger
from shared.loki_client import LokiClient
from shared.exceptions import LokiConnectionError, TransactionNotFoundError
from shared.utils import (
    sanitize_string,
    parse_timestamp,
    format_bytes,
    safe_get,
    extract_ip_from_log
)


class TestConfig:
    """Test configuration management"""
    
    def test_load_config(self):
        settings = get_settings()
        assert settings is not None
        assert settings.loki_url is not None
        assert settings.flask_port == 5000
    
    def test_is_production(self):
        settings = get_settings()
        # Should be False in test environment
        assert not settings.is_production


class TestLogger:
    """Test logging setup"""
    
    def test_get_logger(self):
        logger = get_logger("test_module")
        assert logger is not None
        assert logger.name == "test_module"
    
    def test_log_message(self, caplog):
        import logging
        # Set the caplog to capture at INFO level and enable propagation for test logger
        logger = get_logger("test_logger_caplog")
        # Enable propagation to root logger so caplog can capture it
        logger.propagate = True
        
        with caplog.at_level(logging.INFO, logger="test_logger_caplog"):
            logger.info("Test message")
            # Check if the message was captured
            assert len(caplog.records) > 0
            assert caplog.records[0].message == "Test message"
            assert caplog.records[0].levelname == "INFO"


class TestLokiClient:
    """Test Loki client"""
    
    @patch('requests.get')
    def test_health_check_success(self, mock_get):
        mock_get.return_value.status_code = 200
        
        client = LokiClient()
        assert client.health_check() is True
    
    @patch('requests.get')
    def test_health_check_failure(self, mock_get):
        mock_get.side_effect = Exception("Connection failed")
        
        client = LokiClient()
        assert client.health_check() is False
    
    @patch('requests.get')
    def test_query_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "result": [
                    {
                        "stream": {"job": "modsecurity"},
                        "values": [["1609459200000000000", "log line content"]]
                    }
                ]
            }
        }
        mock_get.return_value = mock_response
        
        client = LokiClient()
        results = client.query('{job="modsecurity"}')
        
        assert len(results) == 1
        assert results[0]["stream"]["job"] == "modsecurity"
    
    @patch('requests.get')
    def test_query_transaction_not_found(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": "success",
            "data": {"result": []}
        }
        mock_get.return_value = mock_response
        
        client = LokiClient()
        
        with pytest.raises(TransactionNotFoundError):
            client.query_transaction("nonexistent_id")


class TestUtils:
    """Test utility functions"""
    
    def test_sanitize_string(self):
        assert sanitize_string("hello<script>") == "helloscript"
        assert sanitize_string("test@example.com") == "test@example.com"
    
    def test_parse_timestamp(self):
        # Unix timestamp
        dt = parse_timestamp(1609459200)
        assert isinstance(dt, datetime)
        
        # ISO string
        dt = parse_timestamp("2025-01-07T03:55:42")
        assert isinstance(dt, datetime)
        
        # datetime object
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        dt = parse_timestamp(now)
        assert dt == now
    
    def test_format_bytes(self):
        assert format_bytes(1024) == "1.00 KB"
        assert format_bytes(1048576) == "1.00 MB"
    
    def test_safe_get(self):
        data = {"a": {"b": {"c": 123}}}
        assert safe_get(data, "a", "b", "c") == 123
        assert safe_get(data, "a", "x", "y", default=0) == 0
    
    def test_extract_ip_from_log(self):
        log = "Connection from 192.168.1.100 to 10.0.0.5"
        ip = extract_ip_from_log(log)
        assert ip == "192.168.1.100"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])