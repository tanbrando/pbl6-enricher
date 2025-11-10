"""
Loki Query Client
Wrapper for Loki API with error handling and retry logic
"""

import requests
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from shared.config import get_settings
from shared.logger import get_logger
from shared.exceptions import (
    LokiConnectionError,
    LokiQueryError,
    TransactionNotFoundError
)

logger = get_logger(__name__)


class LokiClient:
    """
    Loki API Client
    
    Usage:
        client = LokiClient()
        result = client.query('{job="modsecurity"}')
        log = client.query_transaction("transaction_id", job="modsecurity")
    """
    
    def __init__(self, loki_url: Optional[str] = None, timeout: Optional[int] = None):
        """
        Initialize Loki client
        
        Args:
            loki_url: Loki server URL (if None, uses config)
            timeout: Request timeout in seconds (if None, uses config)
        """
        settings = get_settings()
        self.loki_url = loki_url or settings.loki_url
        self.timeout = timeout or settings.loki_timeout
        
        logger.info(f"LokiClient initialized with URL: {self.loki_url}")
    
    def health_check(self) -> bool:
        """
        Check if Loki is healthy
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            response = requests.get(
                urljoin(self.loki_url, "/ready"),
                timeout=2
            )
            is_healthy = response.status_code == 200
            logger.debug(f"Loki health check: {'OK' if is_healthy else 'FAIL'}")
            return is_healthy
        except Exception as e:
            logger.error(f"Loki health check failed: {e}")
            return False
    
    def query(
        self,
        query: str,
        limit: int = 5000,
        time_range: Optional[tuple] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute LogQL query
        
        Args:
            query: LogQL query string (e.g., '{job="modsecurity"}')
            limit: Maximum number of results
            time_range: Optional (start_time, end_time) tuple
        
        Returns:
            List of log results
        
        Raises:
            LokiConnectionError: If cannot connect to Loki
            LokiQueryError: If query fails
        """
        logger.debug(f"Executing query: {query} (limit={limit})")
        
        # Build query parameters
        params = {
            "query": query,
            "limit": limit
        }
        
        # Choose the correct endpoint based on whether time_range is provided
        if time_range:
            # Use query_range endpoint for time range queries
            endpoint = "/loki/api/v1/query_range"
            start_time, end_time = time_range
            # Expect timestamps to be already in nanoseconds (Unix timestamp * 1e9)
            params["start"] = int(start_time)
            params["end"] = int(end_time)
        else:
            # Use instant query endpoint
            endpoint = "/loki/api/v1/query"
        
        # Build full URL for debugging
        full_url = urljoin(self.loki_url, endpoint)
        
        logger.debug(f"Executing {endpoint} - Query: {params['query']}, Limit: {params['limit']}")
        if time_range:
            logger.debug(f"Time range: {start_time} -> {end_time}")
        
        # Execute query
        try:
            response = requests.get(
                full_url,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()
        except requests.exceptions.Timeout:
            logger.error(f"Loki query timeout after {self.timeout}s")
            raise LokiConnectionError(
                "Loki query timeout",
                details={"timeout": self.timeout}
            )
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to Loki: {e}")
            raise LokiConnectionError(
                "Cannot connect to Loki",
                details={"loki_url": self.loki_url}
            )
        except requests.exceptions.HTTPError as e:
            logger.error(f"Loki HTTP error: {e}")
            raise LokiQueryError(
                f"Loki returned error: {e}",
                details={"status_code": response.status_code}
            )
        except Exception as e:
            logger.error(f"Unexpected error during Loki query: {e}")
            raise LokiQueryError(
                f"Query failed: {str(e)}",
                details={"error_type": type(e).__name__}
            )
        
        # Parse response
        data = response.json()
        
        if data.get("status") != "success":
            logger.error(f"Loki query failed: {data}")
            raise LokiQueryError(
                "Loki query returned non-success status",
                details=data
            )
        
        results = data.get("data", {}).get("result", [])
        logger.info(f"Query returned {len(results)} results")
        
        return results
    
    def query_transaction(
        self,
        transaction_id: str,
        source: str = "modsecurity",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_range_minutes: int = 30
    ) -> str:
        """
        Query for specific transaction/event by ID
        
        Args:
            transaction_id: Transaction/event unique ID
            source: Log source name (modsecurity, suricata, zeek, ufw)
            start_time: Start timestamp from Grafana (Unix timestamp in ns or ISO format)
            end_time: End timestamp from Grafana (Unix timestamp in ns or ISO format)
            time_range_minutes: Fallback time range if start/end not provided (±minutes from now)
        
        Returns:
            Raw log content as string
        
        Raises:
            TransactionNotFoundError: If transaction not found
        """
        logger.info(f"Querying transaction: {transaction_id} (source={source})")
        
        # Build query
        query = f'{{source="{source}"}} |= `{transaction_id}`'

        # Determine time range
        if start_time and end_time:
            # Use provided time range from Grafana (already in nanoseconds)
            start_ns = int(start_time) if isinstance(start_time, (int, float)) else int(self._parse_timestamp(start_time).timestamp() * 1e9)
            end_ns = int(end_time) if isinstance(end_time, (int, float)) else int(self._parse_timestamp(end_time).timestamp() * 1e9)
            logger.debug(f"Using provided time range: {start_ns} to {end_ns} (nanoseconds)")
        else:
            # Fallback: use default time range (last N minutes)
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(minutes=time_range_minutes)
            start_ns = int(start_dt.timestamp() * 1e9)
            end_ns = int(end_dt.timestamp() * 1e9)
            logger.debug(f"Using fallback time range: {start_dt} to {end_dt} ({start_ns} to {end_ns} ns)")
        
        # Execute query
        results = self.query(
            query=query,
            limit=1,
            time_range=(start_ns, end_ns)
        )
        
        if not results:
            logger.warning(f"Transaction {transaction_id} not found")
            raise TransactionNotFoundError(
                transaction_id,
                details={"source": source, "time_range": f"{start_dt} to {end_dt}"}
            )
        
        # Extract log content
        # Loki result format: {"stream": {...}, "values": [[timestamp, log_line], ...]}
        log_entry = results[0]
        values = log_entry.get("values", [])
        
        if not values:
            raise TransactionNotFoundError(transaction_id)
        
        # Get the log line (second element of first value tuple)
        log_content = values[0][1]
        
        logger.debug(f"Transaction found, log size: {len(log_content)} bytes")
        return log_content
    
    def query_range(
        self,
        query: str,
        start_time: datetime,
        end_time: datetime,
        limit: int = 5000
    ) -> List[Dict[str, Any]]:
        """
        Query logs within time range
        
        Args:
            query: LogQL query string
            start_time: Range start (datetime)
            end_time: Range end (datetime)
            limit: Maximum results
        
        Returns:
            List of log results
        """
        logger.debug(f"Range query: {start_time} to {end_time}")
        
        # Convert datetime to nanoseconds
        start_ns = int(start_time.timestamp() * 1e9)
        end_ns = int(end_time.timestamp() * 1e9)
        
        return self.query(
            query=query,
            limit=limit,
            time_range=(start_ns, end_ns)
        )
    
    def count_logs(
        self,
        query: str,
        time_range_hours: int = 24
    ) -> int:
        """
        Count logs matching query
        
        Args:
            query: LogQL query string
            time_range_hours: Hours to look back
        
        Returns:
            Count of matching logs
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=time_range_hours)
        
        results = self.query_range(query, start_time, end_time, limit=10000)
        
        total = sum(len(r.get("values", [])) for r in results)
        logger.info(f"Count query returned: {total}")
        
        return total
    
    def _parse_timestamp(self, timestamp: str) -> datetime:
        """
        Parse timestamp from Grafana (can be Unix nanoseconds or ISO format)
        
        Args:
            timestamp: Timestamp string from Grafana
        
        Returns:
            datetime object (timezone aware)
        """
        try:
            # Try parsing as Unix timestamp in nanoseconds (Grafana default)
            ts_ns = int(timestamp)
            ts_seconds = ts_ns / 1e9
            return datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        
        try:
            # Try parsing as Unix timestamp in milliseconds
            ts_ms = int(timestamp)
            if ts_ms > 1e12:  # Likely milliseconds
                ts_seconds = ts_ms / 1e3
                return datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        
        try:
            # Try parsing as ISO format
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            pass
        
        # Fallback: return current time
        logger.warning(f"Could not parse timestamp: {timestamp}, using current time")
        return datetime.now(timezone.utc)


# Singleton instance
_loki_client: Optional[LokiClient] = None


def get_loki_client() -> LokiClient:
    """Get singleton Loki client instance"""
    global _loki_client
    if _loki_client is None:
        _loki_client = LokiClient()
    return _loki_client