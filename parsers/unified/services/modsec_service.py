"""
ModSecurity Service Layer
Business logic for ModSecurity log analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from shared.logger import get_logger
from shared.loki_client import get_loki_client
from shared.exceptions import TransactionNotFoundError, ParseError
from parsers.modsec_parser import ModSecParser

logger = get_logger(__name__)


class ModSecService:
    """
    Service layer for ModSecurity log processing
    Coordinates between Loki client and parser
    """
    
    def __init__(self):
        self.loki_client = get_loki_client()
        self.parser = ModSecParser()
        self.logger = logger
    
    def get_transaction_summary(
        self, 
        transaction_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get transaction summary
        
        Args:
            transaction_id: ModSecurity transaction unique_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Transaction summary dict
        """
        self.logger.info(f"Getting summary for transaction: {transaction_id}")
        
        # Query Loki
        log_content = self.loki_client.query_transaction(
            transaction_id=transaction_id,
            source="modsecurity",
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse
        summary = self.parser.parse_transaction_summary(log_content)
        
        # Add transaction_id if not present
        if "transaction_id" not in summary:
            summary["transaction_id"] = transaction_id
        
        return summary
    
    def get_rules(
        self, 
        transaction_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get all triggered rules for transaction
        
        Args:
            transaction_id: ModSecurity transaction unique_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            List of triggered rules
        """
        self.logger.info(f"Getting rules for transaction: {transaction_id}")
        
        # Query Loki
        log_content = self.loki_client.query_transaction(
            transaction_id=transaction_id,
            source="modsecurity",
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse rules
        rules = self.parser.parse_rules(log_content)
        
        return rules
    
    def get_taxonomy(
        self, 
        transaction_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get attack taxonomy for transaction
        
        Args:
            transaction_id: ModSecurity transaction unique_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Categorized attack tags
        """
        self.logger.info(f"Getting taxonomy for transaction: {transaction_id}")
        
        # Query Loki
        log_content = self.loki_client.query_transaction(
            transaction_id=transaction_id,
            source="modsecurity",
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse taxonomy
        taxonomy = self.parser.parse_taxonomy(log_content)
        
        return taxonomy
    
    def get_http_details(
        self, 
        transaction_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get HTTP request/response details
        
        Args:
            transaction_id: ModSecurity transaction unique_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            HTTP details dict
        """
        self.logger.info(f"Getting HTTP details for transaction: {transaction_id}")
        
        # Query Loki
        log_content = self.loki_client.query_transaction(
            transaction_id=transaction_id,
            source="modsecurity",
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse HTTP
        http_details = self.parser.parse_http_details(log_content)
        
        return http_details
    
    def get_client_analysis(
        self, 
        transaction_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze client behavior (User-Agent, IP, etc.)
        
        Args:
            transaction_id: ModSecurity transaction unique_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Client analysis dict
        """
        self.logger.info(f"Analyzing client for transaction: {transaction_id}")
        
        # Get summary and HTTP details
        summary = self.get_transaction_summary(transaction_id, start_time, end_time)
        http_details = self.get_http_details(transaction_id, start_time, end_time)
        
        # Extract User-Agent
        user_agent = http_details.get("request", {}).get("headers", {}).get("User-Agent", "")
        
        # Basic analysis
        analysis = {
            "user_agent": user_agent,
            "analysis": self._analyze_user_agent(user_agent),
            "ip_info": {
                "src_ip": summary.get("src_ip"),
                "src_port": summary.get("src_port")
            }
        }
        
        return analysis
    
    def _analyze_user_agent(self, user_agent: str) -> Dict[str, Any]:
        """Simple User-Agent analysis"""
        ua_lower = user_agent.lower()
        
        # Detect type
        if not user_agent:
            ua_type = "unknown"
            is_suspicious = True
        elif any(bot in ua_lower for bot in ["bot", "crawler", "spider"]):
            ua_type = "bot"
            is_suspicious = False
        elif any(scanner in ua_lower for scanner in ["nmap", "nikto", "sqlmap", "wpscan", "dirb"]):
            ua_type = "scanner"
            is_suspicious = True
        elif any(tool in ua_lower for tool in ["curl", "wget", "python", "java", "go-http"]):
            ua_type = "automation_tool"
            is_suspicious = True
        elif any(browser in ua_lower for browser in ["mozilla", "chrome", "safari", "firefox"]):
            ua_type = "browser"
            is_suspicious = False
        else:
            ua_type = "unknown"
            is_suspicious = True
        
        return {
            "type": ua_type,
            "is_suspicious": is_suspicious,
            "indicators": self._get_suspicious_indicators(user_agent, ua_type)
        }
    
    def _get_suspicious_indicators(self, user_agent: str, ua_type: str) -> List[str]:
        """Get list of suspicious indicators"""
        indicators = []
        
        if not user_agent:
            indicators.append("Empty User-Agent")
        
        if ua_type == "scanner":
            indicators.append("Known scanning tool detected")
        
        if ua_type == "automation_tool":
            indicators.append("Automation tool (not typical browser)")
        
        # Check for generic browser claims
        if "mozilla" in user_agent.lower() and len(user_agent) < 50:
            indicators.append("Suspiciously short browser User-Agent")
        
        return indicators