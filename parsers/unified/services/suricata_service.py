"""
Suricata Service Layer
Business logic for Suricata log analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone

from shared.logger import get_logger
from shared.loki_client import get_loki_client
from shared.exceptions import TransactionNotFoundError, ParseError
from parsers.suricata_parser import SuricataParser

logger = get_logger(__name__)


class SuricataService:
    """
    Service layer for Suricata log processing
    """
    
    def __init__(self):
        self.loki_client = get_loki_client()
        self.parser = SuricataParser()
        self.logger = logger
    
    def get_flow_summary(
        self,
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get summary for flow_id
        
        Args:
            flow_id: Suricata flow_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Flow summary dict
        """
        self.logger.info(f"Getting summary for flow_id: {flow_id}")
        
        # Query all events for this flow_id
        log_entries = self._query_flow_events(flow_id, start_time, end_time)
        
        # Parse summary
        summary = self.parser.parse_flow_summary(log_entries)
        
        return summary
    
    def get_alerts(
        self,
        flow_id: Optional[str] = None,
        src_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_range_minutes: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get alerts (severity 1 or 2)
        
        Args:
            flow_id: Filter by flow_id (optional)
            src_ip: Filter by source IP (optional)
            dest_ip: Filter by dest IP (optional)
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
            time_range_minutes: Time range to search
        
        Returns:
            List of alerts
        """
        self.logger.info(f"Getting alerts (flow_id={flow_id}, src_ip={src_ip})")
        
        if flow_id:
            log_entries = self._query_flow_events(flow_id, start_time, end_time)
        elif src_ip or dest_ip:
            log_entries = self._query_by_ip(src_ip, dest_ip, time_range_minutes, start_time, end_time)
        else:
            raise ValueError("Must provide flow_id or src_ip/dest_ip")
        
        # Parse alerts
        alerts = self.parser.parse_alerts(log_entries)
        
        return alerts
    
    def get_http_events(
        self,
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get HTTP events for flow
        
        Args:
            flow_id: Suricata flow_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            List of HTTP events
        """
        self.logger.info(f"Getting HTTP events for flow_id: {flow_id}")
        
        log_entries = self._query_flow_events(flow_id, start_time, end_time)
        http_events = self.parser.parse_http_events(log_entries)
        
        return http_events
    
    def get_dns_events(
        self,
        flow_id: Optional[str] = None,
        src_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get DNS events
        
        Args:
            flow_id: Filter by flow_id (optional)
            src_ip: Filter by source IP (optional)
            time_range_minutes: Time range to search
        
        Returns:
            List of DNS events
        """
        self.logger.info(f"Getting DNS events (flow_id={flow_id}, src_ip={src_ip})")
        
        if flow_id:
            log_entries = self._query_flow_events(flow_id, start_time, end_time)
        elif src_ip:
            log_entries = self._query_by_ip(src_ip, start_time, end_time)
        else:
            raise ValueError("Must provide flow_id or src_ip")
        
        dns_events = self.parser.parse_dns_events(log_entries)
        
        return dns_events
    
    def get_tls_events(
        self, 
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get TLS events for flow
        
        Args:
            flow_id: Suricata flow_id
        
        Returns:
            List of TLS events
        """
        self.logger.info(f"Getting TLS events for flow_id: {flow_id}")
        
        log_entries = self._query_flow_events(flow_id, start_time, end_time)
        tls_events = self.parser.parse_tls_events(log_entries)
        
        return tls_events
    
    def get_context_logs(
        self, 
        flow_id: str, 
        start_time: Optional[str] = None, 
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive context for flow (all event types)
        
        Args:
            flow_id: Suricata flow_id
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            All events organized by type
        """
        self.logger.info(f"Getting context logs for flow_id: {flow_id}")
        
        log_entries = self._query_flow_events(flow_id, start_time, end_time)
        
        # Parse all event types
        context = {
            "alerts": self.parser.parse_alerts(log_entries),
            "http": self.parser.parse_http_events(log_entries),
            "dns": self.parser.parse_dns_events(log_entries),
            "tls": self.parser.parse_tls_events(log_entries),
            "flow": self.parser.parse_flow_events(log_entries)
        }
        
        return context
    
    def get_alert_categorization(
        self, 
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Categorize alerts for flow
        
        Args:
            flow_id: Suricata flow_id
        
        Returns:
            Alert categorization stats
        """
        self.logger.info(f"Categorizing alerts for flow_id: {flow_id}")
        
        log_entries = self._query_flow_events(flow_id, start_time, end_time)
        alerts = self.parser.parse_alerts(log_entries)
        
        categorization = self.parser.categorize_alerts(alerts)
        
        return categorization
    
    def correlate_with_zeek(
        self,
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Correlate Suricata events with Zeek logs
        
        Args:
            flow_id: Suricata flow_id
        
        Returns:
            Correlated events from Zeek
        """
        self.logger.info(f"Correlating with Zeek for flow_id: {flow_id}")
        
        # Get Suricata summary to extract 4-tuple
        summary = self.get_flow_summary(flow_id, start_time, end_time)
        
        src_ip = summary.get("src_ip")
        dest_ip = summary.get("dest_ip")
        src_port = summary.get("src_port")
        dest_port = summary.get("dest_port")
        timestamp = summary.get("timestamp")
        
        # Query Zeek logs with same 4-tuple
        # Note: This requires Zeek logs in Loki with job="zeek"
        
        try:
            zeek_query = f'''
            {{source="zeek"}} 
                |= `"id.orig_h":"{src_ip}"` 
                |= `"id.orig_p":{src_port}`
                |= `"id.resp_h":"{dest_ip}"`
                |= `"id.resp_p":{dest_port}`
            '''
            
            if start_time and end_time:
                start_dt = self.loki_client._parse_timestamp(start_time)
                end_dt = self.loki_client._parse_timestamp(end_time)    
            else:
                end_dt = datetime.now(timezone.utc)
                start_dt = end_dt - timedelta(minutes=30)
            
            results = self.loki_client.query_range(
                query=zeek_query,
                start_time=start_dt,
                end_time=end_dt,
                limit=100
            )
            
            # Extract log lines
            zeek_logs = []
            for result in results:
                values = result.get("values", [])
                for timestamp, log_line in values:
                    zeek_logs.append({
                        "timestamp": timestamp,
                        "log": log_line
                    })
            
            return {
                "zeek_logs_found": len(zeek_logs),
                "zeek_logs": zeek_logs[:10]  # Return first 10
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to correlate with Zeek: {e}")
            return {
                "zeek_logs_found": 0,
                "error": str(e)
            }
    
    def correlate_with_ufw(
        self,
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Correlate with UFW firewall blocks
        
        Args:
            flow_id: Suricata flow_id
        
        Returns:
            UFW blocks for same src_ip
        """
        self.logger.info(f"Correlating with UFW for flow_id: {flow_id}")
        
        # Get Suricata summary
        summary = self.get_flow_summary(flow_id, start_time, end_time)
        src_ip = summary.get("src_ip")
        
        try:
            ufw_query = f'''
            {{source="ufw"}} 
                |= `"src_ip":"{src_ip}"`
            '''
            
            if start_time and end_time:
                start_dt = self.loki_client._parse_timestamp(start_time)
                end_dt = self.loki_client._parse_timestamp(end_time)    
            else:
                end_dt = datetime.now(timezone.utc)
                start_dt = end_dt - timedelta(hours=1)
            
            results = self.loki_client.query_range(
                query=ufw_query,
                start_time=start_dt,
                end_time=end_dt,
                limit=50
            )
            
            # Extract blocks
            ufw_blocks = []
            for result in results:
                values = result.get("values", [])
                for timestamp, log_line in values:
                    ufw_blocks.append({
                        "timestamp": timestamp,
                        "log": log_line
                    })
            
            return {
                "ufw_blocks_found": len(ufw_blocks),
                "blocks": ufw_blocks
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to correlate with UFW: {e}")
            return {
                "ufw_blocks_found": 0,
                "error": str(e)
            }
    
    # ===== Private Helper Methods =====
    
    def _query_flow_events(
        self,
        flow_id: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[str]:
        """Query all events for flow_id"""
        query = f'{{source="suricata"}} |= `"flow_id":{flow_id}`'
        
        # Use provided time range or fallback to last 30 minutes
        if start_time and end_time:
            # Parse timestamps from Grafana using loki_client's parser
            start_dt = self.loki_client._parse_timestamp(start_time)
            end_dt = self.loki_client._parse_timestamp(end_time)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(minutes=30)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            limit=1000
        )
        
        # Extract log lines
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        if not log_entries:
            raise TransactionNotFoundError(
                flow_id,
                details={"type": "flow_id", "source": "suricata"}
            )
        
        return log_entries
    
    def _query_by_ip(
        self,
        src_ip: Optional[str],
        dest_ip: Optional[str],
        time_range_minutes: int,
        
    ) -> List[str]:
        """Query events by IP address"""
        
        # Build query
        filters = []
        if src_ip:
            filters.append(f'|= `"src_ip":"{src_ip}"`')
        if dest_ip:
            filters.append(f'|= `"dest_ip":"{dest_ip}"`')
        
        query = '{source="suricata"} ' + ' '.join(filters)
        
        # Time range
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=time_range_minutes)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_time,
            end_time=end_time,
            limit=1000
        )
        
        # Extract log lines
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        return log_entries