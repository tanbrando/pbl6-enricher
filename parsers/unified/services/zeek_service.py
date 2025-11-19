"""
Zeek Service Layer
Business logic for Zeek log analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone

from shared.logger import get_logger
from shared.loki_client import get_loki_client
from shared.exceptions import TransactionNotFoundError, ParseError
from parsers.zeek_parser import ZeekParser

logger = get_logger(__name__)


class ZeekService:
    """
    Service layer for Zeek log processing
    """
    
    def __init__(self):
        self.loki_client = get_loki_client()
        self.parser = ZeekParser()
        self.logger = logger
    
    def get_notice_summary(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get notice summary
        
        Args:
            notice_uid: Zeek notice UID
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Notice summary dict
        """
        self.logger.info(f"Getting summary for notice UID: {notice_uid}")
        
        # Query notice logs
        log_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        
        # Parse summary
        summary = self.parser.parse_notice_summary(log_entries)
        
        # Add connection count
        try:
            conn_entries = self._query_related_connections(
                summary.get("src"),
                summary.get("dst"),
                summary.get("timestamp"),
                start_time=start_time,
                end_time=end_time
            )
            summary["total_connections"] = len(conn_entries)
        except:
            summary["total_connections"] = 0
        
        return summary
    
    def get_related_notices(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_range_minutes: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get all related notices (same src/dst within time range)
        
        Args:
            notice_uid: Primary notice UID
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
            time_range_minutes: Time range to search
        
        Returns:
            List of related notices
        """
        self.logger.info(f"Getting related notices for UID: {notice_uid}")
        
        # Get primary notice
        primary_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(primary_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        # Query all notices for same src/dst
        log_entries = self._query_logs_by_ip(
            src_ip=src,
            dest_ip=dst,
            log_type="notice",
            time_range_minutes=time_range_minutes,
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse notices
        notices = self.parser.parse_notices(log_entries)
        
        return notices
    
    def get_conn_summary(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get connection summary for notice
        
        Args:
            notice_uid: Zeek notice UID
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            Connection statistics
        """
        self.logger.info(f"Getting conn summary for notice UID: {notice_uid}")
        
        # Get notice
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        # Query connections
        conn_entries = self._query_related_connections(
            src_ip=src,
            dest_ip=dst,
            notice_timestamp=summary.get("timestamp"),
            start_time=start_time,
            end_time=end_time
        )
        
        # Parse connection summary
        conn_summary = self.parser.parse_conn_summary(conn_entries)
        
        return conn_summary
    
    def get_http_events(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get HTTP events related to notice
        
        Args:
            notice_uid: Notice UID
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
        
        Returns:
            List of HTTP events
        """
        self.logger.info(f"Getting HTTP events for notice UID: {notice_uid}")
        
        # Get notice IPs
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        # Query HTTP logs
        http_entries = self._query_logs_by_ip(
            src_ip=src,
            dest_ip=dst,
            log_type="http",
            start_time=start_time,
            end_time=end_time,
            time_range_minutes=30
        )
        
        # Parse HTTP events
        http_events = self.parser.parse_http_events(http_entries)
        
        return http_events
    
    def get_ssl_events(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get SSL/TLS events related to notice
        
        Args:
            notice_uid: Notice UID
        
        Returns:
            List of SSL events
        """
        self.logger.info(f"Getting SSL events for notice UID: {notice_uid}")
        
        # Get notice IPs
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        # Query SSL logs
        ssl_entries = self._query_logs_by_ip(
            src_ip=src,
            dest_ip=dst,
            log_type="ssl",
            start_time=start_time,
            end_time=end_time,
            time_range_minutes=30
        )
        
        # Parse SSL events
        ssl_events = self.parser.parse_ssl_events(ssl_entries)
        
        return ssl_events
    
    def get_dns_events(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get DNS events related to notice
        
        Args:
            notice_uid: Notice UID
        
        Returns:
            List of DNS events (queries before/during/after notice)
        """
        self.logger.info(f"Getting DNS events for notice UID: {notice_uid}")
        
        # Get notice
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        notice_time = summary.get("timestamp")
        
        # Query DNS logs
        dns_entries = self._query_logs_by_ip(
            src_ip=src,
            dest_ip=None,
            log_type="dns",
            start_time=start_time,
            end_time=end_time,
            time_range_minutes=30
        )
        
        # Parse DNS events
        dns_events = self.parser.parse_dns_events(dns_entries)
        
        # Annotate position relative to notice
        for event in dns_events:
            event_time = event.get("ts")
            # Simple comparison (should parse timestamps properly)
            if event_time < notice_time:
                event["position"] = "before"
            else:
                event["position"] = "after"
        
        return dns_events
    
    def get_weird_events(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get weird events (protocol anomalies)
        
        Args:
            notice_uid: Notice UID
        
        Returns:
            List of weird events
        """
        self.logger.info(f"Getting weird events for notice UID: {notice_uid}")
        
        # Get notice IPs
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        # Query weird logs
        weird_entries = self._query_logs_by_ip(
            src_ip=src,
            dest_ip=dst,
            log_type="weird",
            start_time=start_time,
            end_time=end_time,
            time_range_minutes=30
        )
        
        # Parse weird events
        weird_events = self.parser.parse_weird_events(weird_entries)
        
        return weird_events
    
    def get_taxonomy(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get notice taxonomy/categorization
        
        Args:
            notice_uid: Notice UID
        
        Returns:
            Categorized notice data
        """
        self.logger.info(f"Getting taxonomy for notice UID: {notice_uid}")
        
        # Get all related notices
        notices = self.get_related_notices(notice_uid, start_time=start_time, end_time=end_time)
        
        # Categorize
        taxonomy = self.parser.categorize_notices(notices)
        
        return taxonomy
    
    def correlate_with_suricata(
        self,
        notice_uid: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Correlate Zeek notice with Suricata alerts
        
        Args:
            notice_uid: Notice UID
        
        Returns:
            Suricata correlation data
        """
        self.logger.info(f"Correlating with Suricata for notice UID: {notice_uid}")
        
        # Get notice
        notice_entries = self._query_logs_by_uid(notice_uid, log_type="notice", start_time=start_time, end_time=end_time)
        summary = self.parser.parse_notice_summary(notice_entries)
        
        src = summary.get("src")
        dst = summary.get("dst")
        
        try:
            # Query Suricata logs
            suricata_query = f'''
            {{source="suricata"}} 
                |= `"src_ip":"{src}"`
                |= `"dest_ip":"{dst}"`
            '''

            if start_time and end_time:
                start_dt = self.loki_client._parse_timestamp(start_time)
                end_dt = self.loki_client._parse_timestamp(end_time)
            else:
                end_dt = datetime.now(timezone.utc)
                start_dt = end_dt - timedelta(minutes=30)
            
            results = self.loki_client.query_range(
                query=suricata_query,
                start_time=start_dt,
                end_time=end_dt,
                limit=100
            )
            
            # Extract events
            suricata_events = []
            for result in results:
                values = result.get("values", [])
                for timestamp, log_line in values:
                    try:
                        import json
                        event = json.loads(log_line)
                        suricata_events.append({
                            "timestamp": event.get("timestamp"),
                            "source": "suricata",
                            "event_type": event.get("event_type"),
                            "signature": event.get("alert", {}).get("signature") if event.get("event_type") == "alert" else None
                        })
                    except:
                        continue
            
            return {
                "suricata_events_found": len(suricata_events),
                "events": suricata_events[:20]  # First 20
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to correlate with Suricata: {e}")
            return {
                "suricata_events_found": 0,
                "error": str(e)
            }
    
    # ===== Private Helper Methods =====
    
    def _query_logs_by_uid(
        self,
        uid: str,
        log_type: str = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[str]:
        """Query Zeek logs by UID"""
        
        # Build query
        if log_type:
            query = f'{{source="zeek", log_type="{log_type}"}} |= `"uid":"{uid}"`'
        else:
            query = f'{{source="zeek"}} |= `"uid":"{uid}"`'
        
        # Use provided time range or fallback to last 24 hours
        if start_time and end_time:
            start_dt = self.loki_client._parse_timestamp(start_time)
            end_dt = self.loki_client._parse_timestamp(end_time)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(hours=24)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            limit=500
        )
        
        # Extract log lines
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        if not log_entries:
            raise TransactionNotFoundError(
                uid,
                details={"type": "notice_uid", "log_type": log_type}
            )
        
        return log_entries
    
    def _query_logs_by_ip(
        self,
        src_ip: Optional[str],
        dest_ip: Optional[str],
        log_type: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_range_minutes: int = 30
    ) -> List[str]:
        """Query Zeek logs by IP address"""
        
        # Build query
        filters = []
        if src_ip:
            filters.append(f'|= `"id.orig_h":"{src_ip}"`')
        if dest_ip:
            filters.append(f'|= `"id.resp_h":"{dest_ip}"`')
        
        query = f'{{source="zeek", log_type="{log_type}"}} ' + ' '.join(filters)
        
        # Use provided time range or fallback
        if start_time and end_time:
            start_dt = self.loki_client._parse_timestamp(start_time)
            end_dt = self.loki_client._parse_timestamp(end_time)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(minutes=time_range_minutes)
        
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
        
        return log_entries
    
    def _query_notice_logs_by_ip(
        self,
        src_ip: str,
        dest_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[str]:
        """Query notice logs by IP addresses"""
        
        # Build query
        filters = []
        if src_ip:
            filters.append(f'|= `"src":"{src_ip}"`')
        if dest_ip:
            filters.append(f'|= `"dst":"{dest_ip}"`')
        
        query = f'{{source="zeek", log_type="notice"}} ' + ' '.join(filters)
        
        # Use provided time range or fallback to last 24 hours
        if start_time and end_time:
            start_dt = self.loki_client._parse_timestamp(start_time)
            end_dt = self.loki_client._parse_timestamp(end_time)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(hours=24)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            limit=500
        )
        
        # Extract log lines
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        return log_entries
    
    def _query_related_connections(
        self,
        src_ip: str,
        dest_ip: str,
        notice_timestamp: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[str]:
        """Query conn.log for related connections"""
        
        query = f'''
        {{source="zeek", log_type="conn"}} 
            |= `{src_ip}`
            |= `{dest_ip}`
        '''
        
        # Use provided time range or fallback to ±30 minutes around notice
        if start_time and end_time:
            start_dt = self.loki_client._parse_timestamp(start_time)
            end_dt = self.loki_client._parse_timestamp(end_time)
        else:
            end_dt = datetime.now(timezone.utc)
            start_dt = end_dt - timedelta(hours=1)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_dt,
            end_time=end_dt,
            limit=500
        )
        
        # Extract log lines
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        return log_entries
    
    def get_notice_summary_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get notice summary by source and destination IPs (for notices without UID)
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            start_time: Start timestamp (from Grafana)
            end_time: End timestamp (from Grafana)
            note_type: Optional notice type filter (e.g., Scan::Port_Scan)
        
        Returns:
            Notice summary dict
        """
        self.logger.info(f"Getting notice for src={src_ip}, dst={dst_ip}")
        
        # Query notice logs by IPs
        log_entries = self._query_notice_logs_by_ip(
            src_ip=src_ip,
            dest_ip=dst_ip,
            start_time=start_time,
            end_time=end_time,
        )
        
        if not log_entries:
            raise TransactionNotFoundError(
                transaction_id=f"{src_ip}:{dst_ip}",
                source="zeek_notice",
                details={"src": src_ip, "dst": dst_ip}
            )
        
        # Parse summary
        summary = self.parser.parse_notice_summary(log_entries)
        
        self.logger.info(f"Notice summary: {summary.get('total_notices')} notices")
        return summary
    
    def get_conn_summary_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get connection summary by IPs"""
        log_entries = self._query_logs_by_ip(src_ip, dst_ip, "conn", start_time, end_time)
        return self.parser.parse_conn_summary(log_entries)
    
    def get_http_events_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get HTTP events by IPs"""
        log_entries = self._query_logs_by_ip(src_ip, dst_ip, "http", start_time, end_time)
        return self.parser.parse_http_events(log_entries)
    
    def get_ssl_events_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get SSL/TLS events by IPs"""
        log_entries = self._query_logs_by_ip(src_ip, dst_ip, "ssl", start_time, end_time)
        return self.parser.parse_ssl_events(log_entries)
    
    def get_dns_events_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get DNS events by IPs"""
        log_entries = self._query_logs_by_ip(src_ip, dst_ip, "dns", start_time, end_time)
        return self.parser.parse_dns_events(log_entries)
    
    def get_weird_events_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get weird events by IPs"""
        log_entries = self._query_logs_by_ip(src_ip, dst_ip, "weird", start_time, end_time)
        return self.parser.parse_weird_events(log_entries)
    
    def correlate_with_suricata_by_ips(
        self,
        src_ip: str,
        dst_ip: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """Correlate with Suricata alerts by IPs"""
        # Use first notice to get timestamp context
        notice_summary = self.get_notice_summary_by_ips(src_ip, dst_ip, start_time, end_time)
        notice_ts = notice_summary.get("timestamp")
        
        # Query Suricata for same IPs around same time
        from services.suricata_service import SuricataService
        suricata_service = SuricataService()
        
        # Build query for Suricata alerts matching src/dst IPs
        try:
            alerts = suricata_service.query_alerts_by_ip(src_ip, dst_ip, start_time, end_time)
            
            return {
                "zeek_notice": notice_summary,
                "suricata_alerts": alerts,
                "correlation_count": len(alerts),
                "correlation_type": "ip_based"
            }
        except Exception as e:
            self.logger.warning(f"Suricata correlation failed: {e}")
            return {
                "zeek_notice": notice_summary,
                "suricata_alerts": [],
                "correlation_count": 0,
                "error": str(e)
            }
