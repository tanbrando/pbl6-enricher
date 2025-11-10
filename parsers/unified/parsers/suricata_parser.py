"""
Suricata EVE JSON Parser
Parses Suricata EVE (Extensible Event Format) logs
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import Counter

from shared.logger import get_logger
from shared.exceptions import ParseError
from shared.utils import safe_get, parse_timestamp

logger = get_logger(__name__)


class SuricataParser:
    """
    Parser for Suricata EVE JSON logs
    
    Handles multiple event types:
    - alert: IDS/IPS alerts
    - http: HTTP requests/responses
    - dns: DNS queries/responses
    - tls: TLS/SSL handshakes
    - flow: Network flow records
    - fileinfo: File transfer info
    """
    
    def __init__(self):
        self.logger = logger
    
    def parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse single EVE JSON line
        
        Args:
            line: Single line from EVE log (JSON string)
        
        Returns:
            Parsed JSON object or None if invalid
        """
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON line: {e}")
            return None
    
    def parse_flow_summary(self, log_entries: List[str]) -> Dict[str, Any]:
        """
        Parse and summarize events for a flow_id
        
        Args:
            log_entries: List of EVE JSON log lines (all events for flow_id)
        
        Returns:
            Flow summary with aggregated data
        """
        self.logger.debug("Parsing flow summary")
        
        events = []
        for line in log_entries:
            event = self.parse_json_line(line)
            if event:
                events.append(event)
        
        if not events:
            raise ParseError("No valid events found in log")
        
        # Get first event for basic info
        first_event = events[0]
        
        # Count event types
        event_types = Counter(e.get("event_type") for e in events)
        
        # Extract connection info from first event
        summary = {
            "flow_id": safe_get(first_event, "flow_id"),
            "timestamp": safe_get(first_event, "timestamp"),
            "src_ip": safe_get(first_event, "src_ip"),
            "src_port": safe_get(first_event, "src_port"),
            "dest_ip": safe_get(first_event, "dest_ip"),
            "dest_port": safe_get(first_event, "dest_port"),
            "proto": safe_get(first_event, "proto"),
            "total_events": len(events),
            "event_breakdown": dict(event_types),
            "total_alerts": event_types.get("alert", 0),
            "total_http_requests": event_types.get("http", 0),
            "total_dns_queries": event_types.get("dns", 0),
            "total_tls_sessions": event_types.get("tls", 0)
        }
        
        # Extract highest alert severity if present
        alert_events = [e for e in events if e.get("event_type") == "alert"]
        if alert_events:
            severities = [safe_get(e, "alert", "severity") for e in alert_events]
            severities = [s for s in severities if s is not None]
            if severities:
                summary["highest_severity"] = min(severities)  # Lower number = higher severity
        
        return summary
    
    def parse_alerts(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract all alert events
        
        Args:
            log_entries: List of EVE JSON log lines
        
        Returns:
            List of alert events
        """
        self.logger.debug("Parsing alerts")
        
        alerts = []
        
        for line in log_entries:
            event = self.parse_json_line(line)
            if not event:
                continue
            
            if event.get("event_type") == "alert":
                alert_data = event.get("alert", {})
                
                alert = {
                    "timestamp": event.get("timestamp"),
                    "signature": alert_data.get("signature"),
                    "category": alert_data.get("category"),
                    "severity": alert_data.get("severity"),
                    "signature_id": alert_data.get("signature_id"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto")
                }
                
                # Filter severity 1 or 2 (high/critical)
                if alert["severity"] in [1, 2]:
                    alerts.append(alert)
        
        self.logger.info(f"Extracted {len(alerts)} high-severity alerts")
        return alerts
    
    def parse_http_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract HTTP events
        
        Args:
            log_entries: List of EVE JSON log lines
        
        Returns:
            List of HTTP events
        """
        self.logger.debug("Parsing HTTP events")
        
        http_events = []
        
        for line in log_entries:
            event = self.parse_json_line(line)
            if not event:
                continue
            
            if event.get("event_type") == "http":
                http_data = event.get("http", {})
                
                http_event = {
                    "timestamp": event.get("timestamp"),
                    "hostname": http_data.get("hostname"),
                    "url": http_data.get("url"),
                    "http_method": http_data.get("http_method"),
                    "status": http_data.get("status"),
                    "http_user_agent": http_data.get("http_user_agent"),
                    "http_content_type": http_data.get("http_content_type"),
                    "length": http_data.get("length"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port")
                }
                
                http_events.append(http_event)
        
        self.logger.info(f"Extracted {len(http_events)} HTTP events")
        return http_events
    
    def parse_dns_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract DNS events
        
        Args:
            log_entries: List of EVE JSON log lines
        
        Returns:
            List of DNS events
        """
        self.logger.debug("Parsing DNS events")
        
        dns_events = []
        
        for line in log_entries:
            event = self.parse_json_line(line)
            if not event:
                continue
            
            if event.get("event_type") == "dns":
                dns_data = event.get("queries", {})
                
                dns_event = {
                    "timestamp": event.get("timestamp"),
                    "dns_type": dns_data.get("type"),  # query or answer
                    "rrname": dns_data.get("rrname"),
                    "rrtype": dns_data.get("rrtype"),
                    "rcode": dns_data.get("rcode"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port")
                }
                
                # Add answers if available (for answer type)
                if dns_data.get("type") == "answer":
                    answers = dns_data.get("answers", [])
                    if answers:
                        dns_event["answers"] = [a.get("rdata") for a in answers]
                
                dns_events.append(dns_event)
        
        self.logger.info(f"Extracted {len(dns_events)} DNS events")
        return dns_events
    
    def parse_tls_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract TLS/SSL events
        
        Args:
            log_entries: List of EVE JSON log lines
        
        Returns:
            List of TLS events
        """
        self.logger.debug("Parsing TLS events")
        
        tls_events = []
        
        for line in log_entries:
            event = self.parse_json_line(line)
            if not event:
                continue
            
            if event.get("event_type") == "tls":
                tls_data = event.get("tls", {})
                
                tls_event = {
                    "timestamp": event.get("timestamp"),
                    "sni": tls_data.get("sni"),
                    "version": tls_data.get("version"),
                    "ja3": safe_get(tls_data, "ja3", "hash"),
                    "ja3s": safe_get(tls_data, "ja3s", "hash"),
                    "subject": tls_data.get("subject"),
                    "issuerdn": tls_data.get("issuerdn"),
                    "notbefore": tls_data.get("notbefore"),
                    "notafter": tls_data.get("notafter"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port")
                }
                
                tls_events.append(tls_event)
        
        self.logger.info(f"Extracted {len(tls_events)} TLS events")
        return tls_events
    
    def parse_flow_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract flow events
        
        Args:
            log_entries: List of EVE JSON log lines
        
        Returns:
            List of flow events
        """
        self.logger.debug("Parsing flow events")
        
        flow_events = []
        
        for line in log_entries:
            event = self.parse_json_line(line)
            if not event:
                continue
            
            if event.get("event_type") == "flow":
                flow_data = event.get("flow", {})
                
                flow_event = {
                    "timestamp": event.get("timestamp"),
                    "flow_id": event.get("flow_id"),
                    "pkts_toserver": flow_data.get("pkts_toserver"),
                    "pkts_toclient": flow_data.get("pkts_toclient"),
                    "bytes_toserver": flow_data.get("bytes_toserver"),
                    "bytes_toclient": flow_data.get("bytes_toclient"),
                    "start": flow_data.get("start"),
                    "end": flow_data.get("end"),
                    "age": flow_data.get("age"),
                    "state": flow_data.get("state"),
                    "reason": flow_data.get("reason"),
                    "src_ip": event.get("src_ip"),
                    "src_port": event.get("src_port"),
                    "dest_ip": event.get("dest_ip"),
                    "dest_port": event.get("dest_port"),
                    "proto": event.get("proto")
                }
                
                flow_events.append(flow_event)
        
        self.logger.info(f"Extracted {len(flow_events)} flow events")
        return flow_events
    
    def categorize_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Categorize alerts by type and severity
        
        Args:
            alerts: List of alert events
        
        Returns:
            Categorized alert statistics
        """
        categories = Counter(a.get("category") for a in alerts)
        severities = Counter(a.get("severity") for a in alerts)
        signatures = Counter(a.get("signature") for a in alerts)
        
        return {
            "by_category": dict(categories.most_common()),
            "by_severity": dict(severities),
            "top_signatures": dict(signatures.most_common(10))
        }