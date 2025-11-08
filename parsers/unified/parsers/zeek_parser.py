"""
Zeek Log Parser
Parses Zeek logs in both TSV and JSON formats
Supports multiple log types: conn, http, dns, ssl, notice, weird
"""

import json
import re
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import Counter

from shared.logger import get_logger
from shared.exceptions import ParseError
from shared.utils import safe_get, parse_timestamp

logger = get_logger(__name__)


class ZeekParser:
    """
    Parser for Zeek logs
    
    Supports:
    - TSV format (default Zeek output)
    - JSON format (with json-logs package)
    
    Log Types:
    - conn: Network connections
    - http: HTTP requests/responses
    - dns: DNS queries/responses
    - ssl: TLS/SSL handshakes
    - notice: Zeek notices/alerts
    - weird: Protocol anomalies
    """
    
    def __init__(self):
        self.logger = logger
    
    def detect_format(self, log_line: str) -> str:
        """
        Detect if log is TSV or JSON
        
        Args:
            log_line: Single log line
        
        Returns:
            'json' or 'tsv'
        """
        log_line = log_line.strip()
        
        # Skip comment lines
        if log_line.startswith('#'):
            return 'comment'
        
        # Try JSON
        if log_line.startswith('{'):
            try:
                json.loads(log_line)
                return 'json'
            except json.JSONDecodeError:
                pass
        
        # Default to TSV
        return 'tsv'
    
    def parse_line(self, log_line: str, log_type: str = None) -> Optional[Dict[str, Any]]:
        """
        Parse single log line (auto-detect format)
        
        Args:
            log_line: Single log line
            log_type: Log type hint (conn, http, dns, etc.)
        
        Returns:
            Parsed log dict or None
        """
        format_type = self.detect_format(log_line)
        
        if format_type == 'comment':
            return None
        elif format_type == 'json':
            return self.parse_json_line(log_line)
        else:
            # TSV parsing needs header context, skip for now
            # In production, you'd parse TSV with header metadata
            self.logger.debug("TSV format detected, attempting JSON fallback")
            return self.parse_json_line(log_line)
    
    def parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON format log line"""
        try:
            data = json.loads(line.strip())
            
            # Normalize field names (Zeek uses dots in field names)
            normalized = self._normalize_field_names(data)
            
            return normalized
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse JSON: {e}")
            return None
    
    def parse_tsv_line(self, line: str, fields: List[str]) -> Optional[Dict[str, Any]]:
        """
        Parse TSV format log line
        
        Args:
            line: TSV log line
            fields: Field names from header
        
        Returns:
            Parsed log dict
        """
        if line.startswith('#'):
            return None
        
        values = line.split('\t')
        
        if len(values) != len(fields):
            self.logger.warning(f"Field count mismatch: {len(values)} vs {len(fields)}")
            return None
        
        # Create dict
        data = {}
        for field, value in zip(fields, values):
            # Handle special values
            if value == '-':
                data[field] = None
            elif value == '(empty)':
                data[field] = ''
            else:
                data[field] = self._convert_value(value)
        
        # Normalize field names
        normalized = self._normalize_field_names(data)
        
        return normalized
    
    def parse_notice_summary(self, log_entries: List[str]) -> Dict[str, Any]:
        """
        Parse notice log for summary
        
        Args:
            log_entries: List of notice.log lines
        
        Returns:
            Notice summary dict
        """
        self.logger.debug("Parsing notice summary")
        
        notices = []
        for line in log_entries:
            notice = self.parse_line(line, log_type='notice')
            if notice:
                notices.append(notice)
        
        if not notices:
            raise ParseError("No valid notices found")
        
        # Get primary notice
        primary = notices[0]
        
        # Count notice types
        notice_types = Counter(n.get('note') for n in notices)
        
        # Count weird events (if any weird logs are included)
        weird_count = sum(1 for n in notices if 'weird' in n.get('note', '').lower())
        
        summary = {
            "notice_uid": primary.get("uid"),
            "timestamp": primary.get("ts"),
            "notice_type": primary.get("note"),
            "msg": primary.get("msg"),
            "src": primary.get("id_orig_h") or primary.get("src"),
            "dst": primary.get("id_resp_h") or primary.get("dst"),
            "proto": primary.get("proto"),
            "total_notices": len(notices),
            "total_weird_events": weird_count,
            "notice_types": dict(notice_types)
        }
        
        return summary
    
    def parse_notices(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract all notices
        
        Args:
            log_entries: List of notice.log lines
        
        Returns:
            List of notice dicts
        """
        self.logger.debug("Parsing notices")
        
        notices = []
        
        for line in log_entries:
            notice = self.parse_line(line, log_type='notice')
            if notice:
                notices.append({
                    "ts": notice.get("ts"),
                    "uid": notice.get("uid"),
                    "notice_type": notice.get("note"),
                    "msg": notice.get("msg"),
                    "sub": notice.get("sub"),
                    "src": notice.get("id_orig_h") or notice.get("src"),
                    "dst": notice.get("id_resp_h") or notice.get("dst"),
                    "proto": notice.get("proto"),
                    "actions": notice.get("actions", [])
                })
        
        self.logger.info(f"Extracted {len(notices)} notices")
        return notices
    
    def parse_conn_summary(self, log_entries: List[str]) -> Dict[str, Any]:
        """
        Parse and summarize connection logs
        
        Args:
            log_entries: List of conn.log lines
        
        Returns:
            Connection summary statistics
        """
        self.logger.debug("Parsing connection summary")
        
        connections = []
        for line in log_entries:
            conn = self.parse_line(line, log_type='conn')
            if conn:
                connections.append(conn)
        
        if not connections:
            return {
                "total_connections": 0,
                "unique_dest_ports": 0,
                "duration": {},
                "bytes": {},
                "packets": {},
                "protocols": {}
            }
        
        # Aggregate stats
        total_conns = len(connections)
        dest_ports = set(c.get("id_resp_p") for c in connections if c.get("id_resp_p"))
        
        # Duration stats
        durations = [c.get("duration") for c in connections if c.get("duration")]
        duration_stats = {
            "total_seconds": sum(durations) if durations else 0,
            "min_seconds": min(durations) if durations else 0,
            "max_seconds": max(durations) if durations else 0,
            "avg_seconds": sum(durations) / len(durations) if durations else 0
        }
        
        # Bytes stats
        orig_bytes = [c.get("orig_bytes") or 0 for c in connections]
        resp_bytes = [c.get("resp_bytes") or 0 for c in connections]
        
        bytes_stats = {
            "orig_bytes": sum(orig_bytes),
            "resp_bytes": sum(resp_bytes),
            "total_bytes": sum(orig_bytes) + sum(resp_bytes),
            "orig_ratio": sum(orig_bytes) / (sum(orig_bytes) + sum(resp_bytes)) if sum(orig_bytes) + sum(resp_bytes) > 0 else 0
        }
        
        # Packet stats
        orig_pkts = [c.get("orig_pkts") or 0 for c in connections]
        resp_pkts = [c.get("resp_pkts") or 0 for c in connections]
        
        packet_stats = {
            "orig_pkts": sum(orig_pkts),
            "resp_pkts": sum(resp_pkts),
            "total_pkts": sum(orig_pkts) + sum(resp_pkts)
        }
        
        # Protocol/service stats
        services = Counter(c.get("service") for c in connections if c.get("service"))
        conn_states = Counter(c.get("conn_state") for c in connections if c.get("conn_state"))
        
        # Top dest ports
        port_counter = Counter(c.get("id_resp_p") for c in connections if c.get("id_resp_p"))
        top_ports = []
        for port, count in port_counter.most_common(10):
            service = self._port_to_service(port)
            # Count successful connections
            success = sum(1 for c in connections if c.get("id_resp_p") == port and c.get("conn_state") == "SF")
            top_ports.append({
                "port": port,
                "service": service,
                "count": count,
                "success": success
            })
        
        summary = {
            "total_connections": total_conns,
            "unique_dest_ports": len(dest_ports),
            "unique_dest_hosts": len(set(c.get("id_resp_h") for c in connections)),
            "duration": duration_stats,
            "bytes": bytes_stats,
            "packets": packet_stats,
            "protocols": dict(services),
            "connection_states": dict(conn_states),
            "top_dest_ports": top_ports
        }
        
        return summary
    
    def parse_http_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract HTTP events
        
        Args:
            log_entries: List of http.log lines
        
        Returns:
            List of HTTP events
        """
        self.logger.debug("Parsing HTTP events")
        
        http_events = []
        
        for line in log_entries:
            http = self.parse_line(line, log_type='http')
            if http:
                http_events.append({
                    "ts": http.get("ts"),
                    "uid": http.get("uid"),
                    "id_orig_h": http.get("id_orig_h"),
                    "id_orig_p": http.get("id_orig_p"),
                    "id_resp_h": http.get("id_resp_h"),
                    "id_resp_p": http.get("id_resp_p"),
                    "method": http.get("method"),
                    "host": http.get("host"),
                    "uri": http.get("uri"),
                    "referrer": http.get("referrer"),
                    "version": http.get("version"),
                    "user_agent": http.get("user_agent"),
                    "request_body_len": http.get("request_body_len"),
                    "response_body_len": http.get("response_body_len"),
                    "status_code": http.get("status_code"),
                    "status_msg": http.get("status_msg")
                })
        
        self.logger.info(f"Extracted {len(http_events)} HTTP events")
        return http_events
    
    def parse_ssl_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract SSL/TLS events
        
        Args:
            log_entries: List of ssl.log lines
        
        Returns:
            List of SSL events
        """
        self.logger.debug("Parsing SSL events")
        
        ssl_events = []
        
        for line in log_entries:
            ssl = self.parse_line(line, log_type='ssl')
            if ssl:
                ssl_events.append({
                    "ts": ssl.get("ts"),
                    "uid": ssl.get("uid"),
                    "id_orig_h": ssl.get("id_orig_h"),
                    "id_orig_p": ssl.get("id_orig_p"),
                    "id_resp_h": ssl.get("id_resp_h"),
                    "id_resp_p": ssl.get("id_resp_p"),
                    "version": ssl.get("version"),
                    "cipher": ssl.get("cipher"),
                    "curve": ssl.get("curve"),
                    "server_name": ssl.get("server_name"),
                    "subject": ssl.get("subject"),
                    "issuer": ssl.get("issuer"),
                    "validation_status": ssl.get("validation_status"),
                    "ja3": ssl.get("ja3"),
                    "ja3s": ssl.get("ja3s"),
                    "established": ssl.get("established")
                })
        
        self.logger.info(f"Extracted {len(ssl_events)} SSL events")
        return ssl_events
    
    def parse_dns_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract DNS events
        
        Args:
            log_entries: List of dns.log lines
        
        Returns:
            List of DNS events
        """
        self.logger.debug("Parsing DNS events")
        
        dns_events = []
        
        for line in log_entries:
            dns = self.parse_line(line, log_type='dns')
            if dns:
                dns_event = {
                    "ts": dns.get("ts"),
                    "uid": dns.get("uid"),
                    "id_orig_h": dns.get("id_orig_h"),
                    "id_orig_p": dns.get("id_orig_p"),
                    "id_resp_h": dns.get("id_resp_h"),
                    "id_resp_p": dns.get("id_resp_p"),
                    "proto": dns.get("proto"),
                    "trans_id": dns.get("trans_id"),
                    "query": dns.get("query"),
                    "qclass": dns.get("qclass"),
                    "qclass_name": dns.get("qclass_name"),
                    "qtype": dns.get("qtype"),
                    "qtype_name": dns.get("qtype_name"),
                    "rcode": dns.get("rcode"),
                    "rcode_name": dns.get("rcode_name"),
                    "AA": dns.get("AA"),
                    "TC": dns.get("TC"),
                    "RD": dns.get("RD"),
                    "RA": dns.get("RA"),
                    "Z": dns.get("Z"),
                    "answers": dns.get("answers"),
                    "TTLs": dns.get("TTLs")
                }
                
                dns_events.append(dns_event)
        
        self.logger.info(f"Extracted {len(dns_events)} DNS events")
        return dns_events
    
    def parse_weird_events(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Extract weird events (protocol anomalies)
        
        Args:
            log_entries: List of weird.log lines
        
        Returns:
            List of weird events
        """
        self.logger.debug("Parsing weird events")
        
        weird_events = []
        
        for line in log_entries:
            weird = self.parse_line(line, log_type='weird')
            if weird:
                weird_events.append({
                    "ts": weird.get("ts"),
                    "uid": weird.get("uid"),
                    "id_orig_h": weird.get("id_orig_h"),
                    "id_orig_p": weird.get("id_orig_p"),
                    "id_resp_h": weird.get("id_resp_h"),
                    "id_resp_p": weird.get("id_resp_p"),
                    "name": weird.get("name"),
                    "addl": weird.get("addl"),
                    "notice": weird.get("notice"),
                    "peer": weird.get("peer")
                })
        
        self.logger.info(f"Extracted {len(weird_events)} weird events")
        return weird_events
    
    def categorize_notices(self, notices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Categorize notices by type
        
        Args:
            notices: List of notice events
        
        Returns:
            Categorized notice statistics
        """
        notice_types = Counter(n.get("notice_type") for n in notices)
        
        # Group by behavior pattern
        behaviors = {
            "Reconnaissance": [],
            "Brute Force": [],
            "Exploitation": [],
            "Anomaly": []
        }
        
        for notice_type in notice_types.keys():
            if "Scan" in notice_type:
                behaviors["Reconnaissance"].append(notice_type)
            elif "Password" in notice_type or "Guessing" in notice_type:
                behaviors["Brute Force"].append(notice_type)
            elif "Exploit" in notice_type or "Attack" in notice_type:
                behaviors["Exploitation"].append(notice_type)
            else:
                behaviors["Anomaly"].append(notice_type)
        
        return {
            "notice_categories": dict(notice_types),
            "behavior_patterns": {k: len(v) for k, v in behaviors.items() if v},
            "severity_distribution": self._assess_notice_severity(notice_types)
        }
    
    # ===== Private Helper Methods =====
    
    def _normalize_field_names(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize Zeek field names
        Convert 'id.orig_h' to 'id_orig_h' for consistency
        """
        normalized = {}
        for key, value in data.items():
            # Replace dots with underscores
            new_key = key.replace('.', '_')
            normalized[new_key] = value
        return normalized
    
    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type"""
        # Try int
        try:
            return int(value)
        except ValueError:
            pass
        
        # Try float
        try:
            return float(value)
        except ValueError:
            pass
        
        # Try boolean
        if value.lower() in ('t', 'true'):
            return True
        if value.lower() in ('f', 'false'):
            return False
        
        # Return as string
        return value
    
    def _port_to_service(self, port: int) -> str:
        """Map port number to service name"""
        port_map = {
            20: "ftp-data",
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            8080: "http-alt"
        }
        return port_map.get(port, "unknown")
    
    def _assess_notice_severity(self, notice_types: Counter) -> Dict[str, int]:
        """Assess severity distribution of notices"""
        severity_map = {
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        for notice_type, count in notice_types.items():
            if any(x in notice_type for x in ["Scan", "Password", "Exploit"]):
                severity_map["high"] += count
            elif any(x in notice_type for x in ["SSH", "HTTP", "SSL"]):
                severity_map["medium"] += count
            else:
                severity_map["low"] += count
        
        return severity_map