"""
UFW Service Layer (JSON Format)
Business logic for UFW firewall log analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta, timezone

from shared.logger import get_logger
from shared.loki_client import get_loki_client
from shared.exceptions import TransactionNotFoundError, ParseError
from parsers.ufw_parser import UFWParser

logger = get_logger(__name__)


class UFWService:
    """
    Service layer for UFW log processing (JSON format)
    """
    
    def __init__(self):
        self.loki_client = get_loki_client()
        self.parser = UFWParser()
        self.logger = logger
    
    def get_port_summary(
        self,
        dest_port: int,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """Get summary statistics for port"""
        self.logger.info(f"Getting summary for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        summary = self.parser.parse_port_summary(log_entries, dest_port)
        
        return summary
    
    def get_blocks_for_port(
        self,
        dest_port: int,
        time_range_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Get all blocks for port"""
        self.logger.info(f"Getting blocks for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        blocks = self.parser.parse_blocks_for_port(log_entries, dest_port)
        
        return blocks
    
    def get_top_sources(
        self,
        dest_port: int,
        time_range_hours: int = 24,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top attacking sources (with zone info)"""
        self.logger.info(f"Getting top sources for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        top_sources = self.parser.get_top_sources_for_port(log_entries, dest_port, limit)
        
        return top_sources
    
    def get_attack_pattern(
        self,
        dest_port: int,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """Analyze attack pattern (with zone analysis)"""
        self.logger.info(f"Analyzing attack pattern for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        pattern = self.parser.analyze_attack_pattern(log_entries, dest_port)
        
        return pattern
    
    def get_zone_statistics(
        self,
        dest_port: int,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get zone-based statistics (NEW)
        
        Args:
            dest_port: Target port number
            time_range_hours: Time range
        
        Returns:
            Zone statistics
        """
        self.logger.info(f"Getting zone statistics for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        zone_stats = self.parser.get_zone_statistics(log_entries, dest_port)
        
        return zone_stats
    
    def get_timeline(
        self,
        dest_port: int,
        time_range_hours: int = 24,
        group_by_zone: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get timeline of blocks (optionally grouped by zone)
        
        Args:
            dest_port: Target port number
            time_range_hours: Time range
            group_by_zone: Group timeline by source zone
        
        Returns:
            Timeline data
        """
        self.logger.info(f"Getting timeline for port {dest_port}")
        
        log_entries = self._query_port_blocks(dest_port, time_range_hours)
        blocks = self.parser.parse_blocks_for_port(log_entries, dest_port)
        
        if group_by_zone:
            # Group by zone and time
            from collections import defaultdict
            zone_timeline = defaultdict(lambda: defaultdict(int))
            
            for block in blocks:
                timestamp = block.get('timestamp', 'unknown')
                zone = block.get('src_zone', 'unknown')
                zone_timeline[zone][timestamp] += 1
            
            # Convert to list format
            timeline = []
            for zone, time_counts in zone_timeline.items():
                for timestamp, count in sorted(time_counts.items()):
                    timeline.append({
                        "timestamp": timestamp,
                        "zone": zone,
                        "count": count
                    })
            
            return timeline
        else:
            # Simple timeline (all zones combined)
            from collections import defaultdict
            time_counts = defaultdict(int)
            
            for block in blocks:
                timestamp = block.get('timestamp', 'unknown')
                time_counts[timestamp] += 1
            
            timeline = []
            for timestamp, count in sorted(time_counts.items()):
                timeline.append({
                    "timestamp": timestamp,
                    "count": count
                })
            
            return timeline
    
    def correlate_with_suricata(
        self,
        dest_port: int,
        time_range_hours: int = 1
    ) -> Dict[str, Any]:
        """Correlate with Suricata alerts"""
        self.logger.info(f"Correlating port {dest_port} with Suricata")
        
        try:
            suricata_query = f'''
            {{source="suricata", event_type="alert"}} 
                |= `"dest_port":{dest_port}`
            '''
            
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=time_range_hours)
            
            results = self.loki_client.query_range(
                query=suricata_query,
                start_time=start_time,
                end_time=end_time,
                limit=100
            )
            
            alerts = []
            for result in results:
                values = result.get("values", [])
                for timestamp, log_line in values:
                    try:
                        import json
                        event = json.loads(log_line)
                        if event.get('event_type') == 'alert':
                            alert_data = event.get('alert', {})
                            alerts.append({
                                "timestamp": event.get('timestamp'),
                                "signature": alert_data.get('signature'),
                                "category": alert_data.get('category'),
                                "severity": alert_data.get('severity'),
                                "src_ip": event.get('src_ip')
                            })
                    except:
                        continue
            
            return {
                "suricata_alerts_found": len(alerts),
                "alerts": alerts[:20]
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to correlate with Suricata: {e}")
            return {
                "suricata_alerts_found": 0,
                "error": str(e)
            }
    
    def correlate_with_zeek(
        self,
        dest_port: int,
        time_range_hours: int = 1
    ) -> Dict[str, Any]:
        """Correlate with Zeek logs"""
        self.logger.info(f"Correlating port {dest_port} with Zeek")
        
        try:
            zeek_query = f'''
            {{source="zeek", log_type="conn"}} 
                |= `"id.resp_p":{dest_port}`
            '''

            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=time_range_hours)
            
            results = self.loki_client.query_range(
                query=zeek_query,
                start_time=start_time,
                end_time=end_time,
                limit=100
            )
            
            connections = []
            for result in results:
                values = result.get("values", [])
                for timestamp, log_line in values:
                    try:
                        import json
                        conn = json.loads(log_line)
                        connections.append({
                            "timestamp": conn.get('ts'),
                            "src_ip": conn.get('id_orig_h') or conn.get('id.orig_h'),
                            "service": conn.get('service'),
                            "conn_state": conn.get('conn_state')
                        })
                    except:
                        continue
            
            return {
                "zeek_connections_found": len(connections),
                "connections": connections[:20]
            }
            
        except Exception as e:
            self.logger.warning(f"Failed to correlate with Zeek: {e}")
            return {
                "zeek_connections_found": 0,
                "error": str(e)
            }
    
    def get_fail2ban_status(
        self,
        dest_port: int,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """Check Fail2ban status for attacking IPs"""
        self.logger.info(f"Checking Fail2ban status for port {dest_port}")
        
        top_sources = self.get_top_sources(dest_port, time_range_hours, limit=20)
        
        banned_ips = []
        
        try:
            for source in top_sources:
                src_ip = source.get('src_ip')
                
                fail2ban_query = f'{{source="fail2ban"}} |= `Ban {src_ip}`'
                results = self.loki_client.query(fail2ban_query, limit=1)
                
                if results:
                    banned_ips.append({
                        "ip": src_ip,
                        "attack_count": source.get('count'),
                        "zone": source.get('src_zone'),
                        "status": "banned"
                    })
        except:
            pass
        
        return {
            "total_attacking_ips": len(top_sources),
            "banned_ips": banned_ips,
            "ban_rate": len(banned_ips) / len(top_sources) if top_sources else 0
        }
    
    # ===== Private Helper Methods =====
    
    def _query_port_blocks(
        self,
        dest_port: int,
        time_range_hours: int
    ) -> List[str]:
        """Query UFW logs for specific port (JSON format)"""
        
        # Query for JSON logs with dest_port field
        query = f'{{source="ufw"}} |= `"dest_port": "{dest_port}"`'

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=time_range_hours)
        
        results = self.loki_client.query_range(
            query=query,
            start_time=start_time,
            end_time=end_time,
            limit=5000
        )
        
        log_entries = []
        for result in results:
            values = result.get("values", [])
            for timestamp, log_line in values:
                log_entries.append(log_line)
        
        return log_entries