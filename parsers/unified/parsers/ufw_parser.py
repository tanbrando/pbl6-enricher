"""
UFW Log Parser (JSON Format)
Parses UFW firewall logs in JSON format (processed by Promtail)
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import Counter

from shared.logger import get_logger
from shared.exceptions import ParseError

logger = get_logger(__name__)


class UFWParser:
    """
    Parser for UFW firewall logs (JSON format)
    
    Log Format (JSON):
    {
      "action": "UFW BLOCK",
      "in": "eth0",
      "src_ip": "113.23.24.47",
      "dest_ip": "172.16.0.5",
      "proto": "TCP",
      "src_port": "42799",
      "dest_port": "21",
      "src_zone": "internet",
      "dest_zone": "internal"
    }
    """
    
    def __init__(self):
        self.logger = logger
    
    def parse_json_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse single UFW JSON log line
        
        Args:
            line: Single JSON log line
        
        Returns:
            Parsed log dict or None if invalid
        """
        try:
            data = json.loads(line.strip())
            
            # Normalize field names and types
            normalized = {
                "action": data.get("action"),
                "interface_in": data.get("in"),
                "interface_out": data.get("out"),
                "src_ip": data.get("src_ip"),
                "dest_ip": data.get("dest_ip"),
                "len": int(data.get("len")) if data.get("len") else None,
                "ttl": int(data.get("ttl")) if data.get("ttl") else None,
                "proto": data.get("proto"),
                "src_port": int(data.get("src_port")) if data.get("src_port") else None,
                "dest_port": int(data.get("dest_port")) if data.get("dest_port") else None,
                "src_zone": data.get("src_zone"),
                "dest_zone": data.get("dest_zone")
            }
            
            # Add timestamp if available
            if "timestamp" in data:
                normalized["timestamp"] = data.get("timestamp")
            
            return normalized
            
        except json.JSONDecodeError as e:
            self.logger.warning(f"Failed to parse UFW JSON: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error parsing UFW log: {e}")
            return None
    
    def parse_port_summary(
        self,
        log_entries: List[str],
        dest_port: int
    ) -> Dict[str, Any]:
        """
        Summarize blocks for specific destination port
        
        Args:
            log_entries: List of UFW JSON log lines
            dest_port: Target port number
        
        Returns:
            Port summary statistics
        """
        self.logger.debug(f"Parsing summary for port {dest_port}")
        
        blocks = []
        
        for line in log_entries:
            parsed = self.parse_json_line(line)
            if parsed and parsed.get('dest_port') == dest_port:
                blocks.append(parsed)
        
        if not blocks:
            return {
                "dest_port": dest_port,
                "total_blocks": 0,
                "unique_sources": 0,
                "proto_distribution": {},
                "zone_distribution": {},
                "time_range": {}
            }
        
        # Aggregate stats
        total_blocks = len(blocks)
        unique_sources = len(set(b.get('src_ip') for b in blocks if b.get('src_ip')))
        
        # Protocol distribution
        proto_dist = Counter(b.get('proto') for b in blocks if b.get('proto'))
        
        # Zone distribution (NEW - very useful!)
        src_zone_dist = Counter(b.get('src_zone') for b in blocks if b.get('src_zone'))
        dest_zone_dist = Counter(b.get('dest_zone') for b in blocks if b.get('dest_zone'))
        
        # Time range
        timestamps = [b.get('timestamp') for b in blocks if b.get('timestamp')]
        time_range = {
            "start": timestamps[0] if timestamps else None,
            "end": timestamps[-1] if timestamps else None
        }
        
        summary = {
            "dest_port": dest_port,
            "total_blocks": total_blocks,
            "unique_sources": unique_sources,
            "proto_distribution": dict(proto_dist),
            "zone_distribution": {
                "src_zones": dict(src_zone_dist),
                "dest_zones": dict(dest_zone_dist)
            },
            "time_range": time_range
        }
        
        return summary
    
    def parse_blocks_for_port(
        self,
        log_entries: List[str],
        dest_port: int
    ) -> List[Dict[str, Any]]:
        """
        Extract all blocks for specific port
        
        Args:
            log_entries: List of UFW JSON log lines
            dest_port: Target port number
        
        Returns:
            List of block events
        """
        self.logger.debug(f"Parsing blocks for port {dest_port}")
        
        blocks = []
        
        for line in log_entries:
            parsed = self.parse_json_line(line)
            if parsed and parsed.get('dest_port') == dest_port:
                blocks.append({
                    "timestamp": parsed.get('timestamp'),
                    "action": parsed.get('action'),
                    "src_ip": parsed.get('src_ip'),
                    "src_port": parsed.get('src_port'),
                    "src_zone": parsed.get('src_zone'),
                    "dest_ip": parsed.get('dest_ip'),
                    "dest_port": parsed.get('dest_port'),
                    "dest_zone": parsed.get('dest_zone'),
                    "proto": parsed.get('proto'),
                    "interface": parsed.get('interface_in'),
                    "packet_size": parsed.get('len'),
                    "ttl": parsed.get('ttl')
                })
        
        self.logger.info(f"Extracted {len(blocks)} blocks for port {dest_port}")
        return blocks
    
    def get_top_sources_for_port(
        self,
        log_entries: List[str],
        dest_port: int,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get top source IPs attacking port
        
        Args:
            log_entries: List of UFW JSON log lines
            dest_port: Target port number
            limit: Number of top sources to return
        
        Returns:
            List of top attacking sources with zone info
        """
        self.logger.debug(f"Getting top sources for port {dest_port}")
        
        blocks = []
        for line in log_entries:
            parsed = self.parse_json_line(line)
            if parsed and parsed.get('dest_port') == dest_port:
                blocks.append(parsed)
        
        # Count by source IP
        src_counter = Counter(b.get('src_ip') for b in blocks if b.get('src_ip'))
        
        # Get top sources with zone info
        top_sources = []
        for src_ip, count in src_counter.most_common(limit):
            # Get zone info for this IP
            ip_blocks = [b for b in blocks if b.get('src_ip') == src_ip]
            
            # Get first/last timestamp
            timestamps = [b.get('timestamp') for b in ip_blocks if b.get('timestamp')]
            
            # Get zone (should be consistent)
            zones = [b.get('src_zone') for b in ip_blocks if b.get('src_zone')]
            zone = zones[0] if zones else None
            
            # Get protocols used
            protocols = Counter(b.get('proto') for b in ip_blocks)
            
            top_sources.append({
                "src_ip": src_ip,
                "count": count,
                "src_zone": zone,
                "first_seen": timestamps[0] if timestamps else None,
                "last_seen": timestamps[-1] if timestamps else None,
                "protocols": dict(protocols)
            })
        
        return top_sources
    
    def analyze_attack_pattern(
        self,
        log_entries: List[str],
        dest_port: int
    ) -> Dict[str, Any]:
        """
        Analyze attack patterns for port with zone analysis
        
        Args:
            log_entries: List of UFW JSON log lines
            dest_port: Target port number
        
        Returns:
            Attack pattern analysis with zone distribution
        """
        blocks = []
        for line in log_entries:
            parsed = self.parse_json_line(line)
            if parsed and parsed.get('dest_port') == dest_port:
                blocks.append(parsed)
        
        if not blocks:
            return {"pattern": "none", "characteristics": {}}
        
        # Analyze characteristics
        unique_sources = len(set(b.get('src_ip') for b in blocks))
        total_blocks = len(blocks)
        
        # Zone analysis
        zone_counter = Counter(b.get('src_zone') for b in blocks)
        internet_blocks = zone_counter.get('internet', 0)
        
        # Determine pattern
        if unique_sources > 50 and total_blocks > 100:
            if internet_blocks > total_blocks * 0.8:
                pattern = "distributed_internet_attack"
                description = "Distributed attack from internet (likely botnet/DDoS)"
            else:
                pattern = "distributed_attack"
                description = "Large number of unique sources"
        elif unique_sources < 10 and total_blocks > 50:
            pattern = "focused_attack"
            description = "Few sources with high attempt rate (targeted scan)"
        elif unique_sources > 20:
            pattern = "scanning_campaign"
            description = "Multiple sources probing same port"
        else:
            pattern = "opportunistic_scan"
            description = "Low-volume scanning activity"
        
        # Protocol analysis
        protocols = Counter(b.get('proto') for b in blocks)
        
        # Calculate attack rate (if timestamps available)
        timestamps = [b.get('timestamp') for b in blocks if b.get('timestamp')]
        attack_rate = None
        if len(timestamps) > 1:
            # Simplified rate calculation
            attack_rate = f"{len(timestamps)} attempts"
        
        return {
            "pattern": pattern,
            "description": description,
            "characteristics": {
                "total_attempts": total_blocks,
                "unique_sources": unique_sources,
                "attempts_per_source": round(total_blocks / unique_sources, 2) if unique_sources > 0 else 0,
                "protocols": dict(protocols),
                "zone_distribution": dict(zone_counter),
                "internet_origin_rate": round(internet_blocks / total_blocks * 100, 2) if total_blocks > 0 else 0,
                "attack_rate": attack_rate
            }
        }
    
    def get_zone_statistics(
        self,
        log_entries: List[str],
        dest_port: int
    ) -> Dict[str, Any]:
        """
        Get detailed zone statistics (NEW - leverages zone data)
        
        Args:
            log_entries: List of UFW JSON log lines
            dest_port: Target port number
        
        Returns:
            Zone-based statistics
        """
        blocks = []
        for line in log_entries:
            parsed = self.parse_json_line(line)
            if parsed and parsed.get('dest_port') == dest_port:
                blocks.append(parsed)
        
        if not blocks:
            return {}
        
        # Group by source zone
        zone_stats = {}
        
        for zone in ['internet', 'internal', 'dmz', 'guest']:
            zone_blocks = [b for b in blocks if b.get('src_zone') == zone]
            
            if zone_blocks:
                unique_ips = len(set(b.get('src_ip') for b in zone_blocks))
                protocols = Counter(b.get('proto') for b in zone_blocks)
                
                zone_stats[zone] = {
                    "total_blocks": len(zone_blocks),
                    "unique_sources": unique_ips,
                    "percentage": round(len(zone_blocks) / len(blocks) * 100, 2),
                    "protocols": dict(protocols)
                }
        
        return zone_stats