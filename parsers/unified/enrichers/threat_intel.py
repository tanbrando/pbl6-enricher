"""
Threat Intelligence Enricher
IP/Domain reputation lookup using public APIs
"""

import requests
from typing import Dict, Optional, Any
from functools import lru_cache
import time

from shared.logger import get_logger
from shared.config import get_settings

logger = get_logger(__name__)


class ThreatIntelEnricher:
    """
    Threat intelligence enrichment
    
    Supports:
    - AbuseIPDB (IP reputation)
    - VirusTotal (IP/Domain reputation)
    - Local blacklist/whitelist
    """
    
    def __init__(self):
        self.logger = logger
        self.settings = get_settings()
        
        # API keys from environment
        self.abuseipdb_key = self.settings.abuseipdb_api_key
        self.virustotal_key = self.settings.virustotal_api_key
        
        # Rate limiting
        self.last_abuseipdb_call = 0
        self.last_virustotal_call = 0
        
        # Local blacklist/whitelist
        self.blacklist = set()
        self.whitelist = set()
        
        self._load_local_lists()
    
    def _load_local_lists(self):
        """Load local blacklist/whitelist"""
        try:
            # Load from file if exists
            from pathlib import Path
            blacklist_file = Path("parsers/data/threat_intel/blacklist.txt")
            if blacklist_file.exists():
                with open(blacklist_file) as f:
                    self.blacklist = set(line.strip() for line in f if line.strip())
                self.logger.info(f"Loaded {len(self.blacklist)} blacklisted IPs")
        except Exception as e:
            self.logger.warning(f"Failed to load blacklist: {e}")
    
    @lru_cache(maxsize=1000)
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich IP with threat intelligence
        
        Args:
            ip_address: IP address to check
        
        Returns:
            Threat intelligence data
        """
        result = {
            "ip": ip_address,
            "reputation": "unknown",
            "is_malicious": False,
            "confidence": 0,
            "sources": []
        }
        
        # Check local blacklist first
        if ip_address in self.blacklist:
            result.update({
                "reputation": "malicious",
                "is_malicious": True,
                "confidence": 100,
                "sources": ["local_blacklist"]
            })
            return result
        
        # Check local whitelist
        if ip_address in self.whitelist:
            result.update({
                "reputation": "clean",
                "is_malicious": False,
                "confidence": 100,
                "sources": ["local_whitelist"]
            })
            return result
        
        # AbuseIPDB lookup
        if self.abuseipdb_key:
            abuseipdb_data = self._check_abuseipdb(ip_address)
            if abuseipdb_data:
                result["abuseipdb"] = abuseipdb_data
                result["sources"].append("abuseipdb")
                
                # Update reputation based on score
                score = abuseipdb_data.get("abuse_confidence_score", 0)
                if score > 75:
                    result["reputation"] = "malicious"
                    result["is_malicious"] = True
                    result["confidence"] = score
                elif score > 50:
                    result["reputation"] = "suspicious"
                    result["confidence"] = score
                elif score > 0:
                    result["reputation"] = "potentially_suspicious"
                    result["confidence"] = score
                else:
                    result["reputation"] = "clean"
        
        # VirusTotal lookup
        if self.virustotal_key:
            vt_data = self._check_virustotal(ip_address)
            if vt_data:
                result["virustotal"] = vt_data
                result["sources"].append("virustotal")
                
                # Update reputation based on detections
                malicious = vt_data.get("malicious", 0)
                suspicious = vt_data.get("suspicious", 0)
                
                if malicious > 3:
                    result["reputation"] = "malicious"
                    result["is_malicious"] = True
                    result["confidence"] = min(100, malicious * 10)
                elif malicious > 0 or suspicious > 0:
                    result["reputation"] = "suspicious"
                    result["confidence"] = min(100, (malicious + suspicious) * 5)
        
        return result
    
    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check IP against AbuseIPDB
        
        API Docs: https://docs.abuseipdb.com/
        """
        if not self.abuseipdb_key:
            return None
        
        # Rate limiting (1 request per second for free tier)
        now = time.time()
        if now - self.last_abuseipdb_call < 1:
            time.sleep(1)
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            self.last_abuseipdb_call = time.time()
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt"),
                    "country_code": data.get("countryCode"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType")
                }
            else:
                self.logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.debug(f"AbuseIPDB lookup failed for {ip_address}: {e}")
            return None
    
    def _check_virustotal(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Check IP against VirusTotal
        
        API Docs: https://developers.virustotal.com/reference/ip-info
        """
        if not self.virustotal_key:
            return None
        
        # Rate limiting (4 requests per minute for free tier)
        now = time.time()
        if now - self.last_virustotal_call < 15:
            time.sleep(15)
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            
            headers = {
                "x-apikey": self.virustotal_key
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            self.last_virustotal_call = time.time()
            
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attributes.get("reputation", 0),
                    "country": attributes.get("country"),
                    "asn": attributes.get("asn")
                }
            else:
                self.logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.debug(f"VirusTotal lookup failed for {ip_address}: {e}")
            return None
    
    def enrich_multiple_ips(self, ip_addresses: list) -> Dict[str, Dict[str, Any]]:
        """Enrich multiple IPs (with caching)"""
        results = {}
        
        for ip in set(ip_addresses):
            if ip:
                results[ip] = self.enrich_ip(ip)
        
        return results
    
    def add_to_blacklist(self, ip_address: str):
        """Add IP to local blacklist"""
        self.blacklist.add(ip_address)
        self.logger.info(f"Added {ip_address} to blacklist")
    
    def add_to_whitelist(self, ip_address: str):
        """Add IP to local whitelist"""
        self.whitelist.add(ip_address)
        self.logger.info(f"Added {ip_address} to whitelist")