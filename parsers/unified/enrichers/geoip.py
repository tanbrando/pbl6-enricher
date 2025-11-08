"""
GeoIP Enricher
IP geolocation using MaxMind GeoLite2 databases
"""

import os
from typing import Dict, Optional, Any
from pathlib import Path

from shared.logger import get_logger
from shared.config import get_settings

logger = get_logger(__name__)


class GeoIPEnricher:
    """
    GeoIP enrichment using MaxMind GeoLite2
    
    Requires:
    - geoip2 library
    - GeoLite2-City.mmdb
    - GeoLite2-ASN.mmdb
    """
    
    def __init__(self):
        self.logger = logger
        self.settings = get_settings()
        self.enabled = False
        self.city_reader = None
        self.asn_reader = None
        
        # Try to initialize GeoIP readers
        self._initialize()
    
    def _initialize(self):
        """Initialize GeoIP database readers"""
        try:
            import geoip2.database
            
            # Get database paths
            city_db_path = Path("parsers/data/geoip/GeoLite2-City.mmdb")
            asn_db_path = Path("parsers/data/geoip/GeoLite2-ASN.mmdb")
            
            # Check if databases exist
            if city_db_path.exists():
                self.city_reader = geoip2.database.Reader(str(city_db_path))
                self.logger.info("✅ GeoLite2-City database loaded")
            else:
                self.logger.warning("⚠️  GeoLite2-City.mmdb not found")
            
            if asn_db_path.exists():
                self.asn_reader = geoip2.database.Reader(str(asn_db_path))
                self.logger.info("✅ GeoLite2-ASN database loaded")
            else:
                self.logger.warning("⚠️  GeoLite2-ASN.mmdb not found")
            
            if self.city_reader or self.asn_reader:
                self.enabled = True
                self.logger.info("✅ GeoIP enrichment enabled")
            else:
                self.logger.warning("⚠️  GeoIP enrichment disabled (no databases)")
                
        except ImportError:
            self.logger.warning("⚠️  geoip2 library not installed. Run: pip install geoip2")
        except Exception as e:
            self.logger.error(f"Failed to initialize GeoIP: {e}")
    
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Enrich IP address with geolocation data
        
        Args:
            ip_address: IP address to enrich
        
        Returns:
            Enrichment data dict
        """
        if not self.enabled:
            return {
                "ip": ip_address,
                "geoip_available": False
            }
        
        # Skip private IPs
        if self._is_private_ip(ip_address):
            return {
                "ip": ip_address,
                "is_private": True,
                "country": "Private",
                "city": None,
                "latitude": None,
                "longitude": None,
                "asn": None,
                "isp": None
            }
        
        result = {
            "ip": ip_address,
            "is_private": False
        }
        
        # City/Location data
        if self.city_reader:
            try:
                response = self.city_reader.city(ip_address)
                
                result.update({
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "postal_code": response.postal.code,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone,
                    "continent": response.continent.name
                })
                
            except Exception as e:
                self.logger.debug(f"City lookup failed for {ip_address}: {e}")
                result.update({
                    "country": "Unknown",
                    "city": None,
                    "latitude": None,
                    "longitude": None
                })
        
        # ASN/ISP data
        if self.asn_reader:
            try:
                response = self.asn_reader.asn(ip_address)
                
                result.update({
                    "asn": f"AS{response.autonomous_system_number}",
                    "asn_organization": response.autonomous_system_organization,
                    "isp": response.autonomous_system_organization
                })
                
            except Exception as e:
                self.logger.debug(f"ASN lookup failed for {ip_address}: {e}")
                result.update({
                    "asn": None,
                    "isp": None
                })
        
        return result
    
    def enrich_multiple_ips(self, ip_addresses: list) -> Dict[str, Dict[str, Any]]:
        """
        Enrich multiple IPs at once
        
        Args:
            ip_addresses: List of IP addresses
        
        Returns:
            Dict mapping IP -> enrichment data
        """
        results = {}
        
        for ip in set(ip_addresses):  # Deduplicate
            if ip:
                results[ip] = self.enrich_ip(ip)
        
        return results
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
    
    def get_distance(self, ip1: str, ip2: str) -> Optional[float]:
        """
        Calculate distance between two IPs (in km)
        
        Args:
            ip1: First IP address
            ip2: Second IP address
        
        Returns:
            Distance in kilometers or None
        """
        if not self.city_reader:
            return None
        
        try:
            geo1 = self.enrich_ip(ip1)
            geo2 = self.enrich_ip(ip2)
            
            lat1, lon1 = geo1.get('latitude'), geo1.get('longitude')
            lat2, lon2 = geo2.get('latitude'), geo2.get('longitude')
            
            if None in (lat1, lon1, lat2, lon2):
                return None
            
            # Haversine formula
            from math import radians, cos, sin, asin, sqrt
            
            lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
            
            dlon = lon2 - lon1
            dlat = lat2 - lat1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            
            # Radius of Earth in kilometers
            r = 6371
            
            return c * r
            
        except Exception as e:
            self.logger.debug(f"Distance calculation failed: {e}")
            return None
    
    def __del__(self):
        """Clean up database readers"""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()