"""
Unified Enrichment Service
Combines all enrichers into single interface
"""

from typing import Dict, List, Any, Optional

from shared.logger import get_logger
from enrichers.geoip import GeoIPEnricher
from enrichers.threat_intel import ThreatIntelEnricher
from enrichers.attack_db import AttackIntelEnricher
from enrichers.user_agent import UserAgentEnricher

logger = get_logger(__name__)


class EnrichmentService:
    """
    Unified enrichment service
    
    Combines:
    - GeoIP enrichment
    - Threat intelligence
    - Attack intelligence
    - User-Agent analysis
    """
    
    def __init__(self):
        self.logger = logger
        
        # Initialize enrichers
        self.geoip = GeoIPEnricher()
        self.threat_intel = ThreatIntelEnricher()
        self.attack_intel = AttackIntelEnricher()
        self.user_agent = UserAgentEnricher()
        
        self.logger.info("✅ Enrichment service initialized")
    
    def enrich_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Full IP enrichment (GeoIP + Threat Intel)
        
        Args:
            ip_address: IP address to enrich
        
        Returns:
            Combined enrichment data
        """
        result = {
            "ip": ip_address
        }
        
        # GeoIP
        geo_data = self.geoip.enrich_ip(ip_address)
        result["geoip"] = geo_data
        
        # Threat intelligence
        threat_data = self.threat_intel.enrich_ip(ip_address)
        result["threat_intel"] = threat_data
        
        # Overall assessment
        result["assessment"] = self._assess_ip(geo_data, threat_data)
        
        return result
    
    def enrich_transaction(
        self,
        src_ip: str,
        dest_ip: Optional[str] = None,
        attack_types: Optional[List[str]] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Full transaction enrichment
        
        Args:
            src_ip: Source IP address
            dest_ip: Destination IP address (optional)
            attack_types: List of attack types (optional)
            user_agent: User-Agent string (optional)
        
        Returns:
            Comprehensive enrichment data
        """
        result = {}
        
        # Source IP enrichment
        if src_ip:
            result["source"] = self.enrich_ip(src_ip)
        
        # Destination IP enrichment
        if dest_ip:
            result["destination"] = self.enrich_ip(dest_ip)
        
        # Attack intelligence
        if attack_types:
            result["attacks"] = self.attack_intel.enrich_multiple_attacks(attack_types)
            result["remediation"] = self.attack_intel.get_remediation_steps(attack_types)
            result["mitre_summary"] = self.attack_intel.get_mitre_summary(attack_types)
        
        # User-Agent analysis
        if user_agent:
            result["user_agent_analysis"] = self.user_agent.analyze(user_agent)
        
        # Overall threat assessment
        result["threat_assessment"] = self._assess_transaction(result)
        
        return result
    
    def _assess_ip(self, geo_data: Dict, threat_data: Dict) -> Dict[str, Any]:
        """Assess IP based on geo and threat data"""
        risk_level = "low"
        risk_score = 0
        factors = []
        
        # Check threat intelligence
        if threat_data.get("is_malicious"):
            risk_level = "critical"
            risk_score += 80
            factors.append("Known malicious IP")
        elif threat_data.get("reputation") == "suspicious":
            risk_level = "high"
            risk_score += 50
            factors.append("Suspicious IP reputation")
        
        # Check AbuseIPDB score
        if "abuseipdb" in threat_data:
            abuse_score = threat_data["abuseipdb"].get("abuse_confidence_score", 0)
            if abuse_score > 75:
                risk_score += 60
                factors.append(f"High abuse score ({abuse_score})")
            elif abuse_score > 50:
                risk_score += 30
                factors.append(f"Moderate abuse score ({abuse_score})")
        
        # Check geographic anomalies
        country = geo_data.get("country")
        if country in ["Unknown", "Private"]:
            # Private IPs are not necessarily risky
            pass
        else:
            # Could add geo-based risk here
            pass
        
        # Finalize risk level
        if risk_score > 70:
            risk_level = "critical"
        elif risk_score > 50:
            risk_level = "high"
        elif risk_score > 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "factors": factors
        }
    
    def _assess_transaction(self, enrichment_data: Dict) -> Dict[str, Any]:
        """Overall transaction threat assessment"""
        risk_score = 0
        risk_factors = []
        
        # Source IP risk
        if "source" in enrichment_data:
            src_assessment = enrichment_data["source"].get("assessment", {})
            risk_score += src_assessment.get("risk_score", 0)
            risk_factors.extend(src_assessment.get("factors", []))
        
        # Attack severity
        if "attacks" in enrichment_data:
            for attack_type, attack_data in enrichment_data["attacks"].items():
                severity = attack_data.get("severity", "Unknown")
                if severity == "Critical":
                    risk_score += 40
                    risk_factors.append(f"Critical attack: {attack_data.get('name')}")
                elif severity == "High":
                    risk_score += 25
                    risk_factors.append(f"High severity attack: {attack_data.get('name')}")
        
        # User-Agent suspiciousness
        if "user_agent_analysis" in enrichment_data:
            ua_analysis = enrichment_data["user_agent_analysis"]
            if ua_analysis.get("is_suspicious"):
                risk_score += 20
                risk_factors.append(f"Suspicious User-Agent: {ua_analysis.get('type')}")
        
        # Determine overall risk level
        if risk_score > 100:
            risk_level = "critical"
        elif risk_score > 70:
            risk_level = "high"
        elif risk_score > 40:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "risk_score": min(100, risk_score),
            "risk_factors": risk_factors,
            "recommendation": self._get_recommendation(risk_level)
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on risk level"""
        recommendations = {
            "critical": "IMMEDIATE ACTION REQUIRED: Block source IP, investigate incident, check for compromise",
            "high": "URGENT: Review logs, consider blocking IP, monitor for further activity",
            "medium": "ATTENTION: Monitor activity, review security posture, consider rate limiting",
            "low": "MONITOR: Continue normal monitoring, log for future reference"
        }
        return recommendations.get(risk_level, "Review security logs")


# Singleton instance
_enrichment_service: Optional[EnrichmentService] = None


def get_enrichment_service() -> EnrichmentService:
    """Get singleton enrichment service instance"""
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = EnrichmentService()
    return _enrichment_service