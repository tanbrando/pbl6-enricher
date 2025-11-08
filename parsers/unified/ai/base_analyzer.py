"""
Base AI Analyzer
Abstract base class for AI analysis providers
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from datetime import datetime

from shared.logger import get_logger

logger = get_logger(__name__)


class BaseAIAnalyzer(ABC):
    """
    Base class for AI analyzers
    
    Implementations:
    - OpenAI (GPT-4, GPT-3.5)
    - Ollama (Local LLMs)
    - Claude (Anthropic)
    - Gemini (Google)
    """
    
    def __init__(self, provider_name: str):
        self.provider_name = provider_name
        self.logger = logger
        self.enabled = False
    
    @abstractmethod
    def analyze_attack(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze attack event
        
        Args:
            event_data: Parsed event data (from parser)
            context: Additional context (enrichment, correlation)
        
        Returns:
            AI analysis result
        """
        pass
    
    @abstractmethod
    def generate_narrative(
        self,
        events: List[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate attack narrative
        
        Args:
            events: List of related events
            enrichment: Enrichment data
        
        Returns:
            Human-readable narrative
        """
        pass
    
    @abstractmethod
    def assess_threat(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assess threat level
        
        Args:
            event_data: Event data
            enrichment: Enrichment data
        
        Returns:
            Threat assessment
        """
        pass
    
    @abstractmethod
    def recommend_actions(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate remediation recommendations
        
        Args:
            event_data: Event data
            enrichment: Enrichment data
        
        Returns:
            List of recommendations
        """
        pass
    
    def _prepare_context(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> str:
        """Prepare context for AI prompt"""
        
        context_parts = []
        
        # Event summary
        context_parts.append("## Event Summary")
        context_parts.append(f"Timestamp: {event_data.get('timestamp', 'N/A')}")
        
        if 'src_ip' in event_data:
            context_parts.append(f"Source IP: {event_data.get('src_ip')}")
        if 'dest_ip' in event_data:
            context_parts.append(f"Destination IP: {event_data.get('dest_ip')}")
        
        # Enrichment data
        if enrichment:
            context_parts.append("\n## Enrichment Data")
            
            # GeoIP
            if 'source' in enrichment and 'geoip' in enrichment['source']:
                geo = enrichment['source']['geoip']
                context_parts.append(f"Source Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}")
                context_parts.append(f"ISP: {geo.get('isp', 'Unknown')}")
            
            # Threat intel
            if 'source' in enrichment and 'threat_intel' in enrichment['source']:
                threat = enrichment['source']['threat_intel']
                context_parts.append(f"IP Reputation: {threat.get('reputation', 'Unknown')}")
                if 'abuseipdb' in threat:
                    abuse = threat['abuseipdb']
                    context_parts.append(f"Abuse Score: {abuse.get('abuse_confidence_score', 0)}/100")
            
            # Attack types
            if 'attacks' in enrichment:
                attack_names = [a.get('name', 'Unknown') for a in enrichment['attacks'].values()]
                context_parts.append(f"Attack Types: {', '.join(attack_names)}")
        
        return "\n".join(context_parts)
    
    def is_enabled(self) -> bool:
        """Check if AI analyzer is enabled"""
        return self.enabled