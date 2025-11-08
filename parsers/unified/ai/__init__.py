"""
AI Analysis Service
Azure OpenAI integration for security event analysis
"""

from typing import Dict, List, Any, Optional

from shared.logger import get_logger
from ai.ai_analyzer import AzureOpenAIAnalyzer

logger = get_logger(__name__)


class AIService:
    """
    AI Analysis Service
    
    Uses Azure OpenAI GPT-4 Turbo for:
    - Attack analysis
    - Threat assessment
    - Narrative generation
    - Remediation recommendations
    """
    
    def __init__(self):
        self.logger = logger
        self.analyzer = AzureOpenAIAnalyzer()
        
        if self.analyzer.is_enabled():
            self.logger.info("✅ AI Service initialized (Azure OpenAI)")
        else:
            self.logger.warning("⚠️  AI Service disabled (Azure OpenAI not configured)")
    
    def analyze(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Full AI analysis of security event
        
        Args:
            event_data: Parsed event data
            enrichment: Enrichment context
        
        Returns:
            Comprehensive AI analysis
        """
        return self.analyzer.analyze_attack(event_data, enrichment)
    
    def generate_narrative(
        self,
        events: List[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate attack narrative"""
        return self.analyzer.generate_narrative(events, enrichment)
    
    def assess_threat(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Assess threat level"""
        return self.analyzer.assess_threat(event_data, enrichment)
    
    def recommend_actions(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Generate recommendations"""
        return self.analyzer.recommend_actions(event_data, enrichment)
    
    def is_enabled(self) -> bool:
        """Check if AI service is enabled"""
        return self.analyzer.is_enabled()


# Singleton instance
_ai_service: Optional[AIService] = None


def get_ai_service() -> AIService:
    """Get singleton AI service instance"""
    global _ai_service
    if _ai_service is None:
        _ai_service = AIService()
    return _ai_service