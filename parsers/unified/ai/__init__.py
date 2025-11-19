"""
AI Analysis Service
Multi-provider AI integration for security event analysis
Supports: Google Gemini (Free), Azure OpenAI
"""

from typing import Dict, List, Any, Optional

from shared.logger import get_logger
from shared.config import get_settings

logger = get_logger(__name__)


class AIService:
    """
    AI Analysis Service
    
    Supports multiple AI providers:
    - Google Gemini 2.0 Flash (FREE tier - default)
    - Azure OpenAI GPT-4 Turbo
    
    Uses AI for:
    - Attack analysis
    - Threat assessment
    - Narrative generation
    - Remediation recommendations
    """
    
    def __init__(self):
        self.logger = logger
        self.settings = get_settings()
        self.analyzer = None
        
        # Select AI provider based on configuration
        ai_provider = self.settings.ai_provider.lower()
        
        if ai_provider == "gemini":
            self._initialize_gemini()
        else:
            self.logger.warning(f"⚠️  Unknown AI provider: {ai_provider}. Defaulting to Gemini.")
            self._initialize_gemini()
    
    def _initialize_gemini(self):
        """Initialize Google Gemini analyzer"""
        try:
            from ai.gemini_analyzer import GeminiAnalyzer
            self.analyzer = GeminiAnalyzer()
            
            if self.analyzer.is_enabled():
                self.logger.info("✅ AI Service initialized (Google Gemini FREE)")
            else:
                self.logger.warning("⚠️  AI Service disabled (Google Gemini not configured)")
        except ImportError as e:
            self.logger.error(f"Failed to import GeminiAnalyzer: {e}")
            self.logger.warning("   Install: pip install google-generativeai")
    
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
        if not self.analyzer:
            return {
                "error": "AI analyzer not initialized",
                "ai_enabled": False
            }
        return self.analyzer.analyze_attack(event_data, enrichment)
    
    def generate_narrative(
        self,
        events: List[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate attack narrative"""
        if not self.analyzer:
            return "AI service not available"
        return self.analyzer.generate_narrative(events, enrichment)
    
    def assess_threat(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Assess threat level"""
        if not self.analyzer:
            return {
                "threat_level": "Unknown",
                "confidence": 0,
                "reasoning": "AI service not available"
            }
        return self.analyzer.assess_threat(event_data, enrichment)
    
    def recommend_actions(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """Generate recommendations"""
        if not self.analyzer:
            return ["AI service not available - manual analysis required"]
        return self.analyzer.recommend_actions(event_data, enrichment)
    
    def is_enabled(self) -> bool:
        """Check if AI service is enabled"""
        return self.analyzer is not None and self.analyzer.is_enabled()


# Singleton instance
_ai_service: Optional[AIService] = None


def get_ai_service() -> AIService:
    """Get singleton AI service instance"""
    global _ai_service
    if _ai_service is None:
        _ai_service = AIService()
    return _ai_service