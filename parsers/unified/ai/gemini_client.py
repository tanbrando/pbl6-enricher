"""
Gemini API Client
Uses OpenAI SDK with Gemini's OpenAI-compatible endpoint
Supports both direct API calls and Azure APIM proxy
"""

from openai import OpenAI
from typing import Dict, Any, Optional, List
from shared.logger import get_logger
from shared.config import get_settings

logger = get_logger(__name__)


class GeminiClient:
    """
    Wrapper for Gemini API using OpenAI SDK
    Supports:
    1. Direct API via OpenAI SDK with Gemini base_url (localhost)
    2. APIM proxy with same interface (Azure VM - bypass datacenter IP blocking)
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.api_key = self.settings.gemini_api_key
        self.use_apim = self.settings.gemini_use_apim
        self.apim_endpoint = self.settings.gemini_apim_endpoint
        self.apim_subscription_key = self.settings.gemini_apim_subscription_key
        
        if self.use_apim:
            self._init_apim()
        else:
            self._init_direct()
    
    def _init_direct(self):
        """Initialize direct Gemini API via OpenAI SDK"""
        # Gemini's OpenAI-compatible endpoint
        if not self.api_key:
            self.logger.warning("⚠️  Google Gemini API key not found. Set in .env:")
            self.logger.warning("   GEMINI_API_KEY=your-api-key-here")
            raise ValueError("GEMINI_API_KEY is required for direct API mode")
        
        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
        )
        self.mode = "direct"
        logger.info("✅ Gemini client initialized (Direct API - OpenAI compatible)")
    
    def _init_apim(self):
        """Initialize APIM proxy mode"""
        if not self.apim_endpoint:
            raise ValueError("GEMINI_APIM_ENDPOINT required when GEMINI_USE_APIM=true")
        
        # APIM mode: Backend policy adds x-goog-api-key automatically
        # Client just calls APIM endpoint with subscription key
        default_headers = {}
        if self.apim_subscription_key:
            default_headers["api-key"] = self.apim_subscription_key
        
        self.client = OpenAI(
            api_key="not-needed",  # APIM backend handles Gemini authentication
            base_url=self.apim_endpoint,
            default_headers=default_headers if default_headers else {}
        )
        self.mode = "apim"
        logger.info(f"✅ Gemini client initialized (APIM Proxy: {self.apim_endpoint})")
        if self.apim_subscription_key:
            logger.info(f"   Using APIM subscription key: {self.apim_subscription_key[:8]}...")
    
    def chat_completions_create(
        self,
        model: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.3,
        max_tokens: int = 2000,
        response_format: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Any:
        """
        Create chat completion using OpenAI SDK
        
        Args:
            model: Model name (e.g., 'gemini-2.5-flash')
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Max tokens to generate
            response_format: Optional format specification (e.g., {"type": "json_object"})
            **kwargs: Additional parameters
        
        Returns:
            OpenAI ChatCompletion response object
        """
        try:
            params = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            # Add response format if specified (for JSON mode)
            if response_format:
                params["response_format"] = response_format
            
            # Add any extra parameters
            params.update(kwargs)
            
            response = self.client.chat.completions.create(**params)
            return response
            
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            raise

