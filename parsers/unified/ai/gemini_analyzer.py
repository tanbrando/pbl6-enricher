"""
Google Gemini Analyzer
Gemini Flash Free integration via Google AI Studio
Uses OpenAI SDK with Gemini's OpenAI-compatible API endpoint
Supports Azure APIM proxy for VM deployments (bypasses datacenter IP blocking)
"""

from typing import Dict, List, Any, Optional
import json

from shared.logger import get_logger
from shared.config import get_settings
from ai.base_analyzer import BaseAIAnalyzer
from ai.gemini_client import GeminiClient

logger = get_logger(__name__)


class GeminiAnalyzer(BaseAIAnalyzer):
    """
    Google Gemini Flash analyzer using OpenAI SDK
    
    Uses Gemini's OpenAI-compatible API endpoint:
    - Direct mode: https://generativelanguage.googleapis.com/v1beta/openai/
    - APIM mode: Routes through Azure API Management to bypass datacenter IP blocking
    
    Requires:
    - openai library (already installed for Azure OpenAI)
    - Google AI Studio API key in .env
    
    Free tier limits:
    - 15 requests per minute
    - 1 million tokens per minute
    - 1500 requests per day
    """
    
    def __init__(self):
        super().__init__("Google Gemini")
        self.settings = get_settings()
        
        # AI settings
        self.temperature = self.settings.ai_temperature
        self.max_tokens = self.settings.ai_max_tokens
        self.timeout = self.settings.ai_timeout
        
        self.model = None
        self.model_name = None
        
        self._initialize()
    
    def _initialize(self):
        """Initialize Google Gemini client"""
        if not self.settings.gemini_enabled:
            self.logger.info("ℹ️  Google Gemini disabled in configuration")
            return
        
        try:
            # Use new unified client (supports both direct and APIM)
            self.client = GeminiClient()
            
            # Try models in order of preference
            model_names = [
                'gemini-2.5-flash',     
                'gemini-2.0-flash',      
            ]
            
            for model_name in model_names:
                try:
                    # Test with simple query using OpenAI SDK
                    test_response = self.client.client.chat.completions.create(
                        model=model_name,
                        messages=[{"role": "user", "content": "Hi"}],
                        max_tokens=10
                    )
                    
                    if test_response and test_response.choices and test_response.choices[0].message.content:
                        self.model_name = model_name
                        self.logger.info(f"   ✅ Model {model_name} is available")
                        break
                except Exception as e:
                    self.logger.warning(f"   ⚠️  Model {model_name} failed: {str(e)[:80]}")
                    continue
            
            if not self.model_name:
                raise Exception("No Gemini model available")
            
            self.enabled = True
            self.logger.info("=" * 60)
            self.logger.info("✅ Google Gemini analyzer initialized")
            
            # Log mode
            if self.settings.gemini_use_apim:
                self.logger.info(f"   Mode: APIM Proxy (Azure VM compatible)")
                self.logger.info(f"   Endpoint: {self.settings.gemini_apim_endpoint}")
            else:
                self.logger.info(f"   Mode: Direct API")
            
            self.logger.info(f"   Model: {self.model_name} (FREE)")
            self.logger.info(f"   Temperature: {self.temperature}")
            self.logger.info(f"   Max Tokens: {self.max_tokens}")
            self.logger.info(f"   Free tier: 15 RPM, 1M TPM, 1500 RPD")
            self.logger.info("=" * 60)
            
        except ImportError:
            self.logger.warning("⚠️  openai library not installed.")
            self.logger.warning("   Run: pip install openai")
        except Exception as e:
            self.logger.error(f"Failed to initialize Google Gemini: {e}")
    
    def analyze_attack(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive attack analysis using Gemini 2.0 Flash
        
        Args:
            event_data: Parsed event data
            context: Enrichment context
        
        Returns:
            Detailed AI analysis
        """
        
        if not self.enabled:
            return self._disabled_response()
        
        # Prepare context
        context_str = self._prepare_context(event_data, context)
        
        # Build prompt
        prompt = f"""You are a senior cybersecurity analyst with expertise in threat intelligence, incident response, and security operations. Analyze this security event and provide a comprehensive report.

{context_str}

## Raw Event Data
{json.dumps(event_data, indent=2)}

Provide analysis in JSON format with the following structure:
{{
  "summary": "Brief one-line summary of the attack",
  "attack_narrative": "Detailed explanation of what happened, step by step",
  "attack_chain": ["Step 1: Initial reconnaissance", "Step 2: Exploitation attempt", "..."],
  "threat_level": "Critical/High/Medium/Low",
  "confidence": 85,
  "attacker_profile": {{
    "sophistication": "High/Medium/Low",
    "automation_level": "Automated/Semi-automated/Manual",
    "likely_intent": "Data exfiltration/Credential theft/Reconnaissance/...",
    "attribution_confidence": "Low/Medium/High"
  }},
  "impact_assessment": {{
    "current_impact": "Description of actual impact",
    "potential_impact": "What could have happened if successful",
    "affected_assets": ["Asset 1", "Asset 2"],
    "business_impact": "Critical/High/Medium/Low"
  }},
  "recommendations": {{
    "immediate": ["Block source IP", "..."],
    "short_term": ["Implement rate limiting", "..."],
    "long_term": ["Security training", "..."]
  }},
  "mitre_attack_techniques": ["T1046", "T1190"],
  "similar_attack_patterns": ["Pattern name 1", "..."]
}}

Be specific, technical, and actionable. Focus on security context relevant to incident response."""

        try:
            # Generate response with OpenAI SDK (Gemini chat completions)
            response = self.client.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=8192
            )
            
            # Debug: Log response info
            self.logger.debug(f"Response received: {type(response)}")
            
            # Extract response text from OpenAI format
            if not response or not response.choices:
                raise Exception("No response from Gemini API")
            
            response_text = response.choices[0].message.content
            
            if not response_text:
                error_msg = "Empty response from Gemini API"
                if hasattr(response.choices[0], 'finish_reason'):
                    error_msg += f" - Finish reason: {response.choices[0].finish_reason}"
                raise Exception(error_msg)
            
            # Clean response - remove markdown code blocks if present
            response_text = response_text.strip()
            
            # Log raw response for debugging
            self.logger.debug(f"Raw response length: {len(response_text)}")
            self.logger.debug(f"Response starts with: {response_text[:100]}")
            self.logger.debug(f"Response ends with: {response_text[-100:]}")
            
            if response_text.startswith("```json"):
                response_text = response_text[7:]  # Remove ```json
            if response_text.startswith("```"):
                response_text = response_text[3:]  # Remove ```
            if response_text.endswith("```"):
                response_text = response_text[:-3]  # Remove trailing ```
            response_text = response_text.strip()
            
            # Check if JSON is complete (ends with })
            if not response_text.endswith('}'):
                self.logger.warning(f"Response appears truncated. Length: {len(response_text)}")
                self.logger.warning(f"Last 200 chars: {response_text[-200:]}")
                # Try to recover by adding closing braces
                open_braces = response_text.count('{')
                close_braces = response_text.count('}')
                if open_braces > close_braces:
                    missing = open_braces - close_braces
                    response_text += '}' * missing
                    self.logger.info(f"Added {missing} closing braces to complete JSON")
            
            # Parse JSON response
            analysis = json.loads(response_text)
            
            # Add metadata
            analysis["ai_provider"] = "Google Gemini"
            analysis["ai_model"] = self.model_name
            analysis["ai_timestamp"] = self._get_timestamp()
            
            return analysis
            
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Gemini JSON response: {e}")
            raw_text = response_text if 'response_text' in locals() else "No response"
            
            # Try to extract partial data
            partial_data = {
                "error": "Invalid JSON response from Gemini - possibly truncated",
                "error_detail": str(e),
                "response_length": len(raw_text) if raw_text else 0,
                "ai_provider": "Google Gemini",
                "status": "failed"
            }
            
            # Try to extract summary if visible
            if raw_text and '"summary"' in raw_text:
                try:
                    import re
                    summary_match = re.search(r'"summary":\s*"([^"]*(?:\\"[^"]*)*)"', raw_text)
                    if summary_match:
                        partial_data["partial_summary"] = summary_match.group(1)
                except:
                    pass
            
            return partial_data
        except Exception as e:
            self.logger.error(f"Gemini analysis failed: {e}")
            # Add more debug info
            debug_info = {
                "error": str(e),
                "ai_provider": "Google Gemini",
                "status": "failed"
            }
            if 'response' in locals() and response:
                if hasattr(response, 'choices'):
                    debug_info["choices_count"] = len(response.choices) if response.choices else 0
            return debug_info
    
    def generate_narrative(
        self,
        events: List[Dict[str, Any]],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate attack narrative from multiple events
        
        Args:
            events: List of related events
            enrichment: Enrichment data
        
        Returns:
            Human-readable narrative
        """
        
        if not self.enabled:
            return "AI analysis not available (Google Gemini not configured)"
        
        # Build prompt
        prompt = f"""Analyze these related security events and create a cohesive incident narrative.

## Events Timeline
{json.dumps(events, indent=2)}

## Enrichment Context
{json.dumps(enrichment, indent=2) if enrichment else "No enrichment data available"}

Create a detailed narrative that:
1. Establishes a timeline of events
2. Explains the attacker's methodology
3. Identifies patterns and correlations
4. Assesses the threat level
5. Recommends response actions

Write in professional SOC analyst style, suitable for incident reports."""

        try:
            response = self.client.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=4096
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return "Failed to generate narrative: Empty response from Gemini"
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.logger.error(f"Gemini narrative generation failed: {e}")
            return f"Failed to generate narrative: {str(e)}"
    
    def assess_threat(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assess threat level
        
        Args:
            event_data: Event data
            enrichment: Enrichment context
        
        Returns:
            Threat assessment
        """
        
        if not self.enabled:
            return {
                "threat_level": "Unknown",
                "confidence": 0,
                "reasoning": "AI service not available"
            }
        
        context_str = self._prepare_context(event_data, enrichment)
        
        prompt = f"""Assess the threat level of this security event.

{context_str}

## Event Data
{json.dumps(event_data, indent=2)}

Provide assessment in JSON format:
{{
  "threat_level": "Critical/High/Medium/Low",
  "confidence": 85,
  "reasoning": "Detailed explanation of threat assessment",
  "risk_factors": ["Factor 1", "Factor 2"],
  "mitigating_factors": ["Factor 1", "Factor 2"]
}}"""

        try:
            response = self.client.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=1024
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return {
                    "threat_level": "Unknown",
                    "confidence": 0,
                    "reasoning": "Empty response from Gemini API"
                }
            
            # Clean and parse JSON
            response_text = response.choices[0].message.content.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            return json.loads(response_text)
            
        except Exception as e:
            self.logger.error(f"Gemini threat assessment failed: {e}")
            return {
                "threat_level": "Unknown",
                "confidence": 0,
                "reasoning": f"Assessment failed: {str(e)}"
            }
    
    def recommend_actions(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate remediation recommendations
        
        Args:
            event_data: Event data
            enrichment: Enrichment context
        
        Returns:
            List of actionable recommendations
        """
        
        if not self.enabled:
            return ["AI service not available - manual analysis required"]
        
        context_str = self._prepare_context(event_data, enrichment)
        
        prompt = f"""Generate actionable security recommendations for this event.

{context_str}

## Event Data
{json.dumps(event_data, indent=2)}

Provide recommendations in JSON format:
{{
  "immediate": ["Action 1", "Action 2"],
  "short_term": ["Action 1", "Action 2"],
  "long_term": ["Action 1", "Action 2"]
}}

Be specific and actionable. Focus on practical steps for incident response and prevention."""

        try:
            response = self.client.client.chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=1024
            )
            
            if not response or not response.choices or not response.choices[0].message.content:
                return ["Failed to generate recommendations: Empty response from Gemini"]
            
            # Clean and parse JSON
            response_text = response.choices[0].message.content.strip()
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            recommendations = json.loads(response_text)
            
            # Flatten into single list with priority prefixes
            actions = []
            for immediate in recommendations.get("immediate", []):
                actions.append(f"🔴 IMMEDIATE: {immediate}")
            for short_term in recommendations.get("short_term", []):
                actions.append(f"🟡 SHORT-TERM: {short_term}")
            for long_term in recommendations.get("long_term", []):
                actions.append(f"🟢 LONG-TERM: {long_term}")
            
            return actions
            
        except Exception as e:
            self.logger.error(f"Gemini recommendations failed: {e}")
            return [f"Failed to generate recommendations: {str(e)}"]
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
