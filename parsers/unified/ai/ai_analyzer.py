"""
Azure OpenAI Analyzer
GPT-4 Turbo integration via Azure OpenAI Service
"""

from typing import Dict, List, Any, Optional
import json

from shared.logger import get_logger
from shared.config import get_settings
from ai.base_analyzer import BaseAIAnalyzer

logger = get_logger(__name__)


class AzureOpenAIAnalyzer(BaseAIAnalyzer):
    """
    Azure OpenAI GPT-4 Turbo analyzer
    
    Requires:
    - openai library (>= 1.0.0)
    - Azure OpenAI credentials in .env
    """
    
    def __init__(self):
        super().__init__("Azure OpenAI")
        self.settings = get_settings()
        
        # Azure OpenAI settings
        self.endpoint = self.settings.azure_openai_endpoint
        self.api_key = self.settings.azure_openai_api_key
        self.api_version = self.settings.azure_openai_api_version
        self.deployment_name = self.settings.azure_openai_deployment_name
        
        # AI settings
        self.temperature = self.settings.ai_temperature
        self.max_tokens = self.settings.ai_max_tokens
        self.timeout = self.settings.ai_timeout
        
        self.client = None
        
        self._initialize()
    
    def _initialize(self):
        """Initialize Azure OpenAI client"""
        if not self.settings.azure_openai_enabled:
            self.logger.info("ℹ️  Azure OpenAI disabled in configuration")
            return
        
        if not self.endpoint or not self.api_key:
            self.logger.warning("⚠️  Azure OpenAI credentials not found. Set in .env:")
            self.logger.warning("   AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/")
            self.logger.warning("   AZURE_OPENAI_API_KEY=your-api-key")
            self.logger.warning("   AZURE_OPENAI_DEPLOYMENT_NAME=gpt4-turbo")
            return
        
        try:
            from openai import AzureOpenAI
            
            self.client = AzureOpenAI(
                azure_endpoint=self.endpoint,
                api_key=self.api_key,
                api_version=self.api_version
            )
            
            self.enabled = True
            self.logger.info("=" * 60)
            self.logger.info("✅ Azure OpenAI analyzer initialized")
            self.logger.info(f"   Endpoint: {self.endpoint}")
            self.logger.info(f"   Deployment: {self.deployment_name}")
            self.logger.info(f"   API Version: {self.api_version}")
            self.logger.info(f"   Temperature: {self.temperature}")
            self.logger.info(f"   Max Tokens: {self.max_tokens}")
            self.logger.info("=" * 60)
            
        except ImportError:
            self.logger.warning("⚠️  openai library not installed. Run: pip install openai>=1.0.0")
        except Exception as e:
            self.logger.error(f"Failed to initialize Azure OpenAI: {e}")
    
    def analyze_attack(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive attack analysis using GPT-4 Turbo
        
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
        prompt = f"""You are a senior cybersecurity analyst. Analyze this security event and provide a comprehensive report.

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
            response = self.client.chat.completions.create(
                model=self.deployment_name,  # Use deployment name for Azure
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cybersecurity analyst specializing in threat analysis and incident response. You work for a Security Operations Center (SOC) and provide detailed, technical, and actionable security analysis. Current date: 2025-01-08. Your analysis should be professional and suitable for enterprise security teams."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            analysis = json.loads(response.choices[0].message.content)
            
            # Add metadata
            analysis["ai_provider"] = "Azure OpenAI"
            analysis["ai_model"] = self.deployment_name
            analysis["ai_timestamp"] = "2025-01-08T00:57:02Z"
            analysis["analyst"] = "tanbrando"
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Azure OpenAI analysis failed: {e}")
            return {
                "error": str(e),
                "ai_provider": "Azure OpenAI",
                "status": "failed"
            }
    
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
            return "AI analysis not available (Azure OpenAI not configured)"
        
        # Build prompt
        prompt = f"""Analyze these related security events and create a cohesive incident narrative.

## Events Timeline
{json.dumps(events, indent=2)}

## Enrichment Data
{json.dumps(enrichment, indent=2) if enrichment else "None"}

Create a detailed narrative explaining:
1. **Initial Access**: How did the attacker gain access?
2. **Actions Taken**: What did the attacker do (chronologically)?
3. **Tools & Techniques**: What tools/methods were used?
4. **Indicators of Compromise**: What evidence was left?
5. **Attack Goal**: What was the attacker trying to achieve?
6. **Outcome**: Was the attack successful? What happened?

Write in clear, professional language suitable for a security incident report. Use technical terminology where appropriate."""

        try:
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity analyst writing incident reports for enterprise SOC teams. Create clear, detailed narratives of security events with technical accuracy."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature + 0.1,  # Slightly higher for narrative
                max_tokens=1500
            )
            
            narrative = response.choices[0].message.content
            return narrative
            
        except Exception as e:
            self.logger.error(f"Narrative generation failed: {e}")
            return f"Error generating narrative: {str(e)}"
    
    def assess_threat(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assess threat level with detailed reasoning
        
        Args:
            event_data: Event data
            enrichment: Enrichment data
        
        Returns:
            Threat assessment
        """
        
        if not self.enabled:
            return self._disabled_response()
        
        context_str = self._prepare_context(event_data, enrichment)
        
        prompt = f"""Assess the threat level of this security event with detailed reasoning.

{context_str}

Provide assessment in JSON format:
{{
  "threat_level": "Critical/High/Medium/Low",
  "risk_score": 85,
  "confidence": 90,
  "reasoning": "Detailed explanation of why this threat level was assigned",
  "key_indicators": [
    "Indicator 1: Known malicious IP with 92% abuse score",
    "Indicator 2: SQL injection targeting production database"
  ],
  "urgency": "Immediate/Urgent/Standard/Low",
  "business_impact": "Critical/High/Medium/Low",
  "recommended_priority": "P0/P1/P2/P3"
}}

Consider in your assessment:
- Attack sophistication and complexity
- Attacker's capabilities and resources
- Potential impact on confidentiality, integrity, availability
- Current security posture and defenses
- Similar past incidents and their outcomes
- Industry threat landscape"""

        try:
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a threat assessment expert with deep knowledge of cyber threats and risk management. Provide accurate, well-reasoned threat evaluations based on industry standards."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,  # Lower for consistent assessments
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            
            assessment = json.loads(response.choices[0].message.content)
            assessment["ai_provider"] = "Azure OpenAI"
            assessment["ai_model"] = self.deployment_name
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Threat assessment failed: {e}")
            return {
                "error": str(e),
                "threat_level": "Unknown",
                "status": "failed"
            }
    
    def recommend_actions(
        self,
        event_data: Dict[str, Any],
        enrichment: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate actionable remediation recommendations
        
        Args:
            event_data: Event data
            enrichment: Enrichment data
        
        Returns:
            List of prioritized recommendations
        """
        
        if not self.enabled:
            return ["AI recommendations not available"]
        
        context_str = self._prepare_context(event_data, enrichment)
        
        prompt = f"""Provide specific, actionable remediation recommendations for this security event.

{context_str}

Return a JSON object with categorized recommendations:
{{
  "immediate": [
    "Block source IP 1.2.3.4 at perimeter firewall",
    "Isolate affected system from network",
    "..."
  ],
  "short_term": [
    "Implement WAF rules for SQL injection patterns",
    "Enable detailed logging on affected services",
    "..."
  ],
  "long_term": [
    "Conduct security awareness training on phishing",
    "Implement zero-trust network architecture",
    "..."
  ]
}}

Make recommendations:
- Specific and actionable (not generic advice)
- Prioritized by urgency and impact
- Technical and detailed
- Feasible to implement with available resources
- Aligned with industry best practices (NIST, CIS, etc.)"""

        try:
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security engineer providing remediation guidance for enterprise environments. Give specific, actionable recommendations that can be immediately implemented."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1200,
                response_format={"type": "json_object"}
            )
            
            recommendations = json.loads(response.choices[0].message.content)
            
            # Flatten into single list with categories
            all_recommendations = []
            
            for category in ["immediate", "short_term", "long_term"]:
                items = recommendations.get(category, [])
                for item in items:
                    all_recommendations.append(f"[{category.upper()}] {item}")
            
            return all_recommendations
            
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
            return [f"Error generating recommendations: {str(e)}"]
    
    def _disabled_response(self) -> Dict[str, Any]:
        """Response when AI is disabled"""
        return {
            "ai_enabled": False,
            "message": "Azure OpenAI integration not configured. Check .env file.",
            "ai_provider": "Azure OpenAI",
            "configuration_required": {
                "AZURE_OPENAI_ENABLED": "true",
                "AZURE_OPENAI_ENDPOINT": "https://your-resource.openai.azure.com/",
                "AZURE_OPENAI_API_KEY": "your-api-key",
                "AZURE_OPENAI_DEPLOYMENT_NAME": "gpt4-turbo"
            }
        }