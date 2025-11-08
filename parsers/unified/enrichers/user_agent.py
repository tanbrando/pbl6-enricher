"""
User-Agent Enricher
Parse and analyze User-Agent strings
Detect bots, scanners, browsers
"""

import re
from typing import Dict, Optional, Any

from shared.logger import get_logger

logger = get_logger(__name__)


class UserAgentEnricher:
    """
    User-Agent analysis and enrichment
    
    Detects:
    - Browsers (Chrome, Firefox, Safari, Edge)
    - Bots (Googlebot, Bingbot, etc.)
    - Scanners (Nmap, Nikto, SQLMap, etc.)
    - Automation tools (curl, wget, python-requests)
    """
    
    def __init__(self):
        self.logger = logger
        
        # Known scanners/attack tools
        self.scanner_patterns = {
            "nmap": r"nmap",
            "nikto": r"nikto",
            "sqlmap": r"sqlmap",
            "wpscan": r"wpscan",
            "dirb": r"dirb",
            "dirbuster": r"dirbuster",
            "gobuster": r"gobuster",
            "masscan": r"masscan",
            "zap": r"owasp.*zap",
            "burp": r"burp",
            "acunetix": r"acunetix",
            "nessus": r"nessus",
            "openvas": r"openvas"
        }
        
        # Automation tools
        self.automation_patterns = {
            "curl": r"curl/",
            "wget": r"wget",
            "python-requests": r"python-requests",
            "python-urllib": r"python-urllib",
            "java": r"java/",
            "go-http": r"go-http-client",
            "ruby": r"ruby",
            "perl": r"perl",
            "node-fetch": r"node-fetch"
        }
        
        # Legitimate bots
        self.bot_patterns = {
            "googlebot": r"googlebot",
            "bingbot": r"bingbot",
            "slurp": r"slurp",  # Yahoo
            "duckduckbot": r"duckduckbot",
            "baiduspider": r"baiduspider",
            "yandexbot": r"yandexbot",
            "facebookexternalhit": r"facebookexternalhit",
            "twitterbot": r"twitterbot",
            "linkedinbot": r"linkedinbot"
        }
        
        # Browsers
        self.browser_patterns = {
            "chrome": r"chrome/(\d+)",
            "firefox": r"firefox/(\d+)",
            "safari": r"safari/(\d+)",
            "edge": r"edg/(\d+)",
            "opera": r"opera/(\d+)",
            "ie": r"msie (\d+)|trident.*rv:(\d+)"
        }
    
    def analyze(self, user_agent: str) -> Dict[str, Any]:
        """
        Analyze User-Agent string
        
        Args:
            user_agent: User-Agent header value
        
        Returns:
            Analysis result with type, indicators, etc.
        """
        if not user_agent:
            return {
                "user_agent": "",
                "type": "empty",
                "is_suspicious": True,
                "confidence": 100,
                "indicators": ["Empty User-Agent header"]
            }
        
        ua_lower = user_agent.lower()
        
        result = {
            "user_agent": user_agent,
            "type": "unknown",
            "is_suspicious": False,
            "confidence": 0,
            "indicators": [],
            "details": {}
        }
        
        # Check for scanners (highest priority)
        for scanner_name, pattern in self.scanner_patterns.items():
            if re.search(pattern, ua_lower):
                result.update({
                    "type": "scanner",
                    "scanner_name": scanner_name,
                    "is_suspicious": True,
                    "confidence": 95,
                    "indicators": [f"Known scanning tool: {scanner_name}"]
                })
                return result
        
        # Check for automation tools
        for tool_name, pattern in self.automation_patterns.items():
            if re.search(pattern, ua_lower):
                result.update({
                    "type": "automation_tool",
                    "tool_name": tool_name,
                    "is_suspicious": True,
                    "confidence": 70,
                    "indicators": [f"Automation tool detected: {tool_name}"]
                })
                return result
        
        # Check for legitimate bots
        for bot_name, pattern in self.bot_patterns.items():
            if re.search(pattern, ua_lower):
                result.update({
                    "type": "bot",
                    "bot_name": bot_name,
                    "is_suspicious": False,
                    "confidence": 90,
                    "indicators": [f"Legitimate bot: {bot_name}"]
                })
                return result
        
        # Check for browsers
        browser_detected = False
        for browser_name, pattern in self.browser_patterns.items():
            match = re.search(pattern, ua_lower)
            if match:
                version = match.group(1) if match.group(1) else match.group(2) if len(match.groups()) > 1 else "unknown"
                
                result.update({
                    "type": "browser",
                    "browser_name": browser_name,
                    "browser_version": version,
                    "is_suspicious": False,
                    "confidence": 80
                })
                
                # Extract OS
                os_info = self._extract_os(user_agent)
                if os_info:
                    result["details"]["os"] = os_info
                
                browser_detected = True
                break
        
        if browser_detected:
            # Additional checks for suspicious browser UAs
            suspicious_indicators = self._check_suspicious_browser(user_agent)
            if suspicious_indicators:
                result["is_suspicious"] = True
                result["confidence"] = 60
                result["indicators"] = suspicious_indicators
            
            return result
        
        # Unknown/generic
        result.update({
            "type": "unknown",
            "is_suspicious": True,
            "confidence": 50,
            "indicators": ["Unrecognized User-Agent pattern"]
        })
        
        return result
    
    def _extract_os(self, user_agent: str) -> Optional[str]:
        """Extract OS from User-Agent"""
        os_patterns = {
            "Windows": r"Windows NT (\d+\.\d+)",
            "macOS": r"Mac OS X ([\d_]+)",
            "Linux": r"Linux",
            "Android": r"Android ([\d.]+)",
            "iOS": r"iPhone OS ([\d_]+)|iPad.*OS ([\d_]+)"
        }
        
        for os_name, pattern in os_patterns.items():
            match = re.search(pattern, user_agent)
            if match:
                version = match.group(1) if match.groups() else ""
                return f"{os_name} {version}".strip()
        
        return None
    
    def _check_suspicious_browser(self, user_agent: str) -> list:
        """Check for suspicious characteristics in browser UA"""
        indicators = []
        
        # Too short
        if len(user_agent) < 50:
            indicators.append("Suspiciously short User-Agent for a browser")
        
        # Missing common browser components
        if "mozilla" in user_agent.lower():
            if "applewebkit" not in user_agent.lower() and "gecko" not in user_agent.lower():
                indicators.append("Mozilla UA missing rendering engine")
        
        # Generic/default UAs
        generic_patterns = [
            r"^mozilla/5\.0$",
            r"^mozilla/4\.0$",
            r"^user-agent$"
        ]
        for pattern in generic_patterns:
            if re.match(pattern, user_agent.lower()):
                indicators.append("Generic/default User-Agent")
                break
        
        return indicators
    
    def batch_analyze(self, user_agents: list) -> Dict[str, Dict[str, Any]]:
        """Analyze multiple User-Agents"""
        results = {}
        
        for ua in set(user_agents):
            if ua:
                results[ua] = self.analyze(ua)
        
        return results
    
    def get_statistics(self, user_agents: list) -> Dict[str, Any]:
        """
        Get statistics for list of User-Agents
        
        Args:
            user_agents: List of User-Agent strings
        
        Returns:
            Statistics summary
        """
        from collections import Counter
        
        types = []
        suspicious_count = 0
        
        for ua in user_agents:
            analysis = self.analyze(ua)
            types.append(analysis.get("type"))
            if analysis.get("is_suspicious"):
                suspicious_count += 1
        
        type_counter = Counter(types)
        
        return {
            "total": len(user_agents),
            "unique": len(set(user_agents)),
            "suspicious_count": suspicious_count,
            "suspicious_rate": round(suspicious_count / len(user_agents) * 100, 2) if user_agents else 0,
            "type_distribution": dict(type_counter),
            "bot_rate": round(type_counter.get("bot", 0) / len(user_agents) * 100, 2) if user_agents else 0,
            "scanner_rate": round(type_counter.get("scanner", 0) / len(user_agents) * 100, 2) if user_agents else 0
        }