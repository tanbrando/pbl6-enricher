"""
ModSecurity Log Parser
Parses ModSecurity audit log format (multi-line)
"""

import re
from typing import Dict, List, Optional, Any
from datetime import datetime

from shared.logger import get_logger
from shared.exceptions import ParseError
from shared.utils import safe_get, parse_timestamp

logger = get_logger(__name__)


class ModSecParser:
    """
    Parser for ModSecurity audit logs
    
    Log Format (Sections):
    --unique_id-A--  # Request metadata
    --unique_id-B--  # Request headers
    --unique_id-C--  # Request body (POST)
    --unique_id-F--  # Response headers
    --unique_id-E--  # Response body
    --unique_id-H--  # Audit log trailer (rules triggered)
    --unique_id-Z--  # End marker
    """
    
    def __init__(self):
        self.logger = logger
    
    def parse_transaction_summary(self, log_content: str) -> Dict[str, Any]:
        """
        Extract transaction summary metadata
        
        Args:
            log_content: Raw ModSecurity audit log
        
        Returns:
            Dictionary with transaction metadata
        """
        self.logger.debug("Parsing transaction summary")
        
        summary = {}
        
        try:
            # Extract Section A (Connection metadata)
            section_a = self._extract_section(log_content, 'A')
            if section_a:
                summary.update(self._parse_section_a(section_a))
            
            # Extract Section B (Request line + headers)
            section_b = self._extract_section(log_content, 'B')
            if section_b:
                summary.update(self._parse_section_b(section_b))
            
            # Extract Section F (Response)
            section_f = self._extract_section(log_content, 'F')
            if section_f:
                summary.update(self._parse_section_f(section_f))
            
            # Extract Section H (Actions/Rules summary)
            section_h = self._extract_section(log_content, 'H')
            if section_h:
                summary.update(self._parse_section_h_summary(section_h))
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to parse transaction summary: {e}")
            raise ParseError(
                "Failed to parse ModSecurity transaction summary",
                details={"error": str(e)}
            )
    
    def parse_rules(self, log_content: str) -> List[Dict[str, Any]]:
        """
        Extract all triggered rules from Section H
        
        Args:
            log_content: Raw ModSecurity audit log
        
        Returns:
            List of triggered rules
        """
        self.logger.debug("Parsing triggered rules")
        
        section_h = self._extract_section(log_content, 'H')
        if not section_h:
            return []
        
        rules = []
        seen_rule_ids = set()
        
        # Pattern to match "Message:" lines (skip "Apache-Error:" duplicates)
        pattern = r'Message:\s*(.+?)\[id\s+"(\d+)"\]\s*\[msg\s+"([^"]+)"\]\s*(?:\[data\s+"([^"]+)"\])?\s*\[severity\s+"([^"]+)"\](?:\s*\[file\s+"([^"]+)"\])?'
        
        for match in re.finditer(pattern, section_h, re.DOTALL):
            rule_id = match.group(2)
            
            # Skip duplicates
            if rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(rule_id)
            
            # Extract rule details
            rule = {
                "rule_id": rule_id,
                "message": match.group(3).strip(),
                "severity": match.group(5).strip().upper(),
                "matched_data": match.group(4).strip() if match.group(4) else None,
                "file": match.group(6).split('/')[-1] if match.group(6) else None
            }
            
            # Extract phase from full message
            phase_match = re.search(r'\(phase\s+(\d+)\)', match.group(1))
            if phase_match:
                rule["phase"] = int(phase_match.group(1))
            else:
                rule["phase"] = None
            
            # Extract tags
            rule["tags"] = self._extract_tags_for_rule(section_h, rule_id)
            
            rules.append(rule)
        
        self.logger.info(f"Extracted {len(rules)} rules")
        return rules
    
    def parse_taxonomy(self, log_content: str) -> Dict[str, Any]:
        """
        Extract attack taxonomy (tags categorization)
        
        Args:
            log_content: Raw ModSecurity audit log
        
        Returns:
            Categorized tags
        """
        self.logger.debug("Parsing taxonomy")
        
        section_h = self._extract_section(log_content, 'H')
        if not section_h:
            return {}
        
        # Extract all tags
        all_tags = re.findall(r'\[tag\s+"([^"]+)"\]', section_h)
        
        # Categorize tags
        taxonomy = {
            "attack_types": {},
            "owasp_top_10": {},
            "owasp_crs_categories": {},
            "capec": [],
            "pci_dss": [],
            "mitre_attack": []
        }
        
        for tag in all_tags:
            if tag.startswith("attack-"):
                taxonomy["attack_types"][tag] = taxonomy["attack_types"].get(tag, 0) + 1
            
            elif tag.startswith("OWASP_TOP_10/"):
                owasp_id = tag.replace("OWASP_TOP_10/", "")
                taxonomy["owasp_top_10"][owasp_id] = taxonomy["owasp_top_10"].get(owasp_id, 0) + 1
            
            elif tag.startswith("OWASP_CRS/"):
                category = tag.replace("OWASP_CRS/", "")
                taxonomy["owasp_crs_categories"][category] = taxonomy["owasp_crs_categories"].get(category, 0) + 1
            
            elif tag.startswith("capec/"):
                capec_id = tag.replace("capec/", "")
                if capec_id not in taxonomy["capec"]:
                    taxonomy["capec"].append(capec_id)
            
            elif tag.startswith("PCI/"):
                pci_id = tag.replace("PCI/", "")
                if pci_id not in taxonomy["pci_dss"]:
                    taxonomy["pci_dss"].append(pci_id)
        
        return taxonomy
    
    def parse_http_details(self, log_content: str) -> Dict[str, Any]:
        """
        Extract HTTP request and response details
        
        Args:
            log_content: Raw ModSecurity audit log
        
        Returns:
            HTTP request/response details
        """
        self.logger.debug("Parsing HTTP details")
        
        result = {
            "request": {},
            "response": {}
        }
        
        # Parse request (Section B)
        section_b = self._extract_section(log_content, 'B')
        if section_b:
            result["request"] = self._parse_http_request(section_b)
        
        # Parse response (Section F)
        section_f = self._extract_section(log_content, 'F')
        if section_f:
            result["response"] = self._parse_http_response(section_f)
        
        return result
    
    # ===== Private Helper Methods =====
    
    def _extract_section(self, log_content: str, section: str) -> Optional[str]:
        """Extract specific section from audit log"""
        pattern = rf'--[a-z0-9]+-{section}--\s*(.*?)(?=--[a-z0-9]+-[A-Z]--|$)'
        match = re.search(pattern, log_content, re.DOTALL)
        return match.group(1).strip() if match else None
    
    def _parse_section_a(self, section_a: str) -> Dict[str, Any]:
        """Parse Section A (connection metadata)"""
        data = {}
        
        # Pattern: [timestamp] unique_id src_ip src_port dst_ip dst_port
        pattern = r'\[([^\]]+)\]\s+(\S+)\s+([0-9.]+)\s+(\d+)\s+([0-9.]+)\s+(\d+)'
        match = re.search(pattern, section_a)
        
        if match:
            data["timestamp"] = match.group(1)
            data["transaction_id"] = match.group(2)
            data["src_ip"] = match.group(3)
            data["src_port"] = int(match.group(4))
            data["dest_ip"] = match.group(5)
            data["dest_port"] = int(match.group(6))
        
        return data
    
    def _parse_section_b(self, section_b: str) -> Dict[str, Any]:
        """Parse Section B (request line + headers)"""
        data = {}
        
        lines = section_b.split('\n')
        
        if lines:
            # First line: METHOD URI PROTOCOL
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) >= 3:
                data["method"] = parts[0]
                data["uri"] = parts[1]
                data["protocol"] = parts[2]
        
        # Extract headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        data["hostname"] = headers.get("Host", "")
        data["user_agent"] = headers.get("User-Agent", "")
        data["request_headers"] = headers
        
        return data
    
    def _parse_section_f(self, section_f: str) -> Dict[str, Any]:
        """Parse Section F (response)"""
        data = {}
        
        lines = section_f.split('\n')
        
        if lines:
            # First line: PROTOCOL STATUS STATUS_TEXT
            response_line = lines[0].strip()
            parts = response_line.split(None, 2)
            if len(parts) >= 2:
                data["protocol"] = parts[0]
                data["status_code"] = int(parts[1])
                if len(parts) == 3:
                    data["status_text"] = parts[2]
        
        # Extract response headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        data["response_headers"] = headers
        
        return data
    
    def _parse_section_h_summary(self, section_h: str) -> Dict[str, Any]:
        """Parse Section H for summary info"""
        data = {}
        
        # Extract action
        action_match = re.search(r'Action:\s*([^\r\n]+)', section_h)
        if action_match:
            data["action"] = action_match.group(1).strip()
        
        # Count rules
        rules_count = len(re.findall(r'\[id\s+"(\d+)"\]', section_h))
        data["total_rules_triggered"] = rules_count
        
        # Determine severity (highest from all rules)
        severities = re.findall(r'\[severity\s+"([^"]+)"\]', section_h)
        severity_order = {"CRITICAL": 4, "ERROR": 3, "WARNING": 2, "NOTICE": 1}
        if severities:
            highest_severity = max(severities, key=lambda s: severity_order.get(s.upper(), 0))
            data["severity"] = highest_severity.upper()
        else:
            data["severity"] = "UNKNOWN"
        
        # Extract primary attack type
        attack_tags = re.findall(r'\[tag\s+"(attack-[^"]+)"\]', section_h)
        if attack_tags:
            data["primary_attack_type"] = attack_tags[0]
        
        return data
    
    def _extract_tags_for_rule(self, section_h: str, rule_id: str) -> List[str]:
        """Extract tags for specific rule"""
        # Find the rule block
        pattern = rf'\[id\s+"{rule_id}"\](.*?)(?=\[id\s+"\d+"\]|Apache-Error:|$)'
        match = re.search(pattern, section_h, re.DOTALL)
        
        if not match:
            return []
        
        rule_block = match.group(1)
        tags = re.findall(r'\[tag\s+"([^"]+)"\]', rule_block)
        
        return list(set(tags))  # Deduplicate
    
    def _parse_http_request(self, section_b: str) -> Dict[str, Any]:
        """Parse HTTP request from Section B"""
        lines = section_b.split('\n')
        
        request = {
            "method": None,
            "uri": None,
            "protocol": None,
            "headers": {}
        }
        
        if lines:
            # Request line
            parts = lines[0].strip().split()
            if len(parts) >= 3:
                request["method"] = parts[0]
                request["uri"] = parts[1]
                request["protocol"] = parts[2]
        
        # Headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                request["headers"][key.strip()] = value.strip()
        
        return request
    
    def _parse_http_response(self, section_f: str) -> Dict[str, Any]:
        """Parse HTTP response from Section F"""
        lines = section_f.split('\n')
        
        response = {
            "protocol": None,
            "status_code": None,
            "status_text": None,
            "headers": {}
        }
        
        if lines:
            # Status line
            parts = lines[0].strip().split(None, 2)
            if len(parts) >= 2:
                response["protocol"] = parts[0]
                response["status_code"] = int(parts[1])
                if len(parts) == 3:
                    response["status_text"] = parts[2]
        
        # Headers
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                response["headers"][key.strip()] = value.strip()
        
        return response