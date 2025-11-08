"""
Attack Intelligence Enricher
Enrich attack types with context, remediation, MITRE ATT&CK
"""

import json
from typing import Dict, Optional, Any, List
from pathlib import Path

from shared.logger import get_logger

logger = get_logger(__name__)


class AttackIntelEnricher:
    """
    Attack intelligence enrichment
    
    Provides:
    - Attack descriptions
    - MITRE ATT&CK mappings
    - OWASP mappings
    - Remediation steps
    - CVE references
    """
    
    def __init__(self):
        self.logger = logger
        self.attack_db = {}
        self.mitre_db = {}
        self.owasp_db = {}
        
        self._load_databases()
    
    def _load_databases(self):
        """Load attack intelligence databases"""
        base_path = Path("parsers/data/attack_intel")
        
        # Load attack intelligence
        try:
            with open(base_path / "attack_intelligence.json") as f:
                self.attack_db = json.load(f)
            self.logger.info(f"✅ Loaded {len(self.attack_db)} attack types")
        except Exception as e:
            self.logger.warning(f"Failed to load attack intelligence: {e}")
        
        # Load MITRE ATT&CK
        try:
            with open(base_path / "mitre_attack.json") as f:
                self.mitre_db = json.load(f)
            self.logger.info(f"✅ Loaded {len(self.mitre_db)} MITRE techniques")
        except Exception as e:
            self.logger.warning(f"Failed to load MITRE ATT&CK: {e}")
        
        # Load OWASP
        try:
            with open(base_path / "owasp_mapping.json") as f:
                self.owasp_db = json.load(f)
            self.logger.info(f"✅ Loaded {len(self.owasp_db)} OWASP categories")
        except Exception as e:
            self.logger.warning(f"Failed to load OWASP mapping: {e}")
    
    def enrich_attack_type(self, attack_type: str) -> Dict[str, Any]:
        """
        Enrich attack type with intelligence
        
        Args:
            attack_type: Attack type (e.g., "attack-lfi", "attack-sqli")
        
        Returns:
            Enriched attack data
        """
        # Get base attack data
        attack_data = self.attack_db.get(attack_type, {
            "name": attack_type,
            "description": "Unknown attack type",
            "severity": "Unknown",
            "remediation": []
        })
        
        result = {
            "attack_type": attack_type,
            **attack_data
        }
        
        # Add MITRE ATT&CK context
        mitre_techniques = attack_data.get("mitre_attack", [])
        if mitre_techniques:
            result["mitre_attack"] = []
            for technique_id in mitre_techniques:
                technique_data = self.mitre_db.get(technique_id, {})
                result["mitre_attack"].append({
                    "id": technique_id,
                    **technique_data
                })
        
        # Add OWASP context
        owasp_categories = attack_data.get("owasp", [])
        if owasp_categories:
            result["owasp"] = []
            for owasp_id in owasp_categories:
                owasp_data = self.owasp_db.get(owasp_id, {})
                result["owasp"].append({
                    "id": owasp_id,
                    **owasp_data
                })
        
        return result
    
    def enrich_multiple_attacks(self, attack_types: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enrich multiple attack types"""
        results = {}
        
        for attack_type in set(attack_types):
            if attack_type:
                results[attack_type] = self.enrich_attack_type(attack_type)
        
        return results
    
    def get_remediation_steps(self, attack_types: List[str]) -> List[str]:
        """
        Get aggregated remediation steps for multiple attacks
        
        Args:
            attack_types: List of attack types
        
        Returns:
            Deduplicated list of remediation steps
        """
        all_steps = []
        
        for attack_type in attack_types:
            attack_data = self.attack_db.get(attack_type, {})
            steps = attack_data.get("remediation", [])
            all_steps.extend(steps)
        
        # Deduplicate while preserving order
        seen = set()
        unique_steps = []
        for step in all_steps:
            if step not in seen:
                seen.add(step)
                unique_steps.append(step)
        
        return unique_steps
    
    def get_mitre_summary(self, attack_types: List[str]) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK summary for attacks
        
        Args:
            attack_types: List of attack types
        
        Returns:
            MITRE summary with tactics and techniques
        """
        techniques = set()
        tactics = set()
        
        for attack_type in attack_types:
            attack_data = self.attack_db.get(attack_type, {})
            mitre_ids = attack_data.get("mitre_attack", [])
            
            for technique_id in mitre_ids:
                techniques.add(technique_id)
                technique_data = self.mitre_db.get(technique_id, {})
                tactic = technique_data.get("tactic")
                if tactic:
                    tactics.add(tactic)
        
        return {
            "tactics": list(tactics),
            "techniques": list(techniques),
            "technique_count": len(techniques)
        }