"""
Test Gemini Analyzer Integration
Tests the GeminiAnalyzer class with new google-genai SDK
"""

import os
import sys
import json
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / 'parsers' / 'unified'))

from dotenv import load_dotenv
load_dotenv()

print("=" * 60)
print("🧪 Testing GeminiAnalyzer Class")
print("=" * 60)

try:
    from ai.gemini_analyzer import GeminiAnalyzer
    
    print("\n📦 Initializing GeminiAnalyzer...")
    analyzer = GeminiAnalyzer()
    
    if not analyzer.enabled:
        print("❌ Analyzer not enabled!")
        exit(1)
    
    print(f"✅ Analyzer initialized with model: {analyzer.model_name}")
    
    # Test data - ModSecurity event
    test_event = {
        "transaction_id": "test-123",
        "client_ip": "192.168.1.100",
        "request_uri": "/admin/login.php",
        "request_method": "POST",
        "response_code": 403,
        "matched_rules": [
            {
                "id": "950004",
                "msg": "SQL Injection Attack Detected",
                "severity": "CRITICAL"
            }
        ]
    }
    
    test_enrichment = {
        "geoip": {
            "country": "Vietnam",
            "city": "Hanoi"
        },
        "threat_intel": {
            "abuse_confidence": 85,
            "is_malicious": True
        }
    }
    
    print("\n🔍 Testing attack analysis...")
    print(f"Event: {json.dumps(test_event, indent=2)}")
    
    analysis = analyzer.analyze_attack(test_event, test_enrichment)
    
    print("\n✅ Analysis result:")
    print(json.dumps(analysis, indent=2, ensure_ascii=False))
    
    print("\n" + "=" * 60)
    print("✅ ALL TESTS PASSED!")
    print("=" * 60)
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"❌ Test failed: {e}")
    import traceback
    traceback.print_exc()
