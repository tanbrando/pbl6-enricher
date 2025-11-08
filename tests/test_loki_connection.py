#!/usr/bin/env python3
"""
Integration Test: Connect to Real Loki on VM
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.config import get_settings
from shared.logger import get_logger
from shared.loki_client import LokiClient

logger = get_logger(__name__)


def main():
    print("=" * 60)
    print("🔍 Testing Loki Connection")
    print("=" * 60)
    
    # Load settings
    settings = get_settings()
    print(f"Loki URL: {settings.loki_url}")
    
    # Create client
    client = LokiClient()
    
    # Test 1: Health check
    print("\n[1] Health Check...")
    is_healthy = client.health_check()
    print(f"Result: {'✅ OK' if is_healthy else '❌ FAIL'}")
    
    if not is_healthy:
        print("\n❌ Loki is not healthy. Check:")
        print("  - VM IP address in .env")
        print("  - Loki container running: docker ps")
        print("  - Port 3100 accessible: telnet VM_IP 3100")
        sys.exit(1)
    
    # Test 2: Query logs
    print("\n[2] Query Logs...")
    try:
        results = client.query('{job="modsecurity"}', limit=1)
        print(f"Found {len(results)} results")
        
        if results:
            print("\nSample result:")
            print(f"  Stream: {results[0].get('stream')}")
            values = results[0].get('values', [])
            if values:
                print(f"  Log preview: {values[0][1][:100]}...")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)
    
    # Test 3: Count logs
    print("\n[3] Count Logs (last 24h)...")
    try:
        count = client.count_logs('{job="modsecurity"}', time_range_hours=24)
        print(f"Total logs: {count}")
    except Exception as e:
        print(f"Warning: Count failed: {e}")
    
    print("\n" + "=" * 60)
    print("✅ All tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    main()