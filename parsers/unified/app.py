"""
Unified Log Parser API
Main Flask application
"""

from flask import Flask, jsonify
from flask_cors import CORS
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from shared.config import get_settings
from shared.logger import get_logger
from shared.loki_client import get_loki_client

# Import blueprints (using relative imports since we're in parsers/unified)
from routes.modsec import modsec_bp
from routes.suricata import suricata_bp
from routes.zeek import zeek_bp
from routes.ufw import ufw_bp

from ai import get_ai_service

# Initialize
settings = get_settings()
logger = get_logger(__name__)

# Create Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['JSON_SORT_KEYS'] = False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = settings.flask_debug

# Register blueprints
app.register_blueprint(modsec_bp, url_prefix='/modsec')
app.register_blueprint(suricata_bp, url_prefix='/suricata')
app.register_blueprint(zeek_bp, url_prefix='/zeek')
app.register_blueprint(ufw_bp, url_prefix='/ufw')

# Health check
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    loki_client = get_loki_client()
    loki_healthy = loki_client.health_check()

    # Check AI service
    ai_service = get_ai_service()
    ai_healthy = ai_service.is_enabled()
    
    return jsonify({
        "status": "ok",
        "service": "unified-log-parser",
        "version": "1.0.0",
        "loki": {
            "status": "ok" if loki_healthy else "unreachable",
            "url": settings.loki_url
        },
        "ai": {
            "status": "enabled" if ai_healthy else "disabled",
            "provider": "Azure OpenAI" if ai_healthy else None,
            "model": settings.azure_openai_deployment_name if ai_healthy else None
        }
    }), 200


@app.route('/', methods=['GET'])
def index():
    """API documentation"""
    ai_service = get_ai_service()

    return jsonify({
        "service": "Unified Log Parser API",
        "version": "1.0.0",
        "description": "Multi-log parser with enrichment and AI-powered security analysis",
        "ai_powered": ai_service.is_enabled(),
        "endpoints": {
            "health": "/health",
            "modsecurity": {
                "summary": "/modsec/transaction/<transaction_id>/summary",
                "rules": "/modsec/transaction/<transaction_id>/rules",
                "taxonomy": "/modsec/transaction/<transaction_id>/taxonomy",
                "http_details": "/modsec/transaction/<transaction_id>/http-details",
                "client_analysis": "/modsec/transaction/<transaction_id>/client-analysis",
                "enrich": "/modsec/transaction/<transaction_id>/enrich",
                "ai_analyze": "/modsec/transaction/<transaction_id>/ai-analyze"
            },
            "suricata": {  
                "flow_summary": "/suricata/flow/<flow_id>/summary",
                "alerts": "/suricata/flow/<flow_id>/alerts",
                "http": "/suricata/flow/<flow_id>/http",
                "dns": "/suricata/flow/<flow_id>/dns",
                "tls": "/suricata/flow/<flow_id>/tls",
                "context": "/suricata/flow/<flow_id>/context",
                "alert_categorization": "/suricata/flow/<flow_id>/alert-categorization",
                "correlation_zeek": "/suricata/flow/<flow_id>/correlation/zeek",
                "correlation_ufw": "/suricata/flow/<flow_id>/correlation/ufw",
                "search_alerts": "/suricata/alerts?src_ip=X.X.X.X",
                "enrich": "/suricata/flow/<flow_id>/enrich",
                "ai_analyze": "/suricata/flow/<flow_id>/ai-analyze"
            },
            "zeek": {  
                "notice_summary": "/zeek/notice/<notice_uid>/summary",
                "related_notices": "/zeek/notice/<notice_uid>/related-notices",
                "conn_summary": "/zeek/notice/<notice_uid>/conn-summary",
                "http": "/zeek/notice/<notice_uid>/http",
                "ssl": "/zeek/notice/<notice_uid>/ssl",
                "dns": "/zeek/notice/<notice_uid>/dns",
                "weird": "/zeek/notice/<notice_uid>/weird",
                "taxonomy": "/zeek/notice/<notice_uid>/taxonomy",
                "correlation_suricata": "/zeek/notice/<notice_uid>/correlation/suricata",
                "enrich": "/zeek/notice/<notice_uid>/enrich",
                "ai_analyze": "/zeek/notice/<notice_uid>/ai-analyze"
            },
            "ufw": {
                "port_summary": "/ufw/port/<dest_port>/summary",
                "blocks": "/ufw/port/<dest_port>/blocks",
                "top_sources": "/ufw/port/<dest_port>/top-sources",
                "attack_pattern": "/ufw/port/<dest_port>/attack-pattern",
                "zone_statistics": "/ufw/port/<dest_port>/zone-statistics",  # ← NEW
                "timeline": "/ufw/port/<dest_port>/timeline?group_by_zone=true",
                "correlation_suricata": "/ufw/port/<dest_port>/correlation/suricata",
                "correlation_zeek": "/ufw/port/<dest_port>/correlation/zeek",
                "fail2ban": "/ufw/port/<dest_port>/fail2ban",
                "enrich_sources": "/ufw/port/<dest_port>/enrich-sources",
                "ai_analyze": "/ufw/port/<dest_port>/ai-analyze"
            }
        },
        "statistics": {
            "total_endpoints": 40, 
            "services": 4,
            "ai_endpoints": 4 if ai_service.is_enabled() else 0
        },
        "capabilities": {
            "log_parsing": ["ModSecurity", "Suricata", "Zeek", "UFW"],
            "enrichment": ["GeoIP", "Threat Intel", "Attack Intel", "User-Agent"],
            "ai_analysis": "Azure OpenAI GPT-4 Turbo" if ai_service.is_enabled() else "Disabled"
        }
    }), 200


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("🚀 Starting Unified Log Parser API")
    logger.info("=" * 60)
    logger.info(f"Environment: {settings.flask_env}")
    logger.info(f"Debug: {settings.flask_debug}")
    logger.info(f"Loki URL: {settings.loki_url}")
    logger.info(f"Listening on {settings.flask_host}:{settings.flask_port}")
    logger.info("=" * 60)
    logger.info("📋 Registered Services:")
    logger.info("  - ModSecurity (/modsec)")
    logger.info("  - Suricata (/suricata)")
    logger.info("  - Zeek (/zeek)")
    logger.info("=" * 60)
    logger.info("🔍 Enrichment Services:")
    logger.info("  - GeoIP (MaxMind GeoLite2)")
    logger.info("  - Threat Intel (AbuseIPDB, VirusTotal)")
    logger.info("  - Attack Intel (MITRE ATT&CK, OWASP)")
    logger.info("  - User-Agent Analysis")
    logger.info("=" * 60)

    # Check AI status
    ai_service = get_ai_service()
    if ai_service.is_enabled():
        logger.info("🤖 AI Analysis: ENABLED")
        logger.info(f"   Provider: Azure OpenAI")
        logger.info(f"   Endpoint: {settings.azure_openai_endpoint}")
        logger.info(f"   Deployment: {settings.azure_openai_deployment_name}")
        logger.info(f"   Temperature: {settings.ai_temperature}")
        logger.info(f"   Max Tokens: {settings.ai_max_tokens}")
    else:
        logger.info("⚠️  AI Analysis: DISABLED")
        logger.info("   Configure Azure OpenAI in .env to enable")
    
    logger.info("=" * 60)
    logger.info(f"🎯 Total Endpoints: 40")
    logger.info("=" * 60)

    
    app.run(
        host=settings.flask_host,
        port=settings.flask_port,
        debug=settings.flask_debug
    )