"""
Zeek API Routes
Flask blueprint for Zeek endpoints
"""

from flask import Blueprint, jsonify, request

from shared.logger import get_logger
from shared.exceptions import LogEnrichmentAPIError, ValidationError
from services.zeek_service import ZeekService
from enrichers import get_enrichment_service
from ai import get_ai_service

logger = get_logger(__name__)

# Create blueprint
zeek_bp = Blueprint('zeek', __name__)

# Initialize service
zeek_service = ZeekService()


def handle_error(error: Exception) -> tuple:
    """Error handler"""
    if isinstance(error, LogEnrichmentAPIError):
        logger.warning(f"API error: {error.message}")
        return jsonify(error.to_dict()), error.status_code
    else:
        logger.error(f"Unexpected error: {str(error)}", exc_info=True)
        return jsonify({
            "error": "InternalServerError",
            "message": "An unexpected error occurred",
            "details": {"error": str(error)}
        }), 500


@zeek_bp.route('/notice/<notice_uid>/summary', methods=['GET'])
def get_notice_summary(notice_uid: str):
    """
    Get notice summary
    
    GET /zeek/notice/<notice_uid>/summary
    
    Response:
        200: Notice summary with stats
        404: Notice not found
        500: Server error
    """
    try:
        summary = zeek_service.get_notice_summary(notice_uid)
        return jsonify(summary), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/related-notices', methods=['GET'])
def get_related_notices(notice_uid: str):
    """
    Get all related notices (same src/dst)
    
    GET /zeek/notice/<notice_uid>/related-notices
    
    Query Parameters:
        time_range: Time range in minutes (default 30)
    
    Response:
        200: List of related notices
        404: Notice not found
        500: Server error
    """
    try:
        time_range = int(request.args.get('time_range', 30))
        
        notices = zeek_service.get_related_notices(
            notice_uid=notice_uid,
            time_range_minutes=time_range
        )
        
        return jsonify(notices), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/conn-summary', methods=['GET'])
def get_conn_summary(notice_uid: str):
    """
    Get connection summary for notice
    
    GET /zeek/notice/<notice_uid>/conn-summary
    
    Response:
        200: Connection statistics
        404: Notice not found
        500: Server error
    """
    try:
        conn_summary = zeek_service.get_conn_summary(notice_uid)
        return jsonify(conn_summary), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/http', methods=['GET'])
def get_http_events(notice_uid: str):
    """
    Get HTTP events related to notice
    
    GET /zeek/notice/<notice_uid>/http
    
    Response:
        200: List of HTTP events
        404: Notice not found
        500: Server error
    """
    try:
        http_events = zeek_service.get_http_events(notice_uid)
        return jsonify(http_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/ssl', methods=['GET'])
def get_ssl_events(notice_uid: str):
    """
    Get SSL/TLS events related to notice
    
    GET /zeek/notice/<notice_uid>/ssl
    
    Response:
        200: List of SSL events
        404: Notice not found
        500: Server error
    """
    try:
        ssl_events = zeek_service.get_ssl_events(notice_uid)
        return jsonify(ssl_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/dns', methods=['GET'])
def get_dns_events(notice_uid: str):
    """
    Get DNS events related to notice
    
    GET /zeek/notice/<notice_uid>/dns
    
    Response:
        200: List of DNS events (annotated with position: before/after)
        404: Notice not found
        500: Server error
    """
    try:
        dns_events = zeek_service.get_dns_events(notice_uid)
        return jsonify(dns_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/weird', methods=['GET'])
def get_weird_events(notice_uid: str):
    """
    Get weird events (protocol anomalies)
    
    GET /zeek/notice/<notice_uid>/weird
    
    Response:
        200: List of weird events
        404: Notice not found
        500: Server error
    """
    try:
        weird_events = zeek_service.get_weird_events(notice_uid)
        return jsonify(weird_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/taxonomy', methods=['GET'])
def get_taxonomy(notice_uid: str):
    """
    Get notice taxonomy/categorization
    
    GET /zeek/notice/<notice_uid>/taxonomy
    
    Response:
        200: Categorized notice types and behaviors
        404: Notice not found
        500: Server error
    """
    try:
        taxonomy = zeek_service.get_taxonomy(notice_uid)
        return jsonify(taxonomy), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/correlation/suricata', methods=['GET'])
def correlate_suricata(notice_uid: str):
    """
    Correlate with Suricata alerts
    
    GET /zeek/notice/<notice_uid>/correlation/suricata
    
    Response:
        200: Suricata correlation data
        404: Notice not found
        500: Server error
    """
    try:
        correlation = zeek_service.correlate_with_suricata(notice_uid)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)
    
@zeek_bp.route('/notice/<notice_uid>/enrich', methods=['GET'])
def enrich_notice(notice_uid: str):
    """
    Get enriched data for notice
    
    GET /zeek/notice/<notice_uid>/enrich
    
    Response:
        200: Enrichment data
        404: Notice not found
        500: Server error
    """
    try:
        # Get notice data
        summary = zeek_service.get_notice_summary(notice_uid)
        
        # Extract data
        src_ip = summary.get("src")
        dest_ip = summary.get("dst")
        notice_type = summary.get("notice_type")
        
        # Map notice type to attack category
        attack_types = []
        if notice_type:
            attack_types.append(notice_type)
        
        # Enrich
        enrichment_service = get_enrichment_service()
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            dest_ip=dest_ip,
            attack_types=attack_types
        )
        
        return jsonify(enrichment), 200
        
    except Exception as e:
        return handle_error(e)
    
@zeek_bp.route('/notice/<notice_uid>/ai-analyze', methods=['GET'])
def ai_analyze_notice(notice_uid: str):
    """
    AI analysis of Zeek notice
    
    GET /zeek/notice/<notice_uid>/ai-analyze
    
    Response:
        200: AI analysis
        404: Notice not found
        503: AI service not available
        500: Server error
    """
    try:
        # Get AI service
        ai_service = get_ai_service()
        
        if not ai_service.is_enabled():
            return jsonify({
                "ai_enabled": False,
                "message": "AI analysis not available. Configure Azure OpenAI in .env"
            }), 503
        
        # Get notice data
        summary = zeek_service.get_notice_summary(notice_uid)
        related_notices = zeek_service.get_related_notices(notice_uid)
        conn_summary = zeek_service.get_conn_summary(notice_uid)
        http_events = zeek_service.get_http_events(notice_uid)
        dns_events = zeek_service.get_dns_events(notice_uid)
        weird_events = zeek_service.get_weird_events(notice_uid)
        
        # Get enrichment
        from parsers.unified.enrichers import get_enrichment_service
        enrichment_service = get_enrichment_service()
        
        src_ip = summary.get("src")
        dest_ip = summary.get("dst")
        notice_type = summary.get("notice_type")
        
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            dest_ip=dest_ip,
            attack_types=[notice_type] if notice_type else []
        )
        
        # Prepare event data
        event_data = {
            **summary,
            "related_notices": related_notices,
            "connection_summary": conn_summary,
            "http_events": http_events,
            "dns_events": dns_events,
            "weird_events": weird_events
        }
        
        # AI analysis
        analysis = ai_service.analyze(event_data, enrichment)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)