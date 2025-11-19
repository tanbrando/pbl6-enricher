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
    
    GET /zeek/notice/<notice_uid>/summary?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Notice summary with stats
        404: Notice not found
        500: Server error
    """
    try:
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        summary = zeek_service.get_notice_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
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
    OR
    GET /zeek/notice/query/conn-summary?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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


@zeek_bp.route('/notice/query/conn-summary', methods=['GET'])
def query_conn_summary_by_ips():
    """Query connection summary by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        conn_summary = zeek_service.get_conn_summary_by_ips(src_ip, dst_ip, start_time, end_time)
        
        return jsonify(conn_summary), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/http', methods=['GET'])
def get_http_events(notice_uid: str):
    """
    Get HTTP events related to notice
    
    GET /zeek/notice/<notice_uid>/http
    OR  
    GET /zeek/notice/query/http?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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


@zeek_bp.route('/notice/query/http', methods=['GET'])
def query_http_by_ips():
    """Query HTTP events by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        http_events = zeek_service.get_http_events_by_ips(src_ip, dst_ip, start_time, end_time)
        return jsonify(http_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/ssl', methods=['GET'])
def get_ssl_events(notice_uid: str):
    """
    Get SSL/TLS events related to notice
    
    GET /zeek/notice/<notice_uid>/ssl
    OR
    GET /zeek/notice/query/ssl?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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


@zeek_bp.route('/notice/query/ssl', methods=['GET'])
def query_ssl_by_ips():
    """Query SSL/TLS events by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        ssl_events = zeek_service.get_ssl_events_by_ips(src_ip, dst_ip, start_time, end_time)
        return jsonify(ssl_events), 200
    except Exception as e:
        return handle_error(e)



@zeek_bp.route('/notice/<notice_uid>/dns', methods=['GET'])
def get_dns_events(notice_uid: str):
    """
    Get DNS events related to notice
    
    GET /zeek/notice/<notice_uid>/dns
    OR
    GET /zeek/notice/query/dns?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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


@zeek_bp.route('/notice/query/dns', methods=['GET'])
def query_dns_by_ips():
    """Query DNS events by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        dns_events = zeek_service.get_dns_events_by_ips(src_ip, dst_ip, start_time, end_time)
        return jsonify(dns_events), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/weird', methods=['GET'])
def get_weird_events(notice_uid: str):
    """
    Get weird events (protocol anomalies)
    
    GET /zeek/notice/<notice_uid>/weird
    OR
    GET /zeek/notice/query/weird?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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


@zeek_bp.route('/notice/query/weird', methods=['GET'])
def query_weird_by_ips():
    """Query weird events by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        weird_events = zeek_service.get_weird_events_by_ips(src_ip, dst_ip, start_time, end_time)
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
    OR
    GET /zeek/notice/query/correlation/suricata?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    
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
    
@zeek_bp.route('/notice/<notice_uid>/geoip', methods=['GET'])
def get_geoip_enrichment(notice_uid: str):
    """
    Get GeoIP enrichment for notice
    
    GET /zeek/notice/<notice_uid>/geoip?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: GeoIP data for source and destination IPs
        404: Notice not found
        500: Server error
    """
    try:
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get notice data
        summary = zeek_service.get_notice_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract IPs
        src_ip = summary.get("src")
        dest_ip = summary.get("dst")
        
        # Get GeoIP enrichment
        enrichment_service = get_enrichment_service()
        geoip_data = enrichment_service.get_geoip_enrichment(src_ip, dest_ip)
        
        return jsonify(geoip_data), 200
        
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/query/geoip', methods=['GET'])
def query_geoip_by_ips():
    """Query GeoIP enrichment by IPs"""
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        enrichment_service = get_enrichment_service()
        geoip_data = enrichment_service.get_geoip_enrichment(src_ip, dst_ip)
        
        return jsonify(geoip_data), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/threat-intel', methods=['GET'])
def get_threat_intel(notice_uid: str):
    """
    Get threat intelligence for notice
    
    GET /zeek/notice/<notice_uid>/threat-intel?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Threat intelligence data
        404: Notice not found
        500: Server error
    """
    try:
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get notice data
        summary = zeek_service.get_notice_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract IP
        src_ip = summary.get("src")
        
        # Get threat intel
        enrichment_service = get_enrichment_service()
        threat_data = enrichment_service.get_threat_intel(src_ip)
        
        return jsonify(threat_data), 200
        
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/query/threat-intel', methods=['GET'])
def query_threat_intel_by_ips():
    """Query threat intelligence by IPs"""
    try:
        src_ip = request.args.get('src')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        enrichment_service = get_enrichment_service()
        threat_data = enrichment_service.get_threat_intel(src_ip)
        
        return jsonify(threat_data), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/<notice_uid>/attack-intel', methods=['GET'])
def get_attack_intel(notice_uid: str):
    """
    Get attack intelligence for notice
    
    GET /zeek/notice/<notice_uid>/attack-intel?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Attack intelligence mapping
        404: Notice not found
        500: Server error
    """
    try:
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get notice data
        summary = zeek_service.get_notice_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract notice type
        notice_type = summary.get("notice_type")
        
        # Map notice type to attack category
        attack_types = []
        if notice_type:
            attack_types.append(notice_type)
        
        # Get attack intel
        enrichment_service = get_enrichment_service()
        attack_data = enrichment_service.get_attack_intel(attack_types)
        
        return jsonify(attack_data), 200
        
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/query/attack-intel', methods=['GET'])
def query_attack_intel_by_ips():
    """Query attack intelligence by notice type"""
    try:
        note_type = request.args.get('note')
        
        if not note_type:
            raise ValidationError("'note' parameter is required (e.g., Scan::Port_Scan)")
        
        attack_types = [note_type]
        enrichment_service = get_enrichment_service()
        attack_data = enrichment_service.get_attack_intel(attack_types)
        
        return jsonify(attack_data), 200
    except Exception as e:
        return handle_error(e)
    
@zeek_bp.route('/notice/<notice_uid>/ai-analyze', methods=['GET'])
def ai_analyze_notice(notice_uid: str):
    """
    AI analysis of Zeek notice
    
    GET /zeek/notice/<notice_uid>/ai-analyze?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
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
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get notice data
        summary = zeek_service.get_notice_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        related_notices = zeek_service.get_related_notices(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        conn_summary = zeek_service.get_conn_summary(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        http_events = zeek_service.get_http_events(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        dns_events = zeek_service.get_dns_events(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        weird_events = zeek_service.get_weird_events(
            notice_uid=notice_uid,
            start_time=start_time,
            end_time=end_time
        )
        
        # Get enrichment
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


@zeek_bp.route('/notice/query/ai-analyze', methods=['GET'])
def query_ai_analyze_by_ips():
    """
    AI analysis by IPs (for notices without UID)
    
    GET /zeek/notice/query/ai-analyze?src=<ip>&dst=<ip>&start=<ts>&end=<ts>&note=<type>
    """
    try:
        # Get AI service
        ai_service = get_ai_service()
        
        if not ai_service.is_enabled():
            return jsonify({
                "ai_enabled": False,
                "message": "AI analysis not available. Set GEMINI_API_KEY in .env to enable AI features (FREE)"
            }), 503
        
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        note_type = request.args.get('note')
        
        if not src_ip:
            raise ValidationError("'src' parameter is required")
        
        # Get notice data by IPs
        summary = zeek_service.get_notice_summary_by_ips(src_ip, dst_ip, start_time, end_time)
        
        # Get related data
        conn_summary = zeek_service.get_conn_summary_by_ips(src_ip, dst_ip, start_time, end_time)
        http_events = zeek_service.get_http_events_by_ips(src_ip, dst_ip, start_time, end_time)
        dns_events = zeek_service.get_dns_events_by_ips(src_ip, dst_ip, start_time, end_time)
        weird_events = zeek_service.get_weird_events_by_ips(src_ip, dst_ip, start_time, end_time)
        
        # Get enrichment
        enrichment_service = get_enrichment_service()
        notice_type_val = note_type or summary.get("notice_type")
        
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            dest_ip=dst_ip,
            attack_types=[notice_type_val] if notice_type_val else []
        )
        
        # Prepare event data
        event_data = {
            **summary,
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


@zeek_bp.route('/notice/query/summary', methods=['GET'])
def query_notice_by_ips():
    """
    Query notice by src and dst IPs (for notices without UID)
    
    GET /zeek/notice/query?src=<src_ip>&dst=<dst_ip>&start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        src: Source IP address (required)
        dst: Destination IP address (required)
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
        note: Notice type filter (optional, e.g., Scan::Port_Scan)
    
    Response:
        200: Notice summary
        400: Missing parameters
        404: Notice not found
        500: Server error
    """
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        note_type = request.args.get('note')
        
        if not src_ip :
            raise ValidationError("'src' parameter is required")
        
        summary = zeek_service.get_notice_summary_by_ips(
            src_ip=src_ip,
            dst_ip=dst_ip,
            start_time=start_time,
            end_time=end_time
        )
        return jsonify(summary), 200
    except Exception as e:
        return handle_error(e)


@zeek_bp.route('/notice/query/correlation/suricata', methods=['GET'])
def query_suricata_correlation_by_ips():
    """
    Query Suricata correlation by IPs
    GET /zeek/notice/query/correlation/suricata?src=<ip>&dst=<ip>&start=<ts>&end=<ts>
    """
    try:
        src_ip = request.args.get('src')
        dst_ip = request.args.get('dst')
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        if not src_ip or not dst_ip:
            raise ValidationError("Both 'src' and 'dst' parameters are required")
        
        correlation = zeek_service.correlate_with_suricata_by_ips(src_ip, dst_ip, start_time, end_time)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)
