"""
Suricata API Routes
Flask blueprint for Suricata endpoints
"""

from flask import Blueprint, jsonify, request

from shared.logger import get_logger
from shared.exceptions import LogEnrichmentAPIError, ValidationError
from services.suricata_service import SuricataService
from enrichers import get_enrichment_service
from ai import get_ai_service

logger = get_logger(__name__)

# Create blueprint
suricata_bp = Blueprint('suricata', __name__)

# Initialize service
suricata_service = SuricataService()


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


@suricata_bp.route('/flow/<flow_id>/summary', methods=['GET'])
def get_flow_summary(flow_id: str):
    """
    Get flow summary
    
    GET /suricata/flow/<flow_id>/summary
    
    Response:
        200: Flow summary
        404: Flow not found
        500: Server error
    """
    try:
        summary = suricata_service.get_flow_summary(flow_id)
        return jsonify(summary), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/alerts', methods=['GET'])
def get_alerts(flow_id: str):
    """
    Get alerts for flow (severity 1 or 2)
    
    GET /suricata/flow/<flow_id>/alerts
    
    Response:
        200: List of alerts
        404: Flow not found
        500: Server error
    """
    try:
        alerts = suricata_service.get_alerts(flow_id=flow_id)
        return jsonify(alerts), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/http', methods=['GET'])
def get_http_events(flow_id: str):
    """
    Get HTTP events for flow
    
    GET /suricata/flow/<flow_id>/http
    
    Response:
        200: List of HTTP events
        404: Flow not found
        500: Server error
    """
    try:
        http_events = suricata_service.get_http_events(flow_id)
        return jsonify(http_events), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/dns', methods=['GET'])
def get_dns_events(flow_id: str):
    """
    Get DNS events for flow
    
    GET /suricata/flow/<flow_id>/dns
    
    Response:
        200: List of DNS events
        404: Flow not found
        500: Server error
    """
    try:
        dns_events = suricata_service.get_dns_events(flow_id=flow_id)
        return jsonify(dns_events), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/tls', methods=['GET'])
def get_tls_events(flow_id: str):
    """
    Get TLS events for flow
    
    GET /suricata/flow/<flow_id>/tls
    
    Response:
        200: List of TLS events
        404: Flow not found
        500: Server error
    """
    try:
        tls_events = suricata_service.get_tls_events(flow_id)
        return jsonify(tls_events), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/context', methods=['GET'])
def get_context(flow_id: str):
    """
    Get comprehensive context (all event types)
    
    GET /suricata/flow/<flow_id>/context
    
    Response:
        200: Context with all events
        404: Flow not found
        500: Server error
    """
    try:
        context = suricata_service.get_context_logs(flow_id)
        return jsonify(context), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/alert-categorization', methods=['GET'])
def get_alert_categorization(flow_id: str):
    """
    Get alert categorization statistics
    
    GET /suricata/flow/<flow_id>/alert-categorization
    
    Response:
        200: Categorized alerts
        404: Flow not found
        500: Server error
    """
    try:
        categorization = suricata_service.get_alert_categorization(flow_id)
        return jsonify(categorization), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/correlation/zeek', methods=['GET'])
def correlate_zeek(flow_id: str):
    """
    Correlate with Zeek logs
    
    GET /suricata/flow/<flow_id>/correlation/zeek
    
    Response:
        200: Zeek correlation data
        404: Flow not found
        500: Server error
    """
    try:
        correlation = suricata_service.correlate_with_zeek(flow_id)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/flow/<flow_id>/correlation/ufw', methods=['GET'])
def correlate_ufw(flow_id: str):
    """
    Correlate with UFW firewall blocks
    
    GET /suricata/flow/<flow_id>/correlation/ufw
    
    Response:
        200: UFW correlation data
        404: Flow not found
        500: Server error
    """
    try:
        correlation = suricata_service.correlate_with_ufw(flow_id)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)


@suricata_bp.route('/alerts', methods=['GET'])
def search_alerts():
    """
    Search alerts by IP
    
    GET /suricata/alerts?src_ip=1.2.3.4&time_range=60
    
    Query Parameters:
        src_ip: Source IP address
        dest_ip: Destination IP address
        time_range: Time range in minutes (default 30)
    
    Response:
        200: List of alerts
        400: Missing parameters
        500: Server error
    """
    try:
        src_ip = request.args.get('src_ip')
        dest_ip = request.args.get('dest_ip')
        time_range = int(request.args.get('time_range', 30))
        
        if not src_ip and not dest_ip:
            raise ValidationError("Must provide src_ip or dest_ip parameter")
        
        alerts = suricata_service.get_alerts(
            src_ip=src_ip,
            dest_ip=dest_ip,
            time_range_minutes=time_range
        )
        
        return jsonify(alerts), 200
        
    except Exception as e:
        return handle_error(e)

@suricata_bp.route('/flow/<flow_id>/enrich', methods=['GET'])
def enrich_flow(flow_id: str):
    """
    Get enriched data for flow
    
    GET /suricata/flow/<flow_id>/enrich
    
    Response:
        200: Enrichment data
        404: Flow not found
        500: Server error
    """
    try:
        # Get flow data
        summary = suricata_service.get_flow_summary(flow_id)
        alerts = suricata_service.get_alerts(flow_id=flow_id)
        
        # Extract data
        src_ip = summary.get("src_ip")
        dest_ip = summary.get("dest_ip")
        
        # Extract attack categories from alerts
        attack_types = []
        for alert in alerts:
            category = alert.get("category", "")
            if category:
                attack_types.append(category)
        
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
    
@suricata_bp.route('/flow/<flow_id>/ai-analyze', methods=['GET'])
def ai_analyze_flow(flow_id: str):
    """
    AI analysis of Suricata flow
    
    GET /suricata/flow/<flow_id>/ai-analyze
    
    Response:
        200: AI analysis
        404: Flow not found
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
        
        # Get flow data
        summary = suricata_service.get_flow_summary(flow_id)
        alerts = suricata_service.get_alerts(flow_id=flow_id)
        http_events = suricata_service.get_http_events(flow_id)
        dns_events = suricata_service.get_dns_events(flow_id=flow_id)
        tls_events = suricata_service.get_tls_events(flow_id)
        
        # Get enrichment
        from parsers.unified.enrichers import get_enrichment_service
        enrichment_service = get_enrichment_service()
        
        src_ip = summary.get("src_ip")
        dest_ip = summary.get("dest_ip")
        
        # Extract attack categories from alerts
        attack_types = list(set([a.get("category") for a in alerts if a.get("category")]))
        
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            dest_ip=dest_ip,
            attack_types=attack_types[:5]  # Top 5 categories
        )
        
        # Prepare comprehensive event data
        event_data = {
            **summary,
            "alerts": alerts,
            "http_events": http_events,
            "dns_events": dns_events,
            "tls_events": tls_events,
            "total_events": len(alerts) + len(http_events) + len(dns_events) + len(tls_events)
        }
        
        # AI analysis
        analysis = ai_service.analyze(event_data, enrichment)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)