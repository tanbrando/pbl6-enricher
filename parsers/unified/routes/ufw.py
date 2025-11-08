"""
UFW API Routes (JSON Format)
Flask blueprint for UFW endpoints
"""

from flask import Blueprint, jsonify, request

from shared.logger import get_logger
from shared.exceptions import LogEnrichmentAPIError, ValidationError
from services.ufw_service import UFWService
from enrichers import get_enrichment_service
from ai import get_ai_service

logger = get_logger(__name__)

# Create blueprint
ufw_bp = Blueprint('ufw', __name__)

# Initialize service
ufw_service = UFWService()


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


@ufw_bp.route('/port/<int:dest_port>/summary', methods=['GET'])
def get_port_summary(dest_port: int):
    """Get port summary (includes zone distribution)"""
    try:
        time_range = int(request.args.get('time_range', 24))
        summary = ufw_service.get_port_summary(dest_port, time_range)
        return jsonify(summary), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/blocks', methods=['GET'])
def get_blocks(dest_port: int):
    """Get all blocks (includes zone info)"""
    try:
        time_range = int(request.args.get('time_range', 24))
        blocks = ufw_service.get_blocks_for_port(dest_port, time_range)
        return jsonify(blocks), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/top-sources', methods=['GET'])
def get_top_sources(dest_port: int):
    """Get top sources (includes zone info)"""
    try:
        time_range = int(request.args.get('time_range', 24))
        limit = int(request.args.get('limit', 10))
        top_sources = ufw_service.get_top_sources(dest_port, time_range, limit)
        return jsonify(top_sources), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/attack-pattern', methods=['GET'])
def get_attack_pattern(dest_port: int):
    """Analyze attack pattern (includes zone analysis)"""
    try:
        time_range = int(request.args.get('time_range', 24))
        pattern = ufw_service.get_attack_pattern(dest_port, time_range)
        return jsonify(pattern), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/zone-statistics', methods=['GET'])
def get_zone_statistics(dest_port: int):
    """
    Get zone-based statistics (NEW)
    
    GET /ufw/port/<dest_port>/zone-statistics
    
    Query Parameters:
        time_range: Time range in hours (default 24)
    
    Response:
        200: Zone statistics
        500: Server error
    """
    try:
        time_range = int(request.args.get('time_range', 24))
        zone_stats = ufw_service.get_zone_statistics(dest_port, time_range)
        return jsonify(zone_stats), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/timeline', methods=['GET'])
def get_timeline(dest_port: int):
    """
    Get timeline (optionally grouped by zone)
    
    Query Parameters:
        time_range: Time range in hours (default 24)
        group_by_zone: true/false (default false)
    """
    try:
        time_range = int(request.args.get('time_range', 24))
        group_by_zone = request.args.get('group_by_zone', 'false').lower() == 'true'
        
        timeline = ufw_service.get_timeline(dest_port, time_range, group_by_zone)
        return jsonify(timeline), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/correlation/suricata', methods=['GET'])
def correlate_suricata(dest_port: int):
    """Correlate with Suricata"""
    try:
        time_range = int(request.args.get('time_range', 1))
        correlation = ufw_service.correlate_with_suricata(dest_port, time_range)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/correlation/zeek', methods=['GET'])
def correlate_zeek(dest_port: int):
    """Correlate with Zeek"""
    try:
        time_range = int(request.args.get('time_range', 1))
        correlation = ufw_service.correlate_with_zeek(dest_port, time_range)
        return jsonify(correlation), 200
    except Exception as e:
        return handle_error(e)


@ufw_bp.route('/port/<int:dest_port>/fail2ban', methods=['GET'])
def get_fail2ban_status(dest_port: int):
    """Get Fail2ban status"""
    try:
        time_range = int(request.args.get('time_range', 24))
        fail2ban = ufw_service.get_fail2ban_status(dest_port, time_range)
        return jsonify(fail2ban), 200
    except Exception as e:
        return handle_error(e)
    
@ufw_bp.route('/port/<int:dest_port>/enrich-sources', methods=['GET'])
def enrich_sources(dest_port: int):
    """
    Enrich top attacking sources for port
    
    GET /ufw/port/<dest_port>/enrich-sources
    
    Query Parameters:
        time_range: Time range in hours (default 24)
        limit: Number of top sources (default 10)
    
    Response:
        200: Enriched source IPs
        500: Server error
    """
    try:
        time_range = int(request.args.get('time_range', 24))
        limit = int(request.args.get('limit', 10))
        
        # Get top sources
        top_sources = ufw_service.get_top_sources(dest_port, time_range, limit)
        
        # Enrich each source IP
        enrichment_service = get_enrichment_service()
        
        enriched_sources = []
        for source in top_sources:
            src_ip = source.get("src_ip")
            
            # Enrich IP
            ip_enrichment = enrichment_service.enrich_ip(src_ip)
            
            # Combine with source data
            enriched_sources.append({
                **source,
                "enrichment": ip_enrichment
            })
        
        return jsonify(enriched_sources), 200
        
    except Exception as e:
        return handle_error(e)
    
@ufw_bp.route('/port/<int:dest_port>/ai-analyze', methods=['GET'])
def ai_analyze_port(dest_port: int):
    """
    AI analysis of UFW port attacks
    
    GET /ufw/port/<dest_port>/ai-analyze
    
    Query Parameters:
        time_range: Time range in hours (default 24)
    
    Response:
        200: AI analysis
        503: AI service not available
        500: Server error
    """
    try:
        time_range = int(request.args.get('time_range', 24))
        
        # Get AI service
        ai_service = get_ai_service()
        
        if not ai_service.is_enabled():
            return jsonify({
                "ai_enabled": False,
                "message": "AI analysis not available. Configure Azure OpenAI in .env"
            }), 503
        
        # Get port attack data
        summary = ufw_service.get_port_summary(dest_port, time_range)
        top_sources = ufw_service.get_top_sources(dest_port, time_range, limit=10)
        attack_pattern = ufw_service.get_attack_pattern(dest_port, time_range)
        zone_stats = ufw_service.get_zone_statistics(dest_port, time_range)
        
        # Get enrichment for top sources
        from parsers.unified.enrichers import get_enrichment_service
        enrichment_service = get_enrichment_service()
        
        # Enrich top 3 attacking IPs
        top_ips = [s.get("src_ip") for s in top_sources[:3]]
        ip_enrichments = {}
        
        for ip in top_ips:
            if ip:
                ip_enrichments[ip] = enrichment_service.enrich_ip(ip)
        
        # Prepare event data
        event_data = {
            "dest_port": dest_port,
            "time_range_hours": time_range,
            "summary": summary,
            "top_sources": top_sources,
            "attack_pattern": attack_pattern,
            "zone_statistics": zone_stats
        }
        
        enrichment = {
            "source_ips": ip_enrichments
        }
        
        # AI analysis
        analysis = ai_service.analyze(event_data, enrichment)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)