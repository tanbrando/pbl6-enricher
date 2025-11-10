"""
ModSecurity API Routes
Flask blueprint for ModSecurity endpoints
"""

from flask import Blueprint, jsonify, request
from typing import Dict, Any

from shared.logger import get_logger
from shared.exceptions import LogEnrichmentAPIError, ValidationError
from shared.models import validate_transaction_id
from services.modsec_service import ModSecService
from enrichers import get_enrichment_service
from ai import get_ai_service

logger = get_logger(__name__)

# Create blueprint
modsec_bp = Blueprint('modsec', __name__)

# Initialize service
modsec_service = ModSecService()


def handle_error(error: Exception) -> tuple:
    """Error handler for all endpoints"""
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


@modsec_bp.route('/transaction/<transaction_id>/summary', methods=['GET'])
def get_transaction_summary(transaction_id: str):
    """
    Get transaction summary
    
    GET /modsec/transaction/<transaction_id>/summary?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Transaction summary
        404: Transaction not found
        500: Server error
    """
    try:
        # Validate transaction_id
        if not validate_transaction_id(transaction_id):
            raise ValidationError(
                f"Invalid transaction_id format: {transaction_id}",
                details={"transaction_id": transaction_id}
            )
        
        # Get time range from query parameters (Grafana sends these)
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get summary
        summary = modsec_service.get_transaction_summary(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify(summary), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/rules', methods=['GET'])
def get_rules(transaction_id: str):
    """
    Get triggered rules
    
    GET /modsec/transaction/<transaction_id>/rules?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: List of rules
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        # Get time range from query parameters
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        rules = modsec_service.get_rules(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify(rules), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/taxonomy', methods=['GET'])
def get_taxonomy(transaction_id: str):
    """
    Get attack taxonomy
    
    GET /modsec/transaction/<transaction_id>/taxonomy?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Categorized tags
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        taxonomy = modsec_service.get_taxonomy(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify(taxonomy), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/http-details', methods=['GET'])
def get_http_details(transaction_id: str):
    """
    Get HTTP request/response details
    
    GET /modsec/transaction/<transaction_id>/http-details?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: HTTP details
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        http_details = modsec_service.get_http_details(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify(http_details), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/client-analysis', methods=['GET'])
def get_client_analysis(transaction_id: str):
    """
    Get client behavior analysis
    
    GET /modsec/transaction/<transaction_id>/client-analysis?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Client analysis
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        analysis = modsec_service.get_client_analysis(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)
    
@modsec_bp.route('/transaction/<transaction_id>/geoip', methods=['GET'])
def get_geoip_enrichment(transaction_id: str):
    """
    Get GeoIP enrichment for transaction
    
    GET /modsec/transaction/<transaction_id>/geoip?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: GeoIP data for source and destination IPs
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get transaction data
        summary = modsec_service.get_transaction_summary(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract IPs
        src_ip = summary.get("src_ip")
        dest_ip = summary.get("dest_ip")
        
        # Get GeoIP enrichment
        enrichment_service = get_enrichment_service()
        geoip_data = enrichment_service.get_geoip_enrichment(src_ip, dest_ip)
        
        return jsonify(geoip_data), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/threat-intel', methods=['GET'])
def get_threat_intel(transaction_id: str):
    """
    Get threat intelligence for transaction
    
    GET /modsec/transaction/<transaction_id>/threat-intel?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Threat intelligence data
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get transaction data
        summary = modsec_service.get_transaction_summary(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract IP
        src_ip = summary.get("src_ip")
        
        # Get threat intel
        enrichment_service = get_enrichment_service()
        threat_data = enrichment_service.get_threat_intel(src_ip)
        
        return jsonify(threat_data), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/attack-intel', methods=['GET'])
def get_attack_intel(transaction_id: str):
    """
    Get attack intelligence for transaction
    
    GET /modsec/transaction/<transaction_id>/attack-intel?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: Attack intelligence (MITRE ATT&CK, OWASP)
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get transaction data
        taxonomy = modsec_service.get_taxonomy(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract attack types
        attack_types = list(taxonomy.get("attack_types", {}).keys())
        
        # Get attack intel
        enrichment_service = get_enrichment_service()
        attack_data = enrichment_service.get_attack_intel(attack_types)
        
        return jsonify(attack_data), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/user-agent', methods=['GET'])
def get_user_agent_analysis(transaction_id: str):
    """
    Get User-Agent analysis for transaction
    
    GET /modsec/transaction/<transaction_id>/user-agent?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: User-Agent analysis
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get HTTP details
        http_details = modsec_service.get_http_details(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # Extract User-Agent
        user_agent = http_details.get("request", {}).get("headers", {}).get("User-Agent")
        
        # Analyze User-Agent
        enrichment_service = get_enrichment_service()
        ua_analysis = enrichment_service.analyze_user_agent(user_agent)
        
        return jsonify(ua_analysis), 200
        
    except Exception as e:
        return handle_error(e)
    

@modsec_bp.route('/transaction/<transaction_id>/ai-analyze', methods=['GET'])
def ai_analyze_transaction(transaction_id: str):
    """
    AI analysis of ModSecurity transaction
    
    GET /modsec/transaction/<transaction_id>/ai-analyze?start=<timestamp>&end=<timestamp>
    
    Query Parameters:
        start: Start timestamp (Unix timestamp in nanoseconds or ISO format)
        end: End timestamp (Unix timestamp in nanoseconds or ISO format)
    
    Response:
        200: AI analysis (narrative, threat assessment, recommendations)
        404: Transaction not found
        503: AI service not available
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        # Get AI service
        ai_service = get_ai_service()
        
        if not ai_service.is_enabled():
            return jsonify({
                "ai_enabled": False,
                "message": "AI analysis not available. Configure Azure OpenAI in .env"
            }), 503
        
        start_time = request.args.get('start')
        end_time = request.args.get('end')
        
        # Get transaction data
        summary = modsec_service.get_transaction_summary(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        rules = modsec_service.get_rules(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        http_details = modsec_service.get_http_details(
            transaction_id=transaction_id,
            start_time=start_time,
            end_time=end_time
        )
        
        # Get enrichment
        from enrichers import get_enrichment_service
        enrichment_service = get_enrichment_service()
        
        src_ip = summary.get("src_ip")
        user_agent = http_details.get("request", {}).get("headers", {}).get("User-Agent")
        
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            attack_types=[r.get("rule_id") for r in rules[:3]],  # Top 3 rules
            user_agent=user_agent
        )
        
        # Prepare event data for AI
        event_data = {
            **summary,
            "rules": rules,
            "http": http_details
        }
        
        # AI analysis
        analysis = ai_service.analyze(event_data, enrichment)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)