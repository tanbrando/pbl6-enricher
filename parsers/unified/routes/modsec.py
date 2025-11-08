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
    
    GET /modsec/transaction/<transaction_id>/summary
    
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
        
        # Get summary
        summary = modsec_service.get_transaction_summary(transaction_id)
        
        return jsonify(summary), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/rules', methods=['GET'])
def get_rules(transaction_id: str):
    """
    Get triggered rules
    
    GET /modsec/transaction/<transaction_id>/rules
    
    Response:
        200: List of rules
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        rules = modsec_service.get_rules(transaction_id)
        
        return jsonify(rules), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/taxonomy', methods=['GET'])
def get_taxonomy(transaction_id: str):
    """
    Get attack taxonomy
    
    GET /modsec/transaction/<transaction_id>/taxonomy
    
    Response:
        200: Categorized tags
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        taxonomy = modsec_service.get_taxonomy(transaction_id)
        
        return jsonify(taxonomy), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/http-details', methods=['GET'])
def get_http_details(transaction_id: str):
    """
    Get HTTP request/response details
    
    GET /modsec/transaction/<transaction_id>/http-details
    
    Response:
        200: HTTP details
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        http_details = modsec_service.get_http_details(transaction_id)
        
        return jsonify(http_details), 200
        
    except Exception as e:
        return handle_error(e)


@modsec_bp.route('/transaction/<transaction_id>/client-analysis', methods=['GET'])
def get_client_analysis(transaction_id: str):
    """
    Get client behavior analysis
    
    GET /modsec/transaction/<transaction_id>/client-analysis
    
    Response:
        200: Client analysis
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        analysis = modsec_service.get_client_analysis(transaction_id)
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return handle_error(e)
    
@modsec_bp.route('/transaction/<transaction_id>/enrich', methods=['GET'])
def enrich_transaction(transaction_id: str):
    """
    Get enriched data for transaction
    
    GET /modsec/transaction/<transaction_id>/enrich
    
    Response:
        200: Enrichment data (GeoIP, Threat Intel, Attack Intel, UA Analysis)
        404: Transaction not found
        500: Server error
    """
    try:
        if not validate_transaction_id(transaction_id):
            raise ValidationError(f"Invalid transaction_id: {transaction_id}")
        
        # Get transaction data
        summary = modsec_service.get_transaction_summary(transaction_id)
        http_details = modsec_service.get_http_details(transaction_id)
        taxonomy = modsec_service.get_taxonomy(transaction_id)
        
        # Extract data for enrichment
        src_ip = summary.get("src_ip")
        dest_ip = summary.get("dest_ip")
        attack_types = list(taxonomy.get("attack_types", {}).keys())
        user_agent = http_details.get("request", {}).get("headers", {}).get("User-Agent")
        
        # Enrich
        enrichment_service = get_enrichment_service()
        enrichment = enrichment_service.enrich_transaction(
            src_ip=src_ip,
            dest_ip=dest_ip,
            attack_types=attack_types,
            user_agent=user_agent
        )
        
        return jsonify(enrichment), 200
        
    except Exception as e:
        return handle_error(e)
    

@modsec_bp.route('/transaction/<transaction_id>/ai-analyze', methods=['GET'])
def ai_analyze_transaction(transaction_id: str):
    """
    AI analysis of ModSecurity transaction
    
    GET /modsec/transaction/<transaction_id>/ai-analyze
    
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
        
        # Get transaction data
        summary = modsec_service.get_transaction_summary(transaction_id)
        rules = modsec_service.get_rules(transaction_id)
        http_details = modsec_service.get_http_details(transaction_id)
        
        # Get enrichment
        from parsers.unified.enrichers import get_enrichment_service
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