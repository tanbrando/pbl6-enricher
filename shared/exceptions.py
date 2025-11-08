"""
Custom Exception Classes
"""


class LogEnrichmentAPIError(Exception):
    """Base exception for all API errors"""
    
    def __init__(self, message: str, status_code: int = 500, details: dict = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self):
        """Convert exception to JSON-serializable dict"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details
        }


class LokiConnectionError(LogEnrichmentAPIError):
    """Raised when cannot connect to Loki"""
    
    def __init__(self, message: str = "Failed to connect to Loki", details: dict = None):
        super().__init__(message, status_code=503, details=details)


class LokiQueryError(LogEnrichmentAPIError):
    """Raised when Loki query fails"""
    
    def __init__(self, message: str = "Loki query failed", details: dict = None):
        super().__init__(message, status_code=500, details=details)


class TransactionNotFoundError(LogEnrichmentAPIError):
    """Raised when transaction/event not found in logs"""
    
    def __init__(self, transaction_id: str, details: dict = None):
        message = f"Transaction {transaction_id} not found in logs"
        super().__init__(message, status_code=404, details=details)


class ParseError(LogEnrichmentAPIError):
    """Raised when log parsing fails"""
    
    def __init__(self, message: str = "Failed to parse log", details: dict = None):
        super().__init__(message, status_code=422, details=details)


class EnrichmentError(LogEnrichmentAPIError):
    """Raised when enrichment fails"""
    
    def __init__(self, message: str = "Enrichment failed", details: dict = None):
        super().__init__(message, status_code=500, details=details)


class ValidationError(LogEnrichmentAPIError):
    """Raised when input validation fails"""
    
    def __init__(self, message: str = "Validation failed", details: dict = None):
        super().__init__(message, status_code=400, details=details)


class CacheError(LogEnrichmentAPIError):
    """Raised when cache operations fail"""
    
    def __init__(self, message: str = "Cache operation failed", details: dict = None):
        super().__init__(message, status_code=500, details=details)