"""
Data Models using Pydantic
Type-safe data structures for API responses
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# ===== Base Models =====

class BaseResponse(BaseModel):
    """Base response model"""
    success: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ErrorResponse(BaseModel):
    """Error response model"""
    success: bool = False
    error: str
    message: str
    status_code: int
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ===== Common Models =====

class GeoIPInfo(BaseModel):
    """GeoIP information"""
    ip: str
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None


class ThreatIntelInfo(BaseModel):
    """Threat intelligence information"""
    ip: str
    reputation: str  # malicious, suspicious, clean, unknown
    abuse_score: Optional[int] = Field(None, ge=0, le=100)
    total_reports: Optional[int] = None
    categories: List[str] = Field(default_factory=list)
    last_reported: Optional[datetime] = None


# ===== ModSecurity Models =====

class ModSecRule(BaseModel):
    """ModSecurity rule information"""
    rule_id: str
    message: str
    severity: str
    phase: int
    file: str
    matched_data: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ModSecTransactionSummary(BaseResponse):
    """ModSecurity transaction summary"""
    transaction_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    hostname: str
    method: str
    uri: str
    status_code: int
    action: str
    severity: str
    total_rules_triggered: int
    primary_attack_type: Optional[str] = None


# ===== Suricata Models =====

class SuricataAlert(BaseModel):
    """Suricata alert information"""
    timestamp: str
    signature: str
    category: str
    severity: int
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str


class SuricataFlowSummary(BaseResponse):
    """Suricata flow summary"""
    flow_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    total_alerts: int
    total_http_requests: int
    total_dns_queries: int
    total_tls_sessions: int


# ===== Zeek Models =====

class ZeekNotice(BaseModel):
    """Zeek notice information"""
    ts: str
    uid: str
    notice_type: str
    msg: str
    sub: Optional[str] = None
    src: str
    dst: str
    proto: str


class ZeekConnection(BaseModel):
    """Zeek connection information"""
    ts: str
    uid: str
    id_orig_h: str
    id_orig_p: int
    id_resp_h: str
    id_resp_p: int
    proto: str
    service: Optional[str] = None
    duration: Optional[float] = None
    orig_bytes: Optional[int] = None
    resp_bytes: Optional[int] = None
    conn_state: Optional[str] = None


class ZeekNoticeSummary(BaseResponse):
    """Zeek notice summary"""
    notice_uid: str
    timestamp: str
    notice_type: str
    msg: str
    src: str
    dst: str
    proto: str
    total_notices: int
    total_weird_events: int
    total_connections: int


# ===== UFW Models =====

class UFWBlock(BaseModel):
    """UFW block information"""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    action: str


class UFWPortSummary(BaseResponse):
    """UFW port summary"""
    dest_port: int
    total_blocks: int
    unique_sources: int
    proto_distribution: Dict[str, int]
    time_range_start: str
    time_range_end: str


# ===== Utility Functions =====

def validate_ip(ip: str) -> bool:
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_transaction_id(tid: str) -> bool:
    """Validate ModSecurity transaction ID format"""
    # Example format: aQwixLvyrQj1czdAm3__DQAAAAQ
    return len(tid) > 10 and tid.replace('_', '').replace('-', '').isalnum()