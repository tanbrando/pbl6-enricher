"""
Configuration Management
Centralized configuration using Pydantic Settings
"""

import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application Settings"""
    
    # ===== Loki Configuration =====
    loki_url: str = Field(
        default="http://localhost:3100",
        description="Loki server URL"
    )
    loki_timeout: int = Field(
        default=10,
        description="Loki query timeout in seconds"
    )
    
    # ===== Flask Configuration =====
    flask_env: str = Field(
        default="development",
        description="Flask environment (development/production)"
    )
    flask_debug: bool = Field(
        default=True,
        description="Enable Flask debug mode"
    )
    flask_host: str = Field(
        default="0.0.0.0",
        description="Flask host"
    )
    flask_port: int = Field(
        default=5000,
        description="Flask port"
    )
    
    # ===== Logging Configuration =====
    log_level: str = Field(
        default="DEBUG",
        description="Logging level (DEBUG/INFO/WARNING/ERROR)"
    )
    log_format: str = Field(
        default="json",
        description="Log format (json/text)"
    )
    log_file: Optional[str] = Field(
        default="./logs/app.log",
        description="Log file path"
    )
    
    # ===== Cache Configuration =====
    redis_enabled: bool = Field(
        default=False,
        description="Enable Redis cache"
    )
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL"
    )
    cache_ttl: int = Field(
        default=3600,
        description="Cache TTL in seconds"
    )
    
    # ===== GeoIP Configuration =====
    geoip_enabled: bool = Field(
        default=False,
        description="Enable GeoIP enrichment"
    )
    geoip_db_path: Optional[str] = Field(
        default="./parsers/data/geoip/GeoLite2-City.mmdb",
        description="GeoIP database path"
    )
    
    # ===== Threat Intelligence =====
    threat_intel_enabled: bool = Field(
        default=False,
        description="Enable threat intelligence enrichment"
    )
    abuseipdb_api_key: Optional[str] = Field(
        default=None,
        description="AbuseIPDB API key"
    )
    virustotal_api_key: Optional[str] = Field(
        default=None,
        description="VirusTotal API key"
    )
    
    # ===== Azure OpenAI Configuration =====
    azure_openai_enabled: bool = Field(
        default=False,
        description="Enable Azure OpenAI AI analysis"
    )
    azure_openai_endpoint: Optional[str] = Field(
        default=None,
        description="Azure OpenAI endpoint URL"
    )
    azure_openai_api_key: Optional[str] = Field(
        default=None,
        description="Azure OpenAI API key"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-01",
        description="Azure OpenAI API version"
    )
    azure_openai_deployment_name: str = Field(
        default="gpt4-turbo",
        description="Azure OpenAI deployment name"
    )
    
    # AI Settings
    ai_temperature: float = Field(
        default=0.3,
        description="AI response temperature (0-1)"
    )
    ai_max_tokens: int = Field(
        default=2000,
        description="AI max response tokens"
    )
    ai_timeout: int = Field(
        default=60,
        description="AI request timeout (seconds)"
    )
    
    # ===== Performance =====
    max_workers: int = Field(
        default=4,
        description="Max concurrent workers"
    )
    request_timeout: int = Field(
        default=30,
        description="Request timeout in seconds"
    )
    
    # Pydantic Settings configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.flask_env.lower() == "production"
    
    @property
    def is_debug(self) -> bool:
        """Check if debug mode is enabled"""
        return self.flask_debug and not self.is_production


# Singleton instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get settings singleton instance"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# Convenience function for quick access
def get_config() -> Settings:
    """Alias for get_settings()"""
    return get_settings()