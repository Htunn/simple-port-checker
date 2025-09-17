"""
Data models for mTLS (Mutual TLS) authentication results.

This module contains Pydantic models for representing mTLS check results,
certificate information, and batch operation results.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CertificateInfo(BaseModel):
    """Information about an X.509 certificate."""
    subject: str = Field(..., description="Certificate subject DN")
    issuer: str = Field(..., description="Certificate issuer DN")
    version: int = Field(..., description="Certificate version")
    serial_number: str = Field(..., description="Certificate serial number")
    not_valid_before: str = Field(..., description="Certificate validity start date")
    not_valid_after: str = Field(..., description="Certificate validity end date")
    signature_algorithm: str = Field(..., description="Signature algorithm used")
    key_algorithm: str = Field(..., description="Public key algorithm")
    key_size: Optional[int] = Field(None, description="Public key size in bits")
    san_dns_names: List[str] = Field(default_factory=list, description="Subject Alternative Name DNS entries")
    san_ip_addresses: List[str] = Field(default_factory=list, description="Subject Alternative Name IP entries")
    is_ca: bool = Field(False, description="Whether this is a CA certificate")
    is_self_signed: bool = Field(False, description="Whether this is a self-signed certificate")
    fingerprint_sha256: str = Field(..., description="SHA-256 fingerprint of the certificate")


class MTLSResult(BaseModel):
    """Result of mTLS authentication check."""
    target: str = Field(..., description="Target hostname or IP address")
    port: int = Field(..., description="Target port number")
    supports_mtls: bool = Field(..., description="Whether the target supports mTLS")
    requires_client_cert: bool = Field(..., description="Whether client certificate is required")
    server_cert_info: Optional[CertificateInfo] = Field(None, description="Server certificate information")
    client_cert_requested: bool = Field(..., description="Whether server requests client certificate")
    handshake_successful: bool = Field(..., description="Whether mTLS handshake was successful")
    error_message: Optional[str] = Field(None, description="Error message if check failed")
    cipher_suite: Optional[str] = Field(None, description="Cipher suite used in successful connection")
    tls_version: Optional[str] = Field(None, description="TLS version used")
    verification_mode: Optional[str] = Field(None, description="Certificate verification mode")
    ca_bundle_path: Optional[str] = Field(None, description="Path to CA bundle used")
    timestamp: str = Field(..., description="Timestamp of the check")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class BatchMTLSResult(BaseModel):
    """Result of batch mTLS checks."""
    results: List[MTLSResult] = Field(..., description="Individual mTLS check results")
    total_targets: int = Field(..., description="Total number of targets checked")
    successful_checks: int = Field(..., description="Number of successful checks")
    failed_checks: int = Field(..., description="Number of failed checks")
    mtls_supported_count: int = Field(..., description="Number of targets supporting mTLS")
    mtls_required_count: int = Field(..., description="Number of targets requiring client certificates")
    timestamp: str = Field(..., description="Batch operation timestamp")

    @classmethod
    def from_results(cls, results: List[MTLSResult]) -> "BatchMTLSResult":
        """Create BatchMTLSResult from individual results."""
        successful = sum(1 for r in results if r.error_message is None)
        failed = len(results) - successful
        mtls_supported = sum(1 for r in results if r.supports_mtls)
        mtls_required = sum(1 for r in results if r.requires_client_cert)
        
        return cls(
            results=results,
            total_targets=len(results),
            successful_checks=successful,
            failed_checks=failed,
            mtls_supported_count=mtls_supported,
            mtls_required_count=mtls_required,
            timestamp=datetime.utcnow().isoformat()
        )


class MTLSConfig(BaseModel):
    """Configuration for mTLS checks."""
    timeout: int = Field(10, description="Connection timeout in seconds", ge=1, le=300)
    verify_ssl: bool = Field(True, description="Whether to verify SSL certificates")
    client_cert_path: Optional[str] = Field(None, description="Path to client certificate file")
    client_key_path: Optional[str] = Field(None, description="Path to client private key file")
    ca_bundle_path: Optional[str] = Field(None, description="Path to CA bundle file")
    max_concurrent: int = Field(10, description="Maximum concurrent connections", ge=1, le=100)


class MTLSTestProfile(BaseModel):
    """Test profile for mTLS validation."""
    name: str = Field(..., description="Profile name")
    description: str = Field(..., description="Profile description")
    targets: List[Dict[str, Any]] = Field(..., description="List of target configurations")
    config: MTLSConfig = Field(..., description="mTLS check configuration")
    expected_results: Optional[Dict[str, Any]] = Field(None, description="Expected test results")
