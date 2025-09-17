"""
Mutual TLS (mTLS) Authentication Checker.

This module provides functionality to check and verify mTLS configurations
on target hosts, including certificate validation, client authentication
requirements, and mTLS handshake analysis.
"""

import asyncio
import ssl
import socket
import logging
import ipaddress
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path
from urllib.parse import urlparse

try:
    import certifi
    CERTIFI_AVAILABLE = True
except ImportError:
    CERTIFI_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from ..models.mtls_result import CertificateInfo, MTLSResult, BatchMTLSResult


class MTLSChecker:
    """
    Production-ready mTLS (Mutual TLS) Authentication Checker.
    
    This class provides methods to check if a target supports mTLS authentication,
    verify certificate requirements, and analyze the mTLS handshake process.
    
    Features:
    - Comprehensive error handling and validation
    - Support for various certificate formats
    - Configurable timeouts and retry logic
    - Detailed logging and metrics
    - Resource cleanup and connection pooling
    """

    def __init__(
        self, 
        timeout: int = 10, 
        verify_ssl: bool = True,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        enable_logging: bool = True
    ):
        """
        Initialize the MTLSChecker with production-ready configuration.
        
        Args:
            timeout: Connection timeout in seconds (1-300)
            verify_ssl: Whether to verify SSL certificates
            max_retries: Maximum number of retry attempts (0-10)
            retry_delay: Delay between retries in seconds (0.1-10.0)
            enable_logging: Whether to enable detailed logging
            
        Raises:
            ValueError: If parameters are out of valid range
        """
        # Validate input parameters
        if not isinstance(timeout, int) or not (1 <= timeout <= 300):
            raise ValueError("Timeout must be an integer between 1 and 300 seconds")
        if not isinstance(max_retries, int) or not (0 <= max_retries <= 10):
            raise ValueError("Max retries must be an integer between 0 and 10")
        if not isinstance(retry_delay, (int, float)) or not (0.1 <= retry_delay <= 10.0):
            raise ValueError("Retry delay must be a number between 0.1 and 10.0 seconds")
            
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        if enable_logging:
            self.logger.setLevel(logging.DEBUG)
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
        else:
            self.logger.setLevel(logging.CRITICAL)
        
        # Initialize metrics
        self._reset_metrics()
        
        # Validate dependencies
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning(
                "Cryptography library not available. Certificate parsing will be limited."
            )

    def _reset_metrics(self):
        """Reset internal metrics."""
        self._metrics = {
            'total_requests': 0,
            'successful_connections': 0,
            'failed_connections': 0,
            'mtls_supported': 0,
            'client_cert_required': 0,
            'handshake_failures': 0,
            'certificate_errors': 0,
            'network_errors': 0,
            'timeout_errors': 0,
            'total_time': 0.0
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance and reliability metrics."""
        return self._metrics.copy()

    def _validate_target(self, target: str) -> str:
        """
        Validate and normalize target hostname or IP.
        
        Args:
            target: Target hostname or IP address
            
        Returns:
            Normalized target string
            
        Raises:
            ValueError: If target is invalid
        """
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")
        
        target = target.strip().lower()
        
        # Remove protocol prefix if present
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(f"https://{target}" if not target.startswith('http') else target)
            target = parsed.hostname or parsed.netloc
        
        # Validate IP address or hostname format
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return target
        except ValueError:
            # Must be a hostname - basic validation
            if not target.replace('-', '').replace('.', '').replace('_', '').isalnum():
                raise ValueError(f"Invalid hostname format: {target}")
            if len(target) > 253:  # Max hostname length
                raise ValueError(f"Hostname too long: {target}")
            if target.startswith('.') or target.endswith('.'):
                raise ValueError(f"Invalid hostname format: {target}")
            return target

    def _validate_port(self, port: int) -> int:
        """
        Validate port number.
        
        Args:
            port: Port number
            
        Returns:
            Validated port number
            
        Raises:
            ValueError: If port is invalid
        """
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("Port must be an integer between 1 and 65535")
        return port

    def _validate_certificate_files(
        self, 
        cert_path: Optional[str], 
        key_path: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Validate certificate and key file paths.
        
        Args:
            cert_path: Path to certificate file
            key_path: Path to private key file
            
        Returns:
            Tuple of validated paths
            
        Raises:
            ValueError: If files are invalid or don't match
        """
        if cert_path is None and key_path is None:
            return None, None
        
        if cert_path is None or key_path is None:
            raise ValueError("Both certificate and key paths must be provided together")
        
        cert_file = Path(cert_path)
        key_file = Path(key_path)
        
        if not cert_file.exists():
            raise ValueError(f"Certificate file not found: {cert_path}")
        if not cert_file.is_file():
            raise ValueError(f"Certificate path is not a file: {cert_path}")
        if not key_file.exists():
            raise ValueError(f"Private key file not found: {key_path}")
        if not key_file.is_file():
            raise ValueError(f"Private key path is not a file: {key_path}")
        
        # Additional validation if cryptography is available
        if CRYPTOGRAPHY_AVAILABLE:
            is_valid, error_msg = validate_certificate_files(str(cert_file), str(key_file))
            if not is_valid:
                raise ValueError(f"Certificate validation failed: {error_msg}")
        
        return str(cert_file), str(key_file)

    async def _execute_with_retry(
        self, 
        operation_name: str, 
        operation_func, 
        *args, 
        **kwargs
    ) -> Any:
        """
        Execute an operation with retry logic.
        
        Args:
            operation_name: Name of the operation for logging
            operation_func: Function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Result of the operation
            
        Raises:
            Exception: Last exception if all retries fail
        """
        last_exception = None
        
        for attempt in range(self.max_retries + 1):
            try:
                start_time = time.time()
                result = await operation_func(*args, **kwargs) if asyncio.iscoroutinefunction(operation_func) else operation_func(*args, **kwargs)
                elapsed = time.time() - start_time
                
                self.logger.debug(
                    f"{operation_name} succeeded on attempt {attempt + 1} in {elapsed:.3f}s"
                )
                return result
                
            except Exception as e:
                last_exception = e
                elapsed = time.time() - start_time
                
                if attempt < self.max_retries:
                    self.logger.warning(
                        f"{operation_name} failed on attempt {attempt + 1} after {elapsed:.3f}s: {e}. "
                        f"Retrying in {self.retry_delay}s..."
                    )
                    await asyncio.sleep(self.retry_delay)
                else:
                    self.logger.error(
                        f"{operation_name} failed after {attempt + 1} attempts: {e}"
                    )
                    break
        
        raise last_exception

    async def check_mtls(
        self, 
        target: str, 
        port: int = 443,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        ca_bundle_path: Optional[str] = None
    ) -> MTLSResult:
        """
        Check if target supports mTLS authentication with comprehensive validation.
        
        Args:
            target: Target hostname or IP address
            port: Target port (default: 443)
            client_cert_path: Path to client certificate file (PEM format)
            client_key_path: Path to client private key file (PEM format)
            ca_bundle_path: Path to CA bundle file
            
        Returns:
            MTLSResult object containing the check results
            
        Raises:
            ValueError: If input parameters are invalid
            ConnectionError: If connection fails after all retries
        """
        # Update metrics
        self._metrics['total_requests'] += 1
        start_time = time.time()
        
        try:
            # Validate inputs
            target = self._validate_target(target)
            port = self._validate_port(port)
            client_cert_path, client_key_path = self._validate_certificate_files(
                client_cert_path, client_key_path
            )
            
            timestamp = datetime.now(timezone.utc).isoformat()
            
            self.logger.info(f"Starting mTLS check for {target}:{port}")
            
            # Execute the check with retry logic
            result = await self._execute_with_retry(
                f"mTLS check {target}:{port}",
                self._perform_mtls_check,
                target, port, client_cert_path, client_key_path, ca_bundle_path, timestamp
            )
            
            # Update metrics
            elapsed = time.time() - start_time
            self._metrics['total_time'] += elapsed
            self._metrics['successful_connections'] += 1
            
            if result.supports_mtls:
                self._metrics['mtls_supported'] += 1
            if result.requires_client_cert:
                self._metrics['client_cert_required'] += 1
            if not result.handshake_successful:
                self._metrics['handshake_failures'] += 1
            
            self.logger.info(f"mTLS check completed for {target}:{port} in {elapsed:.3f}s")
            return result
            
        except Exception as e:
            # Update error metrics
            elapsed = time.time() - start_time
            self._metrics['total_time'] += elapsed
            self._metrics['failed_connections'] += 1
            
            if isinstance(e, (socket.timeout, asyncio.TimeoutError)):
                self._metrics['timeout_errors'] += 1
            elif isinstance(e, (ConnectionError, socket.error)):
                self._metrics['network_errors'] += 1
            elif 'certificate' in str(e).lower():
                self._metrics['certificate_errors'] += 1
            
            self.logger.error(f"mTLS check failed for {target}:{port}: {e}")
            
            # Return error result instead of raising exception
            return MTLSResult(
                target=target,
                port=port,
                supports_mtls=False,
                requires_client_cert=False,
                server_cert_info=None,
                client_cert_requested=False,
                handshake_successful=False,
                error_message=f"Connection failed: {str(e)}",
                cipher_suite=None,
                tls_version=None,
                verification_mode=None,
                ca_bundle_path=None,
                timestamp=datetime.now(timezone.utc).isoformat()
            )

    async def _perform_mtls_check(
        self,
        target: str,
        port: int,
        client_cert_path: Optional[str],
        client_key_path: Optional[str],
        ca_bundle_path: Optional[str],
        timestamp: str
    ) -> MTLSResult:
        """Perform the actual mTLS check."""
        try:
            # First, try a standard TLS connection to see if the server is reachable
            server_cert_info = await self._get_server_certificate_info(target, port)
            
            # Check if client certificate is requested/required
            client_cert_requested, requires_client_cert = await self._check_client_cert_requirement(
                target, port, ca_bundle_path
            )
            
            # If we have client certificates, test mTLS authentication
            mtls_successful = False
            cipher_suite = None
            tls_version = None
            verification_mode = "default"
            error_message = None
            
            if client_cert_path and client_key_path:
                try:
                    mtls_result = await self._perform_mtls_handshake(
                        target, port, client_cert_path, client_key_path, ca_bundle_path
                    )
                    mtls_successful = mtls_result["success"]
                    cipher_suite = mtls_result.get("cipher_suite")
                    tls_version = mtls_result.get("tls_version")
                    error_message = mtls_result.get("error")
                except Exception as e:
                    error_message = f"mTLS handshake failed: {str(e)}"
                    self.logger.debug(f"mTLS handshake error: {e}")
            elif client_cert_requested:
                error_message = "Server requests client certificate but none provided"
            
            return MTLSResult(
                target=target,
                port=port,
                supports_mtls=client_cert_requested,
                requires_client_cert=requires_client_cert,
                server_cert_info=server_cert_info,
                client_cert_requested=client_cert_requested,
                handshake_successful=mtls_successful,
                error_message=error_message,
                cipher_suite=cipher_suite,
                tls_version=tls_version,
                verification_mode=verification_mode,
                ca_bundle_path=ca_bundle_path or (certifi.where() if CERTIFI_AVAILABLE else None),
                timestamp=timestamp
            )
            
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {target}:{port}: {str(e)}")

    async def _get_server_certificate_info(self, target: str, port: int) -> Optional[CertificateInfo]:
        """Get server certificate information with enhanced error handling."""
        if not CRYPTOGRAPHY_AVAILABLE:
            self.logger.warning("Cryptography library not available, certificate parsing disabled")
            return None
            
        try:
            # Create SSL context with proper security settings
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2  # Require at least TLS 1.2
            
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self.logger.warning(f"SSL verification disabled for {target}:{port}")
            
            # Set reasonable cipher preferences
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Connect with timeout
            sock = None
            ssock = None
            try:
                sock = socket.create_connection((target, port), timeout=self.timeout)
                sock.settimeout(self.timeout)
                ssock = context.wrap_socket(sock, server_hostname=target)
                
                # Get certificate in DER format
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    self.logger.warning(f"No certificate received from {target}:{port}")
                    return None
                
                cert = x509.load_der_x509_certificate(cert_der)
                return self._parse_certificate(cert)
                
            finally:
                # Ensure proper cleanup
                if ssock:
                    try:
                        ssock.close()
                    except:
                        pass
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                
        except ssl.SSLError as e:
            self.logger.debug(f"SSL error getting certificate from {target}:{port}: {e}")
            return None
        except socket.timeout:
            self.logger.debug(f"Timeout getting certificate from {target}:{port}")
            return None
        except Exception as e:
            self.logger.debug(f"Failed to get server certificate from {target}:{port}: {e}")
            return None

    async def _check_client_cert_requirement(
        self, 
        target: str, 
        port: int, 
        ca_bundle_path: Optional[str] = None
    ) -> Tuple[bool, bool]:
        """
        Check if server requests/requires client certificates with improved detection.
        
        Returns:
            Tuple of (client_cert_requested, client_cert_required)
        """
        try:
            # Create SSL context without client certificates
            context = ssl.create_default_context(cafile=ca_bundle_path)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            sock = None
            ssock = None
            
            try:
                sock = socket.create_connection((target, port), timeout=self.timeout)
                sock.settimeout(self.timeout)
                
                # Attempt connection without client certificate
                ssock = context.wrap_socket(sock, server_hostname=target)
                
                # If we get here, client cert is not required
                return False, False
                
            except ssl.SSLError as e:
                error_msg = str(e).lower()
                
                # Analyze SSL error to determine certificate requirements
                if any(phrase in error_msg for phrase in [
                    'certificate required', 'client certificate needed',
                    'certificate verify failed', 'certificate unknown',
                    'bad certificate', 'certificate_required'
                ]):
                    # Server requires client certificate
                    return True, True
                elif any(phrase in error_msg for phrase in [
                    'handshake failure', 'protocol version',
                    'cipher mismatch', 'no shared cipher'
                ]):
                    # SSL handshake issue, might support mTLS but not require it
                    return True, False
                else:
                    # Other SSL error, probably doesn't support mTLS
                    self.logger.debug(f"SSL error checking client cert requirement: {e}")
                    return False, False
                    
            except socket.timeout:
                self.logger.debug(f"Timeout checking client cert requirement for {target}:{port}")
                return False, False
            except Exception as e:
                self.logger.debug(f"Error checking client cert requirement for {target}:{port}: {e}")
                return False, False
            finally:
                # Cleanup
                if ssock:
                    try:
                        ssock.close()
                    except:
                        pass
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                
        except Exception as e:
            self.logger.debug(f"Failed to check client cert requirement for {target}:{port}: {e}")
            return False, False

    async def _perform_mtls_handshake(
        self, 
        target: str, 
        port: int,
        client_cert_path: str,
        client_key_path: str,
        ca_bundle_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Perform mTLS handshake with client certificates and enhanced error handling."""
        try:
            # Create SSL context with client certificates
            context = ssl.create_default_context(cafile=ca_bundle_path)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            # Load client certificate and key
            try:
                context.load_cert_chain(client_cert_path, client_key_path)
            except Exception as e:
                return {
                    "success": False,
                    "cipher_suite": None,
                    "tls_version": None,
                    "error": f"Failed to load client certificate: {e}"
                }
            
            if not self.verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            sock = None
            ssock = None
            
            try:
                sock = socket.create_connection((target, port), timeout=self.timeout)
                sock.settimeout(self.timeout)
                ssock = context.wrap_socket(sock, server_hostname=target)
                
                # Get connection details
                cipher_suite = ssock.cipher()
                tls_version = ssock.version()
                
                # Verify the connection is actually using the client certificate
                # by checking if the handshake succeeded with mutual authentication
                peer_cert = ssock.getpeercert()
                
                return {
                    "success": True,
                    "cipher_suite": cipher_suite[0] if cipher_suite else None,
                    "tls_version": tls_version,
                    "error": None,
                    "peer_cert_subject": peer_cert.get('subject') if peer_cert else None
                }
                
            finally:
                # Cleanup
                if ssock:
                    try:
                        ssock.close()
                    except:
                        pass
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
                
        except ssl.SSLError as e:
            return {
                "success": False,
                "cipher_suite": None,
                "tls_version": None,
                "error": f"SSL error: {e}"
            }
        except socket.timeout:
            return {
                "success": False,
                "cipher_suite": None,
                "tls_version": None,
                "error": "Connection timeout"
            }
        except Exception as e:
            return {
                "success": False,
                "cipher_suite": None,
                "tls_version": None,
                "error": str(e)
            }

    def _parse_certificate(self, cert) -> CertificateInfo:
        """Parse X.509 certificate and extract information."""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("Cryptography library not available")
            
        # Extract subject and issuer
        subject = self._format_name(cert.subject)
        issuer = self._format_name(cert.issuer)
        
        # Extract SAN (Subject Alternative Names)
        san_dns_names = []
        san_ip_addresses = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_dns_names.append(name.value)
                elif isinstance(name, x509.IPAddress):
                    san_ip_addresses.append(str(name.value))
        except x509.ExtensionNotFound:
            pass
        
        # Check if it's a CA certificate
        is_ca = False
        try:
            basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = basic_constraints.value.ca
        except x509.ExtensionNotFound:
            pass
        
        # Check if self-signed
        is_self_signed = subject == issuer
        
        # Get key information
        key_algorithm = cert.public_key().__class__.__name__
        key_size = None
        if hasattr(cert.public_key(), 'key_size'):
            key_size = cert.public_key().key_size
        
        # Generate fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        
        # Handle datetime fields with proper UTC handling
        try:
            # Try new UTC properties first (available in newer cryptography versions)
            not_valid_before = cert.not_valid_before_utc.isoformat()
            not_valid_after = cert.not_valid_after_utc.isoformat()
        except AttributeError:
            # Fall back to legacy properties for older versions
            not_valid_before = cert.not_valid_before.isoformat()
            not_valid_after = cert.not_valid_after.isoformat()
        
        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            version=cert.version.value,
            serial_number=str(cert.serial_number),
            not_valid_before=not_valid_before,
            not_valid_after=not_valid_after,
            signature_algorithm=cert.signature_algorithm_oid._name,
            key_algorithm=key_algorithm,
            key_size=key_size,
            san_dns_names=san_dns_names,
            san_ip_addresses=san_ip_addresses,
            is_ca=is_ca,
            is_self_signed=is_self_signed,
            fingerprint_sha256=fingerprint
        )

    def _format_name(self, name) -> str:
        """Format X.509 name to string."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return str(name)
            
        components = []
        for attribute in name:
            components.append(f"{attribute.oid._name}={attribute.value}")
        return ", ".join(components)

    async def batch_check_mtls(
        self, 
        targets: List[Union[str, Tuple[str, int]]],
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        ca_bundle_path: Optional[str] = None,
        max_concurrent: int = 10,
        progress_callback: Optional[callable] = None
    ) -> List[MTLSResult]:
        """
        Perform mTLS checks on multiple targets concurrently with enhanced control.
        
        Args:
            targets: List of hostnames or (hostname, port) tuples
            client_cert_path: Path to client certificate file
            client_key_path: Path to client private key file  
            ca_bundle_path: Path to CA bundle file
            max_concurrent: Maximum concurrent connections (1-50)
            progress_callback: Optional callback function for progress updates
            
        Returns:
            List of MTLSResult objects
            
        Raises:
            ValueError: If parameters are invalid
        """
        if not targets:
            raise ValueError("At least one target must be provided")
        if not isinstance(max_concurrent, int) or not (1 <= max_concurrent <= 50):
            raise ValueError("max_concurrent must be an integer between 1 and 50")
        
        # Validate and normalize targets
        normalized_targets = []
        for target in targets:
            if isinstance(target, str):
                normalized_targets.append((target, 443))
            elif isinstance(target, tuple) and len(target) == 2:
                normalized_targets.append((self._validate_target(target[0]), self._validate_port(target[1])))
            else:
                raise ValueError(f"Invalid target format: {target}. Expected string or (hostname, port) tuple")
        
        # Validate certificate files once
        client_cert_path, client_key_path = self._validate_certificate_files(
            client_cert_path, client_key_path
        )
        
        self.logger.info(f"Starting batch mTLS check for {len(normalized_targets)} targets")
        start_time = time.time()
        
        # Use semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(max_concurrent)
        completed = 0
        
        async def check_single(target_port, index):
            nonlocal completed
            async with semaphore:
                target, port = target_port
                try:
                    result = await self.check_mtls(
                        target, port, client_cert_path, client_key_path, ca_bundle_path
                    )
                    completed += 1
                    
                    # Call progress callback if provided
                    if progress_callback:
                        try:
                            progress_callback(completed, len(normalized_targets), result)
                        except Exception as e:
                            self.logger.warning(f"Progress callback error: {e}")
                    
                    return result
                except Exception as e:
                    completed += 1
                    error_result = MTLSResult(
                        target=target,
                        port=port,
                        supports_mtls=False,
                        requires_client_cert=False,
                        server_cert_info=None,
                        client_cert_requested=False,
                        handshake_successful=False,
                        error_message=str(e),
                        cipher_suite=None,
                        tls_version=None,
                        verification_mode=None,
                        ca_bundle_path=None,
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                    
                    if progress_callback:
                        try:
                            progress_callback(completed, len(normalized_targets), error_result)
                        except Exception as cb_e:
                            self.logger.warning(f"Progress callback error: {cb_e}")
                    
                    return error_result
        
        # Execute all checks concurrently
        tasks = [
            check_single(target_port, i) 
            for i, target_port in enumerate(normalized_targets)
        ]
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=False)
        except Exception as e:
            self.logger.error(f"Batch mTLS check failed: {e}")
            raise
        
        elapsed = time.time() - start_time
        success_count = sum(1 for r in results if r.error_message is None)
        
        self.logger.info(
            f"Batch mTLS check completed: {success_count}/{len(results)} successful "
            f"in {elapsed:.3f}s (avg: {elapsed/len(results):.3f}s per target)"
        )
        
        return results


# Utility functions for certificate generation and validation
def generate_self_signed_cert(
    hostname: str, 
    cert_path: str, 
    key_path: str,
    days_valid: int = 365
) -> bool:
    """
    Generate a self-signed certificate for testing purposes.
    
    Args:
        hostname: Hostname for the certificate
        cert_path: Path to save the certificate file
        key_path: Path to save the private key file
        days_valid: Number of days the certificate should be valid
        
    Returns:
        True if successful, False otherwise
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        print("Error: cryptography library is required for certificate generation")
        return False
        
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography import x509
        from datetime import datetime, timedelta
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Test"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=days_valid)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(hostname),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate and key to files
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        return True
        
    except Exception as e:
        print(f"Failed to generate certificate: {e}")
        return False


def validate_certificate_files(cert_path: str, key_path: str) -> Tuple[bool, str]:
    """
    Validate that certificate and key files are valid and match.
    
    Args:
        cert_path: Path to certificate file
        key_path: Path to private key file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not CRYPTOGRAPHY_AVAILABLE:
        return False, "cryptography library is required for certificate validation"
        
    try:
        # Check if files exist
        if not Path(cert_path).exists():
            return False, f"Certificate file not found: {cert_path}"
        if not Path(key_path).exists():
            return False, f"Private key file not found: {key_path}"
        
        # Load certificate
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
        except Exception as e:
            return False, f"Invalid certificate file: {e}"
        
        # Load private key
        with open(key_path, "rb") as f:
            key_data = f.read()
        try:
            private_key = serialization.load_pem_private_key(key_data, password=None)
        except Exception as e:
            return False, f"Invalid private key file: {e}"
        
        # Verify that certificate and key match
        cert_public_key = cert.public_key()
        private_public_key = private_key.public_key()
        
        # Compare public key numbers for RSA keys
        if hasattr(cert_public_key, 'public_numbers') and hasattr(private_public_key, 'public_numbers'):
            if cert_public_key.public_numbers() != private_public_key.public_numbers():
                return False, "Certificate and private key do not match"
        
        return True, "Certificate and key files are valid"
        
    except Exception as e:
        return False, f"Validation error: {e}"
