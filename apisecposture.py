#!/usr/bin/env python3
"""
API Security Posture Scanner
A comprehensive CLI tool for assessing REST, GraphQL, and gRPC API security posture.

Author: arkanzasfeziii
License: MIT
"""

# === Imports ===
import argparse
import json
import logging
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from pydantic import BaseModel, HttpUrl, ValidationError, field_validator
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

try:
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False


# === Constants ===
VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = f"APISecPostureScanner/{VERSION}"
MAX_RETRIES = 2

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            ⚠️  LEGAL WARNING ⚠️                              ║
╟──────────────────────────────────────────────────────────────────────────────╢
║ This tool is for AUTHORIZED security testing ONLY.                           ║
║ Unauthorized scanning is ILLEGAL in most jurisdictions.                      ║
║                                                                              ║
║ By using this tool, you acknowledge that:                                    ║
║ • You have explicit permission to test the target API                        ║
║ • You understand the legal implications                                      ║
║ • You accept full responsibility for your actions                            ║
║                                                                              ║
║ Author (arkanzasfeziii) assumes NO liability for misuse.                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS protection',
    'X-Content-Type-Options': 'MIME type sniffing protection',
    'X-Frame-Options': 'Clickjacking protection',
    'Content-Security-Policy': 'XSS and injection protection',
    'X-XSS-Protection': 'Legacy XSS protection',
    'Referrer-Policy': 'Referrer information control'
}

# Headers that expose sensitive information
INSECURE_HEADERS = {
    'Server': 'Server software version',
    'X-Powered-By': 'Technology stack',
    'X-AspNet-Version': 'ASP.NET version',
    'X-AspNetMvc-Version': 'ASP.NET MVC version'
}

# Common debug/admin endpoints
DEBUG_ENDPOINTS = [
    '/debug', '/admin', '/swagger', '/api-docs', '/graphql',
    '/docs', '/api/docs', '/v1/docs', '/v2/docs',
    '/.env', '/config', '/healthcheck', '/health',
    '/metrics', '/actuator', '/status'
]

# OWASP API Security Top 10 (2023)
OWASP_API_TOP10 = {
    'API1': 'Broken Object Level Authorization',
    'API2': 'Broken Authentication',
    'API3': 'Broken Object Property Level Authorization',
    'API4': 'Unrestricted Resource Consumption',
    'API5': 'Broken Function Level Authorization',
    'API6': 'Unrestricted Access to Sensitive Business Flows',
    'API7': 'Server Side Request Forgery',
    'API8': 'Security Misconfiguration',
    'API9': 'Improper Inventory Management',
    'API10': 'Unsafe Consumption of APIs'
}


# === Enums ===
class APIType(str, Enum):
    """Supported API types."""
    REST = "rest"
    GRAPHQL = "graphql"
    GRPC = "grpc"
    AUTO = "auto"


class SeverityLevel(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskScore(int, Enum):
    """Numeric risk scores."""
    CRITICAL = 10
    HIGH = 7
    MEDIUM = 5
    LOW = 3
    INFO = 1


# === Data Models ===
class ScanConfig(BaseModel):
    """Configuration for API security scan."""
    url: str
    api_type: APIType = APIType.AUTO
    headers: Dict[str, str] = {}
    auth_token: Optional[str] = None
    proto_file: Optional[Path] = None
    timeout: int = DEFAULT_TIMEOUT
    aggressive: bool = False
    verbose: bool = False

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate URL format."""
        if not v.startswith(('http://', 'https://')):
            v = 'https://' + v
        parsed = urlparse(v)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        return v

    @field_validator('proto_file')
    @classmethod
    def validate_proto(cls, v: Optional[Path]) -> Optional[Path]:
        """Validate proto file exists."""
        if v and not v.exists():
            raise ValueError(f"Proto file not found: {v}")
        return v


@dataclass
class Finding:
    """Represents a security finding."""
    category: str
    title: str
    description: str
    severity: SeverityLevel
    risk_score: int
    owasp_mapping: List[str] = field(default_factory=list)
    evidence: str = ""
    mitigation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan results."""
    target_url: str
    api_type: str
    findings: List[Finding] = field(default_factory=list)
    scan_duration: float = 0.0
    total_checks: int = 0
    total_risk_score: int = 0
    timestamp: str = ""
    errors: List[str] = field(default_factory=list)


# === Utility Functions ===
def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging with rich handler.
    
    Args:
        verbose: Enable verbose logging
        
    Returns:
        Configured logger instance
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)]
    )
    return logging.getLogger("apisecposture")


def calculate_severity(risk_score: int) -> SeverityLevel:
    """
    Calculate severity level from risk score.
    
    Args:
        risk_score: Numeric risk score
        
    Returns:
        Severity level
    """
    if risk_score >= RiskScore.CRITICAL:
        return SeverityLevel.CRITICAL
    elif risk_score >= RiskScore.HIGH:
        return SeverityLevel.HIGH
    elif risk_score >= RiskScore.MEDIUM:
        return SeverityLevel.MEDIUM
    elif risk_score >= RiskScore.LOW:
        return SeverityLevel.LOW
    else:
        return SeverityLevel.INFO


def is_https(url: str) -> bool:
    """Check if URL uses HTTPS."""
    return urlparse(url).scheme == 'https'


def get_base_domain(url: str) -> str:
    """Extract base domain from URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


# === API Type Detection ===
class APIDetector:
    """Detects API type through probing and analysis."""

    def __init__(self, logger: logging.Logger):
        """
        Initialize detector.
        
        Args:
            logger: Logger instance
        """
        self.logger = logger

    def detect(self, url: str, timeout: int, headers: Dict[str, str]) -> APIType:
        """
        Auto-detect API type.
        
        Args:
            url: Target URL
            timeout: Request timeout
            headers: Custom headers
            
        Returns:
            Detected API type
        """
        self.logger.info("Auto-detecting API type...")

        # Check for gRPC (port-based heuristic and error patterns)
        if self._is_grpc(url, timeout):
            return APIType.GRPC

        # Check for GraphQL
        if self._is_graphql(url, timeout, headers):
            return APIType.GRAPHQL

        # Default to REST
        return APIType.REST

    def _is_graphql(self, url: str, timeout: int, headers: Dict[str, str]) -> bool:
        """Check if endpoint is GraphQL."""
        try:
            # Try introspection query
            introspection_query = {
                "query": "{ __schema { queryType { name } } }"
            }
            
            response = requests.post(
                url,
                json=introspection_query,
                headers=headers,
                timeout=timeout,
                verify=True
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    self.logger.info("GraphQL API detected via introspection")
                    return True
                    
        except Exception:
            pass

        # Check common GraphQL paths
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphiql']
        base_url = get_base_domain(url)
        
        for path in graphql_paths:
            try:
                test_url = base_url + path
                response = requests.get(test_url, timeout=timeout, headers=headers)
                if 'graphql' in response.text.lower() or 'graphiql' in response.text.lower():
                    self.logger.info(f"GraphQL API detected at {test_url}")
                    return True
            except Exception:
                continue

        return False

    def _is_grpc(self, url: str, timeout: int) -> bool:
        """Check if endpoint is gRPC."""
        if not GRPC_AVAILABLE:
            return False

        parsed = urlparse(url)
        host = parsed.hostname
        
        # Common gRPC ports
        grpc_ports = [50051, 9090, 8080]
        
        if parsed.port:
            grpc_ports.insert(0, parsed.port)

        for port in grpc_ports:
            try:
                target = f"{host}:{port}"
                channel = grpc.insecure_channel(target)
                
                # Try to connect with short timeout
                grpc.channel_ready_future(channel).result(timeout=2)
                
                self.logger.info(f"gRPC service detected at {target}")
                channel.close()
                return True
                
            except Exception:
                continue

        return False


# === REST Security Checks ===
class RESTSecurityChecker:
    """Security checks for REST APIs."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        """
        Initialize REST checker.
        
        Args:
            config: Scan configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create configured requests session."""
        session = requests.Session()
        session.headers.update({'User-Agent': DEFAULT_USER_AGENT})
        session.headers.update(self.config.headers)
        
        if self.config.auth_token:
            session.headers.update({'Authorization': f'Bearer {self.config.auth_token}'})
        
        return session

    def run_checks(self) -> List[Finding]:
        """
        Execute all REST security checks.
        
        Returns:
            List of security findings
        """
        findings = []
        
        self.logger.info("Running REST API security checks...")
        
        try:
            # Get baseline response
            response = self.session.get(
                self.config.url,
                timeout=self.config.timeout,
                verify=True,
                allow_redirects=False
            )
            
            # Run all checks
            findings.extend(self._check_https())
            findings.extend(self._check_security_headers(response))
            findings.extend(self._check_insecure_headers(response))
            findings.extend(self._check_cors(response))
            findings.extend(self._check_http_methods())
            findings.extend(self._check_rate_limiting(response))
            findings.extend(self._check_authentication())
            findings.extend(self._check_information_disclosure(response))
            findings.extend(self._check_debug_endpoints())
            findings.extend(self._check_tls_configuration())
            
        except requests.RequestException as e:
            self.logger.error(f"Error during REST checks: {e}")

        return findings

    def _check_https(self) -> List[Finding]:
        """Check HTTPS usage."""
        findings = []
        
        if not is_https(self.config.url):
            findings.append(Finding(
                category="Transport Security",
                title="HTTPS Not Used",
                description="API endpoint does not use HTTPS encryption",
                severity=SeverityLevel.CRITICAL,
                risk_score=RiskScore.CRITICAL,
                owasp_mapping=["API8"],
                evidence=f"URL scheme: {urlparse(self.config.url).scheme}",
                mitigation="Enable HTTPS/TLS for all API endpoints. Redirect HTTP to HTTPS. "
                          "Use HSTS header to enforce HTTPS.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"
                ]
            ))
        
        return findings

    def _check_security_headers(self, response: requests.Response) -> List[Finding]:
        """Check for missing security headers."""
        findings = []
        
        for header, description in REQUIRED_SECURITY_HEADERS.items():
            if header not in response.headers:
                severity = SeverityLevel.HIGH if header == 'Strict-Transport-Security' else SeverityLevel.MEDIUM
                risk_score = RiskScore.HIGH if header == 'Strict-Transport-Security' else RiskScore.MEDIUM
                
                findings.append(Finding(
                    category="Security Headers",
                    title=f"Missing {header} Header",
                    description=f"API does not implement {description}",
                    severity=severity,
                    risk_score=risk_score,
                    owasp_mapping=["API8"],
                    evidence=f"Header '{header}' not present in response",
                    mitigation=f"Add '{header}' header to all API responses. "
                              f"Purpose: {description}.",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
                    ]
                ))
        
        return findings

    def _check_insecure_headers(self, response: requests.Response) -> List[Finding]:
        """Check for headers that expose information."""
        findings = []
        
        for header, description in INSECURE_HEADERS.items():
            if header in response.headers:
                findings.append(Finding(
                    category="Information Disclosure",
                    title=f"Information Leakage via {header} Header",
                    description=f"API exposes {description}",
                    severity=SeverityLevel.LOW,
                    risk_score=RiskScore.LOW,
                    owasp_mapping=["API8", "API9"],
                    evidence=f"{header}: {response.headers[header]}",
                    mitigation=f"Remove or obfuscate '{header}' header. "
                              "Avoid exposing technology stack details.",
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                    ]
                ))
        
        return findings

    def _check_cors(self, response: requests.Response) -> List[Finding]:
        """Check CORS configuration."""
        findings = []
        
        cors_header = response.headers.get('Access-Control-Allow-Origin')
        
        if cors_header == '*':
            findings.append(Finding(
                category="CORS Misconfiguration",
                title="Wildcard CORS Policy",
                description="API allows requests from any origin",
                severity=SeverityLevel.HIGH,
                risk_score=RiskScore.HIGH,
                owasp_mapping=["API8"],
                evidence=f"Access-Control-Allow-Origin: {cors_header}",
                mitigation="Restrict CORS to specific trusted origins. Avoid wildcard (*) in production. "
                          "Validate Origin header against allowlist.",
                references=[
                    "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                ]
            ))
        
        credentials_header = response.headers.get('Access-Control-Allow-Credentials')
        if cors_header == '*' and credentials_header == 'true':
            findings.append(Finding(
                category="CORS Misconfiguration",
                title="Critical CORS Misconfiguration",
                description="API allows credentials from any origin (wildcard + credentials)",
                severity=SeverityLevel.CRITICAL,
                risk_score=RiskScore.CRITICAL,
                owasp_mapping=["API8"],
                evidence=f"Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true",
                mitigation="NEVER combine wildcard CORS with credentials. "
                          "Use specific origins when credentials are required.",
                references=[
                    "https://portswigger.net/web-security/cors"
                ]
            ))
        
        return findings

    def _check_http_methods(self) -> List[Finding]:
        """Check for unsupported HTTP methods."""
        findings = []
        
        try:
            # Test OPTIONS to see allowed methods
            response = self.session.options(
                self.config.url,
                timeout=self.config.timeout
            )
            
            allowed_methods = response.headers.get('Allow', '')
            
            # Check for potentially dangerous methods
            dangerous_methods = ['TRACE', 'TRACK', 'DEBUG', 'PUT', 'DELETE']
            
            for method in dangerous_methods:
                if method in allowed_methods.upper():
                    severity = SeverityLevel.MEDIUM if method in ['PUT', 'DELETE'] else SeverityLevel.LOW
                    
                    findings.append(Finding(
                        category="HTTP Methods",
                        title=f"Potentially Unsafe HTTP Method: {method}",
                        description=f"API allows {method} method which may be unnecessary",
                        severity=severity,
                        risk_score=RiskScore.MEDIUM if method in ['PUT', 'DELETE'] else RiskScore.LOW,
                        owasp_mapping=["API5", "API8"],
                        evidence=f"Allow: {allowed_methods}",
                        mitigation=f"Disable {method} method if not required. "
                                  "Implement proper authorization for destructive operations.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
                        ]
                    ))
            
        except requests.RequestException:
            pass
        
        return findings

    def _check_rate_limiting(self, response: requests.Response) -> List[Finding]:
        """Check for rate limiting indicators."""
        findings = []
        
        # Common rate limit headers
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-Rate-Limit-Limit',
            'RateLimit-Limit',
            'X-RateLimit-Remaining',
            'Retry-After'
        ]
        
        has_rate_limiting = any(h in response.headers for h in rate_limit_headers)
        
        if not has_rate_limiting:
            findings.append(Finding(
                category="Rate Limiting",
                title="No Rate Limiting Headers Detected",
                description="API does not advertise rate limiting through standard headers",
                severity=SeverityLevel.MEDIUM,
                risk_score=RiskScore.MEDIUM,
                owasp_mapping=["API4"],
                evidence="No rate limit headers found in response",
                mitigation="Implement rate limiting to prevent abuse. "
                          "Use standard headers (X-RateLimit-*) to communicate limits. "
                          "Consider per-user, per-IP, and per-endpoint limits.",
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                ]
            ))
        
        return findings

    def _check_authentication(self) -> List[Finding]:
        """Check authentication posture."""
        findings = []
        
        try:
            # Test without authentication
            response = requests.get(
                self.config.url,
                timeout=self.config.timeout,
                headers={'User-Agent': DEFAULT_USER_AGENT}
            )
            
            # If successful without auth, might be an issue
            if response.status_code == 200:
                auth_header = response.request.headers.get('Authorization')
                
                if not auth_header:
                    findings.append(Finding(
                        category="Authentication",
                        title="Endpoint Accessible Without Authentication",
                        description="API endpoint returns 200 OK without authentication headers",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=RiskScore.MEDIUM,
                        owasp_mapping=["API2"],
                        evidence=f"Status: {response.status_code} without Authorization header",
                        mitigation="Verify if this endpoint should require authentication. "
                                  "Implement proper authentication for sensitive operations. "
                                  "Use OAuth 2.0, JWT, or API keys appropriately.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                        ]
                    ))
            
            # Check for Basic Auth over HTTP
            if not is_https(self.config.url):
                www_auth = response.headers.get('WWW-Authenticate', '')
                if 'Basic' in www_auth:
                    findings.append(Finding(
                        category="Authentication",
                        title="Basic Authentication Over HTTP",
                        description="API uses Basic Authentication without HTTPS encryption",
                        severity=SeverityLevel.CRITICAL,
                        risk_score=RiskScore.CRITICAL,
                        owasp_mapping=["API2", "API8"],
                        evidence=f"WWW-Authenticate: {www_auth} over HTTP",
                        mitigation="NEVER use Basic Auth over HTTP. Enable HTTPS immediately. "
                                  "Consider stronger authentication mechanisms like OAuth 2.0.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                        ]
                    ))
            
        except requests.RequestException:
            pass
        
        return findings

    def _check_information_disclosure(self, response: requests.Response) -> List[Finding]:
        """Check for information disclosure in responses."""
        findings = []
        
        # Check for stack traces or error details
        error_patterns = [
            (r'at\s+[\w\.]+\([\w\.]+:\d+\)', "Stack trace detected"),
            (r'Exception in thread', "Java exception detected"),
            (r'Traceback \(most recent call last\)', "Python traceback detected"),
            (r'Fatal error:', "PHP fatal error detected"),
            (r'Microsoft.*Error', "Microsoft error message detected"),
            (r'ORA-\d{5}', "Oracle error code detected"),
            (r'MySQL.*Error', "MySQL error detected")
        ]
        
        content = response.text[:5000]  # Check first 5KB
        
        for pattern, description in error_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(Finding(
                    category="Information Disclosure",
                    title="Detailed Error Information Exposed",
                    description=description,
                    severity=SeverityLevel.MEDIUM,
                    risk_score=RiskScore.MEDIUM,
                    owasp_mapping=["API8"],
                    evidence=f"Pattern matched: {pattern}",
                    mitigation="Implement custom error pages that don't expose internal details. "
                              "Log detailed errors server-side only. "
                              "Return generic error messages to clients.",
                    references=[
                        "https://owasp.org/www-community/Improper_Error_Handling"
                    ]
                ))
                break  # One finding is enough
        
        return findings

    def _check_debug_endpoints(self) -> List[Finding]:
        """Check for exposed debug/admin endpoints."""
        findings = []
        
        if not self.config.aggressive:
            return findings  # Skip in non-aggressive mode
        
        base_url = get_base_domain(self.config.url)
        
        for endpoint in DEBUG_ENDPOINTS:
            try:
                test_url = base_url + endpoint
                response = self.session.get(
                    test_url,
                    timeout=self.config.timeout,
                    allow_redirects=False
                )
                
                if response.status_code in [200, 301, 302]:
                    findings.append(Finding(
                        category="Information Disclosure",
                        title=f"Debug/Admin Endpoint Exposed: {endpoint}",
                        description=f"Potentially sensitive endpoint accessible",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=RiskScore.MEDIUM,
                        owasp_mapping=["API9"],
                        evidence=f"Status {response.status_code} at {test_url}",
                        mitigation="Disable debug endpoints in production. "
                                  "Restrict access to admin interfaces. "
                                  "Use proper authentication and IP whitelisting.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                        ]
                    ))
                
                time.sleep(0.5)  # Rate limit our own requests
                
            except requests.RequestException:
                continue
        
        return findings

    def _check_tls_configuration(self) -> List[Finding]:
        """Check TLS/SSL configuration."""
        findings = []
        
        if not is_https(self.config.url):
            return findings
        
        parsed = urlparse(self.config.url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        findings.append(Finding(
                            category="TLS Configuration",
                            title=f"Weak TLS Version: {version}",
                            description="API uses outdated TLS protocol version",
                            severity=SeverityLevel.HIGH,
                            risk_score=RiskScore.HIGH,
                            owasp_mapping=["API8"],
                            evidence=f"TLS version: {version}",
                            mitigation="Upgrade to TLS 1.2 or TLS 1.3. "
                                      "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                            ]
                        ))
                    
                    # Check for weak ciphers (basic check)
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']):
                            findings.append(Finding(
                                category="TLS Configuration",
                                title=f"Weak Cipher Suite: {cipher_name}",
                                description="API uses weak or insecure cipher",
                                severity=SeverityLevel.HIGH,
                                risk_score=RiskScore.HIGH,
                                owasp_mapping=["API8"],
                                evidence=f"Cipher: {cipher_name}",
                                mitigation="Configure strong cipher suites only. "
                                          "Disable weak ciphers (RC4, DES, 3DES, MD5).",
                                references=[
                                    "https://ssl-config.mozilla.org/"
                                ]
                            ))
        
        except Exception as e:
            self.logger.debug(f"TLS check error: {e}")
        
        return findings


# === GraphQL Security Checks ===
class GraphQLSecurityChecker:
    """Security checks for GraphQL APIs."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        """
        Initialize GraphQL checker.
        
        Args:
            config: Scan configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create configured requests session."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': DEFAULT_USER_AGENT,
            'Content-Type': 'application/json'
        })
        session.headers.update(self.config.headers)
        
        if self.config.auth_token:
            session.headers.update({'Authorization': f'Bearer {self.config.auth_token}'})
        
        return session

    def run_checks(self) -> List[Finding]:
        """
        Execute all GraphQL security checks.
        
        Returns:
            List of security findings
        """
        findings = []
        
        self.logger.info("Running GraphQL API security checks...")
        
        findings.extend(self._check_introspection())
        findings.extend(self._check_query_depth())
        findings.extend(self._check_batching())
        findings.extend(self._check_field_suggestions())
        findings.extend(self._check_error_verbosity())
        
        return findings

    def _check_introspection(self) -> List[Finding]:
        """Check if introspection is enabled."""
        findings = []
        
        introspection_query = {
            "query": """
            {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types { name }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                self.config.url,
                json=introspection_query,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data and '__schema' in data.get('data', {}):
                    schema_types = data['data']['__schema'].get('types', [])
                    
                    findings.append(Finding(
                        category="GraphQL Configuration",
                        title="Introspection Enabled",
                        description="GraphQL introspection is enabled in production",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=RiskScore.MEDIUM,
                        owasp_mapping=["API8", "API9"],
                        evidence=f"Successfully queried __schema. Found {len(schema_types)} types.",
                        mitigation="Disable introspection in production environments. "
                                  "Only enable for development/staging. "
                                  "Use allow-lists for production queries.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                        ]
                    ))
                    
                    # Additional check for sensitive type names
                    sensitive_patterns = ['user', 'admin', 'password', 'secret', 'token', 'credit', 'ssn']
                    sensitive_types = [
                        t['name'] for t in schema_types
                        if any(pattern in t['name'].lower() for pattern in sensitive_patterns)
                    ]
                    
                    if sensitive_types:
                        findings.append(Finding(
                            category="GraphQL Configuration",
                            title="Sensitive Types Exposed via Introspection",
                            description="Schema contains potentially sensitive type names",
                            severity=SeverityLevel.LOW,
                            risk_score=RiskScore.LOW,
                            owasp_mapping=["API9"],
                            evidence=f"Sensitive types: {', '.join(sensitive_types[:5])}",
                            mitigation="Review schema for sensitive information exposure. "
                                      "Disable introspection in production.",
                            references=[]
                        ))
        
        except Exception as e:
            self.logger.debug(f"Introspection check error: {e}")
        
        return findings

    def _check_query_depth(self) -> List[Finding]:
        """Check for query depth/complexity limits."""
        findings = []
        
        # Deeply nested query to test limits
        deep_query = {
            "query": """
            {
                level1 {
                    level2 {
                        level3 {
                            level4 {
                                level5 {
                                    level6 {
                                        level7 {
                                            level8 {
                                                level9 {
                                                    level10 { id }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = self.session.post(
                self.config.url,
                json=deep_query,
                timeout=self.config.timeout
            )
            
            # If query succeeds without depth limit error
            if response.status_code == 200:
                data = response.json()
                
                # Check if it's not an error about depth
                if 'errors' not in data or not any(
                    'depth' in str(err).lower() or 'complexity' in str(err).lower()
                    for err in data.get('errors', [])
                ):
                    findings.append(Finding(
                        category="GraphQL Configuration",
                        title="No Query Depth Limits Detected",
                        description="GraphQL endpoint may allow deeply nested queries",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=RiskScore.MEDIUM,
                        owasp_mapping=["API4"],
                        evidence="Deeply nested query accepted without depth limit error",
                        mitigation="Implement query depth and complexity limits. "
                                  "Use libraries like graphql-depth-limit. "
                                  "Set maximum depth to 5-7 levels typically.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                        ]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Query depth check error: {e}")
        
        return findings

    def _check_batching(self) -> List[Finding]:
        """Check if query batching is allowed."""
        findings = []
        
        # Try to send multiple queries in a batch
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"}
        ]
        
        try:
            response = self.session.post(
                self.config.url,
                json=batch_query,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # If it's an array response, batching is enabled
                if isinstance(data, list):
                    findings.append(Finding(
                        category="GraphQL Configuration",
                        title="Query Batching Enabled",
                        description="GraphQL endpoint allows batched queries",
                        severity=SeverityLevel.LOW,
                        risk_score=RiskScore.LOW,
                        owasp_mapping=["API4"],
                        evidence="Successfully executed batched query",
                        mitigation="Consider disabling batching or implementing strict limits. "
                                  "Batching can be abused for DoS attacks. "
                                  "Implement per-batch complexity limits.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                        ]
                    ))
        
        except Exception as e:
            self.logger.debug(f"Batching check error: {e}")
        
        return findings

    def _check_field_suggestions(self) -> List[Finding]:
        """Check if field suggestions are enabled."""
        findings = []
        
        # Query with intentionally wrong field name
        query = {
            "query": "{ nonExistentFieldName12345 }"
        }
        
        try:
            response = self.session.post(
                self.config.url,
                json=query,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                errors = data.get('errors', [])
                
                # Check if errors contain field suggestions
                for error in errors:
                    error_msg = str(error.get('message', ''))
                    if 'did you mean' in error_msg.lower() or 'suggestion' in error_msg.lower():
                        findings.append(Finding(
                            category="GraphQL Configuration",
                            title="Field Suggestions Enabled",
                            description="GraphQL provides field suggestions in error messages",
                            severity=SeverityLevel.INFO,
                            risk_score=RiskScore.INFO,
                            owasp_mapping=["API9"],
                            evidence=f"Error message: {error_msg[:100]}",
                            mitigation="Consider disabling field suggestions in production. "
                                      "This reveals schema structure to attackers.",
                            references=[]
                        ))
                        break
        
        except Exception as e:
            self.logger.debug(f"Field suggestion check error: {e}")
        
        return findings

    def _check_error_verbosity(self) -> List[Finding]:
        """Check error message verbosity."""
        findings = []
        
        # Malformed query to trigger errors
        malformed_query = {
            "query": "{ __schema { INVALID SYNTAX HERE"
        }
        
        try:
            response = self.session.post(
                self.config.url,
                json=malformed_query,
                timeout=self.config.timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                errors = data.get('errors', [])
                
                for error in errors:
                    error_str = str(error)
                    
                    # Check for stack traces or detailed error info
                    if any(indicator in error_str for indicator in [
                        'at line', 'at position', 'stack', 'trace', 'path:'
                    ]):
                        findings.append(Finding(
                            category="Information Disclosure",
                            title="Verbose GraphQL Error Messages",
                            description="GraphQL errors contain detailed debugging information",
                            severity=SeverityLevel.LOW,
                            risk_score=RiskScore.LOW,
                            owasp_mapping=["API8"],
                            evidence=f"Detailed error: {error_str[:150]}",
                            mitigation="Sanitize error messages in production. "
                                      "Return generic errors to clients. "
                                      "Log detailed errors server-side only.",
                            references=[]
                        ))
                        break
        
        except Exception as e:
            self.logger.debug(f"Error verbosity check error: {e}")
        
        return findings


# === gRPC Security Checks ===
class GRPCSecurityChecker:
    """Security checks for gRPC APIs."""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        """
        Initialize gRPC checker.
        
        Args:
            config: Scan configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    def run_checks(self) -> List[Finding]:
        """
        Execute all gRPC security checks.
        
        Returns:
            List of security findings
        """
        if not GRPC_AVAILABLE:
            self.logger.warning("gRPC libraries not available, skipping gRPC checks")
            return []
        
        findings = []
        
        self.logger.info("Running gRPC API security checks...")
        
        findings.extend(self._check_tls_enforcement())
        findings.extend(self._check_reflection_service())
        findings.extend(self._check_health_check())
        
        return findings

    def _check_tls_enforcement(self) -> List[Finding]:
        """Check if gRPC enforces TLS."""
        findings = []
        
        parsed = urlparse(self.config.url)
        host = parsed.hostname
        port = parsed.port or 50051
        
        try:
            # Try insecure connection
            target = f"{host}:{port}"
            channel = grpc.insecure_channel(target)
            
            # If connection succeeds, TLS is not enforced
            try:
                grpc.channel_ready_future(channel).result(timeout=3)
                
                findings.append(Finding(
                    category="gRPC Configuration",
                    title="gRPC Allows Insecure Connections",
                    description="gRPC service accepts non-TLS connections",
                    severity=SeverityLevel.CRITICAL,
                    risk_score=RiskScore.CRITICAL,
                    owasp_mapping=["API8"],
                    evidence=f"Successfully connected to {target} without TLS",
                    mitigation="Enforce TLS for all gRPC connections. "
                              "Use grpc.ssl_channel_credentials(). "
                              "Reject insecure connections at the server level.",
                    references=[
                        "https://grpc.io/docs/guides/auth/"
                    ]
                ))
            except grpc.FutureTimeoutError:
                pass
            finally:
                channel.close()
        
        except Exception as e:
            self.logger.debug(f"gRPC TLS check error: {e}")
        
        return findings

    def _check_reflection_service(self) -> List[Finding]:
        """Check if gRPC reflection is enabled."""
        findings = []
        
        parsed = urlparse(self.config.url)
        host = parsed.hostname
        port = parsed.port or 50051
        
        try:
            target = f"{host}:{port}"
            channel = grpc.insecure_channel(target)
            
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            
            # Try to list services
            request = reflection_pb2.ServerReflectionRequest(
                list_services=""
            )
            
            responses = stub.ServerReflectionInfo(iter([request]))
            
            for response in responses:
                if response.HasField('list_services_response'):
                    services = response.list_services_response.service
                    
                    findings.append(Finding(
                        category="gRPC Configuration",
                        title="gRPC Reflection Enabled",
                        description="gRPC server has reflection service enabled",
                        severity=SeverityLevel.MEDIUM,
                        risk_score=RiskScore.MEDIUM,
                        owasp_mapping=["API9"],
                        evidence=f"Found {len(services)} services via reflection",
                        mitigation="Disable gRPC reflection in production. "
                                  "Reflection exposes service definitions. "
                                  "Only enable for development/debugging.",
                        references=[
                            "https://github.com/grpc/grpc/blob/master/doc/server-reflection.md"
                        ]
                    ))
                    break
            
            channel.close()
        
        except Exception as e:
            self.logger.debug(f"gRPC reflection check error: {e}")
        
        return findings

    def _check_health_check(self) -> List[Finding]:
        """Check if health check service is exposed."""
        findings = []
        
        # Health check endpoint exposure is informational
        # This is a placeholder for future implementation
        
        return findings


# === Core Scanner ===
class APISecurityScanner:
    """Main scanner orchestrating all security checks."""

    def __init__(self, config: ScanConfig):
        """
        Initialize scanner.
        
        Args:
            config: Scan configuration
        """
        self.config = config
        self.console = Console()
        self.logger = setup_logging(config.verbose)
        self.result = ScanResult(
            target_url=config.url,
            api_type=config.api_type.value,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        )

    def run(self) -> ScanResult:
        """
        Execute complete security scan.
        
        Returns:
            Scan results with all findings
        """
        self._print_banner()
        
        start_time = time.time()
        
        try:
            # Auto-detect API type if needed
            if self.config.api_type == APIType.AUTO:
                detector = APIDetector(self.logger)
                detected_type = detector.detect(
                    self.config.url,
                    self.config.timeout,
                    self.config.headers
                )
                self.config.api_type = detected_type
                self.result.api_type = detected_type.value
                self.console.print(f"[cyan]Detected API type:[/cyan] {detected_type.value.upper()}\n")
            
            # Run appropriate checks based on API type
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                
                task = progress.add_task("Running security checks...", total=None)
                
                if self.config.api_type == APIType.REST:
                    checker = RESTSecurityChecker(self.config, self.logger)
                    findings = checker.run_checks()
                    self.result.findings.extend(findings)
                
                elif self.config.api_type == APIType.GRAPHQL:
                    checker = GraphQLSecurityChecker(self.config, self.logger)
                    findings = checker.run_checks()
                    self.result.findings.extend(findings)
                
                elif self.config.api_type == APIType.GRPC:
                    checker = GRPCSecurityChecker(self.config, self.logger)
                    findings = checker.run_checks()
                    self.result.findings.extend(findings)
                
                progress.remove_task(task)
            
            # Calculate totals
            self.result.total_checks = len(self.result.findings)
            self.result.total_risk_score = sum(f.risk_score for f in self.result.findings)
            
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Scan interrupted by user[/yellow]")
            self.result.errors.append("Scan interrupted")
        except Exception as e:
            self.logger.exception("Unexpected error during scan")
            self.result.errors.append(f"Unexpected error: {e}")
        finally:
            self.result.scan_duration = time.time() - start_time
        
        return self.result

    def _print_banner(self) -> None:
        """Print application banner."""
        if PYFIGLET_AVAILABLE:
            banner = pyfiglet.figlet_format("API SecPosture", font="slant")
            self.console.print(f"[bold cyan]{banner}[/bold cyan]")
        else:
            self.console.print("\n[bold cyan]" + "=" * 70 + "[/bold cyan]")
            self.console.print("[bold cyan]    API Security Posture Scanner v" + VERSION + "[/bold cyan]")
            self.console.print("[bold cyan]" + "=" * 70 + "[/bold cyan]\n")
        
        self.console.print(f"[dim]Author: {AUTHOR}[/dim]")
        self.console.print(f"[dim]Target: {self.config.url}[/dim]")
        self.console.print(f"[dim]API Type: {self.config.api_type.value.upper()}[/dim]\n")


# === Reporting ===
class Reporter:
    """Generates formatted scan reports."""

    def __init__(self, console: Console):
        """
        Initialize reporter.
        
        Args:
            console: Rich console for output
        """
        self.console = console

    def print_summary(self, result: ScanResult) -> None:
        """
        Print scan summary to console.
        
        Args:
            result: Scan results
        """
        self.console.print("\n" + "=" * 80)
        self.console.print("[bold cyan]Security Posture Assessment Summary[/bold cyan]")
        self.console.print("=" * 80 + "\n")
        
        # Summary statistics
        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Target API", result.target_url)
        summary_table.add_row("API Type", result.api_type.upper())
        summary_table.add_row("Scan Duration", f"{result.scan_duration:.2f}s")
        summary_table.add_row("Total Findings", str(len(result.findings)))
        summary_table.add_row("Total Risk Score", str(result.total_risk_score))
        summary_table.add_row("Timestamp", result.timestamp)
        
        if result.errors:
            summary_table.add_row("Errors", str(len(result.errors)))
        
        self.console.print(summary_table)
        
        # Severity breakdown
        if result.findings:
            self.console.print("\n[bold cyan]Severity Breakdown[/bold cyan]\n")
            
            severity_counts = {}
            for finding in result.findings:
                severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            
            severity_table = Table(show_header=True, header_style="bold magenta")
            severity_table.add_column("Severity", style="yellow")
            severity_table.add_column("Count", justify="right", style="white")
            
            severity_order = [
                SeverityLevel.CRITICAL,
                SeverityLevel.HIGH,
                SeverityLevel.MEDIUM,
                SeverityLevel.LOW,
                SeverityLevel.INFO
            ]
            
            for severity in severity_order:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    color = self._get_severity_color(severity)
                    severity_table.add_row(
                        f"[{color}]{severity.value.upper()}[/{color}]",
                        str(count)
                    )
            
            self.console.print(severity_table)
            
            # Findings table
            self.console.print("\n[bold cyan]Findings Overview[/bold cyan]\n")
            
            findings_table = Table(show_header=True, header_style="bold magenta")
            findings_table.add_column("Category", style="cyan")
            findings_table.add_column("Title", style="white")
            findings_table.add_column("Severity", style="yellow")
            findings_table.add_column("Risk", justify="right", style="red")
            
            for finding in sorted(result.findings, key=lambda x: x.risk_score, reverse=True):
                color = self._get_severity_color(finding.severity)
                findings_table.add_row(
                    finding.category,
                    finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
                    f"[{color}]{finding.severity.value.upper()}[/{color}]",
                    str(finding.risk_score)
                )
            
            self.console.print(findings_table)
            
            # Detailed findings
            self.console.print("\n[bold cyan]Detailed Findings[/bold cyan]\n")
            for i, finding in enumerate(result.findings, 1):
                self._print_finding_detail(finding, i)
        else:
            self.console.print("\n[bold green]✓ No security issues detected[/bold green]\n")
        
        # Errors
        if result.errors:
            self.console.print("\n[bold yellow]Errors Encountered[/bold yellow]\n")
            for error in result.errors:
                self.console.print(f"  [red]•[/red] {error}")
        
        # Risk assessment
        self._print_risk_assessment(result)
        
        self.console.print("\n" + "=" * 80 + "\n")

    def _print_finding_detail(self, finding: Finding, index: int) -> None:
        """Print detailed information about a single finding."""
        color = self._get_severity_color(finding.severity)
        
        panel_content = f"""[bold]Category:[/bold] {finding.category}
[bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]
[bold]Risk Score:[/bold] {finding.risk_score}/10

[bold]Description:[/bold]
{finding.description}
"""
        
        if finding.evidence:
            panel_content += f"\n[bold]Evidence:[/bold]\n{finding.evidence}\n"
        
        if finding.owasp_mapping:
            owasp_refs = ", ".join(finding.owasp_mapping)
            panel_content += f"\n[bold]OWASP API Security:[/bold] {owasp_refs}\n"
        
        panel_content += f"\n[bold]Mitigation:[/bold]\n{finding.mitigation}"
        
        if finding.references:
            panel_content += f"\n\n[bold]References:[/bold]\n"
            for ref in finding.references:
                panel_content += f"• {ref}\n"
        
        panel = Panel(
            panel_content,
            title=f"[bold]Finding #{index}: {finding.title}[/bold]",
            border_style=color
        )
        
        self.console.print(panel)
        self.console.print()

    def _print_risk_assessment(self, result: ScanResult) -> None:
        """Print overall risk assessment."""
        self.console.print("\n[bold cyan]Overall Risk Assessment[/bold cyan]\n")
        
        total_score = result.total_risk_score
        
        # Risk level determination
        if total_score >= 30:
            risk_level = "CRITICAL"
            color = "red"
            recommendation = "Immediate action required. Multiple critical issues detected."
        elif total_score >= 20:
            risk_level = "HIGH"
            color = "red"
            recommendation = "Address high-severity issues promptly."
        elif total_score >= 10:
            risk_level = "MEDIUM"
            color = "yellow"
            recommendation = "Review and remediate findings as part of regular security maintenance."
        elif total_score > 0:
            risk_level = "LOW"
            color = "blue"
            recommendation = "Minor issues detected. Address when feasible."
        else:
            risk_level = "MINIMAL"
            color = "green"
            recommendation = "No significant security issues detected. Continue monitoring."
        
        self.console.print(f"[bold {color}]Risk Level: {risk_level}[/bold {color}]")
        self.console.print(f"Total Risk Score: {total_score}")
        self.console.print(f"\n{recommendation}")

    def _get_severity_color(self, severity: SeverityLevel) -> str:
        """Get color for severity level."""
        colors = {
            SeverityLevel.CRITICAL: "bold red",
            SeverityLevel.HIGH: "red",
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "cyan"
        }
        return colors.get(severity, "white")

    def export_json(self, result: ScanResult, filepath: Path) -> None:
        """
        Export results to JSON file.
        
        Args:
            result: Scan results
            filepath: Output file path
        """
        data = {
            'target_url': result.target_url,
            'api_type': result.api_type,
            'timestamp': result.timestamp,
            'scan_duration': result.scan_duration,
            'total_checks': result.total_checks,
            'total_risk_score': result.total_risk_score,
            'findings': [
                {
                    'category': f.category,
                    'title': f.title,
                    'description': f.description,
                    'severity': f.severity.value,
                    'risk_score': f.risk_score,
                    'owasp_mapping': f.owasp_mapping,
                    'evidence': f.evidence,
                    'mitigation': f.mitigation,
                    'references': f.references,
                    'metadata': f.metadata
                }
                for f in result.findings
            ],
            'errors': result.errors
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        
        self.console.print(f"\n[green]✓ Results exported to {filepath}[/green]")

    def export_html(self, result: ScanResult, filepath: Path) -> None:
        """
        Export results to HTML file.
        
        Args:
            result: Scan results
            filepath: Output file path
        """
        html_content = self._generate_html_report(result)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.console.print(f"\n[green]✓ HTML report exported to {filepath}[/green]")

    def _generate_html_report(self, result: ScanResult) -> str:
        """Generate HTML report content."""
        # Simplified HTML report
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Posture Report - {result.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .finding {{ margin: 20px 0; padding: 15px; border-left: 4px solid #95a5a6; background: #f8f9fa; }}
        .critical {{ border-left-color: #e74c3c; }}
        .high {{ border-left-color: #e67e22; }}
        .medium {{ border-left-color: #f39c12; }}
        .low {{ border-left-color: #3498db; }}
        .info {{ border-left-color: #1abc9c; }}
        .severity {{ display: inline-block; padding: 3px 10px; border-radius: 3px; color: white; font-weight: bold; font-size: 12px; }}
        .severity.critical {{ background: #e74c3c; }}
        .severity.high {{ background: #e67e22; }}
        .severity.medium {{ background: #f39c12; }}
        .severity.low {{ background: #3498db; }}
        .severity.info {{ background: #1abc9c; }}
        .metadata {{ font-size: 12px; color: #7f8c8d; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>API Security Posture Assessment Report</h1>
        
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Target:</strong> {result.target_url}</p>
            <p><strong>API Type:</strong> {result.api_type.upper()}</p>
            <p><strong>Scan Date:</strong> {result.timestamp}</p>
            <p><strong>Duration:</strong> {result.scan_duration:.2f} seconds</p>
            <p><strong>Total Findings:</strong> {len(result.findings)}</p>
            <p><strong>Total Risk Score:</strong> {result.total_risk_score}</p>
        </div>
        
        <h2>Findings ({len(result.findings)})</h2>
"""
        
        for i, finding in enumerate(result.findings, 1):
            severity_class = finding.severity.value
            html += f"""
        <div class="finding {severity_class}">
            <h3>{i}. {finding.title} <span class="severity {severity_class}">{finding.severity.value.upper()}</span></h3>
            <p><strong>Category:</strong> {finding.category}</p>
            <p><strong>Risk Score:</strong> {finding.risk_score}/10</p>
            <p><strong>Description:</strong> {finding.description}</p>
"""
            
            if finding.evidence:
                html += f"<p><strong>Evidence:</strong> <pre>{finding.evidence}</pre></p>"
            
            if finding.owasp_mapping:
                html += f"<p><strong>OWASP API Security:</strong> {', '.join(finding.owasp_mapping)}</p>"
            
            html += f"<p><strong>Mitigation:</strong> {finding.mitigation}</p>"
            
            if finding.references:
                html += "<p><strong>References:</strong></p><ul>"
                for ref in finding.references:
                    html += f"<li><a href='{ref}' target='_blank'>{ref}</a></li>"
                html += "</ul>"
            
            html += "</div>"
        
        html += f"""
        <div class="metadata">
            <p>Generated by API Security Posture Scanner v{VERSION} | Author: {AUTHOR}</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# === CLI ===
def print_examples() -> None:
    """Print usage examples."""
    console = Console()
    
    examples = """
[bold cyan]Usage Examples:[/bold cyan]

[bold yellow]REST API Examples:[/bold yellow]

1. Basic REST API scan:
   [green]python apisecposture.py https://api.example.com/v1[/green]

2. REST API with custom headers:
   [green]python apisecposture.py https://api.example.com --headers '{"X-API-Key": "secret123"}'[/green]

3. REST API with authentication:
   [green]python apisecposture.py https://api.example.com --auth mytoken123[/green]

4. Aggressive scan with JSON export:
   [green]python apisecposture.py https://api.example.com --aggressive --output results.json[/green]

[bold yellow]GraphQL API Examples:[/bold yellow]

5. GraphQL API scan (auto-detect):
   [green]python apisecposture.py https://api.example.com/graphql[/green]

6. GraphQL with explicit type:
   [green]python apisecposture.py https://api.example.com/graphql --type graphql[/green]

7. GraphQL with authentication:
   [green]python apisecposture.py https://api.example.com/graphql --auth bearer_token --type graphql[/green]

[bold yellow]gRPC API Examples:[/bold yellow]

8. gRPC API scan:
   [green]python apisecposture.py grpc://api.example.com:50051 --type grpc[/green]

9. gRPC with proto file:
   [green]python apisecposture.py grpc://api.example.com:50051 --type grpc --proto service.proto[/green]

[bold yellow]Output Format Examples:[/bold yellow]

10. Export as HTML report:
    [green]python apisecposture.py https://api.example.com --output report.html[/green]

11. Verbose mode with JSON export:
    [green]python apisecposture.py https://api.example.com --verbose --output scan.json[/green]
"""
    
    console.print(examples)


def main() -> int:
    """
    Main entry point for CLI.
    
    Returns:
        Exit code (0 for success, 1 for issues found or error)
    """
    parser = argparse.ArgumentParser(
        description="API Security Posture Scanner - Comprehensive API security assessment tool",
        epilog=f"Author: {AUTHOR} | Version: {VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'url',
        help='Target API URL (e.g., https://api.example.com, grpc://api.example.com:50051)'
    )
    
    parser.add_argument(
        '--type',
        choices=['rest', 'graphql', 'grpc', 'auto'],
        default='auto',
        help='API type (default: auto-detect)'
    )
    
    parser.add_argument(
        '--headers',
        help='Custom HTTP headers as JSON (e.g., \'{"Authorization": "Bearer token"}\')'
    )
    
    parser.add_argument(
        '--auth',
        dest='auth_token',
        help='Authentication token (will be sent as Bearer token)'
    )
    
    parser.add_argument(
        '--proto',
        dest='proto_file',
        type=Path,
        help='Path to .proto file for gRPC (optional)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})'
    )
    
    parser.add_argument(
        '--aggressive',
        action='store_true',
        help='Aggressive mode: more comprehensive checks (requires acknowledgment)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--output',
        help='Export results to file (.json or .html)'
    )
    
    parser.add_argument(
        '--examples',
        action='store_true',
        help='Show usage examples and exit'
    )
    
    parser.add_argument(
        '--i-understand-legal-responsibilities',
        action='store_true',
        help='Acknowledge legal warning (required for scans)'
    )
    
    args = parser.parse_args()
    
    console = Console()
    
    # Show examples if requested
    if args.examples:
        print_examples()
        return 0
    
    # Display legal warning
    console.print(LEGAL_WARNING, style="bold yellow")
    
    if not args.i_understand_legal_responsibilities:
        response = console.input(
            "\n[bold yellow]Do you have explicit authorization to scan this API? (yes/no):[/bold yellow] "
        )
        if response.lower() not in ['yes', 'y']:
            console.print("[red]Scan aborted. Authorization required.[/red]")
            return 1
    
    # Additional check for aggressive mode
    if args.aggressive and not args.i_understand_legal_responsibilities:
        console.print(
            "[red]Aggressive mode requires --i-understand-legal-responsibilities flag[/red]"
        )
        return 1
    
    try:
        # Parse headers
        headers = {}
        if args.headers:
            try:
                headers = json.loads(args.headers)
            except json.JSONDecodeError:
                console.print("[red]Error: Invalid JSON format for headers[/red]")
                return 1
        
        # Create configuration
        config = ScanConfig(
            url=args.url,
            api_type=APIType(args.type),
            headers=headers,
            auth_token=args.auth_token,
            proto_file=args.proto_file,
            timeout=args.timeout,
            aggressive=args.aggressive,
            verbose=args.verbose
        )
        
    except ValidationError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        return 1
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        return 1
    
    # Run scan
    scanner = APISecurityScanner(config)
    result = scanner.run()
    
    # Display results
    reporter = Reporter(console)
    reporter.print_summary(result)
    
    # Export if requested
    if args.output:
        try:
            output_path = Path(args.output)
            
            if output_path.suffix == '.json':
                reporter.export_json(result, output_path)
            elif output_path.suffix == '.html':
                reporter.export_html(result, output_path)
            else:
                console.print("[yellow]Warning: Output format not recognized, defaulting to JSON[/yellow]")
                reporter.export_json(result, output_path.with_suffix('.json'))
        except Exception as e:
            console.print(f"[red]Failed to export results: {e}[/red]")
    
    # Return non-zero if issues found or errors occurred
    if result.findings or result.errors:
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
