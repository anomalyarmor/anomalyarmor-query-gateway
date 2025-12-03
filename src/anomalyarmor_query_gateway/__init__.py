"""AnomalyArmor Query Security Gateway.

A SQL query security gateway for validating database queries against
customer-configured access levels.

Example:
    from anomalyarmor_query_gateway import QuerySecurityGateway, AccessLevel

    gateway = QuerySecurityGateway(
        access_level=AccessLevel.AGGREGATES,
        dialect="postgresql",
    )

    result = gateway.validate_query_sync("SELECT COUNT(*) FROM users")
    if result.allowed:
        print("Query allowed")
    else:
        print(f"Query blocked: {result.reason}")
"""

from .access_levels import AccessLevel
from .audit import AuditLoggerProtocol
from .exceptions import (
    QueryAccessDenied,
    QueryGatewayError,
    QueryParseError,
    UnsupportedDialect,
)
from .gateway import QuerySecurityGateway
from .parser import ParsedQuery, SQLParser
from .result import ValidationResult
from .validator import AccessValidator

__version__ = "1.0.0"

__all__ = [
    "AccessLevel",
    # Validator
    "AccessValidator",
    # Audit
    "AuditLoggerProtocol",
    "ParsedQuery",
    "QueryAccessDenied",
    # Exceptions
    "QueryGatewayError",
    "QueryParseError",
    # Main classes
    "QuerySecurityGateway",
    # Parser
    "SQLParser",
    "UnsupportedDialect",
    "ValidationResult",
]
