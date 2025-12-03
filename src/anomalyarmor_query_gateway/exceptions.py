"""Custom exceptions for query security gateway.

All exceptions inherit from QueryGatewayError for easy catching.
"""

from typing import Any


class QueryGatewayError(Exception):
    """Base exception for all query gateway errors.

    Attributes:
        message: Human-readable error message.
        error_code: Machine-readable error code for programmatic handling.
        context: Additional context for debugging.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "GATEWAY_ERROR",
        context: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.context = context or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "error": self.message,
            "error_code": self.error_code,
            "context": self.context,
        }


class QueryParseError(QueryGatewayError):
    """Raised when SQL query cannot be parsed.

    This typically indicates malformed SQL or unsupported syntax.
    """

    def __init__(
        self,
        message: str,
        query: str | None = None,
        dialect: str | None = None,
    ):
        super().__init__(
            message,
            error_code="QUERY_PARSE_ERROR",
            context={
                "query_preview": query[:100] if query else None,
                "dialect": dialect,
            },
        )
        self.query = query
        self.dialect = dialect


class QueryAccessDenied(QueryGatewayError):
    """Raised when query is blocked by access level rules.

    This is the expected exception when a query violates access policies.
    """

    def __init__(
        self,
        message: str,
        query: str | None = None,
        access_level: str | None = None,
        required_level: str | None = None,
    ):
        super().__init__(
            message,
            error_code="QUERY_ACCESS_DENIED",
            context={
                "query_preview": query[:100] if query else None,
                "access_level": access_level,
                "required_level": required_level,
            },
        )
        self.query = query
        self.access_level = access_level
        self.required_level = required_level


class UnsupportedDialect(QueryGatewayError):
    """Raised when dialect is not supported."""

    def __init__(self, dialect: str):
        super().__init__(
            f"Unsupported SQL dialect: {dialect}",
            error_code="UNSUPPORTED_DIALECT",
            context={"dialect": dialect},
        )
        self.dialect = dialect
