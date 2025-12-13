"""Main query security gateway.

The QuerySecurityGateway is the primary entry point for validating
SQL queries against access level rules.
"""

import contextlib
from typing import Any

from .access_levels import AccessLevel
from .audit import AuditLoggerProtocol
from .exceptions import QueryGatewayError
from .parser import SQLParser
from .result import ValidationResult
from .validator import AccessValidator


class QuerySecurityGateway:
    """Security gateway for customer database queries.

    All queries to customer databases should pass through this gateway.
    The gateway validates queries against the configured access level
    and optionally logs all query attempts for audit purposes.

    Example:
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
            audit_logger=my_logger,
        )

        result = await gateway.validate_query(
            "SELECT COUNT(*) FROM users",
            metadata={"asset_id": "123"}
        )

        if result.allowed:
            # Execute query
            pass
        else:
            raise QueryAccessDenied(result.reason)

    Attributes:
        access_level: The access level being enforced.
        dialect: SQL dialect for parsing and validation.
        audit_logger: Optional logger for audit trail.
    """

    def __init__(
        self,
        access_level: AccessLevel,
        dialect: str,
        audit_logger: AuditLoggerProtocol | None = None,
    ):
        """Initialize the gateway.

        Args:
            access_level: Access level to enforce (schema_only, aggregates, full).
            dialect: SQL dialect (postgresql, mysql, databricks, clickhouse, sqlite).
            audit_logger: Optional implementation of AuditLoggerProtocol.
        """
        self.access_level = access_level
        self.dialect = dialect
        self.audit_logger = audit_logger
        self._parser = SQLParser(dialect)
        self._validator = AccessValidator(access_level, dialect)

    async def validate_query(
        self,
        query: str,
        metadata: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Validate a query against the configured access level.

        This is the primary async method for query validation.
        It parses the query, validates against access rules, and
        logs the attempt if an audit logger is configured.

        Args:
            query: SQL query to validate.
            metadata: Additional context for audit logging (e.g., asset_id, user_id).

        Returns:
            ValidationResult with allowed=True/False and reason.

        Note:
            This method never raises exceptions for invalid queries.
            Parse/validation errors result in denied ValidationResult.
            Only unexpected internal errors propagate.
        """
        metadata = metadata or {}
        result: ValidationResult

        try:
            # Parse the query
            parsed = self._parser.parse(query)

            # Validate against access level
            result = self._validator.validate(parsed)

        except QueryGatewayError as e:
            # Expected gateway errors (parse/validation) = deny the query (fail closed)
            result = ValidationResult.deny(
                reason=f"Query validation failed: {e!s}",
                details={"error_type": type(e).__name__},
            )
        # Note: Unexpected internal errors (AttributeError, KeyError, etc.) propagate

        # Log to audit trail (never fail validation due to logging errors)
        if self.audit_logger is not None:
            with contextlib.suppress(Exception):
                await self.audit_logger.log_query(
                    query=query,
                    access_level=self.access_level,
                    dialect=self.dialect,
                    allowed=result.allowed,
                    rejection_reason=result.reason if not result.allowed else None,
                    metadata=metadata,
                )

        return result

    def validate_query_sync(
        self,
        query: str,
        metadata: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Synchronous version of validate_query.

        Use this when you don't need async/await. Note that this version
        does NOT call the audit logger (which is async-only).

        Args:
            query: SQL query to validate.
            metadata: Not used in sync version (included for API consistency).

        Returns:
            ValidationResult with allowed=True/False and reason.
        """
        try:
            parsed = self._parser.parse(query)
            return self._validator.validate(parsed)
        except QueryGatewayError as e:
            # Expected gateway errors (parse/validation) = deny the query (fail closed)
            return ValidationResult.deny(
                reason=f"Query validation failed: {e!s}",
                details={"error_type": type(e).__name__},
            )
        # Note: Unexpected internal errors (AttributeError, KeyError, etc.) propagate
