"""Audit logging protocol for query validation.

Implementers can provide their own audit logging by implementing
AuditLoggerProtocol.
"""

from typing import Any, Protocol

from .access_levels import AccessLevel


class AuditLoggerProtocol(Protocol):
    """Protocol for audit logging implementations.

    Implement this protocol to log all query validation attempts
    for compliance and debugging purposes.

    Example:
        class DatabaseAuditLogger:
            async def log_query(
                self,
                query: str,
                access_level: AccessLevel,
                dialect: str,
                allowed: bool,
                rejection_reason: str | None,
                metadata: dict[str, Any],
            ) -> None:
                # Store to database, send to logging service, etc.
                await self.db.execute(
                    "INSERT INTO audit_log ...",
                    {"query": query, "allowed": allowed, ...}
                )
    """

    async def log_query(
        self,
        query: str,
        access_level: AccessLevel,
        dialect: str,
        allowed: bool,
        rejection_reason: str | None,
        metadata: dict[str, Any],
    ) -> None:
        """Log a query validation attempt.

        This method is called for every query validation, whether
        allowed or denied. It should be implemented to store logs
        in your preferred audit storage.

        IMPORTANT: This method should not raise exceptions. If logging
        fails, it should fail silently to avoid blocking query validation.
        Consider logging errors to a fallback mechanism.

        Args:
            query: The SQL query that was validated.
            access_level: The access level used for validation.
            dialect: SQL dialect of the query.
            allowed: Whether the query was allowed.
            rejection_reason: If denied, the reason for denial.
            metadata: Additional context (asset_id, user_id, etc.).
        """
        ...
