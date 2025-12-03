"""Tests for main gateway class."""

from typing import Any

import pytest

from anomalyarmor_query_gateway import (
    AccessLevel,
    QuerySecurityGateway,
)


class MockAuditLogger:
    """Mock audit logger for testing."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def log_query(
        self,
        query: str,
        access_level: AccessLevel,
        dialect: str,
        allowed: bool,
        rejection_reason: str | None,
        metadata: dict[str, Any],
    ) -> None:
        self.calls.append(
            {
                "query": query,
                "access_level": access_level,
                "dialect": dialect,
                "allowed": allowed,
                "rejection_reason": rejection_reason,
                "metadata": metadata,
            }
        )


class FailingAuditLogger:
    """Audit logger that always fails - for testing error handling."""

    async def log_query(
        self,
        query: str,
        access_level: AccessLevel,
        dialect: str,
        allowed: bool,
        rejection_reason: str | None,
        metadata: dict[str, Any],
    ) -> None:
        raise RuntimeError("Audit logging failed!")


class TestQuerySecurityGateway:
    """Tests for QuerySecurityGateway."""

    def test_sync_validation_allowed(
        self, postgres_gateway_full: QuerySecurityGateway
    ) -> None:
        """Test synchronous validation that allows query."""
        result = postgres_gateway_full.validate_query_sync("SELECT * FROM users")
        assert result.allowed

    def test_sync_validation_blocked(
        self, postgres_gateway_schema_only: QuerySecurityGateway
    ) -> None:
        """Test synchronous validation that blocks query."""
        result = postgres_gateway_schema_only.validate_query_sync("SELECT * FROM users")
        assert not result.allowed

    def test_sync_validation_invalid_sql(
        self, postgres_gateway_full: QuerySecurityGateway
    ) -> None:
        """Test that invalid SQL is blocked (fail closed)."""
        result = postgres_gateway_full.validate_query_sync("NOT VALID SQL")
        assert not result.allowed
        # Invalid SQL may parse as non-SELECT or fail to parse - either way, blocked
        assert result.reason is not None

    @pytest.mark.asyncio
    async def test_async_validation_allowed(
        self, postgres_gateway_full: QuerySecurityGateway
    ) -> None:
        """Test async validation that allows query."""
        result = await postgres_gateway_full.validate_query("SELECT * FROM users")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_async_validation_blocked(
        self, postgres_gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test async validation that blocks query."""
        result = await postgres_gateway_aggregates.validate_query(
            "SELECT email FROM users"
        )
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_allow(self) -> None:
        """Test that audit logger is called when query is allowed."""
        logger = MockAuditLogger()
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
            audit_logger=logger,
        )

        await gateway.validate_query(
            "SELECT * FROM users",
            metadata={"asset_id": "123"},
        )

        assert len(logger.calls) == 1
        assert logger.calls[0]["allowed"] is True
        assert logger.calls[0]["metadata"]["asset_id"] == "123"

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_block(self) -> None:
        """Test that audit logger is called when query is blocked."""
        logger = MockAuditLogger()
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.SCHEMA_ONLY,
            dialect="postgresql",
            audit_logger=logger,
        )

        await gateway.validate_query("SELECT * FROM users")

        assert len(logger.calls) == 1
        assert logger.calls[0]["allowed"] is False
        assert logger.calls[0]["rejection_reason"] is not None

    @pytest.mark.asyncio
    async def test_audit_logger_failure_does_not_block(self) -> None:
        """Test that audit logger failure doesn't block validation."""
        logger = FailingAuditLogger()
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
            audit_logger=logger,
        )

        # Should not raise, even though logger fails
        result = await gateway.validate_query("SELECT * FROM users")
        assert result.allowed


class TestGatewayAccessLevels:
    """Tests for gateway with different access levels."""

    def test_full_allows_everything(self) -> None:
        """Test that FULL access allows all SELECT queries."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )

        queries = [
            "SELECT * FROM users",
            "SELECT email FROM users WHERE id = 1",
            "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id",
            "SELECT COUNT(*) FROM users",
        ]

        for query in queries:
            result = gateway.validate_query_sync(query)
            assert result.allowed, f"Expected '{query}' to be allowed"

    def test_aggregates_allows_aggregates_only(self) -> None:
        """Test that AGGREGATES access only allows aggregate queries."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

        # Should be allowed
        allowed_queries = [
            "SELECT COUNT(*) FROM users",
            "SELECT SUM(amount) FROM orders",
            "SELECT AVG(price), MIN(price), MAX(price) FROM products",
            "SELECT COUNT(DISTINCT user_id) FROM orders",
        ]

        for query in allowed_queries:
            result = gateway.validate_query_sync(query)
            assert result.allowed, f"Expected '{query}' to be allowed"

        # Should be blocked
        blocked_queries = [
            "SELECT * FROM users",
            "SELECT email FROM users",
            "SELECT name, COUNT(*) FROM users GROUP BY name",
        ]

        for query in blocked_queries:
            result = gateway.validate_query_sync(query)
            assert not result.allowed, f"Expected '{query}' to be blocked"

    def test_schema_only_allows_system_tables_only(self) -> None:
        """Test that SCHEMA_ONLY only allows system table queries."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.SCHEMA_ONLY,
            dialect="postgresql",
        )

        # Should be allowed
        allowed_queries = [
            "SELECT * FROM information_schema.tables",
            "SELECT * FROM pg_catalog.pg_tables",
            "SELECT * FROM pg_tables",
        ]

        for query in allowed_queries:
            result = gateway.validate_query_sync(query)
            assert result.allowed, f"Expected '{query}' to be allowed"

        # Should be blocked
        blocked_queries = [
            "SELECT * FROM users",
            "SELECT COUNT(*) FROM orders",
        ]

        for query in blocked_queries:
            result = gateway.validate_query_sync(query)
            assert not result.allowed, f"Expected '{query}' to be blocked"


class TestGatewayDialects:
    """Tests for gateway with different dialects."""

    @pytest.mark.parametrize(
        "dialect",
        ["postgresql", "mysql", "databricks", "clickhouse", "sqlite"],
    )
    def test_all_dialects_work(self, dialect: str) -> None:
        """Test that all supported dialects work."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect=dialect,
        )

        result = gateway.validate_query_sync("SELECT 1")
        assert result.allowed

    def test_invalid_dialect_raises(self) -> None:
        """Test that invalid dialect raises error."""
        with pytest.raises(ValueError):
            QuerySecurityGateway(
                access_level=AccessLevel.FULL,
                dialect="not_a_real_dialect",
            )
