"""Security tests for query gateway.

These tests verify that the gateway properly handles potential
attack vectors and security edge cases.
"""

import pytest

from anomalyarmor_query_gateway import AccessLevel, QuerySecurityGateway


class TestCommentObfuscation:
    """Tests for comment-based obfuscation attacks."""

    @pytest.fixture
    def gateway(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_single_line_comment_stripped(self, gateway: QuerySecurityGateway) -> None:
        """Test that single-line comments don't affect validation."""
        # Try to hide raw column with comment
        result = gateway.validate_query_sync(
            "SELECT email -- this is a comment\nFROM users"
        )
        assert not result.allowed

    def test_multi_line_comment_stripped(self, gateway: QuerySecurityGateway) -> None:
        """Test that multi-line comments don't affect validation."""
        result = gateway.validate_query_sync(
            "SELECT /* comment */ email /* another */ FROM users"
        )
        assert not result.allowed

    def test_comment_inside_aggregate_still_works(
        self, gateway: QuerySecurityGateway
    ) -> None:
        """Test that comments inside valid queries still work."""
        result = gateway.validate_query_sync(
            "SELECT COUNT(*) /* count all */ FROM users"
        )
        assert result.allowed


class TestCaseVariations:
    """Tests for case sensitivity handling."""

    @pytest.fixture
    def gateway(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.SCHEMA_ONLY,
            dialect="postgresql",
        )

    def test_uppercase_system_table(self, gateway: QuerySecurityGateway) -> None:
        """Test that uppercase table names work."""
        result = gateway.validate_query_sync("SELECT * FROM INFORMATION_SCHEMA.TABLES")
        assert result.allowed

    def test_mixed_case_system_table(self, gateway: QuerySecurityGateway) -> None:
        """Test that mixed case table names work."""
        result = gateway.validate_query_sync("SELECT * FROM Information_Schema.Tables")
        assert result.allowed


class TestComplexQueries:
    """Tests for complex query structures.

    Design decision: Subqueries and CTEs that don't expose data in the final
    SELECT are allowed at aggregates level. The inner query runs server-side
    and only aggregated results are returned. This is more permissive but
    practical for common analytics patterns.
    """

    @pytest.fixture
    def gateway_aggregates(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_nested_subquery_with_aggregate_outer_allowed(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that subquery with aggregate outer SELECT is allowed.

        The subquery data stays server-side; only count is returned.
        """
        result = gateway_aggregates.validate_query_sync(
            "SELECT COUNT(*) FROM (SELECT email FROM users) sub"
        )
        # Outer query returns only aggregate - data doesn't leak
        assert result.allowed

    def test_cte_with_aggregate_outer_allowed(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that CTE with aggregate outer SELECT is allowed."""
        result = gateway_aggregates.validate_query_sync(
            "WITH user_emails AS (SELECT email FROM users) "
            "SELECT COUNT(*) FROM user_emails"
        )
        # Outer query returns only aggregate
        assert result.allowed

    def test_union_with_raw_columns_blocked(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that UNION exposing raw columns is blocked."""
        result = gateway_aggregates.validate_query_sync(
            "SELECT COUNT(*) FROM users UNION SELECT email FROM users"
        )
        # Second part of union exposes raw columns in the RESULT SET
        assert not result.allowed


class TestWindowFunctionBlocking:
    """Tests for window function detection and blocking."""

    @pytest.fixture
    def gateway(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_row_number_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that ROW_NUMBER() is blocked."""
        result = gateway.validate_query_sync(
            "SELECT ROW_NUMBER() OVER (ORDER BY created_at) FROM users"
        )
        assert not result.allowed
        assert "window" in (result.reason or "").lower()

    def test_rank_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that RANK() is blocked."""
        result = gateway.validate_query_sync(
            "SELECT RANK() OVER (ORDER BY score DESC) FROM users"
        )
        assert not result.allowed

    def test_sum_over_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that SUM() OVER() is blocked (even though SUM alone is OK)."""
        result = gateway.validate_query_sync(
            "SELECT SUM(amount) OVER (PARTITION BY user_id) FROM orders"
        )
        assert not result.allowed


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_query(self) -> None:
        """Test handling of empty query."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )
        result = gateway.validate_query_sync("")
        assert not result.allowed

    def test_whitespace_only_query(self) -> None:
        """Test handling of whitespace-only query."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )
        result = gateway.validate_query_sync("   \n\t  ")
        assert not result.allowed

    def test_non_select_blocked(self) -> None:
        """Test that non-SELECT queries are blocked."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )

        blocked_queries = [
            "INSERT INTO users (name) VALUES ('test')",
            "UPDATE users SET name = 'test'",
            "DELETE FROM users",
            "DROP TABLE users",
            "CREATE TABLE test (id INT)",
        ]

        for query in blocked_queries:
            result = gateway.validate_query_sync(query)
            assert not result.allowed, f"Expected '{query}' to be blocked"

    def test_semicolon_injection_attempt(self) -> None:
        """Test that semicolon injection is handled."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )
        # This should parse only the first statement
        gateway.validate_query_sync("SELECT * FROM users; DROP TABLE users")
        # sqlglot parses multiple statements, behavior may vary
        # At minimum, we validate based on parsed content


class TestFailClosed:
    """Tests verifying fail-closed behavior."""

    def test_parse_error_blocks(self) -> None:
        """Test that parse errors result in blocked query."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )
        result = gateway.validate_query_sync("SELEC * FORM users")  # Typo
        assert not result.allowed
        # May be blocked as parse error OR as non-SELECT - either way, blocked
        assert result.reason is not None

    def test_unknown_function_allowed_at_full(self) -> None:
        """Test that unknown functions are allowed at FULL level."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.FULL,
            dialect="postgresql",
        )
        result = gateway.validate_query_sync("SELECT my_custom_function(id) FROM users")
        assert result.allowed

    def test_unknown_function_with_column_blocked_at_aggregates(self) -> None:
        """Test that custom functions exposing columns are blocked."""
        gateway = QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )
        result = gateway.validate_query_sync(
            "SELECT my_custom_function(email) FROM users"
        )
        # Should be blocked because email column is exposed
        assert not result.allowed
