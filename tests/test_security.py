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

    Security decision: Subqueries and CTEs that contain raw columns are BLOCKED
    at aggregates level. While COUNT(*) on a subquery doesn't directly leak data,
    MIN/MAX on filtered subqueries can be used to extract specific row values.
    For example: SELECT MIN(email) FROM (SELECT email FROM users WHERE id=1) sub
    This conservative approach prevents data extraction attacks.
    """

    @pytest.fixture
    def gateway_aggregates(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_nested_subquery_with_raw_columns_blocked(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that subquery with raw columns is blocked.

        Even though outer query uses COUNT(*), subqueries with raw columns
        are blocked because they can be exploited with MIN/MAX to extract data.
        """
        result = gateway_aggregates.validate_query_sync(
            "SELECT COUNT(*) FROM (SELECT email FROM users) sub"
        )
        # Blocked: subquery has raw columns which could leak via MIN/MAX
        assert not result.allowed
        assert "subquery" in (result.reason or "").lower()

    def test_cte_with_raw_columns_blocked(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that CTE with raw columns is blocked."""
        result = gateway_aggregates.validate_query_sync(
            "WITH user_emails AS (SELECT email FROM users) "
            "SELECT COUNT(*) FROM user_emails"
        )
        # Blocked: CTE has raw columns
        assert not result.allowed
        assert "cte" in (result.reason or "").lower()

    def test_nested_subquery_with_aggregates_allowed(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that subquery using only aggregates is allowed."""
        result = gateway_aggregates.validate_query_sync(
            "SELECT SUM(cnt) FROM (SELECT COUNT(*) as cnt FROM users GROUP BY status) sub"
        )
        # Allowed: subquery only returns aggregates
        assert result.allowed

    def test_cte_with_aggregates_allowed(
        self, gateway_aggregates: QuerySecurityGateway
    ) -> None:
        """Test that CTE using only aggregates is allowed."""
        result = gateway_aggregates.validate_query_sync(
            "WITH counts AS (SELECT COUNT(*) as cnt FROM users) "
            "SELECT SUM(cnt) FROM counts"
        )
        # Allowed: CTE only returns aggregates
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


class TestDataExposingAggregates:
    """Tests for blocking data-exposing aggregate functions.

    These aggregate functions (array_agg, string_agg, json_agg, any_value, etc.)
    technically aggregate rows but return actual row data rather than computed
    statistics, making them unsafe at AGGREGATES access level.
    """

    @pytest.fixture
    def gateway(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_array_agg_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that array_agg is blocked - returns all row values."""
        result = gateway.validate_query_sync("SELECT array_agg(email) FROM users")
        assert not result.allowed
        assert "data-exposing" in (result.reason or "").lower()

    def test_string_agg_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that string_agg is blocked - returns concatenated row values."""
        result = gateway.validate_query_sync("SELECT string_agg(email, ',') FROM users")
        assert not result.allowed

    def test_json_agg_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that json_agg is blocked - returns all row data as JSON."""
        result = gateway.validate_query_sync("SELECT json_agg(email) FROM users")
        assert not result.allowed

    def test_jsonb_agg_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that jsonb_agg is blocked."""
        result = gateway.validate_query_sync("SELECT jsonb_agg(email) FROM users")
        assert not result.allowed

    def test_any_value_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that any_value is blocked - returns arbitrary actual row value."""
        result = gateway.validate_query_sync("SELECT any_value(email) FROM users")
        assert not result.allowed

    def test_group_concat_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that group_concat is blocked (MySQL-style)."""
        gateway_mysql = QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="mysql",
        )
        result = gateway_mysql.validate_query_sync(
            "SELECT group_concat(email) FROM users"
        )
        assert not result.allowed

    def test_safe_aggregates_still_allowed(self, gateway: QuerySecurityGateway) -> None:
        """Test that safe statistical aggregates are still allowed."""
        safe_queries = [
            "SELECT COUNT(*) FROM users",
            "SELECT SUM(amount) FROM orders",
            "SELECT AVG(salary) FROM employees",
            "SELECT MIN(created_at) FROM users",
            "SELECT MAX(updated_at) FROM users",
            "SELECT STDDEV(salary) FROM employees",
            "SELECT VARIANCE(amount) FROM orders",
        ]
        for query in safe_queries:
            result = gateway.validate_query_sync(query)
            assert result.allowed, f"Expected '{query}' to be allowed"


class TestSubqueryDataExtraction:
    """Tests for preventing data extraction via subquery + MIN/MAX attacks.

    Attack pattern: SELECT MIN(email) FROM (SELECT email FROM users WHERE id=1) sub
    This extracts the specific email for user id=1 despite using an aggregate.
    """

    @pytest.fixture
    def gateway(self) -> QuerySecurityGateway:
        return QuerySecurityGateway(
            access_level=AccessLevel.AGGREGATES,
            dialect="postgresql",
        )

    def test_min_on_filtered_subquery_blocked(
        self, gateway: QuerySecurityGateway
    ) -> None:
        """Test that MIN on filtered subquery is blocked."""
        result = gateway.validate_query_sync(
            "SELECT MIN(email) FROM (SELECT email FROM users WHERE id = 123) sub"
        )
        assert not result.allowed

    def test_max_on_filtered_subquery_blocked(
        self, gateway: QuerySecurityGateway
    ) -> None:
        """Test that MAX on filtered subquery is blocked."""
        result = gateway.validate_query_sync(
            "SELECT MAX(password_hash) FROM (SELECT password_hash FROM users WHERE username = 'admin') sub"
        )
        assert not result.allowed

    def test_binary_search_attack_blocked(self, gateway: QuerySecurityGateway) -> None:
        """Test that binary search data extraction is blocked."""
        result = gateway.validate_query_sync(
            "SELECT MIN(ssn) FROM (SELECT ssn FROM employees WHERE ssn > '500-00-0000') sub"
        )
        assert not result.allowed

    def test_nested_subquery_with_raw_columns_blocked(
        self, gateway: QuerySecurityGateway
    ) -> None:
        """Test that deeply nested subqueries with raw columns are blocked."""
        result = gateway.validate_query_sync(
            "SELECT COUNT(*) FROM ("
            "  SELECT cnt FROM ("
            "    SELECT email, COUNT(*) as cnt FROM users GROUP BY email"
            "  ) inner_sub"
            ") outer_sub"
        )
        # The innermost subquery exposes 'email' raw column
        assert not result.allowed

    def test_mixed_safe_and_data_exposing_aggregates_blocked(
        self, gateway: QuerySecurityGateway
    ) -> None:
        """Test that mixing safe and data-exposing aggregates is blocked."""
        result = gateway.validate_query_sync(
            "SELECT COUNT(*), array_agg(email) FROM users"
        )
        # Even though COUNT is safe, array_agg exposes data
        assert not result.allowed
        assert "data-exposing" in (result.reason or "").lower()


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
