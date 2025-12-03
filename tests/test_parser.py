"""Tests for SQL parser."""

import pytest

from anomalyarmor_query_gateway import SQLParser
from anomalyarmor_query_gateway.exceptions import QueryParseError


class TestSQLParser:
    """Tests for SQLParser."""

    def test_parse_simple_select(self, postgres_parser: SQLParser) -> None:
        """Test parsing simple SELECT."""
        parsed = postgres_parser.parse("SELECT * FROM users")
        assert parsed.is_select
        assert "users" in parsed.tables
        assert parsed.has_raw_columns

    def test_parse_aggregate_query(self, postgres_parser: SQLParser) -> None:
        """Test parsing aggregate query."""
        parsed = postgres_parser.parse("SELECT COUNT(*) FROM users")
        assert parsed.is_select
        assert parsed.has_aggregates
        assert not parsed.has_raw_columns

    def test_parse_multiple_aggregates(self, postgres_parser: SQLParser) -> None:
        """Test parsing query with multiple aggregates."""
        parsed = postgres_parser.parse(
            "SELECT COUNT(*), SUM(amount), AVG(price) FROM orders"
        )
        assert parsed.has_aggregates
        assert not parsed.has_raw_columns

    def test_parse_mixed_aggregate_and_raw(self, postgres_parser: SQLParser) -> None:
        """Test parsing query with both aggregates and raw columns."""
        parsed = postgres_parser.parse("SELECT name, COUNT(*) FROM users GROUP BY name")
        assert parsed.has_aggregates
        assert parsed.has_raw_columns

    def test_parse_qualified_table(self, postgres_parser: SQLParser) -> None:
        """Test parsing qualified table names."""
        parsed = postgres_parser.parse("SELECT * FROM myschema.users")
        assert "myschema.users" in parsed.tables

    def test_parse_system_table(self, postgres_parser: SQLParser) -> None:
        """Test parsing system table query."""
        parsed = postgres_parser.parse("SELECT * FROM information_schema.tables")
        assert "information_schema.tables" in parsed.tables

    def test_parse_subquery(self, postgres_parser: SQLParser) -> None:
        """Test parsing query with subquery."""
        parsed = postgres_parser.parse("SELECT * FROM (SELECT id FROM users) AS subq")
        assert parsed.has_subqueries

    def test_parse_cte(self, postgres_parser: SQLParser) -> None:
        """Test parsing query with CTE."""
        parsed = postgres_parser.parse(
            "WITH active AS (SELECT * FROM users WHERE active = true) "
            "SELECT * FROM active"
        )
        assert parsed.has_ctes

    def test_parse_window_function(self, postgres_parser: SQLParser) -> None:
        """Test parsing query with window function."""
        parsed = postgres_parser.parse(
            "SELECT id, ROW_NUMBER() OVER (ORDER BY created_at) FROM users"
        )
        assert parsed.has_window_functions

    def test_parse_union(self, postgres_parser: SQLParser) -> None:
        """Test parsing UNION query."""
        parsed = postgres_parser.parse(
            "SELECT id FROM users UNION SELECT id FROM admins"
        )
        assert parsed.has_unions
        assert parsed.is_select

    def test_parse_with_comments_single_line(self, postgres_parser: SQLParser) -> None:
        """Test that single-line comments are stripped."""
        parsed = postgres_parser.parse("SELECT * FROM users -- this is a comment")
        assert parsed.is_select
        assert "users" in parsed.tables

    def test_parse_with_comments_multi_line(self, postgres_parser: SQLParser) -> None:
        """Test that multi-line comments are stripped."""
        parsed = postgres_parser.parse(
            "SELECT /* comment */ * FROM /* another */ users"
        )
        assert parsed.is_select
        assert "users" in parsed.tables

    def test_parse_invalid_sql(self, postgres_parser: SQLParser) -> None:
        """Test parsing invalid SQL raises error."""
        with pytest.raises(QueryParseError):
            postgres_parser.parse("NOT VALID SQL AT ALL")

    def test_parse_count_distinct(self, postgres_parser: SQLParser) -> None:
        """Test parsing COUNT(DISTINCT)."""
        parsed = postgres_parser.parse("SELECT COUNT(DISTINCT user_id) FROM orders")
        assert parsed.has_aggregates
        assert not parsed.has_raw_columns

    def test_parse_aggregate_with_alias(self, postgres_parser: SQLParser) -> None:
        """Test aggregate with alias is still detected correctly."""
        parsed = postgres_parser.parse(
            "SELECT COUNT(*) AS total, AVG(amount) AS avg_amount FROM orders"
        )
        assert parsed.has_aggregates
        assert not parsed.has_raw_columns

    def test_parse_min_max(self, postgres_parser: SQLParser) -> None:
        """Test MIN/MAX are recognized as aggregates."""
        parsed = postgres_parser.parse(
            "SELECT MIN(created_at), MAX(updated_at) FROM orders"
        )
        assert parsed.has_aggregates
        assert not parsed.has_raw_columns

    def test_parse_group_by_with_aggregate(self, postgres_parser: SQLParser) -> None:
        """Test GROUP BY with aggregate still has raw columns in SELECT."""
        parsed = postgres_parser.parse(
            "SELECT status, COUNT(*) FROM orders GROUP BY status"
        )
        assert parsed.has_aggregates
        assert parsed.has_raw_columns  # 'status' is raw in SELECT


class TestDialectParsing:
    """Test parsing across different dialects."""

    def test_mysql_backticks(self) -> None:
        """Test MySQL backtick quoting."""
        parser = SQLParser("mysql")
        parsed = parser.parse("SELECT * FROM `my_table`")
        assert parsed.is_select
        assert "my_table" in parsed.tables

    def test_databricks_three_part_name(self) -> None:
        """Test Databricks three-part table names."""
        parser = SQLParser("databricks")
        parsed = parser.parse("SELECT * FROM catalog.schema.table")
        assert "catalog.schema.table" in parsed.tables

    def test_clickhouse_array_functions(self) -> None:
        """Test ClickHouse can parse array functions."""
        parser = SQLParser("clickhouse")
        parsed = parser.parse("SELECT arrayJoin([1, 2, 3])")
        assert parsed.is_select

    def test_sqlite_pragma_style(self) -> None:
        """Test SQLite table names."""
        parser = SQLParser("sqlite")
        parsed = parser.parse("SELECT * FROM sqlite_master")
        assert "sqlite_master" in parsed.tables
