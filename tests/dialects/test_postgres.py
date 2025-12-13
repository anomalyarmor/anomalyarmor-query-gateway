"""Tests for PostgreSQL dialect rules."""

from anomalyarmor_query_gateway.dialects.postgres import PostgresDialectRules


class TestPostgresDialectRules:
    """Tests for PostgreSQL dialect rules."""

    def test_information_schema_qualified(self) -> None:
        """Test information_schema.* is system table."""
        rules = PostgresDialectRules()
        assert rules.is_system_table("information_schema.tables")
        assert rules.is_system_table("information_schema.columns")
        assert rules.is_system_table("information_schema.schemata")

    def test_pg_catalog_qualified(self) -> None:
        """Test pg_catalog.* is system table."""
        rules = PostgresDialectRules()
        assert rules.is_system_table("pg_catalog.pg_tables")
        assert rules.is_system_table("pg_catalog.pg_class")
        assert rules.is_system_table("pg_catalog.pg_attribute")

    def test_pg_prefix_unqualified(self) -> None:
        """Test pg_* unqualified tables are system tables."""
        rules = PostgresDialectRules()
        assert rules.is_system_table("pg_tables")
        assert rules.is_system_table("pg_views")
        assert rules.is_system_table("pg_indexes")
        assert rules.is_system_table("pg_stat_user_tables")

    def test_user_tables_not_system(self) -> None:
        """Test that user tables are not system tables."""
        rules = PostgresDialectRules()
        assert not rules.is_system_table("users")
        assert not rules.is_system_table("public.users")
        assert not rules.is_system_table("myschema.orders")

    def test_case_insensitive(self) -> None:
        """Test that table name matching is case insensitive."""
        rules = PostgresDialectRules()
        assert rules.is_system_table("INFORMATION_SCHEMA.TABLES")
        assert rules.is_system_table("PG_CATALOG.PG_TABLES")
        assert rules.is_system_table("PG_TABLES")

    def test_three_part_names(self) -> None:
        """Test three-part qualified names."""
        rules = PostgresDialectRules()
        # catalog.schema.table format
        assert rules.is_system_table("mydb.information_schema.tables")
        assert rules.is_system_table("mydb.pg_catalog.pg_class")
        assert not rules.is_system_table("mydb.public.users")

    def test_system_table_description(self) -> None:
        """Test that description is provided."""
        rules = PostgresDialectRules()
        desc = rules.system_table_description
        assert "information_schema" in desc
        assert "pg_catalog" in desc

    def test_qualified_pg_prefix_user_table_not_system(self) -> None:
        """Test that qualified pg_* tables in user schemas are not system tables.

        Bug fix: A table like public.pg_custom_table should NOT be treated
        as a system table. The pg_ prefix only indicates system tables when
        unqualified (resolves via search_path to pg_catalog).
        """
        rules = PostgresDialectRules()
        # Qualified pg_* tables in user schemas are NOT system tables
        assert not rules.is_system_table("public.pg_custom_table")
        assert not rules.is_system_table("myschema.pg_user_data")
        assert not rules.is_system_table("mydb.public.pg_analytics")

        # But pg_catalog.pg_* is still a system table
        assert rules.is_system_table("pg_catalog.pg_tables")

        # And unqualified pg_* is still a system table
        assert rules.is_system_table("pg_tables")
