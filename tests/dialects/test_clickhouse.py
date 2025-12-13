"""Tests for ClickHouse dialect rules."""

from anomalyarmor_query_gateway.dialects.clickhouse import ClickHouseDialectRules


class TestClickHouseDialectRules:
    """Tests for ClickHouse dialect rules."""

    def test_system_database_qualified(self) -> None:
        """Test system.* is system table."""
        rules = ClickHouseDialectRules()
        assert rules.is_system_table("system.tables")
        assert rules.is_system_table("system.columns")
        assert rules.is_system_table("system.parts")

    def test_case_sensitive_system_database(self) -> None:
        """Test that ClickHouse is case-sensitive for system database.

        Bug fix: ClickHouse is case-sensitive, so 'System' and 'SYSTEM'
        are different databases from 'system'. Only lowercase 'system'
        is the actual system database.
        """
        rules = ClickHouseDialectRules()
        # Lowercase 'system' is the system database
        assert rules.is_system_table("system.tables")

        # Uppercase/mixed case are NOT system tables (user-created databases)
        assert not rules.is_system_table("System.tables")
        assert not rules.is_system_table("SYSTEM.tables")
        assert not rules.is_system_table("SYSTEM.TABLES")

    def test_user_tables_not_system(self) -> None:
        """Test that user tables are not system tables."""
        rules = ClickHouseDialectRules()
        assert not rules.is_system_table("default.users")
        assert not rules.is_system_table("mydb.orders")

    def test_unqualified_tables_not_system(self) -> None:
        """Test that unqualified table names are not system tables."""
        rules = ClickHouseDialectRules()
        # Cannot verify unqualified names as system tables
        assert not rules.is_system_table("tables")
        assert not rules.is_system_table("users")

    def test_normalize_preserves_case(self) -> None:
        """Test that normalize_table_name preserves case."""
        rules = ClickHouseDialectRules()
        assert rules.normalize_table_name("System.Tables") == "System.Tables"
        assert rules.normalize_table_name("SYSTEM.TABLES") == "SYSTEM.TABLES"
        assert rules.normalize_table_name("system.tables") == "system.tables"

    def test_system_table_description(self) -> None:
        """Test that description is provided."""
        rules = ClickHouseDialectRules()
        desc = rules.system_table_description
        assert "system" in desc
