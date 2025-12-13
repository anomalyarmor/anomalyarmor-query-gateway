"""Tests for Databricks dialect rules."""

from anomalyarmor_query_gateway.dialects.databricks import DatabricksDialectRules


class TestDatabricksDialectRules:
    """Tests for Databricks dialect rules."""

    def test_system_catalog_tables(self) -> None:
        """Test system.*.* tables are system tables.

        Bug fix: In Databricks Unity Catalog, 'system' is a CATALOG
        (not a schema), containing system tables like system.access.audit.
        """
        rules = DatabricksDialectRules()
        # All tables in the system catalog are system tables
        assert rules.is_system_table("system.access.audit")
        assert rules.is_system_table("system.billing.usage")
        assert rules.is_system_table("system.compute.clusters")
        assert rules.is_system_table("system.information_schema.tables")

    def test_information_schema_any_catalog(self) -> None:
        """Test *.information_schema.* tables are system tables."""
        rules = DatabricksDialectRules()
        # information_schema in any catalog is a system schema
        assert rules.is_system_table("main.information_schema.tables")
        assert rules.is_system_table("main.information_schema.columns")
        assert rules.is_system_table("my_catalog.information_schema.schemata")

    def test_two_part_information_schema(self) -> None:
        """Test information_schema.* with 2-part name."""
        rules = DatabricksDialectRules()
        # 2-part name with information_schema as schema
        assert rules.is_system_table("information_schema.tables")
        assert rules.is_system_table("information_schema.columns")

    def test_user_tables_not_system(self) -> None:
        """Test that user tables are not system tables."""
        rules = DatabricksDialectRules()
        assert not rules.is_system_table("main.default.users")
        assert not rules.is_system_table("my_catalog.my_schema.orders")

    def test_unqualified_tables_not_system(self) -> None:
        """Test that unqualified table names are not system tables."""
        rules = DatabricksDialectRules()
        # Cannot verify 1-part names as system tables
        assert not rules.is_system_table("tables")
        assert not rules.is_system_table("users")

    def test_case_insensitive(self) -> None:
        """Test that table name matching is case insensitive."""
        rules = DatabricksDialectRules()
        assert rules.is_system_table("SYSTEM.ACCESS.AUDIT")
        assert rules.is_system_table("System.Access.Audit")
        assert rules.is_system_table("MAIN.INFORMATION_SCHEMA.TABLES")

    def test_system_table_description(self) -> None:
        """Test that description is provided."""
        rules = DatabricksDialectRules()
        desc = rules.system_table_description
        assert "system" in desc
        assert "information_schema" in desc
