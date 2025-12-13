"""Databricks dialect rules."""

from .base import BaseDialectRules


class DatabricksDialectRules(BaseDialectRules):
    """Databricks-specific validation rules.

    In Databricks Unity Catalog:
    - `system` is a CATALOG containing system tables (system.access.audit, etc.)
    - `information_schema` is a SCHEMA within each catalog

    Databricks uses 3-level naming: catalog.schema.table

    See: https://docs.databricks.com/aws/en/admin/system-tables/
    """

    # The system catalog contains all system tables
    SYSTEM_CATALOGS = frozenset({"system"})
    # information_schema is a schema within any catalog
    SYSTEM_SCHEMAS = frozenset({"information_schema"})

    @property
    def system_table_description(self) -> str:
        return "system.*.* (system catalog), *.information_schema.* (any catalog)"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a Databricks system table.

        Databricks uses 3-level namespace: catalog.schema.table

        System tables include:
        - All tables in the `system` catalog (e.g., system.access.audit)
        - All tables in `information_schema` schema of any catalog

        Args:
            table_path: Table reference (e.g., "system.access.audit").

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # 3-part name: catalog.schema.table
        if len(parts) >= 3:
            catalog = parts[0]
            schema = parts[-2]
            # Check if catalog is the system catalog
            if catalog in self.SYSTEM_CATALOGS:
                return True
            # Check if schema is information_schema
            if schema in self.SYSTEM_SCHEMAS:
                return True

        # 2-part name: schema.table (assume default catalog)
        if len(parts) == 2:
            schema = parts[0]
            if schema in self.SYSTEM_SCHEMAS:
                return True

        # 1-part name: cannot verify
        return False
