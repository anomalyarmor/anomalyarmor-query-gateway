"""Databricks dialect rules."""

from .base import BaseDialectRules


class DatabricksDialectRules(BaseDialectRules):
    """Databricks-specific validation rules.

    System schemas (within any catalog):
    - information_schema: SQL standard metadata
    - system: Databricks system schema

    Databricks uses 3-level naming: catalog.schema.table
    """

    SYSTEM_SCHEMAS = frozenset({"information_schema", "system"})

    @property
    def system_table_description(self) -> str:
        return "information_schema.*, system.* (within any catalog)"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a Databricks system table.

        Databricks uses 3-level namespace: catalog.schema.table
        System tables can be in information_schema or system schema of any catalog.

        Args:
            table_path: Table reference (e.g., "main.information_schema.tables").

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # 3-part name: catalog.schema.table
        if len(parts) >= 3:
            schema = parts[-2]
            if schema in self.SYSTEM_SCHEMAS:
                return True

        # 2-part name: schema.table (assume default catalog)
        if len(parts) == 2:
            schema = parts[0]
            if schema in self.SYSTEM_SCHEMAS:
                return True

        # 1-part name: cannot verify
        return False
