"""PostgreSQL dialect rules."""

from .base import BaseDialectRules


class PostgresDialectRules(BaseDialectRules):
    """PostgreSQL-specific validation rules.

    System tables:
    - information_schema.*: SQL standard metadata
    - pg_catalog.*: PostgreSQL system catalog
    - pg_toast.*: TOAST storage (internal)

    Also allows unqualified pg_* tables (e.g., pg_tables, pg_views).
    """

    SYSTEM_SCHEMAS = frozenset({"information_schema", "pg_catalog", "pg_toast"})

    @property
    def system_table_description(self) -> str:
        return "information_schema.*, pg_catalog.*, pg_* system views"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a PostgreSQL system table.

        Args:
            table_path: Table reference (e.g., "pg_catalog.pg_tables", "pg_tables").

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # Check for qualified names (schema.table or catalog.schema.table)
        if len(parts) >= 2:
            # For 3-part names, schema is second to last
            # For 2-part names, schema is first
            schema = parts[-2]
            if schema in self.SYSTEM_SCHEMAS:
                return True
            # For qualified names with non-system schema, it's NOT a system table
            # even if the table name starts with pg_ (e.g., public.pg_custom_table)
            return False

        # Check for unqualified pg_* tables (these resolve to pg_catalog via search path)
        table_name = parts[-1]
        return bool(table_name.startswith("pg_"))
