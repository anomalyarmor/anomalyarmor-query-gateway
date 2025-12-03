"""MySQL dialect rules."""

from .base import BaseDialectRules


class MySQLDialectRules(BaseDialectRules):
    """MySQL-specific validation rules.

    System schemas/databases:
    - information_schema: SQL standard metadata
    - mysql: MySQL system database
    - performance_schema: Performance monitoring
    - sys: MySQL sys schema (views over performance_schema)
    """

    SYSTEM_SCHEMAS = frozenset(
        {"information_schema", "mysql", "performance_schema", "sys"}
    )

    @property
    def system_table_description(self) -> str:
        return "information_schema.*, mysql.*, performance_schema.*, sys.*"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a MySQL system table.

        In MySQL, the schema/database is the first part of a qualified name.

        Args:
            table_path: Table reference (e.g., "information_schema.tables").

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # Check for qualified names (database.table)
        if len(parts) >= 2:
            database = parts[0]
            if database in self.SYSTEM_SCHEMAS:
                return True

        # Unqualified names cannot be verified as system tables
        return False
