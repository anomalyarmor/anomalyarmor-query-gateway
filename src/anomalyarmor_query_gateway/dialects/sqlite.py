"""SQLite dialect rules."""

from .base import BaseDialectRules


class SQLiteDialectRules(BaseDialectRules):
    """SQLite-specific validation rules.

    System tables:
    - sqlite_master: Schema table (legacy name)
    - sqlite_schema: Schema table (preferred name since 3.33.0)
    - sqlite_temp_master: Temp schema table
    - sqlite_temp_schema: Temp schema table

    SQLite doesn't have schemas in the traditional sense.
    System tables are identified by their exact names.
    """

    SYSTEM_TABLES = frozenset(
        {
            "sqlite_master",
            "sqlite_schema",
            "sqlite_temp_master",
            "sqlite_temp_schema",
            "sqlite_sequence",  # Autoincrement sequence table
        }
    )

    @property
    def system_table_description(self) -> str:
        return "sqlite_master, sqlite_schema, sqlite_sequence"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a SQLite system table.

        Args:
            table_path: Table reference.

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # Get the table name (last part)
        table_name = parts[-1]

        # SQLite also has PRAGMA commands for schema info,
        # but those are handled differently (not as table queries)
        return table_name in self.SYSTEM_TABLES
