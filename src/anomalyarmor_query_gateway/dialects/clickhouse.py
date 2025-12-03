"""ClickHouse dialect rules."""

from .base import BaseDialectRules


class ClickHouseDialectRules(BaseDialectRules):
    """ClickHouse-specific validation rules.

    System database:
    - system: Contains all system tables (system.tables, system.columns, etc.)

    ClickHouse uses 2-level naming: database.table
    """

    SYSTEM_DATABASES = frozenset({"system"})

    @property
    def system_table_description(self) -> str:
        return "system.* (system.tables, system.columns, etc.)"

    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a ClickHouse system table.

        Args:
            table_path: Table reference (e.g., "system.tables").

        Returns:
            True if system table.
        """
        normalized = self.normalize_table_name(table_path)
        parts = normalized.split(".")

        # 2-part name: database.table
        if len(parts) >= 2:
            database = parts[0]
            if database in self.SYSTEM_DATABASES:
                return True

        # Unqualified names cannot be verified as system tables
        return False
