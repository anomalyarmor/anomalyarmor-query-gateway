"""Base class for dialect-specific rules."""

from abc import ABC, abstractmethod


class BaseDialectRules(ABC):
    """Abstract base class for dialect-specific validation rules.

    Each SQL dialect has different system tables and metadata schemas.
    Subclasses define which tables are considered "system" tables that
    are allowed at the schema_only access level.
    """

    @property
    @abstractmethod
    def system_table_description(self) -> str:
        """Human-readable description of allowed system tables.

        Returns:
            Description string for error messages.
        """
        ...

    @abstractmethod
    def is_system_table(self, table_path: str) -> bool:
        """Check if table is a system/metadata table.

        Args:
            table_path: Table reference, possibly qualified (e.g., "pg_catalog.pg_tables").

        Returns:
            True if this is a system table allowed at schema_only level.
        """
        ...

    def normalize_table_name(self, table_path: str) -> str:
        """Normalize table name for consistent comparison.

        Default implementation converts to lowercase.
        Override for case-sensitive dialects.

        Args:
            table_path: Table reference.

        Returns:
            Normalized table path.
        """
        return table_path.lower()
