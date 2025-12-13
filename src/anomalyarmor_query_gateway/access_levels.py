"""Access level definitions for query security gateway.

Access levels control what types of SQL queries are permitted:
- schema_only: Only metadata/system table queries
- aggregates: Only aggregate functions, no raw column values
- full: Any valid SELECT query
"""

from enum import Enum


class AccessLevel(str, Enum):
    """Customer-configured access levels for database queries.

    Inherits from str for easy serialization and database storage.
    Comparison operators follow permission hierarchy (not alphabetical order).

    Note: All comparison operators (__lt__, __le__, __gt__, __ge__) are
    explicitly overridden because `str` already defines them, and we need
    hierarchy-based comparison instead of alphabetical.
    """

    SCHEMA_ONLY = "schema_only"
    """Only metadata queries allowed - information_schema, system tables, DESCRIBE."""

    AGGREGATES = "aggregates"
    """Aggregate functions only - COUNT, SUM, AVG, MIN, MAX, COUNT DISTINCT."""

    FULL = "full"
    """Any valid SELECT query allowed."""

    @classmethod
    def hierarchy(cls) -> list["AccessLevel"]:
        """Return levels in order of increasing permissions.

        Returns:
            List of access levels from most restrictive to least restrictive.
        """
        return [cls.SCHEMA_ONLY, cls.AGGREGATES, cls.FULL]

    def _get_hierarchy_index(self) -> int:
        """Get index in permission hierarchy."""
        return self.hierarchy().index(self)

    def __lt__(self, other: object) -> bool:
        """Compare based on permission hierarchy, not string value."""
        if not isinstance(other, AccessLevel):
            return NotImplemented
        return self._get_hierarchy_index() < other._get_hierarchy_index()

    def __le__(self, other: object) -> bool:
        """Compare based on permission hierarchy, not string value."""
        if not isinstance(other, AccessLevel):
            return NotImplemented
        return self._get_hierarchy_index() <= other._get_hierarchy_index()

    def __gt__(self, other: object) -> bool:
        """Compare based on permission hierarchy, not string value."""
        if not isinstance(other, AccessLevel):
            return NotImplemented
        return self._get_hierarchy_index() > other._get_hierarchy_index()

    def __ge__(self, other: object) -> bool:
        """Compare based on permission hierarchy, not string value."""
        if not isinstance(other, AccessLevel):
            return NotImplemented
        return self._get_hierarchy_index() >= other._get_hierarchy_index()

    def __eq__(self, other: object) -> bool:
        """Check equality by value.

        Supports comparison with both AccessLevel and str for convenience
        (e.g., comparing with values from database/API).

        Args:
            other: Object to compare against.

        Returns:
            True if equal.
        """
        if isinstance(other, AccessLevel):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash(self.value)

    def permits(self, required_level: "AccessLevel") -> bool:
        """Check if this level permits operations requiring the given level.

        Args:
            required_level: The minimum access level required for an operation.

        Returns:
            True if this level has sufficient permissions.

        Example:
            >>> AccessLevel.FULL.permits(AccessLevel.AGGREGATES)
            True
            >>> AccessLevel.SCHEMA_ONLY.permits(AccessLevel.AGGREGATES)
            False
        """
        hierarchy = self.hierarchy()
        return hierarchy.index(self) >= hierarchy.index(required_level)

    @property
    def description(self) -> str:
        """Human-readable description of this access level."""
        descriptions = {
            self.SCHEMA_ONLY: "Metadata access only (system tables, DESCRIBE)",
            self.AGGREGATES: "Aggregate functions only (COUNT, SUM, AVG, MIN, MAX)",
            self.FULL: "Unrestricted read access (any SELECT query)",
        }
        return descriptions[self]

    def __str__(self) -> str:
        """Return string value for serialization."""
        return self.value
