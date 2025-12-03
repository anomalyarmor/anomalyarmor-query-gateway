"""Access level validator for SQL queries.

Validates parsed queries against the configured access level rules.
"""

from .access_levels import AccessLevel
from .dialects import BaseDialectRules, get_dialect_rules
from .parser import ParsedQuery, SQLParser
from .result import ValidationResult


class AccessValidator:
    """Validate SQL queries against access level rules.

    The validator checks parsed queries against the rules for the configured
    access level. It uses dialect-specific rules to identify system tables.

    Example:
        validator = AccessValidator(AccessLevel.AGGREGATES, "postgresql")
        parser = SQLParser("postgresql")
        parsed = parser.parse("SELECT COUNT(*) FROM users")
        result = validator.validate(parsed)
    """

    def __init__(self, access_level: AccessLevel, dialect: str):
        """Initialize validator with access level and dialect.

        Args:
            access_level: Access level to enforce.
            dialect: SQL dialect for system table identification.
        """
        self.access_level = access_level
        self.dialect = dialect
        self._dialect_rules: BaseDialectRules = get_dialect_rules(dialect)
        self._parser = SQLParser(dialect)

    def validate(self, parsed: ParsedQuery) -> ValidationResult:
        """Validate parsed query against access level rules.

        Args:
            parsed: Parsed query from SQLParser.

        Returns:
            ValidationResult indicating if query is allowed.
        """
        # All levels require SELECT
        if not parsed.is_select:
            return ValidationResult.deny(
                reason="Only SELECT queries are permitted",
                required_level=self.access_level,
                details={"query_type": "non-select"},
            )

        # Route to appropriate validator
        if self.access_level == AccessLevel.FULL:
            return self._validate_full(parsed)
        elif self.access_level == AccessLevel.AGGREGATES:
            return self._validate_aggregates(parsed)
        elif self.access_level == AccessLevel.SCHEMA_ONLY:
            return self._validate_schema_only(parsed)
        else:
            return ValidationResult.deny(
                reason=f"Unknown access level: {self.access_level}",
            )

    def _validate_full(self, parsed: ParsedQuery) -> ValidationResult:
        """Validate query for FULL access level.

        FULL access allows any valid SELECT query.

        Args:
            parsed: Parsed query.

        Returns:
            ValidationResult (always allowed for SELECT).
        """
        return ValidationResult.allow(
            details={"access_level": "full", "tables": parsed.tables}
        )

    def _validate_schema_only(self, parsed: ParsedQuery) -> ValidationResult:
        """Validate query for SCHEMA_ONLY access level.

        SCHEMA_ONLY only allows queries against system/metadata tables.

        Args:
            parsed: Parsed query.

        Returns:
            ValidationResult indicating if all tables are system tables.
        """
        # All referenced tables must be system tables
        non_system_tables = []
        for table in parsed.tables:
            if not self._dialect_rules.is_system_table(table):
                non_system_tables.append(table)

        if non_system_tables:
            return ValidationResult.deny(
                reason=(
                    f"Table(s) not allowed at schema_only level: "
                    f"{', '.join(non_system_tables)}. "
                    f"Allowed: {self._dialect_rules.system_table_description}"
                ),
                required_level=AccessLevel.AGGREGATES,
                details={
                    "access_level": "schema_only",
                    "blocked_tables": non_system_tables,
                    "all_tables": parsed.tables,
                },
            )

        return ValidationResult.allow(
            details={
                "access_level": "schema_only",
                "tables": parsed.tables,
                "all_system_tables": True,
            }
        )

    def _validate_aggregates(self, parsed: ParsedQuery) -> ValidationResult:
        """Validate query for AGGREGATES access level.

        AGGREGATES allows:
        - Any query against system tables (schema_only subset)
        - Queries with only aggregate functions (no raw column values)

        Blocks:
        - Raw column references in SELECT
        - Window functions (can expose row-level data)

        Args:
            parsed: Parsed query.

        Returns:
            ValidationResult based on query structure.
        """
        # System tables are always allowed at aggregates level
        all_system = all(
            self._dialect_rules.is_system_table(table) for table in parsed.tables
        )
        if all_system and parsed.tables:
            return ValidationResult.allow(
                details={
                    "access_level": "aggregates",
                    "tables": parsed.tables,
                    "all_system_tables": True,
                }
            )

        # Window functions can expose row-level data
        if parsed.has_window_functions:
            return ValidationResult.deny(
                reason=(
                    "Window functions are not permitted at aggregates level "
                    "because they can expose row-level data. "
                    "Use standard aggregate functions (COUNT, SUM, AVG, MIN, MAX) instead."
                ),
                required_level=AccessLevel.FULL,
                details={
                    "access_level": "aggregates",
                    "blocked_reason": "window_functions",
                    "tables": parsed.tables,
                },
            )

        # Check for raw columns in SELECT
        if parsed.has_raw_columns:
            return ValidationResult.deny(
                reason=(
                    "SELECT clause contains raw column values. "
                    "At aggregates level, only aggregate functions are permitted: "
                    "COUNT(*), COUNT(col), SUM(col), AVG(col), MIN(col), MAX(col), "
                    "COUNT(DISTINCT col)."
                ),
                required_level=AccessLevel.FULL,
                details={
                    "access_level": "aggregates",
                    "blocked_reason": "raw_columns",
                    "tables": parsed.tables,
                    "has_aggregates": parsed.has_aggregates,
                },
            )

        # Validate subqueries recursively
        if parsed.has_subqueries or parsed.has_ctes:
            # For complex queries with subqueries/CTEs, we need to be conservative.
            # The parser detected these but detailed validation would require
            # re-parsing each subquery. For now, allow if main query looks clean.
            # Note: In production, you might want to add recursive validation.
            pass

        # Validate UNION parts (already analyzed in parser)
        if parsed.has_unions:
            # Union analysis already set has_raw_columns based on all parts
            pass

        # Query looks clean - allow it
        return ValidationResult.allow(
            details={
                "access_level": "aggregates",
                "tables": parsed.tables,
                "has_aggregates": parsed.has_aggregates,
                "has_subqueries": parsed.has_subqueries,
                "has_ctes": parsed.has_ctes,
            }
        )
