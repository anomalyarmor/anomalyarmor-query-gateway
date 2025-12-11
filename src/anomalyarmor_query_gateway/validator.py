"""Access level validator for SQL queries.

Validates parsed queries against the configured access level rules.
"""

import sqlglot
from sqlglot import exp

from .access_levels import AccessLevel
from .dialects import BaseDialectRules, get_dialect_rules
from .parser import DATA_EXPOSING_AGGREGATES, ParsedQuery, SQLParser
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
        - Queries with only safe aggregate functions (no raw column values)

        Blocks:
        - Raw column references in SELECT
        - Window functions (can expose row-level data)
        - Data-exposing aggregates (array_agg, string_agg, json_agg, any_value, etc.)
        - Subqueries that could expose raw data

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

        # Data-exposing aggregates (array_agg, string_agg, json_agg, any_value, etc.)
        # return actual row data rather than computed statistics
        if parsed.has_data_exposing_aggregates:
            examples = ", ".join(sorted(DATA_EXPOSING_AGGREGATES)[:5]) + ", etc."
            return ValidationResult.deny(
                reason=(
                    "Data-exposing aggregate functions are not permitted at aggregates level "
                    f"because they return actual row data. Blocked functions include: {examples}. "
                    "Use statistical aggregates (COUNT, SUM, AVG, MIN, MAX) instead."
                ),
                required_level=AccessLevel.FULL,
                details={
                    "access_level": "aggregates",
                    "blocked_reason": "data_exposing_aggregates",
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

        # Recursively validate subqueries and CTEs
        if parsed.has_subqueries or parsed.has_ctes:
            subquery_result = self._validate_subqueries(parsed)
            if not subquery_result.allowed:
                return subquery_result

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

    def _validate_subqueries(self, parsed: ParsedQuery) -> ValidationResult:
        """Recursively validate subqueries and CTEs for AGGREGATES level.

        Subqueries that filter to a single row (via WHERE, LIMIT, etc.) combined
        with MIN/MAX can be used to extract specific row values. This method
        blocks subqueries that could expose raw data.

        Args:
            parsed: Parsed query containing subqueries/CTEs.

        Returns:
            ValidationResult indicating if subqueries are safe.
        """
        try:
            ast = sqlglot.parse_one(
                self._parser._strip_comments(parsed.original),
                dialect=self._parser._sqlglot_dialect,
            )
        except Exception:
            # If we can't re-parse, be conservative and block
            return ValidationResult.deny(
                reason="Unable to validate subquery structure for aggregate access level.",
                required_level=AccessLevel.FULL,
                details={
                    "access_level": "aggregates",
                    "blocked_reason": "subquery_parse_error",
                },
            )

        # Find all subqueries and CTEs
        subqueries = list(ast.find_all(exp.Subquery))
        ctes = list(ast.find_all(exp.CTE))

        # Check each subquery
        for subquery in subqueries:
            # Get the SELECT inside the subquery
            select = subquery.find(exp.Select)
            if select is None:
                continue

            # Parse the subquery as a standalone query
            subquery_sql = select.sql(dialect=self._parser._sqlglot_dialect)
            try:
                subquery_parsed = self._parser.parse(subquery_sql)
            except Exception:
                # If we can't parse the subquery, be conservative
                return ValidationResult.deny(
                    reason="Unable to validate nested subquery for aggregate access level.",
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "nested_subquery_parse_error",
                    },
                )

            # Check if subquery has raw columns (would expose data)
            if subquery_parsed.has_raw_columns:
                return ValidationResult.deny(
                    reason=(
                        "Subquery contains raw column values which could expose row-level data. "
                        "At aggregates level, subqueries must also use only aggregate functions."
                    ),
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "subquery_raw_columns",
                        "tables": parsed.tables,
                    },
                )

            # Check if subquery has data-exposing aggregates
            if subquery_parsed.has_data_exposing_aggregates:
                return ValidationResult.deny(
                    reason=(
                        "Subquery contains data-exposing aggregate functions. "
                        "At aggregates level, use only statistical aggregates."
                    ),
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "subquery_data_exposing_aggregates",
                        "tables": parsed.tables,
                    },
                )

            # Recursively validate nested subqueries within this subquery
            if subquery_parsed.has_subqueries or subquery_parsed.has_ctes:
                nested_result = self._validate_subqueries(subquery_parsed)
                if not nested_result.allowed:
                    return nested_result

        # Check each CTE
        for cte in ctes:
            cte_select = cte.find(exp.Select)
            if cte_select is None:
                continue

            cte_sql = cte_select.sql(dialect=self._parser._sqlglot_dialect)
            try:
                cte_parsed = self._parser.parse(cte_sql)
            except Exception:
                return ValidationResult.deny(
                    reason="Unable to validate CTE for aggregate access level.",
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "cte_parse_error",
                    },
                )

            if cte_parsed.has_raw_columns:
                return ValidationResult.deny(
                    reason=(
                        "CTE contains raw column values which could expose row-level data. "
                        "At aggregates level, CTEs must also use only aggregate functions."
                    ),
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "cte_raw_columns",
                        "tables": parsed.tables,
                    },
                )

            if cte_parsed.has_data_exposing_aggregates:
                return ValidationResult.deny(
                    reason=(
                        "CTE contains data-exposing aggregate functions. "
                        "At aggregates level, use only statistical aggregates."
                    ),
                    required_level=AccessLevel.FULL,
                    details={
                        "access_level": "aggregates",
                        "blocked_reason": "cte_data_exposing_aggregates",
                        "tables": parsed.tables,
                    },
                )

            # Recursively validate nested subqueries within this CTE
            if cte_parsed.has_subqueries or cte_parsed.has_ctes:
                nested_result = self._validate_subqueries(cte_parsed)
                if not nested_result.allowed:
                    return nested_result

        # All subqueries and CTEs are safe
        return ValidationResult.allow()
