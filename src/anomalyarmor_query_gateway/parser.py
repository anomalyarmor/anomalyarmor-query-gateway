"""SQL parser using sqlglot.

Parses SQL queries and extracts structural information needed for
access level validation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError as SqlglotParseError

from .exceptions import QueryParseError

if TYPE_CHECKING:
    pass


# Safe aggregate functions that return computed statistical values (not raw data)
SAFE_AGGREGATE_FUNCTIONS = frozenset(
    {
        "count",
        "sum",
        "avg",
        "min",
        "max",
        "stddev",
        "variance",
        "var_pop",
        "var_samp",
        "stddev_pop",
        "stddev_samp",
        "covar_pop",
        "covar_samp",
        "corr",
        "percentile_cont",
        "percentile_disc",
        "median",
        "mode",
        "approx_count_distinct",
        "approx_percentile",
        "bit_and",
        "bit_or",
        "bit_xor",
        "bool_and",
        "bool_or",
        "every",
    }
)

# Data-exposing aggregate functions that return actual row values
# These are technically aggregates but expose raw data and should be blocked
# at AGGREGATES access level. They include:
# - Collection aggregates: array_agg, string_agg, json_agg, etc.
# - Arbitrary value selectors: any_value, first_value, last_value
DATA_EXPOSING_AGGREGATES = frozenset(
    {
        "array_agg",
        "string_agg",
        "group_concat",
        "listagg",
        "json_agg",
        "jsonb_agg",
        "json_object_agg",
        "jsonb_object_agg",
        "collect_list",
        "collect_set",
        "any_value",
        "first_value",
        "last_value",
    }
)

# All aggregate functions (union of safe and data-exposing)
AGGREGATE_FUNCTIONS = SAFE_AGGREGATE_FUNCTIONS | DATA_EXPOSING_AGGREGATES


@dataclass
class ParsedQuery:
    """Structured representation of a parsed SQL query.

    Contains analysis results needed for access level validation.

    Attributes:
        original: The original SQL query string.
        dialect: SQL dialect used for parsing.
        is_select: Whether this is a SELECT statement.
        tables: List of tables referenced (fully qualified where available).
        has_aggregates: Whether SELECT contains aggregate functions.
        has_raw_columns: Whether SELECT contains raw column references.
        has_data_exposing_aggregates: Whether query uses data-exposing aggregates
            (array_agg, string_agg, json_agg, any_value, etc.) that return raw data.
        has_subqueries: Whether query contains subqueries.
        has_ctes: Whether query contains CTEs (WITH clauses).
        has_window_functions: Whether query contains window functions.
        has_unions: Whether query contains UNION/INTERSECT/EXCEPT.
    """

    original: str
    dialect: str
    is_select: bool = False
    tables: list[str] = field(default_factory=list)
    has_aggregates: bool = False
    has_raw_columns: bool = False
    has_data_exposing_aggregates: bool = False
    has_subqueries: bool = False
    has_ctes: bool = False
    has_window_functions: bool = False
    has_unions: bool = False
    select_expressions: list[exp.Expression] = field(default_factory=list)


class SQLParser:
    """Parse SQL queries using sqlglot.

    Provides dialect-aware SQL parsing and structural analysis.

    Example:
        parser = SQLParser("postgresql")
        parsed = parser.parse("SELECT COUNT(*) FROM users")
        print(parsed.has_aggregates)  # True
    """

    # Map our dialect names to sqlglot dialect names
    DIALECT_MAP: ClassVar[dict[str, str]] = {
        "postgresql": "postgres",
        "postgres": "postgres",
        "mysql": "mysql",
        "databricks": "databricks",
        "clickhouse": "clickhouse",
        "sqlite": "sqlite",
    }

    def __init__(self, dialect: str):
        """Initialize parser with SQL dialect.

        Args:
            dialect: SQL dialect name (postgresql, mysql, databricks, etc.)
        """
        self.dialect = dialect.lower()
        self._sqlglot_dialect = self.DIALECT_MAP.get(self.dialect, self.dialect)

    def parse(self, query: str) -> ParsedQuery:
        """Parse SQL query and analyze structure.

        Args:
            query: SQL query string.

        Returns:
            ParsedQuery with structural analysis.

        Raises:
            QueryParseError: If query cannot be parsed.
        """
        # Strip comments for security (prevent obfuscation attacks)
        cleaned = self._strip_comments(query)

        try:
            ast = sqlglot.parse_one(cleaned, dialect=self._sqlglot_dialect)
        except SqlglotParseError as e:
            raise QueryParseError(
                f"Failed to parse SQL: {e}",
                query=query,
                dialect=self.dialect,
            ) from e
        except Exception as e:
            raise QueryParseError(
                f"Unexpected error parsing SQL: {e}",
                query=query,
                dialect=self.dialect,
            ) from e

        return self._analyze(query, ast)

    def _strip_comments(self, query: str) -> str:
        """Remove SQL comments to prevent obfuscation.

        Handles:
        - Single-line comments: -- comment
        - Multi-line comments: /* comment */
        - Nested comments (PostgreSQL style)

        Args:
            query: Original SQL query.

        Returns:
            Query with comments removed.
        """
        # Remove single-line comments
        result = re.sub(r"--[^\n]*", "", query)
        # Remove multi-line comments (non-nested)
        result = re.sub(r"/\*.*?\*/", "", result, flags=re.DOTALL)
        return result.strip()

    def _analyze(self, original: str, ast: exp.Expression) -> ParsedQuery:
        """Analyze parsed AST and extract structure.

        Args:
            original: Original query string.
            ast: Parsed AST from sqlglot.

        Returns:
            ParsedQuery with analysis results.
        """
        result = ParsedQuery(
            original=original,
            dialect=self.dialect,
        )

        # Check if this is a SELECT statement
        result.is_select = isinstance(ast, exp.Select)

        # Handle UNION/INTERSECT/EXCEPT
        if isinstance(ast, exp.Union):
            result.has_unions = True
            result.is_select = True
            # Analyze both sides of union
            self._analyze_union(ast, result)
            return result

        # Extract tables
        result.tables = self._extract_tables(ast)

        # Check for CTEs
        result.has_ctes = bool(list(ast.find_all(exp.CTE)))

        # Check for subqueries
        result.has_subqueries = self._has_subqueries(ast)

        # Check for window functions
        result.has_window_functions = self._has_window_functions(ast)

        # Analyze SELECT clause if applicable
        if isinstance(ast, exp.Select):
            result.select_expressions = list(ast.expressions)
            result.has_aggregates = self._has_aggregates(ast)
            result.has_raw_columns = self._has_raw_columns(ast)
            result.has_data_exposing_aggregates = self._has_data_exposing_aggregates(
                ast
            )

        return result

    def _analyze_union(self, union: exp.Union, result: ParsedQuery) -> None:
        """Analyze UNION query and merge results.

        Args:
            union: Union expression.
            result: ParsedQuery to update.
        """
        # Get all parts of the union
        for part in [union.left, union.right]:
            if part is None:
                continue

            if isinstance(part, exp.Union):
                self._analyze_union(part, result)
            elif isinstance(part, exp.Select):
                result.tables.extend(self._extract_tables(part))
                result.has_aggregates = result.has_aggregates or self._has_aggregates(
                    part
                )
                result.has_raw_columns = (
                    result.has_raw_columns or self._has_raw_columns(part)
                )
                result.has_subqueries = result.has_subqueries or self._has_subqueries(
                    part
                )
                result.has_window_functions = (
                    result.has_window_functions or self._has_window_functions(part)
                )
                result.has_data_exposing_aggregates = (
                    result.has_data_exposing_aggregates
                    or self._has_data_exposing_aggregates(part)
                )

    def _extract_tables(self, ast: exp.Expression) -> list[str]:
        """Extract all table references from AST.

        Args:
            ast: Parsed AST.

        Returns:
            List of table names (qualified where available).
        """
        tables = []
        for table in ast.find_all(exp.Table):
            parts = []
            if table.catalog:
                parts.append(table.catalog)
            if table.db:
                parts.append(table.db)
            if table.name:
                parts.append(table.name)
            if parts:
                tables.append(".".join(parts))
        return tables

    def _has_subqueries(self, ast: exp.Expression) -> bool:
        """Check if AST contains subqueries.

        Args:
            ast: Parsed AST.

        Returns:
            True if subqueries are present.
        """
        # Look for subqueries in various locations
        for node in ast.walk():
            if isinstance(node, exp.Subquery):
                return True
            # Also check for derived tables
            if (
                isinstance(node, exp.Select)
                and node.parent
                and not isinstance(node.parent, exp.Union)
            ):
                parent = node.parent
                if isinstance(parent, exp.From | exp.Join | exp.Subquery):
                    return True
        return False

    def _has_window_functions(self, ast: exp.Expression) -> bool:
        """Check if AST contains window functions.

        Args:
            ast: Parsed AST.

        Returns:
            True if window functions are present.
        """
        return bool(list(ast.find_all(exp.Window)))

    def _has_aggregates(self, ast: exp.Expression) -> bool:
        """Check if SELECT contains aggregate functions.

        Args:
            ast: Parsed AST (should be SELECT).

        Returns:
            True if aggregate functions are present.
        """
        # Check for explicit aggregate function nodes
        if list(ast.find_all(exp.AggFunc)):
            return True

        # Check for function calls that are aggregates
        for func in ast.find_all(exp.Func):
            if hasattr(func, "name") and func.name.lower() in AGGREGATE_FUNCTIONS:
                return True

        # Check for COUNT, SUM, etc. specifically
        aggregate_types = (
            exp.Count,
            exp.Sum,
            exp.Avg,
            exp.Min,
            exp.Max,
            exp.ArrayAgg,
            exp.GroupConcat,
        )
        return any(list(ast.find_all(agg_type)) for agg_type in aggregate_types)

    def _has_data_exposing_aggregates(self, ast: exp.Expression) -> bool:
        """Check if SELECT contains data-exposing aggregate functions.

        Data-exposing aggregates (array_agg, string_agg, json_agg, any_value, etc.)
        technically aggregate rows but return actual row data rather than computed
        statistics, making them unsafe at AGGREGATES access level.

        Args:
            ast: Parsed AST (should be SELECT).

        Returns:
            True if data-exposing aggregate functions are present.
        """
        # Check for known data-exposing aggregate types that sqlglot recognizes
        # ArrayAgg, GroupConcat are collection aggregates
        # AnyValue, FirstValue, LastValue return arbitrary row values
        data_exposing_types = (
            exp.ArrayAgg,
            exp.GroupConcat,
            exp.AnyValue,
            exp.FirstValue,
            exp.LastValue,
        )
        if any(list(ast.find_all(agg_type)) for agg_type in data_exposing_types):
            return True

        # Check for function calls that are data-exposing aggregates by name
        # This catches functions not recognized by sqlglot as specific types
        for func in ast.find_all(exp.Func):
            func_name = getattr(func, "name", "") or ""
            if func_name.lower() in DATA_EXPOSING_AGGREGATES:
                return True

        # Also check AggFunc nodes for data-exposing function names
        for agg in ast.find_all(exp.AggFunc):
            # Get function name from the name attribute or class name
            agg_name = getattr(agg, "name", "") or ""
            # Convert class name to snake_case for matching (e.g., ArrayAgg -> array_agg)
            if not agg_name:
                class_name = agg.__class__.__name__
                # Convert PascalCase to snake_case using regex
                # Insert underscore before uppercase letters that follow lowercase letters
                agg_name = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", class_name).lower()
            if agg_name.lower() in DATA_EXPOSING_AGGREGATES:
                return True

        return False

    def _has_raw_columns(self, ast: exp.Expression) -> bool:
        """Check if SELECT contains raw column references not in aggregates.

        A "raw column" is a column reference in the SELECT clause that is
        not wrapped in an aggregate function.

        Args:
            ast: Parsed AST (should be SELECT).

        Returns:
            True if raw columns are present in SELECT.
        """
        if not isinstance(ast, exp.Select):
            return False

        # Check each SELECT expression
        return any(self._expression_has_raw_column(expr) for expr in ast.expressions)

    def _expression_has_raw_column(self, expr: exp.Expression) -> bool:
        """Check if expression contains raw (non-aggregated) column reference.

        Args:
            expr: Expression to check.

        Returns:
            True if raw column reference found.
        """
        # If the expression itself is an aggregate, no raw columns
        if self._is_aggregate_expression(expr):
            return False

        # Check for star (SELECT *)
        if isinstance(expr, exp.Star):
            return True

        # Check for column references
        if isinstance(expr, exp.Column):
            return True

        # Check for aliases - look inside
        if isinstance(expr, exp.Alias):
            return self._expression_has_raw_column(expr.this)

        # For other expressions, check for columns not inside aggregates
        for column in expr.find_all(exp.Column):
            if not self._is_inside_aggregate(column):
                return True

        # Check for star inside expressions
        for star in expr.find_all(exp.Star):
            if not self._is_inside_aggregate(star):
                return True

        return False

    def _is_aggregate_expression(self, expr: exp.Expression) -> bool:
        """Check if expression is an aggregate function.

        Args:
            expr: Expression to check.

        Returns:
            True if expression is aggregate.
        """
        # Handle aliases
        if isinstance(expr, exp.Alias):
            return self._is_aggregate_expression(expr.this)

        # Check for aggregate types
        if isinstance(
            expr,
            exp.AggFunc
            | exp.Count
            | exp.Sum
            | exp.Avg
            | exp.Min
            | exp.Max
            | exp.ArrayAgg
            | exp.GroupConcat,
        ):
            return True

        # Check function name
        if isinstance(expr, exp.Func):
            name = getattr(expr, "name", "")
            if name.lower() in AGGREGATE_FUNCTIONS:
                return True

        return False

    def _is_inside_aggregate(self, node: exp.Expression) -> bool:
        """Check if node is inside an aggregate function.

        Args:
            node: Node to check.

        Returns:
            True if any ancestor is an aggregate.
        """
        aggregate_types = (
            exp.AggFunc,
            exp.Count,
            exp.Sum,
            exp.Avg,
            exp.Min,
            exp.Max,
            exp.ArrayAgg,
            exp.GroupConcat,
        )

        parent = node.parent
        while parent is not None:
            if isinstance(parent, aggregate_types):
                return True
            if isinstance(parent, exp.Func):
                name = getattr(parent, "name", "")
                if name.lower() in AGGREGATE_FUNCTIONS:
                    return True
            parent = parent.parent

        return False
