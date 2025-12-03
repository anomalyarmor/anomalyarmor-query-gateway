"""SQL dialect-specific rules for query validation.

Each dialect defines its own system/metadata tables that are allowed
at the schema_only access level.
"""

from .base import BaseDialectRules
from .clickhouse import ClickHouseDialectRules
from .databricks import DatabricksDialectRules
from .mysql import MySQLDialectRules
from .postgres import PostgresDialectRules
from .sqlite import SQLiteDialectRules

__all__ = [
    "BaseDialectRules",
    "ClickHouseDialectRules",
    "DatabricksDialectRules",
    "MySQLDialectRules",
    "PostgresDialectRules",
    "SQLiteDialectRules",
    "get_dialect_rules",
]

# Registry of dialect rules
_DIALECT_REGISTRY: dict[str, type[BaseDialectRules]] = {
    "postgresql": PostgresDialectRules,
    "postgres": PostgresDialectRules,
    "mysql": MySQLDialectRules,
    "databricks": DatabricksDialectRules,
    "clickhouse": ClickHouseDialectRules,
    "sqlite": SQLiteDialectRules,
}


def get_dialect_rules(dialect: str) -> BaseDialectRules:
    """Get dialect rules instance for the given dialect.

    Args:
        dialect: SQL dialect name.

    Returns:
        Dialect rules instance.

    Raises:
        ValueError: If dialect is not supported.
    """
    dialect_lower = dialect.lower()
    rules_class = _DIALECT_REGISTRY.get(dialect_lower)
    if rules_class is None:
        supported = ", ".join(sorted(set(_DIALECT_REGISTRY.keys())))
        raise ValueError(
            f"Unsupported dialect: {dialect}. Supported dialects: {supported}"
        )
    return rules_class()
