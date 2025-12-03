# AnomalyArmor Query Gateway

A SQL query security gateway for validating database queries against customer-configured access levels.

## Overview

The Query Security Gateway provides a transparent, auditable layer for controlling what types of SQL queries can be executed against customer databases. It supports three access levels:

| Level | Description | Allowed Queries |
|-------|-------------|-----------------|
| `schema_only` | Metadata access only | information_schema, pg_catalog, DESCRIBE, system tables |
| `aggregates` | Aggregate functions only | COUNT, SUM, AVG, MIN, MAX, COUNT DISTINCT - no raw column values |
| `full` | Unrestricted read access | Any SELECT query |

## Installation

```bash
pip install anomalyarmor-query-gateway
```

## Quick Start

```python
from anomalyarmor_query_gateway import QuerySecurityGateway, AccessLevel

# Create gateway with desired access level
gateway = QuerySecurityGateway(
    access_level=AccessLevel.AGGREGATES,
    dialect="postgresql",
)

# Validate a query
result = gateway.validate_query_sync("SELECT COUNT(*) FROM users")

if result.allowed:
    print("Query is allowed")
else:
    print(f"Query blocked: {result.reason}")
```

## Access Levels Explained

### `schema_only`

Only allows queries against system/metadata tables:

- **PostgreSQL**: `information_schema.*`, `pg_catalog.*`
- **MySQL**: `information_schema.*`, `mysql.*`, `performance_schema.*`
- **Databricks**: `information_schema.*`, `system.*`
- **ClickHouse**: `system.*`
- **SQLite**: `sqlite_master`, `sqlite_schema`

### `aggregates`

Allows aggregate functions but blocks raw column values:

```python
# Allowed
"SELECT COUNT(*) FROM users"
"SELECT AVG(salary) FROM employees"
"SELECT MIN(created_at), MAX(created_at) FROM orders"

# Blocked
"SELECT * FROM users"
"SELECT email FROM users"
"SELECT salary FROM employees WHERE id = 1"
```

### `full`

Allows any valid SELECT query.

## Async Support

```python
from anomalyarmor_query_gateway import QuerySecurityGateway, AccessLevel

gateway = QuerySecurityGateway(
    access_level=AccessLevel.AGGREGATES,
    dialect="postgresql",
)

# Async validation with audit logging
result = await gateway.validate_query(
    "SELECT COUNT(*) FROM users",
    metadata={"asset_id": "123", "user_id": "456"}
)
```

## Audit Logging

Implement the `AuditLoggerProtocol` to log all query validation attempts:

```python
from anomalyarmor_query_gateway import (
    QuerySecurityGateway,
    AccessLevel,
    AuditLoggerProtocol,
)

class MyAuditLogger(AuditLoggerProtocol):
    async def log_query(
        self,
        query: str,
        access_level: AccessLevel,
        dialect: str,
        allowed: bool,
        rejection_reason: str | None,
        metadata: dict,
    ) -> None:
        # Store to your audit log
        print(f"Query {'allowed' if allowed else 'blocked'}: {query[:50]}...")

gateway = QuerySecurityGateway(
    access_level=AccessLevel.AGGREGATES,
    dialect="postgresql",
    audit_logger=MyAuditLogger(),
)
```

## Supported Dialects

- `postgresql` / `postgres`
- `mysql`
- `databricks`
- `clickhouse`
- `sqlite`

## Security

This package is designed to be a security control layer. Key security features:

1. **Fail-closed**: If parsing fails, the query is blocked
2. **Comment stripping**: SQL comments are removed before parsing to prevent obfuscation
3. **Recursive validation**: Subqueries and CTEs are validated against the same rules
4. **Window function blocking**: Window functions blocked in `aggregates` mode (can expose row-level data)

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/ tests/

# Run type checker
mypy src/
```

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security Issues

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
