# AnomalyArmor Query Gateway

[![Tests](https://github.com/anomalyarmor/anomalyarmor-query-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/anomalyarmor/anomalyarmor-query-gateway/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## What is this?

This is the **open-source SQL security layer** that AnomalyArmor uses to control access to customer databases. Every query we execute against your database passes through this gateway.

**Why open source?** So you can verify exactly what queries we can and cannot run. No black boxes.

## What does it do?

```
                              ┌─────────────────────────────────┐
                              │     Your Database               │
                              │  ┌───────────────────────────┐  │
                              │  │  users   │  orders  │ ... │  │
                              │  └───────────────────────────┘  │
                              └────────────────▲────────────────┘
                                               │
                                               │ BLOCKED or ALLOWED
                                               │
┌──────────────────────────────────────────────┴───────────────────────────────┐
│                         Query Security Gateway                                │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────┐   │
│  │   SQL Parser    │ -> │ Access Validator │ -> │  Allow / Block + Log   │   │
│  │   (sqlglot)     │    │  (level rules)   │    │  (audit trail)         │   │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                                               ▲
                                               │
                              ┌────────────────┴────────────────┐
                              │      AnomalyArmor Platform      │
                              │   (freshness, tags, insights)   │
                              └─────────────────────────────────┘
```

Validates SQL queries against three access levels:

| Level | What We Can Query | What We Cannot Query |
|-------|-------------------|----------------------|
| **Schema Only** | Table names, column types, indexes | Any actual data |
| **Aggregates** | `COUNT(*)`, `AVG(salary)`, `MAX(date)` | `SELECT email FROM users` |
| **Full** | Any SELECT query | - |

The gateway parses your SQL using [sqlglot](https://github.com/tobymao/sqlglot) and blocks queries that violate the configured access level. **If parsing fails, the query is blocked** (fail-closed).

## How do we know it works?

**97 tests** covering access level enforcement, SQL parsing, and security edge cases.

See [TEST_RESULTS.md](TEST_RESULTS.md) for the full breakdown, or run them yourself:

```bash
pip install -e ".[dev]"
pytest -v
```

---

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
