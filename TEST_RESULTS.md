# Test Results

Last updated: 2025-12-03

## Summary

**97 tests passing** across 6 test modules.

```
tests/dialects/test_postgres.py        7 tests   - PostgreSQL dialect rules
tests/test_access_levels.py            7 tests   - Access level enum and hierarchy
tests/test_gateway.py                 17 tests   - Main gateway integration
tests/test_parser.py                  21 tests   - SQL parsing with sqlglot
tests/test_security.py                18 tests   - Security edge cases (injection, obfuscation)
tests/test_validator.py               27 tests   - Access level validation rules
```

## Test Categories

### Access Level Tests
- Verify `schema_only` blocks user table access
- Verify `aggregates` allows only aggregate functions
- Verify `full` allows any SELECT query
- Verify level hierarchy (full > aggregates > schema_only)

### Parser Tests
- Query type detection (SELECT, INSERT, UPDATE, DELETE)
- Aggregate function detection (COUNT, SUM, AVG, MIN, MAX)
- Table extraction from various query patterns
- Subquery and CTE handling

### Validator Tests
- Schema-only: blocks `SELECT * FROM users`
- Schema-only: allows `SELECT * FROM information_schema.tables`
- Aggregates: allows `SELECT COUNT(*) FROM users`
- Aggregates: blocks `SELECT name FROM users`
- Aggregates: blocks `SELECT COUNT(*), name FROM users` (mixed)
- Window functions blocked in aggregates mode

### Security Tests
- SQL comment stripping (prevents obfuscation)
- Unicode character handling
- Nested subquery validation
- CTE validation
- Parse failure = query blocked (fail-closed)

### Dialect Tests
- PostgreSQL: information_schema, pg_catalog
- MySQL: information_schema, mysql, performance_schema
- Databricks: information_schema, system
- ClickHouse: system.*
- SQLite: sqlite_master, sqlite_schema

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_validator.py

# Run with coverage
pytest --cov=anomalyarmor_query_gateway
```

## CI Status

Tests run automatically on every PR via GitHub Actions:
- Python 3.11
- pytest
- mypy (strict mode)
- ruff (linting)
