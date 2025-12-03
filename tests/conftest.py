"""Pytest configuration and fixtures."""

import pytest

from anomalyarmor_query_gateway import AccessLevel, QuerySecurityGateway, SQLParser


@pytest.fixture(params=["postgresql", "mysql", "databricks", "clickhouse", "sqlite"])
def dialect(request: pytest.FixtureRequest) -> str:
    """Parameterized fixture for all supported dialects."""
    return str(request.param)


@pytest.fixture
def postgres_parser() -> SQLParser:
    """PostgreSQL parser fixture."""
    return SQLParser("postgresql")


@pytest.fixture
def mysql_parser() -> SQLParser:
    """MySQL parser fixture."""
    return SQLParser("mysql")


@pytest.fixture
def postgres_gateway_full() -> QuerySecurityGateway:
    """PostgreSQL gateway with full access."""
    return QuerySecurityGateway(
        access_level=AccessLevel.FULL,
        dialect="postgresql",
    )


@pytest.fixture
def postgres_gateway_aggregates() -> QuerySecurityGateway:
    """PostgreSQL gateway with aggregates access."""
    return QuerySecurityGateway(
        access_level=AccessLevel.AGGREGATES,
        dialect="postgresql",
    )


@pytest.fixture
def postgres_gateway_schema_only() -> QuerySecurityGateway:
    """PostgreSQL gateway with schema_only access."""
    return QuerySecurityGateway(
        access_level=AccessLevel.SCHEMA_ONLY,
        dialect="postgresql",
    )
