"""Tests for access level enum."""

from anomalyarmor_query_gateway import AccessLevel


class TestAccessLevel:
    """Tests for AccessLevel enum."""

    def test_string_values(self) -> None:
        """Test that enum values are strings."""
        assert AccessLevel.SCHEMA_ONLY.value == "schema_only"
        assert AccessLevel.AGGREGATES.value == "aggregates"
        assert AccessLevel.FULL.value == "full"

    def test_str_conversion(self) -> None:
        """Test string conversion."""
        assert str(AccessLevel.SCHEMA_ONLY) == "schema_only"
        assert str(AccessLevel.AGGREGATES) == "aggregates"
        assert str(AccessLevel.FULL) == "full"

    def test_hierarchy(self) -> None:
        """Test hierarchy ordering."""
        hierarchy = AccessLevel.hierarchy()
        assert hierarchy == [
            AccessLevel.SCHEMA_ONLY,
            AccessLevel.AGGREGATES,
            AccessLevel.FULL,
        ]

    def test_permits_same_level(self) -> None:
        """Test that level permits itself."""
        assert AccessLevel.SCHEMA_ONLY.permits(AccessLevel.SCHEMA_ONLY)
        assert AccessLevel.AGGREGATES.permits(AccessLevel.AGGREGATES)
        assert AccessLevel.FULL.permits(AccessLevel.FULL)

    def test_permits_lower_level(self) -> None:
        """Test that higher level permits lower level requirements."""
        # FULL permits everything
        assert AccessLevel.FULL.permits(AccessLevel.SCHEMA_ONLY)
        assert AccessLevel.FULL.permits(AccessLevel.AGGREGATES)

        # AGGREGATES permits schema_only
        assert AccessLevel.AGGREGATES.permits(AccessLevel.SCHEMA_ONLY)

    def test_denies_higher_level(self) -> None:
        """Test that lower level denies higher level requirements."""
        # SCHEMA_ONLY doesn't permit aggregates or full
        assert not AccessLevel.SCHEMA_ONLY.permits(AccessLevel.AGGREGATES)
        assert not AccessLevel.SCHEMA_ONLY.permits(AccessLevel.FULL)

        # AGGREGATES doesn't permit full
        assert not AccessLevel.AGGREGATES.permits(AccessLevel.FULL)

    def test_description(self) -> None:
        """Test that descriptions are provided."""
        assert "metadata" in AccessLevel.SCHEMA_ONLY.description.lower()
        assert "aggregate" in AccessLevel.AGGREGATES.description.lower()
        assert "unrestricted" in AccessLevel.FULL.description.lower()
