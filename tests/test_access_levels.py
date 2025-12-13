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


class TestAccessLevelComparison:
    """Tests for AccessLevel comparison operators.

    Bug fix: Comparison operators must follow permission hierarchy,
    not alphabetical order of string values.
    """

    def test_less_than_follows_hierarchy(self) -> None:
        """Test that < follows permission hierarchy."""
        # SCHEMA_ONLY < AGGREGATES < FULL
        assert AccessLevel.SCHEMA_ONLY < AccessLevel.AGGREGATES
        assert AccessLevel.AGGREGATES < AccessLevel.FULL
        assert AccessLevel.SCHEMA_ONLY < AccessLevel.FULL

        # Not less than itself
        assert not AccessLevel.SCHEMA_ONLY < AccessLevel.SCHEMA_ONLY
        assert not AccessLevel.AGGREGATES < AccessLevel.AGGREGATES
        assert not AccessLevel.FULL < AccessLevel.FULL

        # Not less than lower levels
        assert not AccessLevel.FULL < AccessLevel.AGGREGATES
        assert not AccessLevel.AGGREGATES < AccessLevel.SCHEMA_ONLY

    def test_greater_than_follows_hierarchy(self) -> None:
        """Test that > follows permission hierarchy."""
        assert AccessLevel.FULL > AccessLevel.AGGREGATES
        assert AccessLevel.AGGREGATES > AccessLevel.SCHEMA_ONLY
        assert AccessLevel.FULL > AccessLevel.SCHEMA_ONLY

    def test_less_equal_follows_hierarchy(self) -> None:
        """Test that <= follows permission hierarchy."""
        assert AccessLevel.SCHEMA_ONLY <= AccessLevel.SCHEMA_ONLY
        assert AccessLevel.SCHEMA_ONLY <= AccessLevel.AGGREGATES
        assert AccessLevel.AGGREGATES <= AccessLevel.FULL

    def test_greater_equal_follows_hierarchy(self) -> None:
        """Test that >= follows permission hierarchy."""
        assert AccessLevel.FULL >= AccessLevel.FULL
        assert AccessLevel.FULL >= AccessLevel.AGGREGATES
        assert AccessLevel.AGGREGATES >= AccessLevel.SCHEMA_ONLY

    def test_equality(self) -> None:
        """Test equality comparison."""
        assert AccessLevel.FULL == AccessLevel.FULL
        assert AccessLevel.AGGREGATES == AccessLevel.AGGREGATES
        assert AccessLevel.SCHEMA_ONLY == AccessLevel.SCHEMA_ONLY

        assert not AccessLevel.FULL == AccessLevel.AGGREGATES

    def test_string_equality_supported(self) -> None:
        """Test that string equality is supported for convenience.

        String comparison is useful when comparing with values from
        databases or APIs. Note that equality IS symmetric because
        AccessLevel inherits from str.
        """
        # AccessLevel == str works
        assert AccessLevel.FULL == "full"
        assert AccessLevel.AGGREGATES == "aggregates"
        assert AccessLevel.SCHEMA_ONLY == "schema_only"

        # str == AccessLevel also works (AccessLevel is a str subclass)
        assert "full" == AccessLevel.FULL
        assert "aggregates" == AccessLevel.AGGREGATES

    def test_hashable(self) -> None:
        """Test that AccessLevel is hashable for use in sets/dicts."""
        # Should be able to use in sets
        levels = {AccessLevel.FULL, AccessLevel.AGGREGATES, AccessLevel.SCHEMA_ONLY}
        assert len(levels) == 3

        # Should be able to use as dict keys
        level_map = {
            AccessLevel.FULL: "full access",
            AccessLevel.AGGREGATES: "aggregate only",
        }
        assert level_map[AccessLevel.FULL] == "full access"

    def test_comparison_not_alphabetical(self) -> None:
        """Test that comparison doesn't use alphabetical order.

        Alphabetically: "aggregates" < "full" < "schema_only"
        Hierarchy: SCHEMA_ONLY < AGGREGATES < FULL

        If using alphabetical order, SCHEMA_ONLY > FULL would be True.
        """
        # This would be True if using alphabetical comparison
        # schema_only > full alphabetically, but should be False by hierarchy
        assert not AccessLevel.SCHEMA_ONLY > AccessLevel.FULL
        assert AccessLevel.SCHEMA_ONLY < AccessLevel.FULL
