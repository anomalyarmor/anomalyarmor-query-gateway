"""Tests for ValidationResult."""

from anomalyarmor_query_gateway import AccessLevel
from anomalyarmor_query_gateway.result import ValidationResult


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_allow_creates_allowed_result(self) -> None:
        """Test that allow() creates an allowed result."""
        result = ValidationResult.allow()
        assert result.allowed is True
        assert result.reason is None
        assert result.access_level_required is None

    def test_allow_with_details(self) -> None:
        """Test that allow() accepts details."""
        result = ValidationResult.allow(details={"tables": ["users"]})
        assert result.allowed is True
        assert result.details["tables"] == ["users"]

    def test_deny_creates_denied_result(self) -> None:
        """Test that deny() creates a denied result."""
        result = ValidationResult.deny(reason="Access denied")
        assert result.allowed is False
        assert result.reason == "Access denied"

    def test_deny_with_required_level(self) -> None:
        """Test that deny() accepts required_level."""
        result = ValidationResult.deny(
            reason="Need higher access",
            required_level=AccessLevel.FULL,
        )
        assert result.access_level_required == AccessLevel.FULL

    def test_deny_with_details(self) -> None:
        """Test that deny() accepts details."""
        result = ValidationResult.deny(
            reason="Blocked",
            details={"blocked_columns": ["email"]},
        )
        assert result.details["blocked_columns"] == ["email"]

    def test_details_is_immutable(self) -> None:
        """Test that details cannot be modified after creation."""
        result = ValidationResult.allow(details={"key": "value"})

        # Attempting to modify should raise TypeError
        try:
            result.details["new_key"] = "new_value"  # type: ignore[index]
            raise AssertionError("Expected TypeError")
        except TypeError:
            pass  # Expected

    def test_result_is_frozen(self) -> None:
        """Test that the dataclass is frozen (immutable)."""
        result = ValidationResult.allow()

        try:
            result.allowed = False  # type: ignore[misc]
            raise AssertionError("Expected FrozenInstanceError")
        except AttributeError:
            pass  # Expected (FrozenInstanceError is a subclass)


class TestValidationResultToDict:
    """Tests for ValidationResult.to_dict() method."""

    def test_to_dict_allowed_minimal(self) -> None:
        """Test to_dict() for minimal allowed result."""
        result = ValidationResult.allow()
        d = result.to_dict()

        assert d == {"allowed": True}
        assert "reason" not in d
        assert "access_level_required" not in d
        assert "details" not in d

    def test_to_dict_denied_with_reason(self) -> None:
        """Test to_dict() includes reason when present."""
        result = ValidationResult.deny(reason="Query blocked")
        d = result.to_dict()

        assert d["allowed"] is False
        assert d["reason"] == "Query blocked"

    def test_to_dict_with_access_level_required(self) -> None:
        """Test to_dict() includes access_level_required as string value."""
        result = ValidationResult.deny(
            reason="Need higher access",
            required_level=AccessLevel.FULL,
        )
        d = result.to_dict()

        assert d["access_level_required"] == "full"

    def test_to_dict_with_details(self) -> None:
        """Test to_dict() includes details when present."""
        result = ValidationResult.allow(details={"tables": ["users", "orders"]})
        d = result.to_dict()

        assert d["details"] == {"tables": ["users", "orders"]}

    def test_to_dict_full_denied_result(self) -> None:
        """Test to_dict() with all fields populated."""
        result = ValidationResult.deny(
            reason="Raw columns not allowed",
            required_level=AccessLevel.FULL,
            details={"blocked_columns": ["email", "password"]},
        )
        d = result.to_dict()

        assert d == {
            "allowed": False,
            "reason": "Raw columns not allowed",
            "access_level_required": "full",
            "details": {"blocked_columns": ["email", "password"]},
        }

    def test_to_dict_returns_regular_dict_for_details(self) -> None:
        """Test that to_dict() converts MappingProxyType details to regular dict."""
        result = ValidationResult.allow(details={"key": "value"})
        d = result.to_dict()

        # Should be a regular dict, not MappingProxyType
        assert type(d["details"]) is dict
