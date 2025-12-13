"""Validation result types for query security gateway."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .access_levels import AccessLevel

# Empty immutable mapping as default
_EMPTY_DETAILS: MappingProxyType[str, Any] = MappingProxyType({})


@dataclass(frozen=True)
class ValidationResult:
    """Result of query validation.

    Immutable dataclass representing the outcome of query validation.
    All fields including `details` are truly immutable.

    Attributes:
        allowed: Whether the query is permitted.
        reason: Human-readable explanation (especially important when blocked).
        access_level_required: Minimum access level needed for this query.
        details: Additional validation details for debugging (immutable).
    """

    allowed: bool
    reason: str | None = None
    access_level_required: AccessLevel | None = None
    details: Mapping[str, Any] = field(default_factory=lambda: _EMPTY_DETAILS)

    @classmethod
    def allow(cls, details: dict[str, Any] | None = None) -> "ValidationResult":
        """Create an allowed result.

        Args:
            details: Optional details about the validation.

        Returns:
            ValidationResult with allowed=True.
        """
        return cls(
            allowed=True,
            details=MappingProxyType(details) if details else _EMPTY_DETAILS,
        )

    @classmethod
    def deny(
        cls,
        reason: str,
        required_level: AccessLevel | None = None,
        details: dict[str, Any] | None = None,
    ) -> "ValidationResult":
        """Create a denied result.

        Args:
            reason: Why the query was blocked.
            required_level: Minimum access level that would allow this query.
            details: Optional details about the validation.

        Returns:
            ValidationResult with allowed=False.
        """
        return cls(
            allowed=False,
            reason=reason,
            access_level_required=required_level,
            details=MappingProxyType(details) if details else _EMPTY_DETAILS,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        result: dict[str, Any] = {"allowed": self.allowed}
        if self.reason:
            result["reason"] = self.reason
        if self.access_level_required:
            result["access_level_required"] = self.access_level_required.value
        if self.details:
            result["details"] = dict(self.details)
        return result
