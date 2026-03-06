"""Edge-case tests for nocturna_engine.exceptions.base_exceptions."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

import pytest

from nocturna_engine.exceptions.base_exceptions import (
    ConfigError,
    ErrorDetails,
    EventBusError,
    NocturnaError,
    NocturnaTimeoutError,
    PipelineError,
    PluginError,
    PluginExecutionError,
    PluginRegistrationError,
    SecretNotFoundError,
    ValidationError,
    build_error_details,
    error_details_from_exception,
)


# ---------------------------------------------------------------------------
# ErrorDetails dataclass
# ---------------------------------------------------------------------------


class TestErrorDetailsEdgeCases:
    """Edge cases for the frozen ErrorDetails dataclass."""

    def test_empty_string_code_preserved(self) -> None:
        """Empty string code is stored literally (no normalization in dataclass)."""
        details = ErrorDetails(code="", category="cat")
        assert details.code == ""

    def test_whitespace_only_code_preserved(self) -> None:
        details = ErrorDetails(code="   ", category="cat")
        assert details.code == "   "

    def test_context_default_is_empty_dict(self) -> None:
        details = ErrorDetails(code="c", category="cat")
        assert details.context == {}

    def test_as_dict_returns_new_dict_each_call(self) -> None:
        details = ErrorDetails(code="c", category="cat", context={"k": "v"})
        d1 = details.as_dict()
        d2 = details.as_dict()
        assert d1 == d2
        assert d1 is not d2
        assert d1["context"] is not d2["context"]

    def test_frozen_rejects_attribute_mutation(self) -> None:
        details = ErrorDetails(code="c", category="cat")
        with pytest.raises(AttributeError):
            details.code = "other"  # type: ignore[misc]

    def test_as_dict_none_remediation_serialized(self) -> None:
        details = ErrorDetails(code="c", category="cat", remediation=None)
        assert details.as_dict()["remediation"] is None

    def test_as_dict_retryable_false_by_default(self) -> None:
        details = ErrorDetails(code="c", category="cat")
        assert details.as_dict()["retryable"] is False


# ---------------------------------------------------------------------------
# build_error_details
# ---------------------------------------------------------------------------


class TestBuildErrorDetails:
    """Edge cases for the build_error_details factory."""

    def test_whitespace_only_code_falls_back_to_runtime_error(self) -> None:
        result = build_error_details(code="   ", category="cat")
        assert result["code"] == "runtime_error"

    def test_empty_code_falls_back_to_runtime_error(self) -> None:
        result = build_error_details(code="", category="cat")
        assert result["code"] == "runtime_error"

    def test_whitespace_only_category_falls_back_to_runtime(self) -> None:
        result = build_error_details(code="c", category="  \t ")
        assert result["category"] == "runtime"

    def test_empty_category_falls_back_to_runtime(self) -> None:
        result = build_error_details(code="c", category="")
        assert result["category"] == "runtime"

    def test_none_context_becomes_empty_dict(self) -> None:
        result = build_error_details(code="c", category="cat", context=None)
        assert result["context"] == {}

    def test_ordered_dict_context_normalised_to_plain_dict(self) -> None:
        ctx: OrderedDict[str, Any] = OrderedDict([("b", 2), ("a", 1)])
        result = build_error_details(code="c", category="cat", context=ctx)
        assert isinstance(result["context"], dict)
        assert result["context"] == {"b": 2, "a": 1}

    def test_numeric_context_key_converted_to_str(self) -> None:
        ctx: dict[Any, Any] = {42: "val"}
        result = build_error_details(code="c", category="cat", context=ctx)  # type: ignore[arg-type]
        assert "42" in result["context"]

    def test_retryable_truthy_int_coerced_to_bool(self) -> None:
        result = build_error_details(code="c", category="cat", retryable=1)  # type: ignore[arg-type]
        assert result["retryable"] is True

    def test_retryable_zero_coerced_to_false(self) -> None:
        result = build_error_details(code="c", category="cat", retryable=0)  # type: ignore[arg-type]
        assert result["retryable"] is False

    def test_code_with_leading_trailing_whitespace_stripped(self) -> None:
        result = build_error_details(code=" my_code ", category="cat")
        assert result["code"] == "my_code"


# ---------------------------------------------------------------------------
# NocturnaError  __init__ edge cases
# ---------------------------------------------------------------------------


class TestNocturnaErrorInit:
    """Edge cases for the base NocturnaError constructor."""

    def test_none_message_uses_code_as_message(self) -> None:
        err = NocturnaError(None)
        assert err.message == "nocturna_error"
        assert str(err) == "nocturna_error"

    def test_empty_message_falls_back_to_code(self) -> None:
        err = NocturnaError("")
        assert err.message == "nocturna_error"

    def test_whitespace_only_message_falls_back_to_code(self) -> None:
        err = NocturnaError("   ")
        assert err.message == "nocturna_error"

    def test_whitespace_only_code_falls_back_to_default(self) -> None:
        err = NocturnaError("msg", code="   ")
        assert err.code == "nocturna_error"

    def test_whitespace_only_category_falls_back_to_default(self) -> None:
        err = NocturnaError("msg", category="  \t\n  ")
        assert err.category == "runtime"

    def test_retryable_none_uses_class_default(self) -> None:
        err = NocturnaError("msg", retryable=None)
        assert err.retryable is False

    def test_retryable_explicit_overrides_default(self) -> None:
        err = NocturnaError("msg", retryable=True)
        assert err.retryable is True

    def test_remediation_none_uses_class_default(self) -> None:
        err = NocturnaError("msg", remediation=None)
        assert err.remediation is None

    def test_remediation_explicit_overrides_none_default(self) -> None:
        err = NocturnaError("msg", remediation="Do X.")
        assert err.remediation == "Do X."

    def test_context_property_returns_copy(self) -> None:
        err = NocturnaError("msg", context={"a": 1})
        ctx1 = err.context
        ctx2 = err.context
        assert ctx1 == ctx2
        assert ctx1 is not ctx2

    def test_to_error_dict_matches_details(self) -> None:
        err = NocturnaError("msg", code="c", category="cat", retryable=True, remediation="R", context={"k": "v"})
        d = err.to_error_dict()
        assert d == {"code": "c", "category": "cat", "retryable": True, "remediation": "R", "context": {"k": "v"}}


# ---------------------------------------------------------------------------
# Subclass hierarchy – defaults propagation
# ---------------------------------------------------------------------------


_SUBCLASS_PARAMS = [
    (ConfigError, "config_error", "configuration", False, "Fix runtime configuration and retry."),
    (ValidationError, "validation_error", "validation", False, "Validate input payload and retry with corrected values."),
    (PluginError, "plugin_error", "plugin", False, None),
    (PluginRegistrationError, "plugin_registration_error", "plugin_registration", False, "Fix plugin metadata/manifest and register again."),
    (PluginExecutionError, "plugin_execution_error", "plugin_execution", False, "Inspect plugin logs, target, and runtime context."),
    (EventBusError, "event_bus_error", "event_bus", True, "Retry event publish/subscribe operation."),
    (PipelineError, "pipeline_error", "pipeline", False, "Inspect pipeline steps and dependency availability."),
    (SecretNotFoundError, "secret_not_found", "secrets", False, "Provide required secret in environment/keyring and retry."),
    (NocturnaTimeoutError, "timeout", "timeout", True, "Increase timeout or reduce workload scope and retry."),
]


class TestSubclassDefaultsPropagation:
    """Verify every subclass propagates the right defaults."""

    @pytest.mark.parametrize(
        ("cls", "expected_code", "expected_category", "expected_retryable", "expected_remediation"),
        _SUBCLASS_PARAMS,
        ids=[c[0].__name__ for c in _SUBCLASS_PARAMS],
    )
    def test_subclass_defaults(
        self,
        cls: type[NocturnaError],
        expected_code: str,
        expected_category: str,
        expected_retryable: bool,
        expected_remediation: str | None,
    ) -> None:
        err = cls("test")
        assert err.code == expected_code
        assert err.category == expected_category
        assert err.retryable is expected_retryable
        assert err.remediation == expected_remediation

    @pytest.mark.parametrize(
        "cls",
        [ConfigError, ValidationError, PluginError, PluginRegistrationError,
         PluginExecutionError, EventBusError, PipelineError, SecretNotFoundError,
         NocturnaTimeoutError],
        ids=lambda c: c.__name__,
    )
    def test_subclass_isinstance_nocturna_error(self, cls: type[NocturnaError]) -> None:
        assert isinstance(cls("test"), NocturnaError)

    def test_plugin_registration_is_plugin_error(self) -> None:
        assert isinstance(PluginRegistrationError("test"), PluginError)

    def test_plugin_execution_is_plugin_error(self) -> None:
        assert isinstance(PluginExecutionError("test"), PluginError)

    def test_subclass_explicit_retryable_overrides_default(self) -> None:
        """EventBusError.default_retryable=True but explicit False overrides."""
        err = EventBusError("msg", retryable=False)
        assert err.retryable is False

    def test_subclass_explicit_remediation_overrides_default(self) -> None:
        err = ConfigError("msg", remediation="Custom fix.")
        assert err.remediation == "Custom fix."

    def test_subclass_explicit_code_overrides_default(self) -> None:
        err = PipelineError("msg", code="custom_code")
        assert err.code == "custom_code"

    def test_subclass_explicit_category_overrides_default(self) -> None:
        err = SecretNotFoundError("msg", category="custom_cat")
        assert err.category == "custom_cat"


# ---------------------------------------------------------------------------
# error_details_from_exception
# ---------------------------------------------------------------------------


class TestErrorDetailsFromException:
    """Edge cases for error_details_from_exception."""

    def test_plain_exception_returns_defaults(self) -> None:
        result = error_details_from_exception(ValueError("boom"))
        assert result["code"] == "runtime_error"
        assert result["category"] == "runtime"
        assert result["retryable"] is False

    def test_nocturna_error_extracts_structured_fields(self) -> None:
        err = ConfigError("msg", context={"host": "localhost"})
        result = error_details_from_exception(err)
        assert result["code"] == "config_error"
        assert result["category"] == "configuration"
        assert result["context"]["host"] == "localhost"

    def test_caller_context_overrides_exception_context(self) -> None:
        """Caller-supplied context keys take precedence over exception context."""
        err = NocturnaError("msg", context={"shared": "from_exc", "exc_only": "yes"})
        result = error_details_from_exception(err, context={"shared": "from_caller"})
        assert result["context"]["shared"] == "from_caller"
        assert result["context"]["exc_only"] == "yes"

    def test_default_code_used_when_exception_code_is_empty(self) -> None:
        """If NocturnaError has code that normalises away, default_code fills."""
        # code="   " -> normalized to default_code "nocturna_error" in constructor
        err = NocturnaError("msg", code="   ")
        result = error_details_from_exception(err, default_code="fallback")
        # The exception itself normalizes to "nocturna_error" already.
        assert result["code"] == "nocturna_error"

    def test_non_base_exception_uses_all_defaults(self) -> None:
        result = error_details_from_exception(
            RuntimeError("x"),
            default_code="dc",
            default_category="dcat",
            default_retryable=True,
            default_remediation="dremediation",
            context={"k": "v"},
        )
        assert result["code"] == "dc"
        assert result["category"] == "dcat"
        assert result["retryable"] is True
        assert result["remediation"] == "dremediation"
        assert result["context"] == {"k": "v"}

    def test_nocturna_error_remediation_not_string_falls_to_default(self) -> None:
        """When exception's remediation is None, default_remediation fills."""
        err = PluginError("msg")  # default_remediation is None
        result = error_details_from_exception(err, default_remediation="fallback_rem")
        assert result["remediation"] == "fallback_rem"

    def test_nocturna_error_retryable_propagated(self) -> None:
        err = EventBusError("msg")  # default_retryable=True
        result = error_details_from_exception(err)
        assert result["retryable"] is True

    def test_none_context_from_both_sides(self) -> None:
        err = NocturnaError("msg")
        result = error_details_from_exception(err, context=None)
        assert result["context"] == {}

    def test_keyboard_interrupt_treated_as_plain_exception(self) -> None:
        """KeyboardInterrupt (BaseException) should not be treated as NocturnaError."""
        result = error_details_from_exception(KeyboardInterrupt())
        assert result["code"] == "runtime_error"
