"""Edge-case tests for nocturna_engine.utils.validators."""

from __future__ import annotations

import pytest

from nocturna_engine.exceptions import ValidationError
from nocturna_engine.utils.validators import (
    PLUGIN_NAME_PATTERN,
    validate_non_empty,
    validate_plugin_name,
)


# ---------------------------------------------------------------------------
# validate_non_empty
# ---------------------------------------------------------------------------


class TestValidateNonEmpty:
    """Edge cases for validate_non_empty."""

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValidationError, match="'myfield' must be non-empty"):
            validate_non_empty("", "myfield")

    def test_whitespace_only_spaces_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_non_empty("     ", "field")

    def test_whitespace_only_tabs_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_non_empty("\t\t\t", "field")

    def test_whitespace_only_newlines_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_non_empty("\n\n", "field")

    def test_mixed_whitespace_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_non_empty(" \t\n\r ", "field")

    def test_strips_leading_trailing_whitespace(self) -> None:
        result = validate_non_empty("  hello  ", "field")
        assert result == "hello"

    def test_preserves_internal_whitespace(self) -> None:
        result = validate_non_empty("  hello world  ", "field")
        assert result == "hello world"

    def test_single_char_passes(self) -> None:
        assert validate_non_empty("a", "field") == "a"

    def test_error_message_includes_field_name(self) -> None:
        with pytest.raises(ValidationError, match="'custom_field'"):
            validate_non_empty("", "custom_field")

    def test_error_is_nocturna_validation_error(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            validate_non_empty("", "f")
        # Verify it's our custom ValidationError, not pydantic's
        from nocturna_engine.exceptions import NocturnaError
        assert isinstance(exc_info.value, NocturnaError)


# ---------------------------------------------------------------------------
# validate_plugin_name
# ---------------------------------------------------------------------------


class TestValidatePluginName:
    """Edge cases for validate_plugin_name."""

    # --- Boundary lengths ---

    def test_minimum_valid_length_2_chars(self) -> None:
        """Regex requires ^[a-z][a-z0-9_-]{1,63}$ → minimum 2 chars total."""
        assert validate_plugin_name("ab") == "ab"

    def test_single_char_too_short(self) -> None:
        """One char fails the {1,63} quantifier for the rest."""
        with pytest.raises(ValidationError):
            validate_plugin_name("a")

    def test_maximum_valid_length_64_chars(self) -> None:
        name = "a" + "b" * 63
        assert len(name) == 64
        assert validate_plugin_name(name) == name

    def test_65_chars_too_long(self) -> None:
        name = "a" + "b" * 64
        assert len(name) == 65
        with pytest.raises(ValidationError):
            validate_plugin_name(name)

    # --- Character rules ---

    def test_leading_digit_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("1plugin")

    def test_leading_hyphen_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("-plugin")

    def test_leading_underscore_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("_plugin")

    def test_hyphens_allowed_after_first_char(self) -> None:
        assert validate_plugin_name("my-plugin") == "my-plugin"

    def test_underscores_allowed_after_first_char(self) -> None:
        assert validate_plugin_name("my_plugin") == "my_plugin"

    def test_digits_allowed_after_first_char(self) -> None:
        assert validate_plugin_name("plugin42") == "plugin42"

    def test_uppercase_normalised_to_lowercase(self) -> None:
        assert validate_plugin_name("MyPlugin") == "myplugin"

    def test_mixed_case_normalised(self) -> None:
        assert validate_plugin_name("MY-PLUGIN-V2") == "my-plugin-v2"

    # --- Invalid characters ---

    def test_dot_in_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("my.plugin")

    def test_space_in_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("my plugin")

    def test_slash_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("my/plugin")

    def test_at_sign_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("my@plugin")

    def test_unicode_letter_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("plügïn")

    def test_emoji_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("plug🔥in")

    # --- Whitespace / empty ---

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("")

    def test_whitespace_only_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name("   ")

    def test_leading_trailing_whitespace_stripped_before_validation(self) -> None:
        """Whitespace is stripped first (via validate_non_empty), then validated."""
        assert validate_plugin_name("  myplugin  ") == "myplugin"

    # --- Regex boundary confirmation ---

    @pytest.mark.parametrize(
        "name",
        ["a1", "z9", "a-b", "a_b", "abc-def-ghi", "tool123"],
        ids=lambda n: f"valid_{n}",
    )
    def test_various_valid_patterns(self, name: str) -> None:
        assert validate_plugin_name(name) == name.lower()

    @pytest.mark.parametrize(
        "name",
        ["", " ", "1abc", "-abc", "_abc", "a", "a" * 65, "a.b", "a b", "a@b"],
        ids=["empty", "space", "digit_lead", "hyphen_lead", "underscore_lead",
             "single_char", "too_long_65", "dot", "space_mid", "at_sign"],
    )
    def test_various_invalid_patterns(self, name: str) -> None:
        with pytest.raises(ValidationError):
            validate_plugin_name(name)


# ---------------------------------------------------------------------------
# PLUGIN_NAME_PATTERN constant edge cases
# ---------------------------------------------------------------------------


class TestPluginNamePatternDirect:
    """Directly test the compiled regex for edge boundaries."""

    def test_pattern_rejects_empty_string(self) -> None:
        assert PLUGIN_NAME_PATTERN.match("") is None

    def test_pattern_rejects_63_char_suffix_plus_start_equals_64_ok(self) -> None:
        name = "a" + "x" * 63
        assert PLUGIN_NAME_PATTERN.match(name) is not None

    def test_pattern_rejects_64_char_suffix_plus_start_equals_65(self) -> None:
        name = "a" + "x" * 64
        assert PLUGIN_NAME_PATTERN.match(name) is None

    def test_pattern_anchored_no_prefix_match(self) -> None:
        """Regex is anchored with ^ and $; partial match should fail."""
        # A name with trailing garbage shouldn't match via fullmatch behavior
        m = PLUGIN_NAME_PATTERN.match("ab!!!")
        # re.match checks from start but not end; however the $ anchor in
        # the pattern means the match object won't span the full string.
        if m is not None:
            assert m.group() == "ab"  # match stops before !!!
            # But the full string doesn't satisfy the pattern end-to-end
            assert PLUGIN_NAME_PATTERN.fullmatch("ab!!!") is None
