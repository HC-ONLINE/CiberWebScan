"""
Unit tests for extract_forms.

Covers form action resolution (absolute/relative/root/missing + base_url),
field metadata (labels, required, readonly, disabled), hidden-field and
CSRF-token detection (via the shared core.attacks.csrf.CSRF_TOKEN_NAMES
source), select options, buttons, and malformed/empty HTML.
"""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup

from ciberwebscan.core.attacks.csrf import CSRF_TOKEN_NAMES
from ciberwebscan.core.scraping.extractor import extract_forms
from ciberwebscan.export.models import FormInfo

pytestmark = pytest.mark.unit


def _soup(html: str) -> BeautifulSoup:
    """Build a BeautifulSoup object from a controlled HTML fragment."""
    return BeautifulSoup(html, "html.parser")


def _field(form: dict, name: str) -> dict:
    """Return the field dict with the given name from a form."""
    for f in form["fields"]:
        if f["name"] == name:
            return f
    raise AssertionError(f"field {name!r} not found in form")


class TestActionResolution:
    """Tests for form action URL resolution."""

    def test_absolute_action_preserved(self):
        """Absolute actions are left untouched."""
        soup = _soup('<form action="https://other.com/submit" method="post"></form>')
        result = extract_forms(soup, base_url="https://example.com")
        assert result[0]["action"] == "https://other.com/submit"

    def test_root_relative_action(self):
        """Root-relative actions resolve against the base domain."""
        soup = _soup('<form action="/login"></form>')
        result = extract_forms(soup, base_url="https://example.com/dir/page")
        assert result[0]["action"] == "https://example.com/login"

    def test_relative_action_with_base_url(self):
        """Relative actions resolve against the base URL directory."""
        soup = _soup('<form action="submit.php"></form>')
        result = extract_forms(soup, base_url="https://example.com/dir/page")
        assert result[0]["action"] == "https://example.com/dir/submit.php"

    def test_missing_action_without_base_url(self):
        """A missing action stays an empty string when no base_url is given."""
        soup = _soup("<form method='get'></form>")
        result = extract_forms(soup)
        assert result[0]["action"] == ""

    def test_missing_action_with_base_url_resolves_to_base(self):
        """With a base_url, a missing action resolves to the page URL (HTML spec)."""
        soup = _soup("<form></form>")
        result = extract_forms(soup, base_url="https://example.com/dir/page")
        assert result[0]["action"] == "https://example.com/dir/page"

    def test_no_base_url_keeps_raw_action(self):
        """Without base_url the current raw semantics are preserved."""
        soup = _soup('<form action="/rel/path"></form>')
        result = extract_forms(soup)
        assert result[0]["action"] == "/rel/path"

    def test_base_url_does_not_alter_absolute_scheme_relative(self):
        """Protocol-relative actions resolve using the base scheme."""
        soup = _soup('<form action="//cdn.example.com/x"></form>')
        result = extract_forms(soup, base_url="https://example.com/dir/page")
        assert result[0]["action"] == "https://cdn.example.com/x"


class TestFormMetadata:
    """Tests for method, enctype, id and name extraction."""

    def test_method_defaults_to_get_and_uppercased(self):
        soup = _soup("<form></form>")
        assert extract_forms(soup)[0]["method"] == "GET"

    def test_method_preserves_and_uppercases(self):
        soup = _soup('<form method="post"></form>')
        assert extract_forms(soup)[0]["method"] == "POST"

    def test_enctype_id_name_extracted(self):
        soup = _soup('<form id="f1" name="login" enctype="multipart/form-data"></form>')
        form = extract_forms(soup)[0]
        assert form["enctype"] == "multipart/form-data"
        assert form["id"] == "f1"
        assert form["name"] == "login"

    def test_multiple_forms(self):
        soup = _soup('<form action="/a"></form><form action="/b"></form>')
        result = extract_forms(soup)
        assert len(result) == 2
        assert result[0]["action"] == "/a"
        assert result[1]["action"] == "/b"


class TestFieldTypes:
    """Tests for input, textarea, select and button extraction."""

    def test_input_type_defaults_to_text(self):
        soup = _soup('<form><input name="q"></form>')
        assert _field(extract_forms(soup)[0], "q")["type"] == "text"

    def test_input_explicit_type(self):
        soup = _soup('<form><input type="email" name="e"></form>')
        assert _field(extract_forms(soup)[0], "e")["type"] == "email"

    def test_input_type_case_preserved(self):
        """The raw type value keeps its original case (observable data)."""
        soup = _soup('<form><input type="TEXT" name="q"></form>')
        assert _field(extract_forms(soup)[0], "q")["type"] == "TEXT"

    def test_tag_reflects_element(self):
        soup = _soup(
            '<form><input name="i"><textarea name="t"></textarea>'
            '<select name="s"></select></form>'
        )
        form = extract_forms(soup)[0]
        assert _field(form, "i")["tag"] == "input"
        assert _field(form, "t")["tag"] == "textarea"
        assert _field(form, "s")["tag"] == "select"

    def test_button_without_name_skipped(self):
        soup = _soup('<form><input name="q"><button type="submit">Go</button></form>')
        form = extract_forms(soup)
        assert len(form[0]["fields"]) == 1

    def test_button_with_name_included(self):
        soup = _soup('<form><button name="action" value="save">Save</button></form>')
        field = _field(extract_forms(soup)[0], "action")
        assert field["tag"] == "button"
        assert field["value"] == "save"

    def test_placeholder_and_id_extracted(self):
        soup = _soup('<form><input name="q" id="qid" placeholder="Search"></form>')
        field = _field(extract_forms(soup)[0], "q")
        assert field["id"] == "qid"
        assert field["placeholder"] == "Search"

    def test_value_extracted(self):
        soup = _soup('<form><input type="hidden" name="t" value="abc"></form>')
        assert _field(extract_forms(soup)[0], "t")["value"] == "abc"


class TestLabelsAndValidation:
    """Tests for label association and validation attributes."""

    def test_label_by_for_attribute(self):
        soup = _soup(
            '<form><label for="u">Username</label><input id="u" name="u"></form>'
        )
        assert _field(extract_forms(soup)[0], "u")["label"] == "Username"

    def test_label_wrapping_field(self):
        soup = _soup("<form><label>Email <input name='e'></label></form>")
        assert _field(extract_forms(soup)[0], "e")["label"] == "Email"

    def test_no_label_is_empty_string(self):
        soup = _soup('<form><input name="q"></form>')
        assert _field(extract_forms(soup)[0], "q")["label"] == ""

    def test_required_flag(self):
        soup = _soup('<form><input name="q" required></form>')
        assert _field(extract_forms(soup)[0], "q")["required"] is True

    def test_not_required_by_default(self):
        soup = _soup('<form><input name="q"></form>')
        assert _field(extract_forms(soup)[0], "q")["required"] is False

    def test_readonly_flag(self):
        soup = _soup('<form><input name="q" readonly></form>')
        assert _field(extract_forms(soup)[0], "q")["readonly"] is True

    def test_disabled_flag(self):
        soup = _soup('<form><input name="q" disabled></form>')
        assert _field(extract_forms(soup)[0], "q")["disabled"] is True

    def test_pattern_maxlength_minlength(self):
        soup = _soup(
            '<form><input name="q" pattern="[A-Z]+" maxlength="10" minlength="2">'
            "</form>"
        )
        field = _field(extract_forms(soup)[0], "q")
        assert field["pattern"] == "[A-Z]+"
        assert field["maxlength"] == "10"
        assert field["minlength"] == "2"


class TestHiddenAndCsrf:
    """Tests for hidden-field and CSRF-token detection."""

    def test_hidden_input_detected(self):
        soup = _soup('<form><input type="hidden" name="h" value="x"></form>')
        field = _field(extract_forms(soup)[0], "h")
        assert field["is_hidden"] is True
        assert field["is_csrf_token"] is False

    def test_hidden_detection_case_insensitive(self):
        """type='HIDDEN' (uppercase) is still recognized as hidden."""
        soup = _soup('<form><input type="HIDDEN" name="h"></form>')
        assert _field(extract_forms(soup)[0], "h")["is_hidden"] is True

    def test_visible_input_not_hidden(self):
        soup = _soup('<form><input type="text" name="q"></form>')
        field = _field(extract_forms(soup)[0], "q")
        assert field["is_hidden"] is False
        assert field["is_csrf_token"] is False

    @pytest.mark.parametrize("token_name", sorted(CSRF_TOKEN_NAMES))
    def test_known_csrf_names_detected(self, token_name):
        """Every name in the shared CSRF source is recognized when hidden."""
        soup = _soup(f'<form><input type="hidden" name="{token_name}"></form>')
        field = _field(extract_forms(soup)[0], token_name)
        assert field["is_csrf_token"] is True

    def test_csrf_detection_case_insensitive_name(self):
        """Field-name matching is case-insensitive."""
        soup = _soup('<form><input type="hidden" name="CSRFToken"></form>')
        assert _field(extract_forms(soup)[0], "CSRFToken")["is_csrf_token"] is True

    def test_csrf_requires_hidden_type(self):
        """A CSRF-named field that is NOT hidden is not flagged as a token."""
        soup = _soup('<form><input type="text" name="csrf_token"></form>')
        field = _field(extract_forms(soup)[0], "csrf_token")
        assert field["is_csrf_token"] is False
        assert field["is_hidden"] is False

    def test_hidden_non_csrf_not_flagged(self):
        """A hidden field with an unrelated name is hidden but not CSRF."""
        soup = _soup('<form><input type="hidden" name="return_to" value="/"></form>')
        field = _field(extract_forms(soup)[0], "return_to")
        assert field["is_hidden"] is True
        assert field["is_csrf_token"] is False

    def test_single_shared_csrf_source(self):
        """The detection uses the shared CSRF_TOKEN_NAMES set (no duplicate list)."""
        assert "csrfmiddlewaretoken" in CSRF_TOKEN_NAMES
        assert "csrf_token" in CSRF_TOKEN_NAMES
        assert "xsrf" in CSRF_TOKEN_NAMES


class TestSelectOptions:
    """Tests for select option extraction."""

    def test_options_with_value(self):
        soup = _soup(
            '<form><select name="c"><option value="1">One</option></select></form>'
        )
        assert _field(extract_forms(soup)[0], "c")["options"] == ["1"]

    def test_option_without_value_uses_text(self):
        soup = _soup('<form><select name="c"><option>Two</option></select></form>')
        assert _field(extract_forms(soup)[0], "c")["options"] == ["Two"]

    def test_multiple_options_order_preserved(self):
        soup = _soup(
            '<form><select name="c"><option value="a">A</option>'
            '<option value="b">B</option></select></form>'
        )
        assert _field(extract_forms(soup)[0], "c")["options"] == ["a", "b"]

    def test_empty_select_yields_empty_options_list(self):
        """An empty select yields an empty options list."""
        soup = _soup('<form><select name="c"></select></form>')
        assert _field(extract_forms(soup)[0], "c")["options"] == []

    def test_non_select_fields_have_no_options(self):
        """Only select elements carry an 'options' key."""
        soup = _soup('<form><input name="q"></form>')
        assert "options" not in _field(extract_forms(soup)[0], "q")


class TestEdgeCases:
    """Tests for empty, malformed or attribute-less HTML."""

    def test_empty_html_returns_no_forms(self):
        assert extract_forms(_soup("")) == []

    def test_html_without_forms(self):
        assert extract_forms(_soup("<div><p>No forms here</p></div>")) == []

    def test_form_without_fields(self):
        """A form with no inputs yields an empty fields list."""
        result = extract_forms(_soup('<form action="/x"></form>'))
        assert result[0]["fields"] == []

    def test_custom_selector(self):
        soup = _soup('<form action="/a"></form><form class="extra" action="/b"></form>')
        result = extract_forms(soup, selector="form.extra")
        assert len(result) == 1
        assert result[0]["action"] == "/b"

    def test_nested_form_elements_ignored_by_selector(self):
        """Only elements matching the form selector are extracted as forms."""
        soup = _soup("<div><form action='/x'></form></div>")
        assert len(extract_forms(soup, selector="form")) == 1

    def test_attributes_absent_defaults(self):
        """Missing attributes fall back to documented defaults."""
        soup = _soup("<form></form>")
        form = extract_forms(soup)[0]
        assert form["method"] == "GET"
        assert form["enctype"] == ""
        assert form["id"] == ""
        assert form["name"] == ""
        assert form["fields"] == []


class TestModelCompatibility:
    """Tests that extracted forms fit the existing FormInfo export model."""

    def test_form_populates_forminfo(self):
        """A rich form maps cleanly onto FormInfo without errors."""
        soup = _soup(
            '<form action="/login" method="post" id="f" name="n" '
            'enctype="application/x-www-form-urlencoded">'
            '<label for="u">User</label>'
            '<input id="u" name="u" required>'
            '<input type="hidden" name="csrfmiddlewaretoken" value="tok">'
            '<select name="c"><option value="1">One</option></select>'
            "</form>"
        )
        form = extract_forms(soup)[0]
        info = FormInfo(
            action=form["action"],
            method=form["method"],
            enctype=form["enctype"],
            id=form["id"],
            name=form["name"],
            fields=form["fields"],
        )
        assert info.action == "/login"
        assert info.method == "POST"
        assert len(info.fields) == 3
        csrf_field = _field(info.model_dump(), "csrfmiddlewaretoken")
        assert csrf_field["is_csrf_token"] is True

    def test_fields_are_json_serializable(self):
        """Field dicts (including new metadata) serialize to JSON."""
        import json

        soup = _soup(
            '<form><input type="hidden" name="csrf_token" value="v">'
            '<select name="c"><option value="1">One</option></select></form>'
        )
        form = extract_forms(soup)[0]
        payload = json.dumps(form)
        assert "is_csrf_token" in payload
        assert "is_hidden" in payload

    def test_empty_form_list_compatible(self):
        """An empty forms list is accepted by the export model."""
        info = FormInfo(action="", method="GET", fields=[])
        assert info.fields == []
