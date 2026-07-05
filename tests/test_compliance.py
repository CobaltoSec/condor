"""Tests for compliance framework mapping."""
import pytest
from condor.compliance import get_compliance_refs


def test_returns_dict_for_known_id():
    refs = get_compliance_refs("ASI01")
    assert isinstance(refs, dict)
    assert all(k in refs for k in ("iso_42001", "nist_ai_rmf", "eu_ai_act"))


def test_all_10_asi_categories_present():
    for i in range(1, 11):
        asi_id = f"ASI{i:02d}"
        refs = get_compliance_refs(asi_id)
        assert refs, f"{asi_id} has no compliance mapping"
        assert len(refs["iso_42001"]) >= 1
        assert len(refs["nist_ai_rmf"]) >= 1
        assert len(refs["eu_ai_act"]) >= 1


def test_unknown_id_returns_empty():
    refs = get_compliance_refs("ASI99")
    assert refs == {}


def test_empty_string_returns_empty():
    assert get_compliance_refs("") == {}


def test_asi01_iso_contains_expected_reference():
    refs = get_compliance_refs("ASI01")
    iso = " ".join(refs["iso_42001"])
    assert "A.9" in iso


def test_asi09_eu_ai_act_contains_article_50():
    refs = get_compliance_refs("ASI09")
    eu = " ".join(refs["eu_ai_act"])
    assert "50" in eu


def test_all_values_are_nonempty_strings():
    for i in range(1, 11):
        refs = get_compliance_refs(f"ASI{i:02d}")
        for key, vals in refs.items():
            for v in vals:
                assert isinstance(v, str) and v.strip(), f"{key} has empty entry"
