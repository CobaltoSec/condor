"""Compliance framework mapping for OWASP ASI Top 10 categories."""
from __future__ import annotations

_COMPLIANCE_MAP: dict[str, dict[str, list[str]]] = {
    "ASI01": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.9.1", "ISO/IEC 42001:2023 A.9.2"],
        "nist_ai_rmf": ["GOVERN 6.1", "MAP 5.2", "MEASURE 2.6"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 15 – Accuracy & Robustness"],
    },
    "ASI02": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.8.4", "ISO/IEC 42001:2023 A.9.2"],
        "nist_ai_rmf": ["MAP 1.5", "MANAGE 4.1", "MEASURE 2.7"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 15 – Accuracy & Robustness"],
    },
    "ASI03": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.9.3", "ISO/IEC 42001:2023 A.7.2"],
        "nist_ai_rmf": ["GOVERN 1.7", "MAP 1.6", "MANAGE 2.4"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 12 – Record-keeping"],
    },
    "ASI04": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.5.19", "ISO/IEC 42001:2023 A.8.8"],
        "nist_ai_rmf": ["GOVERN 5.1", "MAP 3.5", "MANAGE 3.1"],
        "eu_ai_act":   ["Article 25 – Obligations of AI Deployers", "Article 28 – Third-party Obligations"],
    },
    "ASI05": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.8.28", "ISO/IEC 42001:2023 A.9.4"],
        "nist_ai_rmf": ["MAP 2.1", "MEASURE 2.7", "MANAGE 2.2"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 15 – Accuracy & Robustness"],
    },
    "ASI06": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.8.6", "ISO/IEC 42001:2023 A.9.4"],
        "nist_ai_rmf": ["MAP 5.1", "MANAGE 2.2", "MEASURE 2.5"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 10 – Data Governance"],
    },
    "ASI07": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.8.20", "ISO/IEC 42001:2023 A.9.3"],
        "nist_ai_rmf": ["GOVERN 1.4", "MAP 2.2", "MANAGE 1.3"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 14 – Human Oversight"],
    },
    "ASI08": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.8.6", "ISO/IEC 42001:2023 A.17.1"],
        "nist_ai_rmf": ["MANAGE 3.2", "MEASURE 2.2", "MAP 5.2"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 15 – Accuracy & Robustness"],
    },
    "ASI09": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.7.4", "ISO/IEC 42001:2023 A.7.2"],
        "nist_ai_rmf": ["GOVERN 6.1", "GOVERN 6.2", "MAP 2.3"],
        "eu_ai_act":   ["Article 50 – Transparency Obligations", "Article 13 – Transparency"],
    },
    "ASI10": {
        "iso_42001":   ["ISO/IEC 42001:2023 A.9.1", "ISO/IEC 42001:2023 A.7.4"],
        "nist_ai_rmf": ["GOVERN 1.2", "MANAGE 1.3", "MAP 1.6"],
        "eu_ai_act":   ["Article 9 – Risk Management", "Article 14 – Human Oversight"],
    },
}


def get_compliance_refs(owasp_id: str) -> dict[str, list[str]]:
    """Return compliance framework references for an OWASP ASI category."""
    return _COMPLIANCE_MAP.get(owasp_id, {})
