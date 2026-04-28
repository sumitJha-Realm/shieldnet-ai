"""Tests for typo-tolerant phishing keyword detection in URL scoring."""

from utils.url_feature_extractor import find_phishing_keyword_matches, calculate_risk_score


def _base_features(domain: str = "example.com") -> dict:
    return {
        "domain": domain,
        "dnsStatus": "active",
        "hostingFlags": {
            "domainAgeDays": 800,
            "sslValid": True,
            "isSharedHosting": False,
            "isCloudHosted": True,
        },
        "urlStructure": {
            "entropyScore": 2.2,
            "hasSuspiciousTld": False,
            "hasIpAddress": False,
        },
        "payloadTypes": [],
    }


def test_find_phishing_keyword_matches_detects_distance_2():
    text = "https://example.com/logln/verlfy-account"
    matches = find_phishing_keyword_matches(
        text=text,
        keywords={"login", "verify", "account"},
        max_edit_distance=2,
        long_keyword_edit_distance=3,
    )

    assert "account" in matches["exact"]
    fuzzy_by_kw = {m["keyword"]: m for m in matches["fuzzy"]}
    assert fuzzy_by_kw["login"]["distance"] == 1
    assert fuzzy_by_kw["verify"]["distance"] == 1


def test_find_phishing_keyword_matches_allows_distance_3_for_long_terms():
    text = "https://example.com/credentxxx/session"
    matches = find_phishing_keyword_matches(
        text=text,
        keywords={"credential"},
        max_edit_distance=2,
        long_keyword_edit_distance=3,
        long_keyword_min_len=9,
    )

    assert matches["exact"] == []
    assert len(matches["fuzzy"]) == 1
    assert matches["fuzzy"][0]["keyword"] == "credential"
    assert matches["fuzzy"][0]["distance"] == 3


def test_calculate_risk_score_adds_keyword_bonus_for_fuzzy_hits():
    features = _base_features()
    risk, breakdown = calculate_risk_score(
        features=features,
        max_similarity=0.0,
        url="https://example.com/logln/verlfy",
        phishing_keywords=["login", "verify"],
    )

    keyword_factor = next((f for f in breakdown if f["key"] == "keywordBonus"), None)
    assert keyword_factor is not None
    assert keyword_factor["contribution"] > 0
    assert keyword_factor["exactMatches"] == []
    assert len(keyword_factor["fuzzyMatches"]) >= 1
    assert risk > 0
