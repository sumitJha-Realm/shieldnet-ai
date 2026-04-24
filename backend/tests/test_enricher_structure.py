"""Unit tests for enricher.structure — local URL analysis (no network)."""

import pytest
from enricher.structure import analyze_structure, detect_brand_impersonation, _shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # All unique chars → high entropy
        e = _shannon_entropy("abcdefghijklmnop")
        assert e > 3.5

    def test_moderate_entropy(self):
        e = _shannon_entropy("https://gov.in/login")
        assert 2.5 < e < 5.0


class TestAnalyzeStructure:
    def test_basic_url(self):
        r = analyze_structure("https://example.com/path?q=1")
        assert r.scheme == "https"
        assert r.domain == "example.com"
        assert r.path == "/path"
        assert r.url_length > 0
        assert r.entropy > 0

    def test_subdomain_depth(self):
        r = analyze_structure("http://a.b.c.evil.com/x")
        assert r.subdomain == "a.b.c"
        assert r.subdomain_depth == 3

    def test_gov_in_cctld(self):
        r = analyze_structure("https://incometax.gov.in/portal")
        assert r.domain == "incometax.gov.in"
        assert r.subdomain == ""
        assert r.subdomain_depth == 0

    def test_subdomain_on_gov_in(self):
        r = analyze_structure("https://sub.incometax.gov.in/portal")
        assert r.domain == "incometax.gov.in"
        assert r.subdomain == "sub"
        assert r.subdomain_depth == 1

    def test_ip_address_domain(self):
        r = analyze_structure("http://192.168.1.1/admin")
        assert r.is_ip_address is True

    def test_not_ip(self):
        r = analyze_structure("https://google.com/")
        assert r.is_ip_address is False

    def test_suspicious_keywords(self):
        r = analyze_structure("https://evil.com/login/verify?password=x")
        assert "login" in r.suspicious_keywords
        assert "verify" in r.suspicious_keywords
        assert "password" in r.suspicious_keywords

    def test_no_keywords(self):
        r = analyze_structure("https://gov.in/about")
        assert r.suspicious_keywords == []

    def test_url_encoding_detected(self):
        r = analyze_structure("https://evil.com/path%20encoded?a=%3Cscript%3E")
        assert r.has_url_encoding is True

    def test_no_url_encoding(self):
        r = analyze_structure("https://clean.com/path")
        assert r.has_url_encoding is False

    def test_special_chars(self):
        r = analyze_structure("https://evil.com/pa%th@with!special~")
        assert r.special_char_count >= 4

    def test_excessive_hyphens(self):
        r = analyze_structure("https://google-secure-login-verify.tk/x")
        assert r.excessive_hyphens is True
        assert r.hyphen_count >= 3

    def test_no_excessive_hyphens(self):
        r = analyze_structure("https://my-site.com/")
        assert r.excessive_hyphens is False

    def test_query_params_parsed(self):
        r = analyze_structure("https://x.com/p?a=1&b=2&b=3")
        assert "a" in r.query_params
        assert r.query_params["b"] == ["2", "3"]

    def test_fragment(self):
        r = analyze_structure("https://x.com/page#section")
        assert r.fragment == "section"


class TestBrandImpersonation:
    def test_exact_match(self):
        r = detect_brand_impersonation("gov.in")
        assert r.is_exact_match is True
        assert r.edit_distance == 0
        assert r.closest_brand == "Government of India Portal"

    def test_close_impersonation(self):
        r = detect_brand_impersonation("g0v.in")
        assert r.is_exact_match is False
        assert r.edit_distance <= 2
        assert r.known_domain == "gov.in"

    def test_rbi_typo(self):
        r = detect_brand_impersonation("rbl.org.in")
        assert r.is_exact_match is False
        assert r.edit_distance <= 2
        assert r.known_domain == "rbi.org.in"

    def test_irctc_exact(self):
        r = detect_brand_impersonation("irctc.co.in")
        assert r.is_exact_match is True
        assert r.closest_brand == "Indian Railway Catering & Tourism"

    def test_distant_domain(self):
        r = detect_brand_impersonation("totallyunrelated.xyz")
        assert r.is_exact_match is False
        assert r.edit_distance > 5
