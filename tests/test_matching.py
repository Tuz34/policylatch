from policylatch.matching import domain_matches, text_matches


def test_plain_text_patterns_use_substring_matching():
    assert text_matches("Remove-Item -Recurse", "remove") is True
    assert text_matches("Remove-Item -Recurse", "rm") is False


def test_domain_patterns_use_complete_hostname_globs():
    assert domain_matches("github.com", "github.com") is True
    assert domain_matches("api.github.com", "*.github.com") is True
    assert domain_matches("github.com", "*.github.com") is False
    assert domain_matches("github.com", "github*") is True
    assert domain_matches("github.io", "github*") is True
