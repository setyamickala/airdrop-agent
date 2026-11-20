"""K3: `eval` is gone and `api` steps are allowlisted (https, GET/POST only,
same host as the quest url, domain_allowlist, or api_allowlist; private hosts
never allowed)."""
import pytest

from aa.jsonio import Denied


def _quest_with_step(home, step):
    from aa.quest import dsl

    q = dsl.scaffold("T", "https://example.com/quest", "generic")
    q["steps"].append(step)
    return q


def test_validate_rejects_eval(home):
    from aa.quest import dsl

    q = _quest_with_step(home, {"eval": "document.title"})
    errs = dsl.validate(q)
    assert any("eval" in e and "removed" in e for e in errs)


def test_validate_rejects_api_localhost(home):
    from aa.quest import dsl

    for url in ("https://localhost/admin", "https://127.0.0.1/x",
                "https://169.254.169.254/latest/meta-data/"):
        q = _quest_with_step(home, {"api": {"method": "GET", "url": url}})
        assert dsl.validate(q), url


def test_validate_rejects_api_http_and_put(home):
    from aa.quest import dsl

    q = _quest_with_step(home, {"api": {"method": "GET", "url": "http://example.com/x"}})
    assert any("https" in e for e in dsl.validate(q))
    q = _quest_with_step(home, {"api": {"method": "PUT", "url": "https://example.com/x"}})
    assert any("PUT" in e for e in dsl.validate(q))
    q = _quest_with_step(home, {"api": {"url": "https://evil.example/x"}})
    assert dsl.validate(q)


def test_validate_accepts_api_same_host(home):
    from aa.quest import dsl

    q = _quest_with_step(home, {"api": {"method": "GET", "url": "https://example.com/api/points"}})
    assert dsl.validate(q) == []
    q = _quest_with_step(home, {"api": {"url": "https://example.com/api/points"}})
    assert dsl.validate(q) == []


def test_validate_accepts_api_allowlisted_domain(home):
    from aa.quest import dsl

    # galxe.com is on domain_allowlist in the shipped policy.yaml.
    q = _quest_with_step(home, {"api": {"url": "https://app.galxe.com/api/points"}})
    assert dsl.validate(q) == []


def test_runner_rejects_eval_and_unallowed_api(home):
    import asyncio

    from aa.quest import runner

    q = _quest_with_step(home, {"eval": "1+1"})
    with pytest.raises(Denied):
        asyncio.run(runner._do_step(None, "eval", "1+1", "id", q, []))
    q = _quest_with_step(home, {"api": {"url": "https://localhost/x"}})
    with pytest.raises(Denied):
        asyncio.run(runner._do_step(None, "api", {"url": "https://localhost/x"}, "id", q, []))


def test_api_needs_gate_detects_credentials():
    from aa.quest.runner import _api_needs_gate

    assert _api_needs_gate({"url": "https://example.com/x",
                            "headers": {"Authorization": "Bearer abc"}})
    assert _api_needs_gate({"url": "https://example.com/x",
                            "headers": {"X-Api-Key": "abc"}})
    assert _api_needs_gate({"url": "https://example.com/x", "json": {"token": "abc"}})
    assert _api_needs_gate({"url": "https://example.com/x",
                            "json": {"user": {"password": "abc"}}})
    assert not _api_needs_gate({"url": "https://example.com/x"})
    assert not _api_needs_gate({"url": "https://example.com/x", "json": {"points": 3}})
