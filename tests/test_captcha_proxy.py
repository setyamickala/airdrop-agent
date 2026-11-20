"""Proxied captcha solver tasks (round 4, priority 3c). HTTP is mocked."""
import json

import pytest

from aa.browser import captcha


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def test_proxy_parts():
    assert captcha._proxy_parts("") is None
    assert captcha._proxy_parts("http://user:pw@proxy.example:8080") == {
        "scheme": "http", "host": "proxy.example", "port": 8080,
        "username": "user", "password": "pw"}
    assert captcha._proxy_parts("proxy.example:3128")["scheme"] == "http"
    assert captcha._proxy_parts("not-a-proxy") is None


def test_anticaptcha_task_uses_proxy(monkeypatch):
    seen = {}

    def _post(url, **kw):
        seen.update(kw.get("json") or {})
        if "createTask" in url:
            return _Resp({"errorId": 0, "taskId": 7})
        return _Resp({"errorId": 0, "status": "ready",
                      "solution": {"gRecaptchaResponse": "tok-123"}})

    monkeypatch.setattr(captcha.requests, "post", _post)
    out = captcha.solve_token("anticaptcha", "key", "turnstile", "sitekey",
                              "https://example.com", proxy="http://u:p@proxy.example:8080")
    assert out == "tok-123"
    task = seen["task"]
    assert task["type"] == "TurnstileTask"  # not Proxyless
    assert task["proxyAddress"] == "proxy.example"
    assert task["proxyPort"] == 8080
    assert task["proxyLogin"] == "u"


def test_anticaptcha_task_stays_proxyless_without_proxy(monkeypatch):
    seen = {}

    def _post(url, **kw):
        seen.update(kw.get("json") or {})
        if "createTask" in url:
            return _Resp({"errorId": 0, "taskId": 7})
        return _Resp({"errorId": 0, "status": "ready", "solution": {"token": "tok-9"}})

    monkeypatch.setattr(captcha.requests, "post", _post)
    assert captcha.solve_token("anticaptcha", "key", "turnstile", "sitekey",
                               "https://example.com") == "tok-9"
    assert seen["task"]["type"] == "TurnstileTaskProxyless"
    assert "proxyAddress" not in seen["task"]


def test_2captcha_posts_proxy(monkeypatch):
    seen = {}

    def _post(url, **kw):
        seen.update(kw.get("data") or {})
        return _Resp({"status": 1, "request": "cid-1"})

    def _get(url, **kw):
        return _Resp({"status": 1, "request": "tok-2"})

    monkeypatch.setattr(captcha.requests, "post", _post)
    monkeypatch.setattr(captcha.requests, "get", _get)
    monkeypatch.setattr(captcha.time, "sleep", lambda s: None)
    out = captcha.solve_token("2captcha", "key", "turnstile", "sitekey",
                              "https://example.com", proxy="proxy.example:3128")
    assert out == "tok-2"
    assert seen["proxy"] == "proxy.example:3128"
    assert seen["proxytype"] == "HTTP"
