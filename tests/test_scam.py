def test_ok_domain(home):
    from aa import scam_check

    v = scam_check.check_url("https://app.uniswap.org/swap")
    assert v["verdict"] in ("ok", "warn")


def test_lookalike(home):
    from aa import scam_check

    v = scam_check.check_url("https://app-uniswap.org")
    assert v["verdict"] in ("warn", "bad")


def test_punycode(home):
    from aa import scam_check

    v = scam_check.check_url("https://xn--uniswap-ycd.com")
    assert v["verdict"] != "ok"


def test_drainer_words(home):
    from aa import scam_check

    v = scam_check.check_page_text("Connect wallet and sign to claim. Approve all to continue.")
    assert v["verdict"] in ("ok", "warn")


def test_bad_host(home):
    from aa import scam_check

    assert scam_check.check_url("http://127.0.0.1:8080")["verdict"] == "warn"


def test_blocklist_domain_from_policy(home):
    from aa import config, scam_check

    y = config.policy()
    y["blocklist"] = ["evil.example.com", "0x" + "ab" * 20]
    config.save_yaml("policy.yaml", y)
    v = scam_check.check_url("https://evil.example.com/claim")
    assert v["verdict"] == "bad"
    assert scam_check.check_url("https://sub.evil.example.com/")["verdict"] == "bad"
    # An address entry in the blocklist must not turn an unrelated domain bad.
    assert scam_check.check_url("https://app.uniswap.org/")["verdict"] == "ok"


def test_login_keyword_is_warn_and_drainer_combo_is_bad(home):
    from aa import scam_check

    assert scam_check.check_url("https://login-example.com")["verdict"] == "warn"
    assert scam_check.check_url("https://verify-wallet-seed.com")["verdict"] == "bad"
    assert scam_check.check_url("https://wallet-seed-approve.xyz")["verdict"] == "bad"


def test_ip_literal_and_http_are_at_least_warn(home):
    from aa import scam_check

    assert scam_check.check_url("https://127.0.0.1/")["verdict"] == "warn"
    assert scam_check.check_url("http://example.com/")["verdict"] == "warn"
