def test_extract_link_and_kind():
    from aa.radar import extract

    e = extract.extract("Airdrop baru di https://claim.example.xyz/jackpot whitelist mint free")
    assert e["links"][0]["url"].startswith("https://claim.example.xyz")
    assert e["kind"] in ("claim", "whitelist", "airdrop")


def test_extract_no_link():
    from aa.radar import extract

    e = extract.extract("testnet monad lagi rame, pada farming")
    assert e["links"] == []
    assert e["kind"] == "testnet"


def test_score_explained():
    from aa.radar import score

    s = score.score({"project": "Monad", "kind": "testnet", "trust": 3, "links": [{"url": "https://monad.xyz", "type": "web"}],
                     "text": "incentivized testnet with points program", "scam": "ok", "age_days": 400})
    assert 0 <= s["score"] <= 100
    assert s["reasons"]


def test_score_penalises_scam():
    from aa.radar import score

    clean = {"project": "X", "kind": "airdrop", "trust": 1, "text": "", "scam": "ok",
             "links": [{"url": "https://app.uniswap.org", "type": "web"}]}
    dirty = dict(clean, links=[{"url": "https://xn--uniswap-ycd.com", "type": "web"}])
    assert score.score(clean)["score"] > score.score(dirty)["score"]


def test_worth_it_threshold(home):
    from aa.radar import score

    assert score.worth_it({"kind": "airdrop", "trust": 3,
                                                      "links": [{"url": "https://app.uniswap.org", "type": "web"}]})[0]
    assert not score.worth_it({"kind": "unknown"})[0]


def _item(**over):
    it = {"project": "TestProj", "kind": "airdrop", "trust": 3, "source": "test",
          "text": "incentivized testnet with points program",
          "links": [{"url": "https://app.uniswap.org/swap", "type": "quest"}]}
    it.update(over)
    return it


def test_ingest_queues_clean_item(home, monkeypatch):
    from aa import db
    from aa.radar import pipeline
    from aa import scam_check

    monkeypatch.setattr(scam_check, "domain_age", lambda d: 400)
    res = pipeline.ingest([_item()])
    assert res["stored"] == 1
    assert len(res["queued"]) == 1
    assert db.one("SELECT status FROM radar_items WHERE url=?",
                  ("https://app.uniswap.org/swap",))["status"] == "queued"


def test_ingest_rejects_when_any_link_is_bad(home, monkeypatch):
    from aa.radar import pipeline
    from aa import scam_check

    monkeypatch.setattr(scam_check, "domain_age", lambda d: 400)
    it = _item(links=[{"url": "https://app.uniswap.org/swap", "type": "quest"},
                      {"url": "https://xn--uniswap-ycd.com/claim", "type": "web"}])
    res = pipeline.ingest([it])
    assert res["stored"] == 1
    assert res["queued"] == []
    assert res["rejected"] == 1


def test_ingest_auto_queue_false_stores_without_quest(home, monkeypatch):
    from aa import config, db
    from aa.radar import pipeline
    from aa import scam_check

    monkeypatch.setattr(scam_check, "domain_age", lambda d: 400)
    y = config.load_yaml("radar_sources.yaml")
    y["auto_queue"] = False
    config.save_yaml("radar_sources.yaml", y)
    res = pipeline.ingest([_item()])
    assert res["stored"] == 1
    assert res["queued"] == []
    assert db.one("SELECT status FROM radar_items WHERE url=?",
                  ("https://app.uniswap.org/swap",))["status"] == "new"
    assert db.one("SELECT 1 FROM quests WHERE url=?", ("https://app.uniswap.org/swap",)) is None
