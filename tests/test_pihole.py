"""Pi-hole as a DNS source. A fake API, never a real resolver."""
import pytest
import requests
from floorbit.plugins.base import PluginError

T0 = 1_794_650_400


class Answer:
    def __init__(self, body, status=200):
        self.status_code = status
        self._body = body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError("not JSON")
        return self._body


def iso(ts):
    from datetime import UTC, datetime
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


PIHOLE = [{"id": i, "time": T0 + 1500 - i + 0.5, "type": "A", "domain": "gateway.discord.gg",
           "client": {"ip": f"198.51.100.{i % 40 + 1}", "name": None},
           "status": "GRAVITY" if i % 4 == 0 else "FORWARDED"}
          for i in range(1500)]


@pytest.fixture
def pihole(monkeypatch):
    calls = []

    def fake(self, method, url, **kw):
        path = url.removeprefix("https://pihole.example.com")
        calls.append((method, path, kw.get("params"), self.headers.get("X-FTL-SID")))
        if method == "POST" and path == "/api/auth":
            ok = kw["json"]["password"] == "example-app-password"
            return Answer({"session": {"valid": ok, "sid": "example-sid" if ok else None}}, 200 if ok else 401)
        if self.headers.get("X-FTL-SID") != "example-sid":
            return Answer({"error": {"key": "unauthorized"}}, 401)
        if method == "DELETE":
            return Answer({}, 204)
        p = kw["params"]
        if p.get("from") is None:
            return Answer({"queries": PIHOLE[:1], "recordsTotal": len(PIHOLE)})
        rows = [r for r in PIHOLE if p["from"] <= r["time"] < p["until"]]
        return Answer({"queries": rows[p["start"]:p["start"] + p["length"]], "recordsTotal": len(PIHOLE)})

    monkeypatch.setattr(requests.Session, "request", fake)
    return calls


SETTINGS = {"url": "https://pihole.example.com", "password": "example-app-password"}


def test_pihole_signs_in_reads_pages_and_signs_out(make, pihole, monkeypatch):
    import time
    monkeypatch.setattr(time, "time", lambda: T0 + 2000)
    got = make(**SETTINGS).dns_queries(T0 + 100)
    assert len(got) == 1401 and all(e["ts"] > T0 + 100 for e in got)
    assert got[0] == {"ts": T0 + 1500.5, "domain": "gateway.discord.gg", "client": "198.51.100.1", "blocked": True}
    methods = [(m, p) for m, p, _params, _sid in pihole]
    assert methods == [("POST", "/api/auth"), ("GET", "/api/queries"), ("GET", "/api/queries"), ("DELETE", "/api/auth")]
    assert pihole[2][2]["start"] == 1000


def test_pihole_explains_a_wrong_password(make, pihole):
    with pytest.raises(PluginError, match=r"^Pi-hole refused the password\.$"):
        make(**{**SETTINGS, "password": "wrong"}).test()
    assert "1500 lookups kept" in make(**SETTINGS).test()
