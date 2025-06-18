import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ioc_collector.collectors.collector_abuse import collect_abuse
from ioc_collector.collectors.collector_otx import collect_otx
from ioc_collector.collectors.collector_urlhaus import collect_urlhaus
from ioc_collector.utils.utils import load_config


class MockResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


def test_collect_abuse_mock(monkeypatch):
    os.environ["ABUSE_MOCK_FILE"] = str(Path("data/mock/abuse_sample.json").resolve())
    config = load_config()
    iocs = collect_abuse(None, config)
    assert iocs
    assert iocs[0].source == "AbuseIPDB"
    os.environ.pop("ABUSE_MOCK_FILE")


def test_collect_otx_mock(monkeypatch):
    sample = json.load(open("data/mock/otx_sample.json"))
    monkeypatch.setattr("requests.get", lambda *a, **k: MockResponse(sample))
    iocs = collect_otx("dummy")
    assert iocs
    assert iocs[0].source == "OTX"


def test_collect_urlhaus_mock(monkeypatch):
    sample = json.load(open("data/mock/urlhaus_sample.json"))
    monkeypatch.setattr("requests.get", lambda *a, **k: MockResponse(sample))
    iocs = collect_urlhaus()
    assert iocs
    assert iocs[0].source == "URLHaus"
