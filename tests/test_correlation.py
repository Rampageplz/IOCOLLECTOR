from ioc_collector.report import build_correlation_dataframe, save_correlation_reports
import requests


def test_build_correlation_dataframe():
    iocs = [
        {"ioc_value": "1.1.1.1", "ioc_type": "IP", "source": "AbuseIPDB"},
        {"ioc_value": "1.1.1.1", "ioc_type": "IP", "source": "OTX"},
        {"ioc_value": "evil.com", "ioc_type": "URL", "source": "URLHaus"},
    ]
    df = build_correlation_dataframe(iocs)
    row = df[df["ioc_value"] == "1.1.1.1"].iloc[0]
    assert row["source_count"] == 2
    assert set(row["sources"]) == {"AbuseIPDB", "OTX"}
    assert row["risk_score"] == 20


class DummyResp:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data

    def raise_for_status(self):
        pass


def test_save_correlation_reports(tmp_path, monkeypatch):
    iocs = [
        {"ioc_value": "1.1.1.1", "ioc_type": "IP", "source": "AbuseIPDB"},
        {"ioc_value": "hashval", "ioc_type": "SHA256", "source": "OTX"},
        {"ioc_value": "example.com", "ioc_type": "DOMAIN", "source": "OTX"},
        {"ioc_value": "http://bad.com", "ioc_type": "URL", "source": "URLHaus"},
    ]

    def mock_get(url, timeout=10):
        return DummyResp({"country": "US", "as": "AS13335"})

    monkeypatch.setattr(requests, "get", mock_get)
    csv_path = tmp_path / "out.csv"
    xlsx_path = tmp_path / "out.xlsx"
    save_correlation_reports(iocs, csv_path, xlsx_path)
    assert csv_path.exists()
    assert xlsx_path.exists()
